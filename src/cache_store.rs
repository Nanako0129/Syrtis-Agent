//! Producer and receiver report caches on the secure root
//! (`spec/cache-store-v1.md`).
//!
//! Entries are the frozen `src/cache.rs` format: metadata, body, file name and
//! the 30-day rule come from there and are not re-derived here. Every byte read
//! into memory is reserved on the [`MemoryLedger`] first. A cache entry grants
//! nothing: this module reads no state and decides no grant.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use crate::{
    cache::{
        CacheKey, CacheMetadata, CacheRole, cache_filename, decode_metadata, encode_metadata,
        validate_entry,
    },
    report::Endpoint,
    report_peer::decode_reservation,
    secure_fs::{CACHE_PREFIXES, SecureRoot, StorageError},
    security::{
        LOGICAL_BODY_MAX, MemoryLedger, MemoryReservation, REMOTE_MEMORY_MAX, SecurityError,
    },
};

/// Entries per role.
pub const CACHE_ENTRIES_MAX: usize = 256;
/// File bytes per role, summed over the entries' file sizes.
pub const CACHE_BYTES_MAX: u64 = 64 * 1024 * 1024;
/// Metadata bytes per entry.
pub const METADATA_MAX: usize = 64 * 1024;
/// Length prefix of the metadata (`u32` big-endian).
const LENGTH_BYTES: usize = 4;
/// The largest file an entry can be: length, metadata, body.
pub const ENTRY_FILE_MAX: usize = LENGTH_BYTES + METADATA_MAX + LOGICAL_BODY_MAX;

/// A body `get` returned. It holds a ledger reservation of its length,
/// released on drop.
pub struct CachedBody {
    body: Vec<u8>,
    _reservation: MemoryReservation,
}

impl CachedBody {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl std::fmt::Debug for CachedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedBody")
            .field("len", &self.body.len())
            .finish()
    }
}

#[derive(Clone, Debug)]
struct Indexed {
    size: u64,
    created_at_ms: i64,
    expires_at_ms: i64,
    grant_id: String,
    peer_static: String,
}

/// One role's cache. One instance per `(root, role)`.
///
/// One mutex guards the index and serializes every operation, file I/O
/// included. `None` in it is the sticky unknown state.
// ponytail: one lock for reads and writes; split it if concurrent `get`s
// ever measurably queue.
pub struct CacheStore {
    root: Arc<SecureRoot>,
    role: CacheRole,
    ledger: MemoryLedger,
    index: Mutex<Option<BTreeMap<String, Indexed>>>,
}

type Index = BTreeMap<String, Indexed>;

fn prefix(role: CacheRole) -> &'static str {
    match role {
        CacheRole::Producer => CACHE_PREFIXES[0],
        CacheRole::Receiver => CACHE_PREFIXES[1],
    }
}

/// `u32be(metadata length) ‖ metadata ‖ body`, split; `None` when the
/// length field is over [`METADATA_MAX`] or past the end of the file.
fn split(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let length: [u8; LENGTH_BYTES] = bytes.get(..LENGTH_BYTES)?.try_into().ok()?;
    let length = usize::try_from(u32::from_be_bytes(length)).ok()?;
    if length > METADATA_MAX {
        return None;
    }
    let end = LENGTH_BYTES.checked_add(length)?;
    let metadata = bytes.get(LENGTH_BYTES..end)?;
    let body = bytes.get(end..)?;
    (body.len() <= LOGICAL_BODY_MAX).then_some((metadata, body))
}

enum Loaded {
    Entry(Indexed),
    Delete,
    Gone,
}

impl CacheStore {
    /// Removes the role's stale temp files, lists its entries and indexes
    /// each one from its metadata (no body decode). An entry whose metadata
    /// does not decode, holds the other role, does not hash to its file
    /// name, or whose file is over [`ENTRY_FILE_MAX`] is deleted. Each file
    /// read reserves `size + 1` first: no room is `Busy`.
    pub fn open(
        root: Arc<SecureRoot>,
        role: CacheRole,
        ledger: MemoryLedger,
    ) -> Result<Self, StorageError> {
        let prefix = prefix(role);
        root.remove_stale_temps(prefix)?;
        let mut index = Index::new();
        for (name, size) in root.list(prefix)? {
            match load(&root, &ledger, role, &name, size)? {
                Loaded::Entry(entry) => {
                    index.insert(name, entry);
                }
                Loaded::Delete => root.remove_file(&name)?,
                Loaded::Gone => {}
            }
        }
        Ok(Self {
            root,
            role,
            ledger,
            index: Mutex::new(Some(index)),
        })
    }

    /// Stores `body` under `key`, replacing the entry of the same key.
    /// A key of the other role, an invalid key or a retention over 30 days
    /// is `Refused(Invalid)`; metadata over [`METADATA_MAX`] or a body over
    /// `LOGICAL_BODY_MAX` is `Refused(Bounds)`. Nothing is written then.
    /// Before writing, the oldest entries are deleted until the new one
    /// fits both caps. The file buffer is reserved on the ledger for the
    /// call (`Busy` without room).
    pub fn put(
        &self,
        key: &CacheKey,
        body: &[u8],
        created_at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<(), StorageError> {
        let invalid = |_| StorageError::Refused(SecurityError::Invalid);
        if key.role != self.role {
            return Err(StorageError::Refused(SecurityError::Invalid));
        }
        let name = format!(
            "{}{}",
            prefix(self.role),
            cache_filename(key).map_err(invalid)?
        );
        let metadata = CacheMetadata::for_body(key.clone(), created_at_ms, expires_at_ms, body);
        let metadata = encode_metadata(&metadata).map_err(invalid)?;
        if metadata.len() > METADATA_MAX || body.len() > LOGICAL_BODY_MAX {
            return Err(StorageError::Refused(SecurityError::Bounds));
        }
        let total = LENGTH_BYTES + metadata.len() + body.len();
        let _buffer = self.ledger.reserve(total).ok_or(StorageError::Busy)?;
        let mut bytes = Vec::with_capacity(total);
        // `metadata.len() <= METADATA_MAX`, so it fits a `u32`.
        bytes.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&metadata);
        bytes.extend_from_slice(body);

        let mut guard = self.lock();
        let index = guard.as_mut().ok_or(StorageError::Unknown)?;
        let result = self.evict_for(index, &name, total as u64).and_then(|()| {
            self.root
                .stage(&name, &bytes)
                .and_then(|staged| staged.publish())
        });
        if result.is_err() {
            *guard = None;
            return Err(StorageError::Unknown);
        }
        index.insert(
            name,
            Indexed {
                size: total as u64,
                created_at_ms,
                expires_at_ms,
                grant_id: key.grant_id.clone(),
                peer_static: key.peer_static.clone(),
            },
        );
        Ok(())
    }

    /// The validated body stored under `key`, or `None`: not indexed, a key
    /// of the other role, expired, or failing validation (the file is then
    /// deleted). Three separate reservations: the file buffer (`size + 1`)
    /// before the read, the decode cost after it, and the body length
    /// before `validate_entry`, which copies the body. Any of them failing
    /// is `Busy` with the file left in place. The first two are released on
    /// return; the third travels with the returned [`CachedBody`]. A file
    /// that fails the root's file checks is `UnsafeState` and makes the
    /// store sticky unknown; in that state `get` is `None`.
    pub fn get(&self, key: &CacheKey, now_ms: i64) -> Result<Option<CachedBody>, StorageError> {
        if key.role != self.role {
            return Ok(None);
        }
        let Ok(hash) = cache_filename(key) else {
            return Ok(None);
        };
        let name = format!("{}{hash}", prefix(self.role));
        let mut guard = self.lock();
        let Some(index) = guard.as_mut() else {
            return Ok(None);
        };
        let Some(size) = index.get(&name).map(|entry| entry.size) else {
            return Ok(None);
        };
        let size = usize::try_from(size).map_err(|_| StorageError::Corrupt)?;
        let _file = self
            .ledger
            .reserve(size.saturating_add(1))
            .ok_or(StorageError::Busy)?;
        let bytes = match self.root.read_file_sized(&name, size) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                index.remove(&name);
                return Ok(None);
            }
            Err(StorageError::Corrupt) => return self.delete(&mut guard, &name),
            Err(StorageError::UnsafeState) => {
                *guard = None;
                return Err(StorageError::UnsafeState);
            }
            Err(error) => return Err(error),
        };
        let Some((metadata, body)) = split(&bytes) else {
            return self.delete(&mut guard, &name);
        };
        let Ok(endpoint) = Endpoint::try_from(key.endpoint) else {
            return self.delete(&mut guard, &name);
        };
        // The three reservations are held together, so it is their sum
        // that has to fit the ledger.
        let fits = |cost: usize| {
            size.saturating_add(1)
                .saturating_add(cost)
                .saturating_add(body.len())
                <= REMOTE_MEMORY_MAX
        };
        let cost = match decode_reservation(body, endpoint) {
            Ok(cost) if fits(cost) => cost,
            // Refused by the shape gate, or more than the whole ledger
            // even when it is idle: no retry can ever decode it.
            _ => return self.delete(&mut guard, &name),
        };
        let _decode = self.ledger.reserve(cost).ok_or(StorageError::Busy)?;
        let copy = self.ledger.reserve(body.len()).ok_or(StorageError::Busy)?;
        match validate_entry(metadata, body, &hash, self.role, now_ms) {
            Ok(entry) => Ok(Some(CachedBody {
                body: entry.body,
                _reservation: copy,
            })),
            Err(_) => self.delete(&mut guard, &name),
        }
    }

    /// Deletes every entry of `grant_id` (lowercase hex); returns how many.
    pub fn remove_grant(&self, grant_id: &str) -> Result<usize, StorageError> {
        self.remove_where(|entry| entry.grant_id == grant_id)
    }

    /// Deletes every entry of `peer_static` (lowercase hex); returns how many.
    pub fn remove_peer(&self, peer_static: &str) -> Result<usize, StorageError> {
        self.remove_where(|entry| entry.peer_static == peer_static)
    }

    /// Deletes every entry; returns how many.
    pub fn clear(&self) -> Result<usize, StorageError> {
        self.remove_where(|_| true)
    }

    /// Deletes every entry with `now_ms >= expiresAtUnixMs`; returns how
    /// many.
    pub fn purge_expired(&self, now_ms: i64) -> Result<usize, StorageError> {
        self.remove_where(|entry| now_ms >= entry.expires_at_ms)
    }

    /// Indexed entries; `Unknown` in the sticky unknown state.
    pub fn len(&self) -> Result<usize, StorageError> {
        Ok(self.lock().as_ref().ok_or(StorageError::Unknown)?.len())
    }

    /// Whether no entry is indexed; `Unknown` in the sticky unknown state.
    pub fn is_empty(&self) -> Result<bool, StorageError> {
        self.len().map(|len| len == 0)
    }

    /// Indexed file bytes; `Unknown` in the sticky unknown state.
    pub fn bytes(&self) -> Result<u64, StorageError> {
        Ok(self
            .lock()
            .as_ref()
            .ok_or(StorageError::Unknown)?
            .values()
            .map(|entry| entry.size)
            .sum())
    }

    fn lock(&self) -> MutexGuard<'_, Option<Index>> {
        // A panic while holding the lock leaves the index as of the last
        // completed step, which still matches the disk entry by entry.
        self.index.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Deletes the oldest entries other than `name` (by `createdAtUnixMs`,
    /// then name) until `name` at `size` bytes fits both caps.
    fn evict_for(&self, index: &mut Index, name: &str, size: u64) -> Result<(), StorageError> {
        let mut oldest: Vec<(i64, String)> = index
            .iter()
            .filter(|(other, _)| other.as_str() != name)
            .map(|(other, entry)| (entry.created_at_ms, other.clone()))
            .collect();
        oldest.sort();
        let mut oldest = oldest.into_iter();
        loop {
            let others = index.len() - usize::from(index.contains_key(name));
            let other_bytes: u64 = index
                .iter()
                .filter(|(other, _)| other.as_str() != name)
                .map(|(_, entry)| entry.size)
                .sum();
            if others < CACHE_ENTRIES_MAX && other_bytes + size <= CACHE_BYTES_MAX {
                return Ok(());
            }
            // `size <= ENTRY_FILE_MAX < CACHE_BYTES_MAX`, so the loop ends
            // at the latest when no other entry is left.
            let Some((_, victim)) = oldest.next() else {
                return Ok(());
            };
            self.root.remove_file(&victim)?;
            index.remove(&victim);
        }
    }

    /// Deletes `name`'s file and index entry; `Ok(None)`, or `Unknown`
    /// (sticky) when the removal fails.
    fn delete(
        &self,
        guard: &mut MutexGuard<'_, Option<Index>>,
        name: &str,
    ) -> Result<Option<CachedBody>, StorageError> {
        match self.root.remove_file(name) {
            Ok(()) => {
                if let Some(index) = guard.as_mut() {
                    index.remove(name);
                }
                Ok(None)
            }
            Err(_) => {
                **guard = None;
                Err(StorageError::Unknown)
            }
        }
    }

    fn remove_where(&self, matches: impl Fn(&Indexed) -> bool) -> Result<usize, StorageError> {
        let mut guard = self.lock();
        let index = guard.as_mut().ok_or(StorageError::Unknown)?;
        let victims: Vec<String> = index
            .iter()
            .filter(|(_, entry)| matches(entry))
            .map(|(name, _)| name.clone())
            .collect();
        for victim in &victims {
            if self.root.remove_file(victim).is_err() {
                *guard = None;
                return Err(StorageError::Unknown);
            }
            index.remove(victim);
        }
        Ok(victims.len())
    }
}

/// Reads one listed file and indexes it from its metadata.
fn load(
    root: &SecureRoot,
    ledger: &MemoryLedger,
    role: CacheRole,
    name: &str,
    size: u64,
) -> Result<Loaded, StorageError> {
    let Some(size) = usize::try_from(size)
        .ok()
        .filter(|size| *size <= ENTRY_FILE_MAX)
    else {
        return Ok(Loaded::Delete);
    };
    let _file = ledger.reserve(size + 1).ok_or(StorageError::Busy)?;
    let bytes = match root.read_file_sized(name, size) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(Loaded::Gone),
        Err(StorageError::Corrupt) => return Ok(Loaded::Delete),
        Err(error) => return Err(error),
    };
    let Some((metadata, _)) = split(&bytes) else {
        return Ok(Loaded::Delete);
    };
    let Ok(metadata) = decode_metadata(metadata) else {
        return Ok(Loaded::Delete);
    };
    let key = &metadata.cache_key;
    let named = cache_filename(key)
        .is_ok_and(|hash| name.strip_prefix(prefix(role)) == Some(hash.as_str()));
    if key.role != role || !named {
        return Ok(Loaded::Delete);
    }
    Ok(Loaded::Entry(Indexed {
        size: bytes.len() as u64,
        created_at_ms: metadata.created_at_unix_ms,
        expires_at_ms: metadata.expires_at_unix_ms,
        grant_id: key.grant_id.clone(),
        peer_static: key.peer_static.clone(),
    }))
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests {
    use super::*;
    use crate::{
        report::{GraphRecord, GraphResponse, ReportRequest, encode_response},
        secure_fs::{
            Step,
            seams::{self, Reset},
            test_support::{SUFFIX, TempHome, retry_busy},
        },
        security::{AGGREGATION_REVISION, REPORT_SCHEMA_VERSION, TZDB_REVISION},
    };

    const CREATED: i64 = 1_800_000_000_000;
    const EXPIRES: i64 = CREATED + 1_000_000;
    const NOW: i64 = CREATED + 1;

    fn key(epoch: u64) -> CacheKey {
        CacheKey {
            aggregation_revision: AGGREGATION_REVISION,
            auth_epoch: epoch,
            clients: vec![],
            end_date_exclusive: "2025-02-01".into(),
            endpoint: 1,
            grant_id: "22".repeat(16),
            peer_static: "33".repeat(32),
            report_schema: REPORT_SCHEMA_VERSION,
            role: CacheRole::Producer,
            source_scope_generation: 3,
            start_date: "2025-01-01".into(),
            timezone: "UTC".into(),
            tzdb_revision: TZDB_REVISION.into(),
        }
    }

    /// A body `validate_entry` accepts for `key`, with `records` records.
    fn body(key: &CacheKey, records: u64) -> Vec<u8> {
        let request = ReportRequest {
            aggregation_revision: key.aggregation_revision,
            auth_epoch: key.auth_epoch,
            clients: key.clients.clone(),
            end_date_exclusive: key.end_date_exclusive.clone(),
            endpoint: key.endpoint,
            grant_id: key.grant_id.clone(),
            protocol: 1,
            report_schema: key.report_schema,
            request_id: "11".repeat(16),
            source_scope_generation: key.source_scope_generation,
            start_date: key.start_date.clone(),
            timezone: key.timezone.clone(),
            tzdb_revision: key.tzdb_revision.clone(),
        };
        let rows = (0..records)
            .map(|n| GraphRecord {
                date: "2025-01-02".into(),
                client: format!("{n:06}"),
                model: None,
                provider: None,
                input_tokens: n,
                output_tokens: 0,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                reasoning_tokens: 0,
                total_tokens: n,
                message_count: 0,
                turn_count: 0,
                cost_nano_usd: 0,
            })
            .collect();
        encode_response(&GraphResponse::from_request(&request, rows, false)).unwrap()
    }

    fn open(home: &TempHome) -> CacheStore {
        retry_busy(|| {
            let root = Arc::new(SecureRoot::open_under(&home.path, SUFFIX)?);
            CacheStore::open(root, CacheRole::Producer, MemoryLedger::default())
        })
        .unwrap()
    }

    fn fail_at(step: Step) {
        seams::set_hook(Some(Box::new(move |at| {
            if at == step {
                Err(std::io::Error::other("injected"))
            } else {
                Ok(())
            }
        })));
    }

    /// The store is sticky unknown: `get` is `None`, writes and removals
    /// are `Unknown`, and so are `len` and `bytes`.
    fn assert_unknown(store: &CacheStore, label: &str) {
        let probe = key(1);
        assert!(store.get(&probe, NOW).unwrap().is_none(), "{label}");
        assert_eq!(
            store.put(&probe, &body(&probe, 0), CREATED, EXPIRES),
            Err(StorageError::Unknown),
            "{label}"
        );
        assert_eq!(store.clear(), Err(StorageError::Unknown), "{label}");
        assert_eq!(
            store.purge_expired(NOW),
            Err(StorageError::Unknown),
            "{label}"
        );
        assert_eq!(store.len(), Err(StorageError::Unknown), "{label}");
        assert_eq!(store.bytes(), Err(StorageError::Unknown), "{label}");
    }

    /// Acceptance (8): a failed replace makes the store sticky unknown; a
    /// reopen sees the old body (failure at the rename) or the new one
    /// (failure at the directory sync after it), never anything else.
    #[test]
    fn a_failed_put_is_sticky_unknown_and_reopens_old_or_new() {
        for (step, expect_new) in [
            (Step::CreateTemp, false),
            (Step::SyncFile, false),
            (Step::Rename, false),
            (Step::SyncDir, true),
        ] {
            let home = TempHome::new();
            let store = open(&home);
            let probe = key(1);
            let (old, new) = (body(&probe, 1), body(&probe, 2));
            store.put(&probe, &old, CREATED, EXPIRES).unwrap();
            let _reset = Reset;
            fail_at(step);
            assert_eq!(
                store.put(&probe, &new, CREATED, EXPIRES),
                Err(StorageError::Unknown),
                "{step:?}"
            );
            seams::set_hook(None);
            assert_unknown(&store, &format!("{step:?}"));
            drop(store);
            let reopened = open(&home);
            let got = reopened.get(&probe, NOW).unwrap().unwrap();
            let expected = if expect_new { &new } else { &old };
            assert_eq!(got.body(), expected.as_slice(), "{step:?}");
            assert_eq!(reopened.len(), Ok(1), "{step:?}");
        }
    }

    /// Control for the test above: the same replace without a failure.
    #[test]
    fn control_the_same_put_succeeds_and_reopens_new() {
        let home = TempHome::new();
        let store = open(&home);
        let probe = key(1);
        store
            .put(&probe, &body(&probe, 1), CREATED, EXPIRES)
            .unwrap();
        store
            .put(&probe, &body(&probe, 2), CREATED, EXPIRES)
            .unwrap();
        drop(store);
        let got = open(&home).get(&probe, NOW).unwrap().unwrap();
        assert_eq!(got.body(), body(&probe, 2).as_slice());
    }

    /// Acceptance (8): a failed removal (`Step::Unlink`, or the directory
    /// sync after it) is sticky unknown, from every path that removes:
    /// `clear`, `remove_grant`, eviction in `put`, and the delete of an
    /// entry `get` found invalid.
    #[test]
    fn a_failed_unlink_is_sticky_unknown() {
        for step in [Step::Unlink, Step::SyncDir] {
            for path in ["clear", "remove_grant", "evict", "get"] {
                let home = TempHome::new();
                let store = open(&home);
                let first = key(1);
                store
                    .put(&first, &body(&first, 0), CREATED, EXPIRES)
                    .unwrap();
                let _reset = Reset;
                fail_at(step);
                let label = format!("{step:?} {path}");
                let result = match path {
                    "clear" => store.clear().map(|_| ()),
                    "remove_grant" => store.remove_grant(&first.grant_id).map(|_| ()),
                    "evict" => {
                        // Fill to the count cap without the hook, then one
                        // more put must evict `first`.
                        seams::set_hook(None);
                        for epoch in 2..=CACHE_ENTRIES_MAX as u64 {
                            let other = key(epoch);
                            store.put(&other, b"x", CREATED + 1, EXPIRES).unwrap();
                        }
                        fail_at(step);
                        let last = key(CACHE_ENTRIES_MAX as u64 + 1);
                        store.put(&last, b"x", CREATED + 1, EXPIRES)
                    }
                    _ => {
                        // Expired: `get` deletes it.
                        store.get(&first, EXPIRES).map(|_| ())
                    }
                };
                assert_eq!(result, Err(StorageError::Unknown), "{label}");
                seams::set_hook(None);
                assert_unknown(&store, &label);
            }
        }
    }
}
