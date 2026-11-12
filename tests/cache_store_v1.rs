//! SA-2B3a acceptance: the on-disk producer and receiver caches
//! (`spec/cache-store-v1.md`) through the public API.
//!
//! macOS and Linux only: elsewhere no secure root can be opened. The
//! fault-injection cases need test-only seams and live in the unit tests of
//! `src/cache_store.rs`; the `secure_fs` primitive cases live in the unit
//! tests of `src/secure_fs/unix.rs`.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::{
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use syrtis_agent::{
    cache::{CACHE_RETENTION_MILLIS, CacheKey, CacheRole, cache_filename},
    cache_store::{CACHE_BYTES_MAX, CACHE_ENTRIES_MAX, CacheStore},
    report::{Endpoint, GraphRecord, GraphResponse, ReportRequest, encode_response},
    report_peer::decode_reservation,
    secure_fs::{SecureRoot, StorageError},
    security::{
        AGGREGATION_REVISION, LOGICAL_BODY_MAX, MemoryLedger, REMOTE_MEMORY_MAX,
        REPORT_SCHEMA_VERSION, SecurityError, TZDB_REVISION,
    },
};

const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];
const CREATED: i64 = 1_800_000_000_000;
const EXPIRES: i64 = CREATED + 1_000_000;
const NOW: i64 = CREATED + 1;
const MIB: usize = 1024 * 1024;

struct TempHome {
    path: PathBuf,
}

impl TempHome {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "syrtis-cache-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { path }
    }

    fn root(&self) -> PathBuf {
        SUFFIX
            .iter()
            .fold(self.path.clone(), |path, part| path.join(part))
    }

    /// The file of `key` in its role's namespace.
    fn file(&self, key: &CacheKey) -> PathBuf {
        let prefix = match key.role {
            CacheRole::Producer => "pcache-",
            CacheRole::Receiver => "rcache-",
        };
        self.root()
            .join(format!("{prefix}{}", cache_filename(key).unwrap()))
    }

    /// Names in the root that start with `prefix`.
    fn names(&self, prefix: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.root())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(prefix))
            .collect();
        names.sort();
        names
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Retries only `Busy`, for about 2 s: a fork-to-exec child of this binary
/// can still hold a lock this process just released.
fn retry_busy<T>(mut f: impl FnMut() -> Result<T, StorageError>) -> Result<T, StorageError> {
    for _ in 0..200 {
        match f() {
            Err(StorageError::Busy) => thread::sleep(Duration::from_millis(10)),
            other => return other,
        }
    }
    f()
}

fn open_root(home: &TempHome) -> Arc<SecureRoot> {
    Arc::new(retry_busy(|| SecureRoot::open_under(&home.path, SUFFIX)).unwrap())
}

fn open_store(home: &TempHome, role: CacheRole) -> CacheStore {
    CacheStore::open(open_root(home), role, MemoryLedger::default()).unwrap()
}

/// Both stores on one root, as the runtime will hold them.
fn open_both(home: &TempHome, ledger: &MemoryLedger) -> (CacheStore, CacheStore) {
    let root = open_root(home);
    (
        CacheStore::open(Arc::clone(&root), CacheRole::Producer, ledger.clone()).unwrap(),
        CacheStore::open(root, CacheRole::Receiver, ledger.clone()).unwrap(),
    )
}

fn key(role: CacheRole, epoch: u64) -> CacheKey {
    CacheKey {
        aggregation_revision: AGGREGATION_REVISION,
        auth_epoch: epoch,
        // Empty: every client, so the numbered record clients below fit.
        clients: vec![],
        end_date_exclusive: "2025-02-01".into(),
        endpoint: 1,
        grant_id: "22".repeat(16),
        peer_static: "33".repeat(32),
        report_schema: REPORT_SCHEMA_VERSION,
        role,
        source_scope_generation: 3,
        start_date: "2025-01-01".into(),
        timezone: "UTC".into(),
        tzdb_revision: TZDB_REVISION.into(),
    }
}

/// A graph body `validate_entry` accepts for `key`, with `records` records.
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
            model: Some("model".into()),
            provider: None,
            input_tokens: n,
            output_tokens: 1,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            total_tokens: n + 1,
            message_count: 1,
            turn_count: 1,
            cost_nano_usd: 7,
        })
        .collect();
    encode_response(&GraphResponse::from_request(&request, rows, false)).unwrap()
}

fn get(store: &CacheStore, key: &CacheKey) -> Option<Vec<u8>> {
    store
        .get(key, NOW)
        .unwrap()
        .map(|cached| cached.body().to_vec())
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Acceptance (1): each role returns the exact body, also after a reopen.
#[test]
fn each_role_round_trips_the_exact_body_and_survives_reopen() {
    let home = TempHome::new();
    let ledger = MemoryLedger::default();
    let (producer, receiver) = open_both(&home, &ledger);
    let (p, r) = (key(CacheRole::Producer, 1), key(CacheRole::Receiver, 1));
    let (p_body, r_body) = (body(&p, 3), body(&r, 5));
    producer.put(&p, &p_body, CREATED, EXPIRES).unwrap();
    receiver.put(&r, &r_body, CREATED, EXPIRES).unwrap();
    assert_eq!(get(&producer, &p).unwrap(), p_body);
    assert_eq!(get(&receiver, &r).unwrap(), r_body);
    drop((producer, receiver));
    let (producer, receiver) = open_both(&home, &ledger);
    assert_eq!(get(&producer, &p).unwrap(), p_body);
    assert_eq!(get(&receiver, &r).unwrap(), r_body);
    assert_eq!((producer.len(), receiver.len()), (Ok(1), Ok(1)));
}

/// Acceptance (2): a producer file renamed into the receiver namespace is
/// deleted when the receiver opens (its metadata holds the producer role).
#[test]
fn a_producer_file_renamed_into_the_receiver_namespace_is_deleted_on_open() {
    let home = TempHome::new();
    let p = key(CacheRole::Producer, 1);
    let producer = open_store(&home, CacheRole::Producer);
    producer.put(&p, &body(&p, 1), CREATED, EXPIRES).unwrap();
    drop(producer);
    let moved = home
        .root()
        .join(format!("rcache-{}", cache_filename(&p).unwrap()));
    std::fs::rename(home.file(&p), &moved).unwrap();
    let receiver = open_store(&home, CacheRole::Receiver);
    assert!(!exists(&moved));
    assert_eq!(receiver.len(), Ok(0));
}

/// Acceptance (2): the writer binds the role; a key of the other role is
/// refused with nothing written, and reads as a miss.
#[test]
fn a_store_refuses_a_key_of_the_other_role_and_writes_nothing() {
    let home = TempHome::new();
    let receiver = open_store(&home, CacheRole::Receiver);
    let p = key(CacheRole::Producer, 1);
    assert_eq!(
        receiver.put(&p, &body(&p, 1), CREATED, EXPIRES),
        Err(StorageError::Refused(SecurityError::Invalid))
    );
    assert_eq!(home.names("rcache-"), Vec::<String>::new());
    assert_eq!(home.names("pcache-"), Vec::<String>::new());
    assert_eq!(home.names(".rcache-"), Vec::<String>::new());
    assert_eq!(receiver.len(), Ok(0));
    assert!(get(&receiver, &p).is_none());
}

/// Acceptance (3) count cap, and (2): the 257th entry evicts the oldest;
/// a full producer cache leaves the receiver's `put` and `len` alone.
#[test]
fn the_257th_entry_evicts_the_oldest_and_a_full_producer_leaves_the_receiver_alone() {
    let home = TempHome::new();
    let ledger = MemoryLedger::default();
    let (producer, receiver) = open_both(&home, &ledger);
    let r = key(CacheRole::Receiver, 1);
    receiver.put(&r, &body(&r, 1), CREATED, EXPIRES).unwrap();
    let total = CACHE_ENTRIES_MAX as u64 + 1;
    for epoch in 1..=total {
        let p = key(CacheRole::Producer, epoch);
        // Created times increase with the epoch: epoch 1 is the oldest.
        producer
            .put(&p, b"x", CREATED + epoch as i64, EXPIRES)
            .unwrap();
    }
    assert_eq!(producer.len(), Ok(CACHE_ENTRIES_MAX));
    assert!(!exists(&home.file(&key(CacheRole::Producer, 1))));
    assert!(exists(&home.file(&key(CacheRole::Producer, 2))));
    assert!(exists(&home.file(&key(CacheRole::Producer, total))));
    assert_eq!(home.names("pcache-").len(), CACHE_ENTRIES_MAX);
    // The receiver kept its entry and still takes new ones.
    assert_eq!(receiver.len(), Ok(1));
    let r2 = key(CacheRole::Receiver, 2);
    receiver.put(&r2, &body(&r2, 1), CREATED, EXPIRES).unwrap();
    assert_eq!(receiver.len(), Ok(2));
    assert!(get(&receiver, &r).is_some());
    assert_eq!(producer.len(), Ok(CACHE_ENTRIES_MAX));
}

/// Acceptance (3): replacing a key at the count cap evicts nothing.
#[test]
fn replacing_a_key_does_not_add_an_entry() {
    let home = TempHome::new();
    let producer = open_store(&home, CacheRole::Producer);
    for epoch in 1..=CACHE_ENTRIES_MAX as u64 {
        let p = key(CacheRole::Producer, epoch);
        producer
            .put(&p, b"x", CREATED + epoch as i64, EXPIRES)
            .unwrap();
    }
    let last = key(CacheRole::Producer, CACHE_ENTRIES_MAX as u64);
    producer.put(&last, b"yy", CREATED + 999, EXPIRES).unwrap();
    assert_eq!(producer.len(), Ok(CACHE_ENTRIES_MAX));
    assert_eq!(home.names("pcache-").len(), CACHE_ENTRIES_MAX);
    assert!(exists(&home.file(&key(CacheRole::Producer, 1))));
}

/// Acceptance (3) byte cap: the oldest entries are deleted until the new
/// one fits, two of them here.
#[test]
fn the_byte_cap_evicts_the_oldest_until_the_new_entry_fits() {
    let home = TempHome::new();
    let producer = open_store(&home, CacheRole::Producer);
    let big = vec![b'x'; LOGICAL_BODY_MAX];
    // A, B 10 MiB; C, D 16 MiB; E 10 MiB: 62 MiB of bodies. F (16 MiB)
    // needs A and B gone.
    let sizes = [10 * MIB, 10 * MIB, 16 * MIB, 16 * MIB, 10 * MIB, 16 * MIB];
    for (n, size) in sizes.iter().enumerate() {
        let p = key(CacheRole::Producer, n as u64 + 1);
        producer
            .put(&p, &big[..*size], CREATED + n as i64, EXPIRES)
            .unwrap();
        assert!(producer.bytes().unwrap() <= CACHE_BYTES_MAX, "{n}");
    }
    for (n, kept) in [false, false, true, true, true, true].iter().enumerate() {
        let file = home.file(&key(CacheRole::Producer, n as u64 + 1));
        assert_eq!(exists(&file), *kept, "{n}");
    }
    assert_eq!(producer.len(), Ok(4));
}

/// Acceptance (4): at `now == expiresAt` the entry is a miss and its file
/// is gone.
#[test]
fn an_entry_reads_as_none_at_expires_at_and_its_file_is_deleted() {
    let home = TempHome::new();
    let producer = open_store(&home, CacheRole::Producer);
    let p = key(CacheRole::Producer, 1);
    producer.put(&p, &body(&p, 1), CREATED, EXPIRES).unwrap();
    assert!(producer.get(&p, EXPIRES - 1).unwrap().is_some());
    assert!(producer.get(&p, EXPIRES).unwrap().is_none());
    assert!(!exists(&home.file(&p)));
    assert_eq!(producer.len(), Ok(0));
}

/// Acceptance (4): `purge_expired` deletes only expired entries.
#[test]
fn purge_expired_removes_only_expired_entries() {
    let home = TempHome::new();
    let producer = open_store(&home, CacheRole::Producer);
    let (early, late) = (key(CacheRole::Producer, 1), key(CacheRole::Producer, 2));
    producer.put(&early, b"x", CREATED, EXPIRES).unwrap();
    producer.put(&late, b"x", CREATED, EXPIRES + 1).unwrap();
    assert_eq!(producer.purge_expired(EXPIRES - 1), Ok(0));
    assert_eq!(producer.purge_expired(EXPIRES), Ok(1));
    assert!(!exists(&home.file(&early)));
    assert!(exists(&home.file(&late)));
}

/// Acceptance (4): a retention over 30 days is refused and nothing is
/// written; exactly 30 days is accepted (control).
#[test]
fn a_retention_over_30_days_is_refused_and_writes_nothing() {
    let home = TempHome::new();
    let producer = open_store(&home, CacheRole::Producer);
    let p = key(CacheRole::Producer, 1);
    assert_eq!(
        producer.put(&p, b"x", CREATED, CREATED + CACHE_RETENTION_MILLIS + 1),
        Err(StorageError::Refused(SecurityError::Invalid))
    );
    assert_eq!(home.names("pcache-"), Vec::<String>::new());
    assert_eq!(home.names(".pcache-"), Vec::<String>::new());
    producer
        .put(&p, b"x", CREATED, CREATED + CACHE_RETENTION_MILLIS)
        .unwrap();
    assert!(exists(&home.file(&p)));
}

/// Acceptance (5), plus a file grown past its indexed size: each tampered
/// entry reads as `None` and its file is deleted. Each is checked against
/// an untampered control in the same store.
#[test]
fn tampered_entries_read_as_none_and_are_deleted() {
    type Tamper = fn(&mut Vec<u8>);
    let cases: [(&str, Tamper); 5] = [
        ("flip a body bit", |bytes| {
            let last = bytes.len() - 2;
            bytes[last] ^= 0x01;
        }),
        ("truncate", |bytes| bytes.truncate(bytes.len() - 1)),
        ("metadata length past the end", |bytes| {
            let past = u32::try_from(bytes.len()).unwrap();
            bytes[..4].copy_from_slice(&past.to_be_bytes());
        }),
        ("non-canonical metadata", |bytes| {
            // Swap two same-length keys with same-length values, so the
            // file keeps its size and only the key order breaks.
            let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            let text = std::str::from_utf8(&bytes[4..4 + length]).unwrap();
            let created = format!("\"createdAtUnixMs\":{CREATED}");
            let expires = format!("\"expiresAtUnixMs\":{EXPIRES}");
            assert_eq!(created.len(), expires.len());
            let swapped = text
                .replacen(&created, "\u{0}", 1)
                .replacen(&expires, &created, 1)
                .replacen('\u{0}', &expires, 1);
            assert_eq!(swapped.len(), length);
            assert_ne!(swapped, text);
            bytes[4..4 + length].copy_from_slice(swapped.as_bytes());
        }),
        ("grown past the indexed size", |bytes| bytes.push(b' ')),
    ];
    for (label, tamper) in cases {
        let home = TempHome::new();
        let producer = open_store(&home, CacheRole::Producer);
        let (victim, control) = (key(CacheRole::Producer, 1), key(CacheRole::Producer, 2));
        producer
            .put(&victim, &body(&victim, 2), CREATED, EXPIRES)
            .unwrap();
        producer
            .put(&control, &body(&control, 2), CREATED, EXPIRES)
            .unwrap();
        let path = home.file(&victim);
        let mut bytes = std::fs::read(&path).unwrap();
        tamper(&mut bytes);
        // Rewrites in place: same inode, mode 0600, one link.
        std::fs::write(&path, &bytes).unwrap();
        assert!(get(&producer, &victim).is_none(), "{label}");
        assert!(!exists(&path), "{label}");
        assert!(get(&producer, &control).is_some(), "{label}");
        assert_eq!(producer.len(), Ok(1), "{label}");
    }
}

/// Acceptance (6): each removal deletes only its matches, and a reopen
/// agrees.
#[test]
fn remove_grant_remove_peer_and_clear_remove_only_matches() {
    let home = TempHome::new();
    let producer = open_store(&home, CacheRole::Producer);
    let mut keys = Vec::new();
    for (n, (grant, peer)) in [("aa", "01"), ("aa", "02"), ("bb", "01"), ("bb", "02")]
        .iter()
        .enumerate()
    {
        let mut k = key(CacheRole::Producer, n as u64);
        k.grant_id = grant.repeat(16);
        k.peer_static = peer.repeat(32);
        producer.put(&k, b"x", CREATED, EXPIRES).unwrap();
        keys.push(k);
    }
    assert_eq!(producer.remove_grant(&"aa".repeat(16)), Ok(2));
    let alive: Vec<bool> = keys.iter().map(|k| exists(&home.file(k))).collect();
    assert_eq!(alive, [false, false, true, true]);
    assert_eq!(producer.remove_peer(&"01".repeat(32)), Ok(1));
    let alive: Vec<bool> = keys.iter().map(|k| exists(&home.file(k))).collect();
    assert_eq!(alive, [false, false, false, true]);
    drop(producer);
    let producer = open_store(&home, CacheRole::Producer);
    assert_eq!(producer.len(), Ok(1));
    assert_eq!(producer.remove_grant(&"cc".repeat(16)), Ok(0));
    assert_eq!(producer.clear(), Ok(1));
    assert_eq!(home.names("pcache-"), Vec::<String>::new());
    drop(producer);
    assert_eq!(open_store(&home, CacheRole::Producer).len(), Ok(0));
}

/// Acceptance (7): a full ledger is `Busy` and the file stays.
#[test]
fn a_full_ledger_makes_get_busy_and_keeps_the_file() {
    let home = TempHome::new();
    let ledger = MemoryLedger::default();
    let (producer, _receiver) = open_both(&home, &ledger);
    let p = key(CacheRole::Producer, 1);
    producer.put(&p, &body(&p, 4), CREATED, EXPIRES).unwrap();
    let fill = ledger.reserve(REMOTE_MEMORY_MAX).unwrap();
    assert_eq!(producer.get(&p, NOW).err(), Some(StorageError::Busy));
    assert!(exists(&home.file(&p)));
    drop(fill);
    assert!(producer.get(&p, NOW).unwrap().is_some());
}

/// Acceptance (7): `get` needs the file buffer (`size + 1`), the decode
/// cost and the body length at once. One byte less is `Busy` with the file
/// kept; exactly that much succeeds. A success then holds only the body
/// length, released on drop.
#[test]
fn get_needs_the_file_decode_and_copy_reservations_together() {
    let home = TempHome::new();
    let ledger = MemoryLedger::default();
    let (producer, _receiver) = open_both(&home, &ledger);
    let p = key(CacheRole::Producer, 1);
    let bytes = body(&p, 40);
    producer.put(&p, &bytes, CREATED, EXPIRES).unwrap();
    assert_eq!(ledger.used(), 0, "put returns the ledger to its baseline");
    let size = std::fs::metadata(home.file(&p)).unwrap().len() as usize;
    let cost = decode_reservation(&bytes, Endpoint::Graph).unwrap();
    let need = (size + 1) + cost + bytes.len();

    let held = ledger.reserve(REMOTE_MEMORY_MAX - (need - 1)).unwrap();
    assert_eq!(producer.get(&p, NOW).err(), Some(StorageError::Busy));
    assert!(exists(&home.file(&p)));
    drop(held);

    let held = ledger.reserve(REMOTE_MEMORY_MAX - need).unwrap();
    let cached = producer.get(&p, NOW).unwrap().unwrap();
    assert_eq!(cached.body(), bytes.as_slice());
    assert_eq!(ledger.used(), REMOTE_MEMORY_MAX - need + bytes.len());
    drop(held);
    assert_eq!(ledger.used(), bytes.len());
    drop(cached);
    assert_eq!(ledger.used(), 0);
}

/// Acceptance (7): `open` and `put` return the ledger to its baseline.
#[test]
fn open_and_put_return_the_ledger_to_its_baseline() {
    let home = TempHome::new();
    let ledger = MemoryLedger::default();
    let baseline = ledger.reserve(1_000).unwrap();
    let (producer, receiver) = open_both(&home, &ledger);
    let (p, r) = (key(CacheRole::Producer, 1), key(CacheRole::Receiver, 1));
    producer.put(&p, &body(&p, 3), CREATED, EXPIRES).unwrap();
    receiver.put(&r, &body(&r, 3), CREATED, EXPIRES).unwrap();
    assert_eq!(ledger.used(), 1_000);
    drop((producer, receiver));
    let (producer, _receiver) = open_both(&home, &ledger);
    assert_eq!(producer.len(), Ok(1));
    assert_eq!(ledger.used(), 1_000);
    drop(baseline);
}

/// Acceptance (7): a body whose decode cost exceeds the whole ledger can
/// never be read: `None` and the file deleted, not `Busy`.
#[test]
fn a_body_costing_more_than_the_whole_ledger_is_deleted_not_busy() {
    let home = TempHome::new();
    let ledger = MemoryLedger::default();
    let (producer, _receiver) = open_both(&home, &ledger);
    let p = key(CacheRole::Producer, 1);
    let bytes = body(&p, 70_000);
    assert!(bytes.len() <= LOGICAL_BODY_MAX, "{}", bytes.len());
    let cost = decode_reservation(&bytes, Endpoint::Graph).unwrap();
    assert!(cost > REMOTE_MEMORY_MAX, "{cost}");
    producer.put(&p, &bytes, CREATED, EXPIRES).unwrap();
    assert!(producer.get(&p, NOW).unwrap().is_none());
    assert!(!exists(&home.file(&p)));
    assert_eq!(ledger.used(), 0);
}

/// The three reservations of a `get` are held together: a body whose decode
/// cost alone fits the ledger but whose three reservations do not is deleted
/// too, since it would otherwise be `Busy` on every call.
#[test]
fn a_body_whose_three_reservations_exceed_the_ledger_is_deleted_not_busy() {
    let home = TempHome::new();
    let ledger = MemoryLedger::default();
    let (producer, _receiver) = open_both(&home, &ledger);
    let p = key(CacheRole::Producer, 1);
    let bytes = body(&p, 66_000);
    let cost = decode_reservation(&bytes, Endpoint::Graph).unwrap();
    assert!(cost <= REMOTE_MEMORY_MAX, "{cost}");
    producer.put(&p, &bytes, CREATED, EXPIRES).unwrap();
    let size = std::fs::metadata(home.file(&p)).unwrap().len() as usize;
    assert!(size + 1 + cost + bytes.len() > REMOTE_MEMORY_MAX, "{cost}");
    assert!(producer.get(&p, NOW).unwrap().is_none());
    assert!(!exists(&home.file(&p)));
    assert_eq!(ledger.used(), 0);
}

/// Acceptance (7b): a file swapped after indexing (a symlink; a `0644`
/// file) is `UnsafeState`, nothing is followed or deleted, and the store
/// stays unknown until it is reopened.
#[test]
fn a_swapped_file_is_unsafe_state_and_sticky_until_reopen() {
    for swap in ["symlink", "mode 0644"] {
        let home = TempHome::new();
        let producer = open_store(&home, CacheRole::Producer);
        let (victim, other) = (key(CacheRole::Producer, 1), key(CacheRole::Producer, 2));
        producer
            .put(&victim, &body(&victim, 1), CREATED, EXPIRES)
            .unwrap();
        producer
            .put(&other, &body(&other, 1), CREATED, EXPIRES)
            .unwrap();
        let path = home.file(&victim);
        let original = std::fs::read(&path).unwrap();
        let outside = home.path.join("outside");
        match swap {
            "symlink" => {
                std::fs::rename(&path, &outside).unwrap();
                symlink(&outside, &path).unwrap();
            }
            _ => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap(),
        }
        assert_eq!(
            producer.get(&victim, NOW).err(),
            Some(StorageError::UnsafeState),
            "{swap}"
        );
        // Sticky: the untouched entry is a miss and writes are `Unknown`.
        assert!(get(&producer, &other).is_none(), "{swap}");
        assert_eq!(
            producer.put(&other, b"x", CREATED, EXPIRES),
            Err(StorageError::Unknown),
            "{swap}"
        );
        assert_eq!(producer.clear(), Err(StorageError::Unknown), "{swap}");
        // Nothing was followed, deleted or changed.
        assert!(exists(&path), "{swap}");
        let target = if swap == "symlink" { &outside } else { &path };
        assert_eq!(std::fs::read(target).unwrap(), original, "{swap}");
        // While the swapped file is there a reopen fails closed too.
        drop(producer);
        assert_eq!(
            CacheStore::open(
                open_root(&home),
                CacheRole::Producer,
                MemoryLedger::default()
            )
            .err(),
            Some(StorageError::UnsafeState),
            "{swap}"
        );
        // After repair a reopen recovers.
        std::fs::remove_file(&path).unwrap();
        let producer = open_store(&home, CacheRole::Producer);
        assert_eq!(get(&producer, &other).unwrap(), body(&other, 1), "{swap}");
    }
}

/// Acceptance (9): temp files left by a crash in the store's own namespace
/// are removed on open; the other role's are not.
#[test]
fn stale_temps_are_removed_on_open() {
    let home = TempHome::new();
    drop(open_store(&home, CacheRole::Producer));
    let dir = home.root();
    let mine = dir.join(".pcache-00.tmp");
    let theirs = dir.join(".rcache-00.tmp");
    std::fs::write(&mine, b"x").unwrap();
    std::fs::write(&theirs, b"x").unwrap();
    let _producer = open_store(&home, CacheRole::Producer);
    assert!(!exists(&mine));
    assert!(exists(&theirs));
}

/// `open` reserves `size + 1` before reading each file: without room it is
/// `Busy`, and the file stays.
#[test]
fn open_is_busy_without_room_for_a_file_and_keeps_it() {
    let home = TempHome::new();
    let p = key(CacheRole::Producer, 1);
    let producer = open_store(&home, CacheRole::Producer);
    producer.put(&p, &body(&p, 1), CREATED, EXPIRES).unwrap();
    drop(producer);
    let ledger = MemoryLedger::default();
    let fill = ledger.reserve(REMOTE_MEMORY_MAX).unwrap();
    assert_eq!(
        CacheStore::open(open_root(&home), CacheRole::Producer, ledger.clone()).err(),
        Some(StorageError::Busy)
    );
    assert!(exists(&home.file(&p)));
    drop(fill);
    let producer = CacheStore::open(open_root(&home), CacheRole::Producer, ledger).unwrap();
    assert_eq!(producer.len(), Ok(1));
}
