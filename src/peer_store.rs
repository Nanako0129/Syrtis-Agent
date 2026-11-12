//! Receiver peer store: `peers.json` on the secure root (`spec/peer-store-v1.md`).
//!
//! It shares the [`SecureRoot`] (and so the owner lock) of the
//! [`StateStore`]. A record is written only from a [`ConfirmedGrant`] and
//! grants the receiver nothing: every request is still authorized by the
//! producer against its own grant and the Noise static binding.

use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockWriteGuard};

use serde::{Deserialize, Serialize};

use crate::{
    canonical::CanonicalJsonV1,
    pairing::ConfirmedGrant,
    secure_fs::{SecureRoot, StorageError},
    security::{
        PEER_PROTOCOL_VERSION, PairOffer, SecurityError, decode_fixed_hex, hex_encode, pair_url,
    },
    state_store::{NODE_LABEL_MAX_BYTES, StateStore},
};

pub const PEERS_FILE: &str = "peers.json";
pub const PEERS_SCHEMA_VERSION: u64 = 1;
/// Read bound. Sixteen records stay far below it.
pub const PEERS_FILE_MAX_BYTES: usize = 1024 * 1024;
/// Records, one per producer.
pub const PEERS_MAX: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    Active,
    Revoked,
    Expired,
}

/// One producer this receiver paired with. Holds no secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRecord {
    pub auth_epoch: u64,
    /// Receiver wall clock, Unix ms.
    pub created_at_ms: i64,
    /// Producer wall clock, Unix ms; never compared with `created_at_ms`.
    pub expires_at_ms: i64,
    pub grant_id: [u8; 16],
    pub host: String,
    pub initiator_static: [u8; 32],
    pub node_label: Option<String>,
    pub pending_id: [u8; 16],
    pub port: u16,
    pub responder_static: [u8; 32],
    pub source_scope_generation: u64,
    pub state: PeerState,
}

impl PeerRecord {
    /// The record for a grant Grant status confirmed `active`. `host` and
    /// `port` are the claimed offer's, carried by the grant; `node_label` is
    /// the receiver's own input. Nothing is validated here:
    /// [`PeerStore::upsert`] refuses what load would refuse.
    pub fn from_confirmed(
        grant: &ConfirmedGrant,
        node_label: Option<String>,
        created_at_ms: i64,
    ) -> Self {
        Self {
            auth_epoch: grant.auth_epoch,
            created_at_ms,
            expires_at_ms: grant.expires_at_ms,
            grant_id: grant.grant_id,
            host: grant.host.clone(),
            initiator_static: grant.initiator_static,
            node_label,
            pending_id: grant.pending_id,
            port: grant.port,
            responder_static: grant.responder_static,
            source_scope_generation: grant.source_scope_generation,
            state: PeerState::Active,
        }
    }
}

/// Whether the receiver may use `record`: `active`, and bound to the
/// identity in the state store *now*. The identity is read on every call,
/// so a record made before a reset is unusable after it. An unreadable
/// state is unusable.
pub fn usable(record: &PeerRecord, store: &StateStore) -> bool {
    record.state == PeerState::Active
        && store
            .state()
            .and_then(|state| state.identity_public())
            .is_ok_and(|identity| identity == record.initiator_static)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PeersFile {
    peers: Vec<PeerFile>,
    schema: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PeerFile {
    auth_epoch: u64,
    created_at: i64,
    expires_at: i64,
    grant_id: String,
    host: String,
    initiator_static: String,
    node_label: Option<String>,
    pending_id: String,
    port: u16,
    responder_static: String,
    source_scope_generation: u64,
    state: PeerState,
}

/// CanonicalJsonV1 bytes of `peers.json`. Fails (`Corrupt`) only on a
/// string CanonicalJsonV1 refuses, such as a non-NFC node label.
pub fn encode_peers(peers: &[PeerRecord]) -> Result<Vec<u8>, StorageError> {
    let file = PeersFile {
        peers: peers
            .iter()
            .map(|peer| PeerFile {
                auth_epoch: peer.auth_epoch,
                created_at: peer.created_at_ms,
                expires_at: peer.expires_at_ms,
                grant_id: hex_encode(&peer.grant_id),
                host: peer.host.clone(),
                initiator_static: hex_encode(&peer.initiator_static),
                node_label: peer.node_label.clone(),
                pending_id: hex_encode(&peer.pending_id),
                port: peer.port,
                responder_static: hex_encode(&peer.responder_static),
                source_scope_generation: peer.source_scope_generation,
                state: peer.state,
            })
            .collect(),
        schema: PEERS_SCHEMA_VERSION,
    };
    CanonicalJsonV1::encode(&file).map_err(|_| StorageError::Corrupt)
}

/// Strict decode of `peers.json`, the one load rule: an integer `schema`
/// other than 1 is `Incompatible`; everything else that fails is `Corrupt`.
/// Every write runs its bytes through this first.
pub fn decode_peers(bytes: &[u8]) -> Result<Vec<PeerRecord>, StorageError> {
    if bytes.len() > PEERS_FILE_MAX_BYTES {
        return Err(StorageError::Corrupt);
    }
    let value = CanonicalJsonV1::decode_value(bytes).map_err(corrupt)?;
    let schema = value
        .as_object()
        .and_then(|object| object.get("schema"))
        .filter(|schema| schema.is_u64() || schema.is_i64())
        .ok_or(StorageError::Corrupt)?;
    if schema.as_u64() != Some(PEERS_SCHEMA_VERSION) {
        return Err(StorageError::Incompatible);
    }
    // `decode` re-encodes and compares bytes: a missing, extra or reordered
    // key, or a non-NFC string, is refused with any other non-canonical form.
    let file: PeersFile = CanonicalJsonV1::decode(bytes).map_err(corrupt)?;
    if file.peers.len() > PEERS_MAX {
        return Err(StorageError::Corrupt);
    }
    let peers = file
        .peers
        .into_iter()
        .map(|peer| {
            let label_ok = peer
                .node_label
                .as_ref()
                .is_none_or(|label| label.len() <= NODE_LABEL_MAX_BYTES);
            if !label_ok || !endpoint_valid(&peer.host, peer.port) {
                return Err(StorageError::Corrupt);
            }
            Ok(PeerRecord {
                auth_epoch: peer.auth_epoch,
                created_at_ms: peer.created_at,
                expires_at_ms: peer.expires_at,
                grant_id: decode_fixed_hex(&peer.grant_id).map_err(corrupt)?,
                host: peer.host,
                initiator_static: decode_fixed_hex(&peer.initiator_static).map_err(corrupt)?,
                node_label: peer.node_label,
                pending_id: decode_fixed_hex(&peer.pending_id).map_err(corrupt)?,
                port: peer.port,
                responder_static: decode_fixed_hex(&peer.responder_static).map_err(corrupt)?,
                source_scope_generation: peer.source_scope_generation,
                state: peer.state,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Strictly increasing: sorted and unique in one check.
    if !peers
        .windows(2)
        .all(|pair| pair[0].responder_static < pair[1].responder_static)
    {
        return Err(StorageError::Corrupt);
    }
    Ok(peers)
}

fn corrupt<E>(_: E) -> StorageError {
    StorageError::Corrupt
}

/// The frozen Pair URL rule for `host` and `port` (canonical host, port at
/// least 1024), reached through the public `pair_url` rather than a second
/// copy of it. The other offer fields are well-formed placeholders.
fn endpoint_valid(host: &str, port: u16) -> bool {
    pair_url(&PairOffer {
        expires_at: 0,
        host: host.to_owned(),
        offer_id: hex_encode(&[0; 16]),
        port,
        responder_static: hex_encode(&[0; 32]),
        secret: hex_encode(&[0; 32]),
        version: PEER_PROTOCOL_VERSION,
    })
    .is_ok()
}

/// The durable peer list. In-memory state advances only after a commit is
/// durable; any commit failure makes the store sticky-unknown until it is
/// reopened, as [`StateStore`] does. One `PeerStore` per root.
pub struct PeerStore {
    root: Arc<SecureRoot>,
    /// Serializes writers.
    commit: Mutex<()>,
    /// `None` is the sticky unknown state.
    current: RwLock<Option<Vec<PeerRecord>>>,
}

impl PeerStore {
    /// Loads `peers.json` from `root` (normally [`StateStore::root`]). An
    /// absent file is an empty list and is not created.
    pub fn open(root: Arc<SecureRoot>) -> Result<Self, StorageError> {
        root.remove_stale_temp(PEERS_FILE)?;
        let peers = match root.read_file(PEERS_FILE, PEERS_FILE_MAX_BYTES)? {
            Some(bytes) => decode_peers(&bytes)?,
            None => Vec::new(),
        };
        Ok(Self {
            root,
            commit: Mutex::new(()),
            current: RwLock::new(Some(peers)),
        })
    }

    /// A snapshot, sorted by `responderStatic`.
    pub fn peers(&self) -> Result<Vec<PeerRecord>, StorageError> {
        self.current
            .read()
            .map_err(|_| StorageError::Unknown)?
            .clone()
            .ok_or(StorageError::Unknown)
    }

    /// Adds `record`, replacing the record of the same producer. Only an
    /// `active` record (from [`PeerRecord::from_confirmed`]) is accepted.
    /// A 17th producer is `Refused(Bounds)`; a record load would refuse is
    /// `Refused(Invalid)`; a record with a lower `authEpoch` than the one
    /// it would replace is `Refused(Conflict)`, so a stale answer cannot
    /// overwrite a newer pairing. A refusal writes nothing.
    pub fn upsert(&self, record: PeerRecord) -> Result<(), StorageError> {
        if record.state != PeerState::Active {
            return Err(StorageError::Refused(SecurityError::Invalid));
        }
        self.commit(|peers| {
            let mut next = peers.to_vec();
            match next.binary_search_by(|peer| peer.responder_static.cmp(&record.responder_static))
            {
                Ok(index) if next[index].auth_epoch > record.auth_epoch => {
                    return Err(StorageError::Refused(SecurityError::Conflict));
                }
                Ok(index) => next[index] = record,
                Err(_) if next.len() >= PEERS_MAX => {
                    return Err(StorageError::Refused(SecurityError::Bounds));
                }
                Err(index) => next.insert(index, record),
            }
            Ok(next)
        })
    }

    /// Marks the producer's record `revoked` or `expired`. `active` comes
    /// only from [`Self::upsert`], and an unknown producer is refused; both
    /// are `Refused(Invalid)` with nothing written. A record holding another
    /// `grantId` (the producer was paired again since the answer was asked
    /// for) is `Refused(Conflict)`, nothing written.
    pub fn set_state(
        &self,
        responder_static: &[u8; 32],
        grant_id: &[u8; 16],
        state: PeerState,
    ) -> Result<(), StorageError> {
        if state == PeerState::Active {
            return Err(StorageError::Refused(SecurityError::Invalid));
        }
        self.commit(|peers| {
            let mut next = peers.to_vec();
            let peer = find(&mut next, responder_static, grant_id)?;
            peer.state = state;
            Ok(next)
        })
    }

    /// Stores what Grant status answered `active` for the producer's grant:
    /// its `authEpoch`, `sourceScopeGeneration` and `expiresAt`. Only for
    /// the record holding `grant_id` and still `active`, and never to a
    /// lower `authEpoch`; anything else is `Refused(Conflict)`. An unknown
    /// producer is `Refused(Invalid)`. A refusal writes nothing.
    pub fn update_grant(
        &self,
        responder_static: &[u8; 32],
        grant_id: &[u8; 16],
        auth_epoch: u64,
        source_scope_generation: u64,
        expires_at_ms: i64,
    ) -> Result<(), StorageError> {
        self.commit(|peers| {
            let mut next = peers.to_vec();
            let peer = find(&mut next, responder_static, grant_id)?;
            if peer.state != PeerState::Active || auth_epoch < peer.auth_epoch {
                return Err(StorageError::Refused(SecurityError::Conflict));
            }
            peer.auth_epoch = auth_epoch;
            peer.source_scope_generation = source_scope_generation;
            peer.expires_at_ms = expires_at_ms;
            Ok(next)
        })
    }

    /// Removes the producer's record; an absent one is not an error.
    pub fn remove(&self, responder_static: &[u8; 32]) -> Result<(), StorageError> {
        self.commit(|peers| {
            Ok(peers
                .iter()
                .filter(|peer| peer.responder_static != *responder_static)
                .cloned()
                .collect())
        })
    }

    fn commit(
        &self,
        change: impl FnOnce(&[PeerRecord]) -> Result<Vec<PeerRecord>, StorageError>,
    ) -> Result<(), StorageError> {
        // The mutex guards `()`, so its poison carries no information.
        let _serial = self.commit.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.peers()?;
        let next = change(&current)?;
        if next == current {
            return Ok(());
        }
        // Never write a file that load would refuse: the bytes go through
        // the load decoder first. A refusal is a caller error, not sticky.
        let bytes =
            encode_peers(&next).map_err(|_| StorageError::Refused(SecurityError::Invalid))?;
        decode_peers(&bytes).map_err(|_| StorageError::Refused(SecurityError::Invalid))?;
        let staged = match self.root.stage(PEERS_FILE, &bytes) {
            Ok(staged) => staged,
            Err(_) => {
                *self.write()? = None;
                return Err(StorageError::Unknown);
            }
        };
        let mut current = self.write()?;
        match staged.publish() {
            Ok(()) => {
                *current = Some(next);
                Ok(())
            }
            Err(_) => {
                *current = None;
                Err(StorageError::Unknown)
            }
        }
    }

    fn write(&self) -> Result<RwLockWriteGuard<'_, Option<Vec<PeerRecord>>>, StorageError> {
        self.current.write().map_err(|_| StorageError::Unknown)
    }
}

/// The producer's record, only if it holds `grant_id`: an unknown producer
/// is `Refused(Invalid)`, another grant `Refused(Conflict)`.
fn find<'a>(
    peers: &'a mut [PeerRecord],
    responder_static: &[u8; 32],
    grant_id: &[u8; 16],
) -> Result<&'a mut PeerRecord, StorageError> {
    let peer = peers
        .iter_mut()
        .find(|peer| peer.responder_static == *responder_static)
        .ok_or(StorageError::Refused(SecurityError::Invalid))?;
    if peer.grant_id != *grant_id {
        return Err(StorageError::Refused(SecurityError::Conflict));
    }
    Ok(peer)
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests {
    use super::*;
    use crate::secure_fs::{
        Step,
        seams::{self, Reset},
        test_support::{SUFFIX, TempHome, retry_busy},
    };

    fn record(n: u8) -> PeerRecord {
        PeerRecord {
            auth_epoch: 1,
            created_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_702_592_000_000,
            grant_id: [n; 16],
            host: "127.0.0.1".into(),
            initiator_static: [0xb2; 32],
            node_label: None,
            pending_id: [n ^ 0x80; 16],
            port: 49_200,
            responder_static: [n; 32],
            source_scope_generation: 1,
            state: PeerState::Active,
        }
    }

    fn open(home: &TempHome) -> PeerStore {
        retry_busy(|| PeerStore::open(Arc::new(SecureRoot::open_under(&home.path, SUFFIX)?)))
            .unwrap()
    }

    /// Acceptance (4): a failure at any commit step makes the store sticky
    /// `Unknown` for reads and writes; a reopen sees the old list or the new
    /// one, never anything else. A failed rename leaves the old file; a
    /// failure after it leaves the new one.
    #[test]
    fn a_failed_commit_is_sticky_unknown_and_reopens_old_or_new() {
        for (step, expect_new) in [
            (Step::CreateTemp, false),
            (Step::Write, false),
            (Step::WriteRest, false),
            (Step::SyncFile, false),
            (Step::Rename, false),
            (Step::SyncDir, true),
        ] {
            let home = TempHome::new();
            let store = open(&home);
            store.upsert(record(1)).unwrap();
            let old = store.peers().unwrap();
            let _reset = Reset;
            seams::set_hook(Some(Box::new(move |at| {
                if at == step {
                    Err(std::io::Error::other("injected"))
                } else {
                    Ok(())
                }
            })));
            assert_eq!(
                store.upsert(record(2)),
                Err(StorageError::Unknown),
                "{step:?}"
            );
            seams::set_hook(None);
            assert_eq!(store.peers(), Err(StorageError::Unknown), "{step:?}");
            assert_eq!(
                store.upsert(record(3)),
                Err(StorageError::Unknown),
                "{step:?}"
            );
            assert_eq!(
                store.remove(&[1; 32]),
                Err(StorageError::Unknown),
                "{step:?}"
            );
            drop(store);
            let reopened = open(&home).peers().unwrap();
            let new = vec![record(1), record(2)];
            assert_eq!(reopened, if expect_new { new } else { old }, "{step:?}");
            assert!(!home.root().join(".peers.json.tmp").exists(), "{step:?}");
        }
    }

    /// Control for the test above: the same commit without a failure.
    #[test]
    fn control_the_same_commit_succeeds_and_reopens_new() {
        let home = TempHome::new();
        let store = open(&home);
        store.upsert(record(1)).unwrap();
        store.upsert(record(2)).unwrap();
        drop(store);
        assert_eq!(open(&home).peers().unwrap(), vec![record(1), record(2)]);
    }
}
