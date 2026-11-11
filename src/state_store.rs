//! Durable agent state: `state.json` on the secure root.
//!
//! The key set is frozen by `spec/v1.md`; value encodings, initial values,
//! load invariants and the commit sequence are in `spec/state-store-v1.md`.
//! The store owns what [`ReferenceState`] does not: the listen config, the
//! identity private key and the local-control token.

use std::{
    collections::BTreeSet,
    fmt,
    sync::{Mutex, RwLock, RwLockWriteGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use snow::resolvers::{CryptoResolver, DefaultResolver};

use crate::{
    canonical::{CanonicalJsonV1, constant_time_eq},
    secure_fs::{SecureRoot, StorageError},
    security::{
        AuthorizationRequest, CONSENT_SCOPE, CONTROL_VERSION, Grant, GrantState, Offer, OfferState,
        Pending, PendingState, ReferenceState, STATE_SCHEMA_VERSION, SecurityError, Terminal,
        TerminalKind, authorize, decode_fixed_hex, hex_encode, verify_control_command,
    },
};

pub const STATE_FILE: &str = "state.json";
/// Read bound for `state.json`. Guards against a corrupt same-UID file, not
/// an attacker; it is deliberately far above any reachable state.
pub const STATE_FILE_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const NODE_LABEL_MAX_BYTES: usize = 128;
const ACTIVE_GRANTS_MAX: usize = 16;
const GRANT_ENDPOINTS: [u16; 4] = [1, 2, 3, 4];
const BIND_PORT_FIRST: u16 = 49_152;
const BIND_PORT_COUNT: u16 = 16_384;

/// A 32-byte secret whose `Debug` never shows its value.
#[derive(Clone)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret32(redacted)")
    }
}

impl PartialEq for Secret32 {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for Secret32 {}

/// `config` minus `sharingEnabled`, which is [`ReferenceState::sharing_enabled`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenConfig {
    pub bind_host: Option<String>,
    pub bind_port: u16,
    pub node_label: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredState {
    pub reference: ReferenceState,
    pub config: ListenConfig,
    pub identity_private: Secret32,
    pub control_token: Secret32,
}

/// What a caller supplies to authorize one peer request. Everything else in
/// the predicate comes from the store's current durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationQuery {
    pub grant_id: [u8; 16],
    pub auth_epoch: u64,
    pub source_scope_generation: u64,
    pub endpoint: u16,
    pub os_now_unix_seconds: i64,
}

/// The durable store. In-memory state advances only after a commit is
/// durable; any commit failure makes the store sticky-unknown until the
/// process restarts.
pub struct StateStore {
    root: SecureRoot,
    /// Serializes writers.
    commit: Mutex<()>,
    /// `None` is the sticky unknown state. Writers hold this exclusively from
    /// before the rename until the in-memory swap; authorization reads it.
    current: RwLock<Option<StoredState>>,
}

type Current<'a> = RwLockWriteGuard<'a, Option<StoredState>>;

impl StateStore {
    /// Loads `state.json`, or creates the initial state when it is absent.
    /// `os_now_seconds` is used only for a new state's install wall.
    pub fn open(root: SecureRoot, os_now_seconds: i64) -> Result<Self, StorageError> {
        root.remove_stale_temp(STATE_FILE)?;
        let state = match root.read_file(STATE_FILE, STATE_FILE_MAX_BYTES)? {
            Some(bytes) => decode_state(&bytes)?,
            None => {
                let fresh = initial_state(os_now_seconds)?;
                root.stage(STATE_FILE, &encode_state(&fresh)?)?.publish()?;
                fresh
            }
        };
        Ok(Self {
            root,
            commit: Mutex::new(()),
            current: RwLock::new(Some(state)),
        })
    }

    /// A copy of the current durable state.
    pub fn state(&self) -> Result<StoredState, StorageError> {
        self.current
            .read()
            .map_err(|_| StorageError::Unknown)?
            .clone()
            .ok_or(StorageError::Unknown)
    }

    /// The frozen nine-conjunct predicate, evaluated against the current
    /// durable state under the shared guard. False while sticky-unknown.
    pub fn authorize(&self, query: &AuthorizationQuery) -> bool {
        let Ok(current) = self.current.read() else {
            return false;
        };
        let Some(state) = current.as_ref() else {
            return false;
        };
        let reference = &state.reference;
        let Some(grant) = reference
            .grants
            .iter()
            .find(|grant| grant.grant_id == query.grant_id)
        else {
            return false;
        };
        authorize(
            grant,
            &AuthorizationRequest {
                sharing_enabled: reference.sharing_enabled,
                auth_epoch: query.auth_epoch,
                deny_floor: reference.deny_floor,
                source_scope_generation: query.source_scope_generation,
                counter_source_scope_generation: reference.source_scope_generation,
                os_now_unix_seconds: query.os_now_unix_seconds,
                last_accepted_wall_unix_seconds: reference.last_accepted_wall_unix_seconds(),
                endpoint: query.endpoint,
            },
        )
    }

    /// Commits one [`ReferenceState`] transition durably.
    pub fn transition(
        &self,
        change: impl FnOnce(&ReferenceState) -> Result<ReferenceState, SecurityError>,
    ) -> Result<(), StorageError> {
        self.commit(WallMay::OnlyAdvance, |current| {
            Ok(StoredState {
                reference: change(&current.reference).map_err(StorageError::Refused)?,
                ..current.clone()
            })
        })
    }

    /// `disable_commit` with a fresh CSPRNG record ID.
    pub fn disable(&self, terminal_at_ms: i64) -> Result<(), StorageError> {
        let record_id = random()?;
        self.transition(|state| state.disable_commit(record_id, terminal_at_ms))
    }

    /// `uninstall_commit` with a fresh CSPRNG record ID.
    pub fn uninstall(&self, terminal_at_ms: i64) -> Result<(), StorageError> {
        let record_id = random()?;
        self.transition(|state| state.uninstall_commit(record_id, terminal_at_ms))
    }

    /// Clock checkpoint: `compact_terminals`, which advances the durable wall.
    pub fn checkpoint(&self, os_now_seconds: i64) -> Result<(), StorageError> {
        self.transition(|state| state.compact_terminals(os_now_seconds))
    }

    /// Owner-confirmed reset, the only recovery from a clock anomaly.
    ///
    /// First a durable disable; then a new state whose wall is
    /// `os_now_seconds` (the only counter allowed to go down), with
    /// `nextAuthEpoch` carried over, `denyFloor = max(old, next - 1)`,
    /// `sourceScopeGeneration = old + 1`, no offer, pending or grant, the
    /// terminal records kept, and a new identity key and control token. The
    /// listen config is kept; sharing stays off.
    pub fn reset(&self, os_now_seconds: i64, terminal_at_ms: i64) -> Result<(), StorageError> {
        let fresh = ReferenceState::new(os_now_seconds).map_err(StorageError::Refused)?;
        let identity_private = Secret32(random()?);
        let control_token = Secret32(random()?);
        self.disable(terminal_at_ms)?;
        self.commit(WallMay::Decrease, |old| {
            let previous = &old.reference;
            let mut reference = fresh;
            reference.next_auth_epoch = previous.next_auth_epoch;
            reference.deny_floor = previous
                .deny_floor
                .max(previous.next_auth_epoch.saturating_sub(1));
            reference.source_scope_generation = previous
                .source_scope_generation
                .checked_add(1)
                .ok_or(StorageError::Refused(SecurityError::Bounds))?;
            reference.terminal = previous.terminal.clone();
            Ok(StoredState {
                reference,
                config: old.config.clone(),
                identity_private,
                control_token,
            })
        })
    }

    fn commit(
        &self,
        wall: WallMay,
        change: impl FnOnce(&StoredState) -> Result<StoredState, StorageError>,
    ) -> Result<(), StorageError> {
        let _serial = self.commit.lock().map_err(|_| StorageError::Unknown)?;
        let current = self.state()?;
        let next = change(&current)?;
        counters_never_go_backwards(&current.reference, &next.reference, wall)?;
        // Never write a state that load would refuse.
        validate(&next)?;
        let bytes = encode_state(&next)?;
        #[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
        if seams::bypassed(seams::EARLY_SWAP) {
            *self.write()? = Some(next.clone());
        }
        let staged = match self.root.stage(STATE_FILE, &bytes) {
            Ok(staged) => staged,
            Err(_) => {
                stick(&mut *self.write()?);
                return Err(StorageError::Unknown);
            }
        };
        // Exclusive from before the rename until the in-memory swap, so no
        // authorization can read the pre-commit state once the new file may
        // be visible.
        let current = self.write()?;
        #[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
        if seams::bypassed(seams::EXCLUSIVE_GUARD) {
            drop(current);
            let published = staged.publish();
            return finish(self.write()?, published, next);
        }
        let published = staged.publish();
        finish(current, published, next)
    }

    fn write(&self) -> Result<Current<'_>, StorageError> {
        self.current.write().map_err(|_| StorageError::Unknown)
    }
}

/// Whether a commit may lower the durable wall. Only the owner-confirmed
/// reset may.
#[derive(Clone, Copy, Eq, PartialEq)]
enum WallMay {
    OnlyAdvance,
    Decrease,
}

/// `nextAuthEpoch`, `denyFloor` and `sourceScopeGeneration` never decrease,
/// and neither does the wall outside reset, whatever a caller's closure
/// returns. A violation is a caller bug, not an I/O failure: the commit is
/// refused before anything is staged, the in-memory state is unchanged, and
/// the store does not go sticky-unknown, because the durable state is known.
fn counters_never_go_backwards(
    old: &ReferenceState,
    new: &ReferenceState,
    wall: WallMay,
) -> Result<(), StorageError> {
    #[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
    if seams::bypassed(seams::COUNTERS) {
        return Ok(());
    }
    let forward = new.next_auth_epoch >= old.next_auth_epoch
        && new.deny_floor >= old.deny_floor
        && new.source_scope_generation >= old.source_scope_generation
        && (wall == WallMay::Decrease
            || new.last_accepted_wall_unix_seconds() >= old.last_accepted_wall_unix_seconds());
    if forward {
        Ok(())
    } else {
        Err(StorageError::Refused(SecurityError::Conflict))
    }
}

fn finish(
    mut current: Current<'_>,
    published: Result<(), StorageError>,
    next: StoredState,
) -> Result<(), StorageError> {
    match published {
        Ok(()) => {
            *current = Some(next);
            Ok(())
        }
        Err(_) => {
            stick(&mut current);
            Err(StorageError::Unknown)
        }
    }
}

fn stick(current: &mut Option<StoredState>) {
    #[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
    if seams::bypassed(seams::NO_STICKY) {
        return;
    }
    *current = None;
}

/// Whole seconds since the Unix epoch, strictly positive.
pub fn os_now_seconds() -> Result<i64, StorageError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .filter(|seconds| *seconds > 0)
        .ok_or(StorageError::Unavailable)
}

fn random<const N: usize>() -> Result<[u8; N], StorageError> {
    let mut bytes = [0; N];
    DefaultResolver
        .resolve_rng()
        .ok_or(StorageError::Unavailable)?
        .try_fill_bytes(&mut bytes)
        .map_err(|_| StorageError::Unavailable)?;
    Ok(bytes)
}

fn initial_state(os_now_seconds: i64) -> Result<StoredState, StorageError> {
    let reference = ReferenceState::new(os_now_seconds).map_err(StorageError::Refused)?;
    // 65536 is a multiple of 16384, so the modulo is unbiased.
    let bind_port = BIND_PORT_FIRST + u16::from_be_bytes(random()?) % BIND_PORT_COUNT;
    Ok(StoredState {
        reference,
        config: ListenConfig {
            bind_host: None,
            bind_port,
            node_label: None,
        },
        identity_private: Secret32(random()?),
        control_token: Secret32(random()?),
    })
}

// ---------------------------------------------------------------- codec ---

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateFile {
    config: ConfigFile,
    control_token: String,
    counters: CountersFile,
    grants: Vec<GrantFile>,
    identity_private: String,
    offers: Vec<OfferFile>,
    pending: Vec<PendingFile>,
    schema: u16,
    terminal: Vec<TerminalFile>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigFile {
    bind_host: Option<String>,
    bind_port: u16,
    node_label: Option<String>,
    sharing_enabled: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CountersFile {
    deny_floor: u64,
    last_accepted_wall_unix_seconds: i64,
    next_auth_epoch: u64,
    source_scope_generation: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OfferFile {
    created_at: i64,
    expires_at: i64,
    offer_id: String,
    secret_hash: String,
    state: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingFile {
    created_at: i64,
    expires_at: i64,
    initiator_static: String,
    offer_id: String,
    pending_id: String,
    sas_code: String,
    sas_generation: u64,
    state: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantFile {
    auth_epoch: u64,
    created_at: i64,
    endpoints: [u16; 4],
    expires_at: i64,
    grant_id: String,
    initiator_static: String,
    responder_static: String,
    scope: String,
    source_scope_generation: u64,
    state: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalFile {
    auth_epoch: u64,
    cleanup_complete: bool,
    kind: String,
    record_id: String,
    terminal_at: i64,
}

/// camelCase variant names, matching `GrantState`'s serde output.
macro_rules! enum_codec {
    ($encode:ident, $decode:ident, $type:ident { $($variant:ident => $name:literal),+ $(,)? }) => {
        fn $encode(value: $type) -> &'static str {
            match value {
                $($type::$variant => $name),+
            }
        }

        fn $decode(value: &str) -> Result<$type, StorageError> {
            match value {
                $($name => Ok($type::$variant),)+
                _ => Err(StorageError::Corrupt),
            }
        }
    };
}

enum_codec!(offer_state_name, offer_state, OfferState {
    Active => "active", Consumed => "consumed", Cancelled => "cancelled", Expired => "expired",
});
enum_codec!(pending_state_name, pending_state, PendingState {
    AwaitingApproval => "awaitingApproval", Approved => "approved",
    Rejected => "rejected", Expired => "expired",
});
enum_codec!(grant_state_name, grant_state, GrantState {
    Active => "active", Revoked => "revoked", Expired => "expired",
});
enum_codec!(terminal_kind_name, terminal_kind, TerminalKind {
    Offer => "offer", Pending => "pending", Grant => "grant", Reset => "reset",
    Uninstall => "uninstall",
});

fn hex<const N: usize>(value: &str) -> Result<[u8; N], StorageError> {
    decode_fixed_hex(value).map_err(|_| StorageError::Corrupt)
}

/// CanonicalJsonV1 bytes of `state.json`.
pub fn encode_state(state: &StoredState) -> Result<Vec<u8>, StorageError> {
    let reference = &state.reference;
    let file = StateFile {
        config: ConfigFile {
            bind_host: state.config.bind_host.clone(),
            bind_port: state.config.bind_port,
            node_label: state.config.node_label.clone(),
            sharing_enabled: reference.sharing_enabled,
        },
        control_token: hex_encode(state.control_token.expose()),
        counters: CountersFile {
            deny_floor: reference.deny_floor,
            last_accepted_wall_unix_seconds: reference.last_accepted_wall_unix_seconds(),
            next_auth_epoch: reference.next_auth_epoch,
            source_scope_generation: reference.source_scope_generation,
        },
        grants: reference
            .grants
            .iter()
            .map(|grant| GrantFile {
                auth_epoch: grant.auth_epoch,
                created_at: grant.created_at_ms,
                endpoints: grant.endpoints,
                expires_at: grant.expires_at_ms,
                grant_id: hex_encode(&grant.grant_id),
                initiator_static: hex_encode(&grant.initiator_static),
                responder_static: hex_encode(&grant.responder_static),
                scope: grant.scope.to_owned(),
                source_scope_generation: grant.source_scope_generation,
                state: grant_state_name(grant.state).to_owned(),
            })
            .collect(),
        identity_private: hex_encode(state.identity_private.expose()),
        offers: reference
            .offers
            .iter()
            .map(|offer| OfferFile {
                created_at: offer.created_at_ms,
                expires_at: offer.expires_at_ms,
                offer_id: hex_encode(&offer.offer_id),
                secret_hash: hex_encode(&offer.secret_hash),
                state: offer_state_name(offer.state).to_owned(),
            })
            .collect(),
        pending: reference
            .pending
            .iter()
            .map(|pending| PendingFile {
                created_at: pending.created_at_ms,
                expires_at: pending.expires_at_ms,
                initiator_static: hex_encode(&pending.initiator_static),
                offer_id: hex_encode(&pending.offer_id),
                pending_id: hex_encode(&pending.pending_id),
                sas_code: pending.sas_code.clone(),
                sas_generation: pending.sas_generation,
                state: pending_state_name(pending.state).to_owned(),
            })
            .collect(),
        schema: STATE_SCHEMA_VERSION,
        terminal: reference
            .terminal
            .iter()
            .map(|terminal| TerminalFile {
                auth_epoch: terminal.auth_epoch,
                cleanup_complete: terminal.cleanup_complete,
                kind: terminal_kind_name(terminal.kind).to_owned(),
                record_id: hex_encode(&terminal.record_id),
                terminal_at: terminal.terminal_at_ms,
            })
            .collect(),
    };
    CanonicalJsonV1::encode(&file).map_err(|_| StorageError::Corrupt)
}

/// Strict decode of `state.json`: schema 1, CanonicalJsonV1, the exact frozen
/// key set, and every load invariant.
pub fn decode_state(bytes: &[u8]) -> Result<StoredState, StorageError> {
    let value = CanonicalJsonV1::decode_value(bytes).map_err(|_| StorageError::Corrupt)?;
    let schema = value.get("schema").and_then(Value::as_u64);
    check(
        schema == Some(u64::from(STATE_SCHEMA_VERSION)),
        Check::Schema,
    )?;
    // `decode` re-encodes the typed value and compares bytes, so a missing,
    // extra or reordered key is rejected along with any non-canonical form.
    let file: StateFile = CanonicalJsonV1::decode(bytes).map_err(|_| StorageError::Corrupt)?;
    let counters = file.counters;
    // `new` refuses a wall that is not strictly positive.
    let mut reference = ReferenceState::new(counters.last_accepted_wall_unix_seconds)
        .map_err(|_| StorageError::Corrupt)?;
    reference.sharing_enabled = file.config.sharing_enabled;
    reference.next_auth_epoch = counters.next_auth_epoch;
    reference.deny_floor = counters.deny_floor;
    reference.source_scope_generation = counters.source_scope_generation;
    reference.offers = file
        .offers
        .into_iter()
        .map(|offer| {
            Ok(Offer {
                offer_id: hex(&offer.offer_id)?,
                secret_hash: hex(&offer.secret_hash)?,
                created_at_ms: offer.created_at,
                expires_at_ms: offer.expires_at,
                state: offer_state(&offer.state)?,
            })
        })
        .collect::<Result<_, StorageError>>()?;
    reference.pending = file
        .pending
        .into_iter()
        .map(|pending| {
            Ok(Pending {
                pending_id: hex(&pending.pending_id)?,
                offer_id: hex(&pending.offer_id)?,
                initiator_static: hex(&pending.initiator_static)?,
                sas_code: pending.sas_code,
                sas_generation: pending.sas_generation,
                created_at_ms: pending.created_at,
                expires_at_ms: pending.expires_at,
                state: pending_state(&pending.state)?,
            })
        })
        .collect::<Result<_, StorageError>>()?;
    reference.grants = file
        .grants
        .into_iter()
        .map(|grant| {
            // The frozen scope is the only value a `&'static str` can carry.
            if grant.scope != CONSENT_SCOPE {
                return Err(StorageError::Corrupt);
            }
            Ok(Grant {
                grant_id: hex(&grant.grant_id)?,
                initiator_static: hex(&grant.initiator_static)?,
                responder_static: hex(&grant.responder_static)?,
                scope: CONSENT_SCOPE,
                endpoints: grant.endpoints,
                auth_epoch: grant.auth_epoch,
                source_scope_generation: grant.source_scope_generation,
                created_at_ms: grant.created_at,
                expires_at_ms: grant.expires_at,
                state: grant_state(&grant.state)?,
            })
        })
        .collect::<Result<_, StorageError>>()?;
    reference.terminal = file
        .terminal
        .into_iter()
        .map(|terminal| {
            Ok(Terminal {
                record_id: hex(&terminal.record_id)?,
                kind: terminal_kind(&terminal.kind)?,
                auth_epoch: terminal.auth_epoch,
                terminal_at_ms: terminal.terminal_at,
                cleanup_complete: terminal.cleanup_complete,
            })
        })
        .collect::<Result<_, StorageError>>()?;
    let state = StoredState {
        reference,
        config: ListenConfig {
            bind_host: file.config.bind_host,
            bind_port: file.config.bind_port,
            node_label: file.config.node_label,
        },
        identity_private: Secret32(hex(&file.identity_private)?),
        control_token: Secret32(hex(&file.control_token)?),
    };
    validate(&state)?;
    Ok(state)
}

/// Load invariants (`spec/state-store-v1.md`). Only properties every
/// transition preserves: no record-count cap, because revoke, disable,
/// reset, uninstall and reject may exceed 256 records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Check {
    Schema,
    GrantEpoch,
    DenyFloor,
    Endpoints,
    SharingOff,
    ActiveGrants,
    RecordIds,
    TerminalIds,
    BindHost,
    Wildcard,
    NodeLabel,
}

fn check(ok: bool, check: Check) -> Result<(), StorageError> {
    #[cfg(test)]
    if seams::skipped(check) {
        return Ok(());
    }
    match (ok, check) {
        (true, _) => Ok(()),
        (false, Check::Schema) => Err(StorageError::Incompatible),
        (false, _) => Err(StorageError::Corrupt),
    }
}

fn validate(state: &StoredState) -> Result<(), StorageError> {
    let reference = &state.reference;
    let next = reference.next_auth_epoch;
    let grants = &reference.grants;
    let active = || {
        grants
            .iter()
            .filter(|grant| grant.state == GrantState::Active)
    };
    check(
        grants.iter().all(|grant| grant.auth_epoch < next),
        Check::GrantEpoch,
    )?;
    check(reference.deny_floor < next, Check::DenyFloor)?;
    check(
        grants
            .iter()
            .all(|grant| grant.endpoints == GRANT_ENDPOINTS),
        Check::Endpoints,
    )?;
    check(
        reference.sharing_enabled || active().next().is_none(),
        Check::SharingOff,
    )?;
    check(active().count() <= ACTIVE_GRANTS_MAX, Check::ActiveGrants)?;
    let mut ids = BTreeSet::new();
    let unique = reference
        .offers
        .iter()
        .all(|offer| ids.insert(offer.offer_id))
        && reference
            .pending
            .iter()
            .all(|pending| ids.insert(pending.pending_id))
        && grants.iter().all(|grant| ids.insert(grant.grant_id));
    check(unique, Check::RecordIds)?;
    let mut terminal_ids = BTreeSet::new();
    check(
        reference
            .terminal
            .iter()
            .all(|terminal| terminal_ids.insert(terminal.record_id)),
        Check::TerminalIds,
    )?;
    if let Some(host) = &state.config.bind_host {
        check(
            bind_host_valid(host, state.config.bind_port),
            Check::BindHost,
        )?;
        check(host != "0.0.0.0" && host != "::", Check::Wildcard)?;
    }
    if let Some(label) = &state.config.node_label {
        check(label.len() <= NODE_LABEL_MAX_BYTES, Check::NodeLabel)?;
    }
    Ok(())
}

/// The frozen host/port rule, reached through the public `listenConfigure`
/// validator rather than a second copy of it.
fn bind_host_valid(host: &str, port: u16) -> bool {
    let request_id = [0; 16];
    let command = json!({
        "body": { "bindHost": host, "bindPort": port },
        "commandId": 8,
        "controlVersion": CONTROL_VERSION,
        "requestId": hex_encode(&request_id),
    });
    CanonicalJsonV1::encode(&command)
        .is_ok_and(|bytes| verify_control_command(&bytes, &request_id, 8).is_ok())
}

/// Test-only store seams; absent from non-test builds.
#[cfg(test)]
mod seams {
    use std::cell::Cell;

    use super::Check;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) const EXCLUSIVE_GUARD: u32 = 1 << 0;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) const EARLY_SWAP: u32 = 1 << 1;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) const NO_STICKY: u32 = 1 << 2;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) const COUNTERS: u32 = 1 << 3;

    thread_local! {
        static BYPASS: Cell<u32> = const { Cell::new(0) };
        static SKIP: Cell<u32> = const { Cell::new(0) };
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn bypass(flags: u32) {
        BYPASS.with(|cell| cell.set(flags));
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn bypassed(flag: u32) -> bool {
        BYPASS.with(|cell| cell.get() & flag != 0)
    }
    pub(super) fn skip(checks: &[Check]) {
        SKIP.with(|cell| {
            cell.set(
                checks
                    .iter()
                    .fold(0, |bits, check| bits | 1 << *check as u32),
            )
        });
    }
    pub(super) fn skipped(check: Check) -> bool {
        SKIP.with(|cell| cell.get() & 1 << check as u32 != 0)
    }

    pub(super) struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            bypass(0);
            skip(&[]);
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    const GOLDEN: &str = include_str!("../tests/fixtures/v1/runtime/storage/state-golden.json");

    fn golden_value() -> Value {
        CanonicalJsonV1::decode_value(GOLDEN.trim_end().as_bytes()).unwrap()
    }

    fn bytes_of(value: &Value) -> Vec<u8> {
        CanonicalJsonV1::encode(value).unwrap()
    }

    /// Each fixture changes one thing in the golden state. It must fail
    /// closed; skipping only the named check must let it load, which proves
    /// that check, and nothing else, is what refuses it.
    #[test]
    fn every_load_invariant_fails_closed_and_only_its_own_check_refuses_it() {
        let _reset = seams::Reset;
        assert!(decode_state(GOLDEN.trim_end().as_bytes()).is_ok());
        type Mutation = fn(&mut Value);
        let cases: &[(Check, StorageError, Mutation)] = &[
            (Check::Schema, StorageError::Incompatible, |v| {
                v["schema"] = 2.into()
            }),
            (Check::Schema, StorageError::Incompatible, |v| {
                v["schema"] = 0.into()
            }),
            (Check::GrantEpoch, StorageError::Corrupt, |v| {
                v["grants"][0]["authEpoch"] = 3.into()
            }),
            (Check::DenyFloor, StorageError::Corrupt, |v| {
                v["counters"]["denyFloor"] = 3.into()
            }),
            (Check::Endpoints, StorageError::Corrupt, |v| {
                v["grants"][0]["endpoints"] = serde_json::json!([1, 2, 3, 5])
            }),
            (Check::SharingOff, StorageError::Corrupt, |v| {
                v["config"]["sharingEnabled"] = false.into()
            }),
            (Check::ActiveGrants, StorageError::Corrupt, |v| {
                let template = v["grants"][0].clone();
                let grants = v["grants"].as_array_mut().unwrap();
                for n in 0..16u8 {
                    let mut grant = template.clone();
                    grant["grantId"] =
                        hex_encode(&[0xe0 | (n >> 4), n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                            .into();
                    grants.push(grant);
                }
            }),
            (Check::RecordIds, StorageError::Corrupt, |v| {
                v["grants"][1]["grantId"] = v["offers"][0]["offerId"].clone()
            }),
            (Check::RecordIds, StorageError::Corrupt, |v| {
                v["pending"][1]["pendingId"] = v["offers"][1]["offerId"].clone()
            }),
            (Check::TerminalIds, StorageError::Corrupt, |v| {
                v["terminal"][1]["recordId"] = v["terminal"][0]["recordId"].clone()
            }),
            (Check::BindHost, StorageError::Corrupt, |v| {
                v["config"]["bindHost"] = "Bad_Host".into()
            }),
            (Check::BindHost, StorageError::Corrupt, |v| {
                v["config"]["bindPort"] = 80.into()
            }),
            (Check::Wildcard, StorageError::Corrupt, |v| {
                v["config"]["bindHost"] = "0.0.0.0".into()
            }),
            (Check::Wildcard, StorageError::Corrupt, |v| {
                v["config"]["bindHost"] = "::".into()
            }),
            (Check::NodeLabel, StorageError::Corrupt, |v| {
                v["config"]["nodeLabel"] = "n".repeat(NODE_LABEL_MAX_BYTES + 1).into()
            }),
        ];
        for (index, (check, error, mutate)) in cases.iter().enumerate() {
            let mut value = golden_value();
            mutate(&mut value);
            let bytes = bytes_of(&value);
            assert_eq!(
                decode_state(&bytes).err(),
                Some(*error),
                "case {index} {check:?}"
            );
            seams::skip(&[*check]);
            let skipped = decode_state(&bytes);
            seams::skip(&[]);
            assert!(
                skipped.is_ok(),
                "case {index}: {check:?} is not what refused it: {skipped:?}"
            );
        }
        // Boundaries that must still load: 16 active grants, a 128-byte label.
        let mut value = golden_value();
        value["config"]["nodeLabel"] = "n".repeat(NODE_LABEL_MAX_BYTES).into();
        assert!(decode_state(&bytes_of(&value)).is_ok());
    }

    /// Structural rules enforced by decoding itself, with no bypass: the
    /// fixture differs from the loading golden state in one field.
    #[test]
    fn structural_violations_fail_closed() {
        type Mutation = fn(&mut Value);
        let cases: &[Mutation] = &[
            |v| v["counters"]["lastAcceptedWallUnixSeconds"] = 0.into(),
            |v| v["counters"]["lastAcceptedWallUnixSeconds"] = (-1).into(),
            |v| v["grants"][0]["scope"] = "usage.aggregate.read.v2".into(),
            |v| v["grants"][0]["state"] = "Active".into(),
            |v| v["offers"][0]["state"] = "unknown".into(),
            |v| v["terminal"][0]["kind"] = "revoke".into(),
            |v| v["offers"][0]["offerId"] = "0101".into(),
            |v| v["identityPrivate"] = "5A".repeat(32).into(),
            |v| v["extra"] = 1.into(),
            |v| {
                v["config"].as_object_mut().unwrap().remove("nodeLabel");
            },
            |v| {
                v["grants"][0]
                    .as_object_mut()
                    .unwrap()
                    .insert("peer".into(), 1.into());
            },
        ];
        for (index, mutate) in cases.iter().enumerate() {
            let mut value = golden_value();
            mutate(&mut value);
            assert_eq!(
                decode_state(&bytes_of(&value)).err(),
                Some(StorageError::Corrupt),
                "case {index}"
            );
        }
        let mut value = golden_value();
        value["counters"]["lastAcceptedWallUnixSeconds"] = 1.into();
        assert!(
            decode_state(&bytes_of(&value)).is_ok(),
            "control: a wall of 1 loads"
        );
        let mut spaced = GOLDEN.trim_end().as_bytes().to_vec();
        spaced.insert(1, b' ');
        assert_eq!(decode_state(&spaced).err(), Some(StorageError::Corrupt));
    }

    #[test]
    fn the_state_codec_round_trips_and_redacts_secrets() {
        let state = decode_state(GOLDEN.trim_end().as_bytes()).unwrap();
        assert_eq!(encode_state(&state).unwrap(), GOLDEN.trim_end().as_bytes());
        assert_eq!(
            format!("{:?}", state.identity_private),
            "Secret32(redacted)"
        );
        assert!(bind_host_valid("192.168.1.20", 1_024));
        assert!(!bind_host_valid("192.168.1.20", 1_023));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    mod disk {
        use std::{
            io,
            path::Path,
            process::{Command, Stdio},
            sync::{Arc, Mutex as StdMutex, mpsc},
            thread,
            time::Duration,
        };

        use super::*;
        use crate::{
            secure_fs::{
                Step,
                seams::{self as fs_seams, Reset as FsReset},
                test_support::{SUFFIX, TempHome},
            },
            security::{OfferClaim, PendingApproval, offer_secret_hash},
        };

        const NOW: i64 = 1_700_000_000;
        const NOW_MS: i64 = NOW * 1_000;
        const RESPONDER: [u8; 32] = [0xc1; 32];
        /// Every hook point of one commit, in order.
        const COMMIT_STEPS: [Step; 7] = [
            Step::CreateTemp,
            Step::Write,
            Step::WriteRest,
            Step::SyncFile,
            Step::Staged,
            Step::Rename,
            Step::SyncDir,
        ];

        fn open(home: &Path) -> Result<StateStore, StorageError> {
            StateStore::open(SecureRoot::open_under(home, SUFFIX)?, NOW)
        }

        fn id(n: u8) -> [u8; 16] {
            [n; 16]
        }

        /// Sharing on, offer `n` claimed by pending `n + 10`, not yet approved.
        fn claimed(state: &ReferenceState, n: u8) -> Result<ReferenceState, SecurityError> {
            let state = if state.sharing_enabled {
                state.clone()
            } else {
                state.enable_sharing()?
            };
            let offer = Offer {
                offer_id: id(n),
                secret_hash: offer_secret_hash(&id(n), &[n; 32], &RESPONDER),
                created_at_ms: NOW_MS,
                expires_at_ms: NOW_MS + 600_000,
                state: OfferState::Active,
            };
            let state = state.create_offer(offer, NOW)?;
            let claim = OfferClaim {
                offer_id: id(n),
                secret: [n; 32],
                responder_static: RESPONDER,
                pending_id: id(n + 10),
                initiator_static: [0xb1; 32],
                sas_code: "0A1B-2C3D".into(),
                sas_generation: 1,
            };
            Ok(state.claim_offer(claim, NOW)?.0)
        }

        fn approve(state: &ReferenceState, n: u8) -> Result<ReferenceState, SecurityError> {
            state.approve_pending(
                PendingApproval {
                    pending_id: id(n + 10),
                    sas_generation: 1,
                    grant_id: id(n + 20),
                    responder_static: RESPONDER,
                    grant_expires_at_ms: NOW_MS + 86_400_000,
                    disclosure_exact: true,
                },
                NOW,
            )
        }

        fn query(n: u8, auth_epoch: u64) -> AuthorizationQuery {
            AuthorizationQuery {
                grant_id: id(n + 20),
                auth_epoch,
                source_scope_generation: 1,
                endpoint: 1,
                os_now_unix_seconds: NOW,
            }
        }

        fn store_with_grant(home: &TempHome) -> StateStore {
            let store = open(&home.path).unwrap();
            store.transition(|r| approve(&claimed(r, 1)?, 1)).unwrap();
            assert!(store.authorize(&query(1, 1)));
            store
        }

        fn enospc() -> io::Error {
            io::Error::from_raw_os_error(libc::ENOSPC)
        }

        #[test]
        fn a_commit_runs_its_system_calls_in_the_contract_order() {
            let home = TempHome::new();
            let store = open(&home.path).unwrap();
            let _reset = FsReset;
            let seen = Arc::new(StdMutex::new(Vec::new()));
            let record = Arc::clone(&seen);
            fs_seams::set_hook(Some(Box::new(move |step| {
                record.lock().unwrap().push(step);
                Ok(())
            })));
            store.transition(|r| r.enable_sharing()).unwrap();
            assert_eq!(*seen.lock().unwrap(), COMMIT_STEPS);
        }

        #[test]
        fn an_error_at_any_step_is_sticky_and_leaves_the_old_or_new_state() {
            for step in COMMIT_STEPS {
                let home = TempHome::new();
                let store = open(&home.path).unwrap();
                let _reset = FsReset;
                fs_seams::set_hook(Some(Box::new(move |at| {
                    if at == step { Err(enospc()) } else { Ok(()) }
                })));
                assert_eq!(
                    store.transition(|r| r.enable_sharing()),
                    Err(StorageError::Unknown),
                    "{step:?}"
                );
                fs_seams::set_hook(None);
                // Sticky: no retry, no reads, no authorization, no second owner.
                assert_eq!(store.state().err(), Some(StorageError::Unknown));
                assert_eq!(
                    store.transition(|r| r.enable_sharing()),
                    Err(StorageError::Unknown)
                );
                assert_eq!(store.checkpoint(NOW), Err(StorageError::Unknown));
                assert_eq!(open(&home.path).err(), Some(StorageError::Busy));
                drop(store);
                let reopened = open(&home.path).unwrap().state().unwrap();
                let new = matches!(step, Step::SyncDir);
                assert_eq!(reopened.reference.sharing_enabled, new, "{step:?}");
                assert!(!home.root().join(".state.json.tmp").exists(), "{step:?}");
            }
        }

        /// Negative control for stickiness: without it, a revoke whose
        /// directory sync failed leaves the revoked grant authorizing.
        #[test]
        fn a_failed_revoke_cannot_leave_the_grant_authorizing() {
            for bypass in [0, seams::NO_STICKY] {
                let home = TempHome::new();
                let store = store_with_grant(&home);
                let _fs_reset = FsReset;
                let _reset = seams::Reset;
                seams::bypass(bypass);
                fs_seams::set_hook(Some(Box::new(|at| {
                    if at == Step::SyncDir {
                        Err(enospc())
                    } else {
                        Ok(())
                    }
                })));
                assert_eq!(
                    store.transition(|r| r.revoke_commit(id(21), NOW_MS)),
                    Err(StorageError::Unknown)
                );
                assert_eq!(
                    store.authorize(&query(1, 1)),
                    bypass != 0,
                    "bypass {bypass}"
                );
            }
        }

        /// The child side of `abort_at_any_step…`. A no-op in a normal run.
        #[test]
        fn child_process_entry() {
            let (Ok(home), Ok(step)) = (
                std::env::var("SYRTIS_CHILD_HOME"),
                std::env::var("SYRTIS_CHILD_ABORT_AT"),
            ) else {
                return;
            };
            let store = open(Path::new(&home)).unwrap();
            let step = COMMIT_STEPS[step.parse::<usize>().unwrap()];
            fs_seams::set_hook(Some(Box::new(move |at| {
                if at == step {
                    std::process::abort();
                }
                Ok(())
            })));
            let _ = store.transition(|r| r.enable_sharing());
            std::process::exit(3);
        }

        #[test]
        fn a_crash_at_any_step_leaves_the_old_or_new_state() {
            for (index, step) in COMMIT_STEPS.iter().enumerate() {
                let home = TempHome::new();
                drop(open(&home.path).unwrap());
                let status = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "state_store::tests::disk::child_process_entry",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env("SYRTIS_CHILD_HOME", &home.path)
                    .env("SYRTIS_CHILD_ABORT_AT", index.to_string())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap();
                // Killed by SIGABRT, not a clean or test-failure exit.
                assert_eq!(status.code(), None, "{step:?}: {status:?}");
                let reopened = open(&home.path).unwrap().state().unwrap();
                let new = matches!(step, Step::SyncDir);
                assert_eq!(reopened.reference.sharing_enabled, new, "{step:?}");
                assert!(!home.root().join(".state.json.tmp").exists(), "{step:?}");
            }
        }

        /// Pauses the writer at `pause`, then asks `probe` on another thread.
        /// Returns what the reader answered within 1 s (None if it was
        /// still blocked), and what it answered after the writer finished.
        fn race(
            store: &Arc<StateStore>,
            bypass: u32,
            pause: Step,
            change: fn(&ReferenceState) -> Result<ReferenceState, SecurityError>,
            probe: AuthorizationQuery,
        ) -> (Option<bool>, bool) {
            let (reached_tx, reached_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel::<()>();
            let writer = {
                let store = Arc::clone(store);
                thread::spawn(move || {
                    let _fs_reset = FsReset;
                    let _reset = seams::Reset;
                    seams::bypass(bypass);
                    fs_seams::set_hook(Some(Box::new(move |at| {
                        if at == pause {
                            reached_tx.send(()).unwrap();
                            release_rx.recv().unwrap();
                        }
                        Ok(())
                    })));
                    store.transition(change)
                })
            };
            reached_rx.recv().unwrap();
            let (seen_tx, seen_rx) = mpsc::channel();
            let reader = {
                let store = Arc::clone(store);
                thread::spawn(move || seen_tx.send(store.authorize(&probe)).unwrap())
            };
            let during = seen_rx.recv_timeout(Duration::from_millis(1_000)).ok();
            release_tx.send(()).unwrap();
            writer.join().unwrap().unwrap();
            let after = match during {
                Some(answer) => answer,
                None => seen_rx.recv().unwrap(),
            };
            reader.join().unwrap();
            (during, after)
        }

        /// Revoke direction: paused after the rename, before the in-memory
        /// swap, authorization never answers true for the revoked grant.
        #[test]
        fn a_revoke_paused_after_rename_never_authorizes_the_grant() {
            let revoke: fn(&ReferenceState) -> Result<ReferenceState, SecurityError> =
                |r| r.revoke_commit(id(21), NOW_MS);
            let home = TempHome::new();
            let store = Arc::new(store_with_grant(&home));
            let (during, after) = race(&store, 0, Step::SyncDir, revoke, query(1, 1));
            assert_eq!(during, None, "the reader must wait for the exclusive guard");
            assert!(!after);
            assert!(!store.authorize(&query(1, 1)));

            // Negative control: without the exclusive guard the reader sees
            // the pre-commit state after the new file is in place.
            let home = TempHome::new();
            let store = Arc::new(store_with_grant(&home));
            let (during, _) = race(
                &store,
                seams::EXCLUSIVE_GUARD,
                Step::SyncDir,
                revoke,
                query(1, 1),
            );
            assert_eq!(during, Some(true));
        }

        /// Approve direction: paused after the temp file is synced and
        /// before the rename, the new grant does not authorize.
        #[test]
        fn an_approval_paused_before_rename_does_not_authorize_yet() {
            let approve_1: fn(&ReferenceState) -> Result<ReferenceState, SecurityError> =
                |r| approve(r, 1);
            for (bypass, expected) in [(0, Some(false)), (seams::EARLY_SWAP, Some(true))] {
                let home = TempHome::new();
                let store = Arc::new(open(&home.path).unwrap());
                store.transition(|r| claimed(r, 1)).unwrap();
                let (during, after) = race(&store, bypass, Step::Staged, approve_1, query(1, 1));
                assert_eq!(during, expected, "bypass {bypass}");
                assert_eq!(after, expected == Some(true));
                // Once the commit is durable the grant authorizes.
                assert!(store.authorize(&query(1, 1)));
            }
        }

        #[test]
        fn an_approval_whose_rename_fails_never_authorizes_even_after_reload() {
            let home = TempHome::new();
            let store = open(&home.path).unwrap();
            store.transition(|r| claimed(r, 1)).unwrap();
            let _reset = FsReset;
            fs_seams::set_hook(Some(Box::new(|at| {
                if at == Step::Rename {
                    Err(enospc())
                } else {
                    Ok(())
                }
            })));
            assert_eq!(
                store.transition(|r| approve(r, 1)),
                Err(StorageError::Unknown)
            );
            fs_seams::set_hook(None);
            assert!(!store.authorize(&query(1, 1)));
            drop(store);
            let store = open(&home.path).unwrap();
            assert!(store.state().unwrap().reference.grants.is_empty());
            assert!(!store.authorize(&query(1, 1)));
            // Control: the same approval commits and authorizes normally.
            store.transition(|r| approve(r, 1)).unwrap();
            assert!(store.authorize(&query(1, 1)));
        }

        /// A closure that lowers any counter is refused before anything is
        /// written, and the store stays usable. Negative control: with the
        /// check bypassed, the same closure commits the lowered counter.
        #[test]
        fn a_commit_that_lowers_a_counter_is_refused_and_not_sticky() {
            type Lower = fn(&mut ReferenceState);
            let lowerings: [(&str, Lower); 4] = [
                ("nextAuthEpoch", |r| r.next_auth_epoch -= 1),
                ("denyFloor", |r| r.deny_floor -= 1),
                ("sourceScopeGeneration", |r| r.source_scope_generation -= 1),
                ("lastAcceptedWallUnixSeconds", |r| {
                    let mut earlier =
                        ReferenceState::new(r.last_accepted_wall_unix_seconds() - 50).unwrap();
                    earlier.sharing_enabled = r.sharing_enabled;
                    earlier.next_auth_epoch = r.next_auth_epoch;
                    earlier.deny_floor = r.deny_floor;
                    earlier.source_scope_generation = r.source_scope_generation;
                    *r = earlier;
                }),
            ];
            for (name, lower) in lowerings {
                for bypass in [0, seams::COUNTERS] {
                    let home = TempHome::new();
                    let store = open(&home.path).unwrap();
                    store
                        .transition(|r| {
                            let mut raised = r.clone();
                            raised.next_auth_epoch = 5;
                            raised.deny_floor = 3;
                            raised.source_scope_generation = 4;
                            Ok(raised)
                        })
                        .unwrap();
                    store.checkpoint(NOW + 100).unwrap();
                    let before = store.state().unwrap();
                    let file_before = std::fs::read(home.root().join("state.json")).unwrap();
                    let lowered = || {
                        store.transition(|r| {
                            let mut next = r.clone();
                            lower(&mut next);
                            Ok(next)
                        })
                    };
                    let _reset = seams::Reset;
                    seams::bypass(bypass);
                    let result = lowered();
                    seams::bypass(0);
                    if bypass == 0 {
                        assert_eq!(
                            result,
                            Err(StorageError::Refused(SecurityError::Conflict)),
                            "{name}"
                        );
                        assert_eq!(store.state().unwrap(), before, "{name}");
                        assert_eq!(
                            std::fs::read(home.root().join("state.json")).unwrap(),
                            file_before,
                            "{name}"
                        );
                        // Not sticky: the store still commits.
                        store.checkpoint(NOW + 101).unwrap();
                    } else {
                        assert_eq!(result, Ok(()), "{name}: bypass did not admit the lowering");
                        assert_ne!(store.state().unwrap(), before, "{name}");
                        drop(store);
                        assert_ne!(open(&home.path).unwrap().state().unwrap(), before, "{name}");
                    }
                }
            }
        }

        #[test]
        fn a_refused_transition_writes_nothing_and_is_not_sticky() {
            let home = TempHome::new();
            let store = open(&home.path).unwrap();
            let before = std::fs::read(home.root().join("state.json")).unwrap();
            assert_eq!(
                store.transition(|r| r.revoke_commit(id(9), NOW_MS)),
                Err(StorageError::Refused(SecurityError::Invalid))
            );
            assert_eq!(
                std::fs::read(home.root().join("state.json")).unwrap(),
                before
            );
            store.transition(|r| r.enable_sharing()).unwrap();
        }
    }
}
