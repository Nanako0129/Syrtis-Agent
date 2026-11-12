//! Pairing wire (`spec/pairing-v1.md`): the producer's Pair claim, Pair
//! status and Grant status handlers, owner approval, and the receiver's
//! claim, poll and grant-confirmation client.
//!
//! Identity, offers, pending claims and grants live only in the durable
//! [`StateStore`]. Every change goes through [`StateStore::transition`] with
//! a closure that calls only frozen `ReferenceState` transitions; status
//! answers come from one [`StateStore::state`] snapshot and authorize
//! nothing. The client returns what it confirmed and stores nothing; the
//! caller persists a [`ConfirmedGrant`] through `peer_store`.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    net::TcpStream,
    sync::{Mutex, OnceLock, PoisonError},
    time::{Duration, Instant},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    canonical::{CanonicalJsonV1, constant_time_eq},
    noise::{
        self, Deadline, INITIATOR_READ_TIMEOUT, INITIATOR_WRITE_TIMEOUT, NoiseError,
        RESPONDER_READ_TIMEOUT, RESPONDER_WRITE_TIMEOUT, Received, Session, StaticKey,
    },
    report::ReportRequest,
    report_peer::{self, Reports},
    secure_fs::StorageError,
    security::{
        ClockStatus, Frame, FrameKind, Grant, GrantState, MemoryLedger, OfferClaim,
        PEER_PROTOCOL_VERSION, PendingApproval, PendingState, ReferenceState, SecurityError,
        clock_status, decode_fixed_hex, hex_encode, offer_secret_hash, pair_sas, parse_pair_url,
    },
    state_store::{StateStore, random},
};

/// v1 never re-issues a SAS, so every pending claim has generation 1.
pub const SAS_GENERATION: u64 = 1;
pub const GRANT_LIFETIME_MS: i64 = 30 * 86_400_000;
/// Largest Pair claim, Pair status or Grant status request payload,
/// applied after the key-set dispatch. A Peer request is bounded only by
/// the frame (`FRAME_PAYLOAD_MAX`).
pub const PAIRING_PAYLOAD_MAX: usize = 4_096;
pub const RATE_INTERVAL: Duration = Duration::from_secs(1);
pub const RATE_TABLE_MAX: usize = 256;
/// Attempt records per offer. A record is removed only by the record rule
/// ([`ClaimAttempts`]); there is no eviction to make room. With all five
/// used, a claim still connects but creates no record.
pub const CLAIM_ATTEMPTS_MAX: usize = 5;
/// Connect or handshake failures in one `claim` call.
pub const CLAIM_CONNECT_FAILURES_MAX: usize = 5;
/// Authenticated `busy` answers in one `claim` call.
pub const CLAIM_BUSY_MAX: usize = 5;
pub const CLAIM_RETRY_INTERVAL: Duration = Duration::from_secs(1);
pub const POLL_INTERVAL: Duration = Duration::from_secs(3);
/// Longest offer (900 s) plus 60 s of grace, on the receiver's monotonic clock.
pub const POLL_WINDOW: Duration = Duration::from_secs(960);
pub const POLL_REQUESTS_MAX: u32 = 320;

const PROTOCOL: u16 = PEER_PROTOCOL_VERSION;
const PENDING_TAG: &[u8] = b"syrtis-pair-pending-v1\0";
const GRANT_TAG: &[u8] = b"syrtis-pair-grant-v1\0";

/// `SHA-256("syrtis-pair-pending-v1\0" || secretHash || hFinal)[..16]`.
///
/// `secretHash` is the value a handshake observer cannot compute: `hFinal`
/// is public to anyone who knows `responderStatic` and saw the handshake.
pub fn derive_pending_id(secret_hash: &[u8; 32], h_final: &[u8; 32]) -> [u8; 16] {
    first_16(
        Sha256::new()
            .chain_update(PENDING_TAG)
            .chain_update(secret_hash)
            .chain_update(h_final),
    )
}

/// `SHA-256("syrtis-pair-grant-v1\0" || pendingId)[..16]`.
pub fn derive_grant_id(pending_id: &[u8; 16]) -> [u8; 16] {
    first_16(
        Sha256::new()
            .chain_update(GRANT_TAG)
            .chain_update(pending_id),
    )
}

fn first_16(hasher: Sha256) -> [u8; 16] {
    let mut id = [0; 16];
    id.copy_from_slice(&hasher.finalize()[..16]);
    id
}

/// The error codes a pairing surface may send (`spec/v1.md` (iii)).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum PeerCode {
    Invalid = 1,
    Unauthorized = 2,
    Busy = 5,
    Incompatible = 6,
    Internal = 8,
}

impl PeerCode {
    pub fn wire(self) -> u16 {
        self as u16
    }

    fn from_wire(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::Invalid),
            2 => Some(Self::Unauthorized),
            5 => Some(Self::Busy),
            6 => Some(Self::Incompatible),
            8 => Some(Self::Internal),
            _ => None,
        }
    }
}

/// Total map from a store error to the peer code. Every arm is reached only
/// after the secret check or independently of any ID, so it is no oracle.
pub fn storage_error_code(error: StorageError) -> PeerCode {
    match error {
        StorageError::Refused(SecurityError::Unauthorized) => PeerCode::Unauthorized,
        StorageError::Refused(
            SecurityError::Bounds
            | SecurityError::Canonical
            | SecurityError::Conflict
            | SecurityError::Expired
            | SecurityError::Invalid,
        ) => PeerCode::Internal,
        StorageError::Busy => PeerCode::Busy,
        StorageError::UnsafeState
        | StorageError::Unknown
        | StorageError::Incompatible
        | StorageError::Corrupt
        | StorageError::Unavailable => PeerCode::Internal,
    }
}

/// The map for Pair claim: [`storage_error_code`], except that a store
/// `Busy` is `internal`. So a `busy` on Pair claim can only come from the
/// rate limiter, before any state is read, and a receiver may take it as
/// proof that nothing was committed.
fn claim_error_code(error: StorageError) -> PeerCode {
    match error {
        StorageError::Busy => PeerCode::Internal,
        other => storage_error_code(other),
    }
}

// ----------------------------------------------------------------- wire ---

/// The Pair bearer secret: lowercase hex on the wire, [`Secret32`] in memory.
/// A decode error never echoes the input.
///
/// [`Secret32`]: crate::state_store::Secret32
struct WireSecret(crate::state_store::Secret32);

impl fmt::Debug for WireSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for WireSecret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex_encode(self.0.expose()))
    }
}

impl<'de> Deserialize<'de> for WireSecret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        decode_fixed_hex::<32>(&text)
            .map(|bytes| Self(crate::state_store::Secret32::new(bytes)))
            .map_err(|_| D::Error::custom("secret is not 32 lowercase hex bytes"))
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairClaimRequest {
    offer_id: String,
    protocol: u16,
    secret: WireSecret,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairStatusRequest {
    pending_id: String,
    protocol: u16,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantStatusRequest {
    grant_id: String,
    protocol: u16,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairClaimResponse {
    expires_at: i64,
    pending_id: String,
    protocol: u16,
}

/// Pair status response (pending). `awaiting` is the wire name of the
/// stored `awaitingApproval`; `approved` and `active` do not decode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum WaitingState {
    Awaiting,
    Rejected,
    Expired,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairStatusPending {
    protocol: u16,
    state: WaitingState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum ApprovedState {
    Approved,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairStatusApproved {
    auth_epoch: u64,
    expires_at: i64,
    grant_id: String,
    protocol: u16,
    source_scope_generation: u64,
    state: ApprovedState,
}

/// Grant status `state`. `approved` does not decode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum GrantStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantStatusResponse {
    auth_epoch: u64,
    expires_at: i64,
    grant_id: String,
    protocol: u16,
    source_scope_generation: u64,
    state: GrantStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PeerErrorPayload {
    code: u16,
    protocol: u16,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, PeerCode> {
    CanonicalJsonV1::encode(value).map_err(|_| PeerCode::Internal)
}

/// A dispatched request: a pairing surface or the report path.
#[derive(Debug)]
enum Parsed {
    Pairing(Request),
    Report(Box<ReportRequest>),
}

/// A dispatched pairing request. Holds the secret only as [`Secret32`].
///
/// [`Secret32`]: crate::state_store::Secret32
#[derive(Debug)]
enum Request {
    Claim {
        offer_id: [u8; 16],
        secret: crate::state_store::Secret32,
    },
    PairStatus([u8; 16]),
    GrantStatus([u8; 16]),
}

/// Producer step (2) for one request frame: the kind, then
/// [`parse_request`]; for a Peer request, the payload `requestId` must be
/// the frame header's.
fn parse_frame(frame: &Frame) -> Result<Parsed, PeerCode> {
    if frame.kind != FrameKind::Request {
        return Err(PeerCode::Invalid);
    }
    let parsed = parse_request(&frame.payload)?;
    if let Parsed::Report(request) = &parsed {
        if request.request_id != hex_encode(&frame.request_id) {
            return Err(PeerCode::Invalid);
        }
    }
    Ok(parsed)
}

/// CanonicalJsonV1, exact key-set dispatch, the 4,096-byte cap for the
/// three pairing surfaces, `protocol`, typed decode. Reads no state and
/// depends on no ID. The frame bounds every payload to `FRAME_PAYLOAD_MAX`
/// before this runs.
fn parse_request(payload: &[u8]) -> Result<Parsed, PeerCode> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Surface {
        Claim,
        PairStatus,
        GrantStatus,
        Report,
    }
    let value = CanonicalJsonV1::decode_value(payload).map_err(|_| PeerCode::Invalid)?;
    let object = value.as_object().ok_or(PeerCode::Invalid)?;
    let keys: Vec<&str> = object.keys().map(String::as_str).collect();
    let surface = match keys.as_slice() {
        ["offerId", "protocol", "secret"] => Surface::Claim,
        ["pendingId", "protocol"] => Surface::PairStatus,
        ["grantId", "protocol"] => Surface::GrantStatus,
        // The Peer request (`spec/v1.md`), served by `report_peer`.
        [
            "aggregationRevision",
            "authEpoch",
            "clients",
            "endDateExclusive",
            "endpoint",
            "grantId",
            "protocol",
            "reportSchema",
            "requestId",
            "sourceScopeGeneration",
            "startDate",
            "timezone",
            "tzdbRevision",
        ] => Surface::Report,
        _ => return Err(PeerCode::Invalid),
    };
    if surface != Surface::Report && payload.len() > PAIRING_PAYLOAD_MAX {
        return Err(PeerCode::Invalid);
    }
    let protocol = &object["protocol"];
    if !(protocol.is_u64() || protocol.is_i64()) {
        return Err(PeerCode::Invalid);
    }
    if protocol.as_u64() != Some(u64::from(PROTOCOL)) {
        return Err(PeerCode::Incompatible);
    }
    let id = |text: &str| decode_fixed_hex::<16>(text).map_err(|_| PeerCode::Invalid);
    Ok(Parsed::Pairing(match surface {
        Surface::Report => {
            return CanonicalJsonV1::decode(payload)
                .map(|request| Parsed::Report(Box::new(request)))
                .map_err(|_| PeerCode::Invalid);
        }
        Surface::Claim => {
            let request: PairClaimRequest =
                CanonicalJsonV1::decode(payload).map_err(|_| PeerCode::Invalid)?;
            Request::Claim {
                offer_id: id(&request.offer_id)?,
                secret: request.secret.0,
            }
        }
        Surface::PairStatus => {
            let request: PairStatusRequest =
                CanonicalJsonV1::decode(payload).map_err(|_| PeerCode::Invalid)?;
            Request::PairStatus(id(&request.pending_id)?)
        }
        Surface::GrantStatus => {
            let request: GrantStatusRequest =
                CanonicalJsonV1::decode(payload).map_err(|_| PeerCode::Invalid)?;
            Request::GrantStatus(id(&request.grant_id)?)
        }
    }))
}

// ---------------------------------------------------------------- clock ---

/// Time sources, injectable for tests.
pub trait Clock: Send + Sync {
    /// Monotonic time since an arbitrary origin.
    fn monotonic(&self) -> Duration;
    /// OS wall clock, whole seconds since the Unix epoch.
    fn os_now_seconds(&self) -> Result<i64, StorageError>;
    fn sleep(&self, duration: Duration);
}

/// The OS clocks. Every instance reads monotonic time from one
/// process-wide origin, so readings from different instances compare.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn monotonic(&self) -> Duration {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        ORIGIN.get_or_init(Instant::now).elapsed()
    }

    fn os_now_seconds(&self) -> Result<i64, StorageError> {
        crate::state_store::os_now_seconds()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Per remote static, the monotonic time its last request was admitted.
#[derive(Debug, Default)]
pub struct RateLimiter(Mutex<HashMap<[u8; 32], Duration>>);

impl RateLimiter {
    /// Drops entries at least [`RATE_INTERVAL`] old, then refuses a static
    /// admitted less than [`RATE_INTERVAL`] ago, or a new static while the
    /// table holds [`RATE_TABLE_MAX`]. Only an admission stores a time.
    pub fn admit(&self, remote_static: &[u8; 32], now: Duration) -> bool {
        let mut last = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        last.retain(|_, admitted| now.saturating_sub(*admitted) < RATE_INTERVAL);
        if last.contains_key(remote_static) || last.len() >= RATE_TABLE_MAX {
            return false;
        }
        last.insert(*remote_static, now);
        true
    }
}

// ------------------------------------------------------------- producer ---

/// The producer side of the peer wire for one agent: the pairing surfaces
/// and the report path.
pub struct Producer<'a> {
    pub store: &'a StateStore,
    /// The agent identity, read from the store once by the caller, so a
    /// handshake touches no state.
    pub identity: &'a StaticKey,
    pub ledger: &'a MemoryLedger,
    /// The pairing limiter; the report path does not use it.
    pub limiter: &'a RateLimiter,
    pub clock: &'a dyn Clock,
    /// The report path's source, per-grant limit and compute slot.
    pub reports: &'a Reports,
}

impl fmt::Debug for Producer<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Producer { .. }")
    }
}

impl Producer<'_> {
    /// Serves one accepted connection: handshake, one request, then one
    /// response or error frame (a Peer request: the report path's chunks or
    /// error frame), close. A handshake or frame failure closes without
    /// sending anything: there is no request ID to answer.
    pub fn serve(&self, stream: TcpStream) {
        let Ok(mut session) = noise::accept(stream, self.identity) else {
            return;
        };
        let Ok(received) = session.receive(self.ledger, Deadline::after(RESPONDER_READ_TIMEOUT))
        else {
            return;
        };
        let request_id = received.frame().request_id;
        let parsed = parse_frame(received.frame());
        drop(received);
        let answer = match parsed {
            Ok(Parsed::Report(request)) => {
                return report_peer::serve(self, session, request_id, &request);
            }
            Ok(Parsed::Pairing(request)) => {
                self.answer(request, session.remote_static(), session.h_final())
            }
            Err(code) => Err(code),
        };
        let frame = match answer {
            Ok(payload) => Frame {
                kind: FrameKind::Response,
                final_chunk: true,
                request_id,
                chunk_index: 0,
                chunk_count: 1,
                payload,
            },
            Err(code) => error_frame(request_id, code.wire()),
        };
        let _ = session.send(&frame, Deadline::after(RESPONDER_WRITE_TIMEOUT));
    }

    /// Steps (3)–(5) for one parsed pairing request.
    fn answer(
        &self,
        request: Request,
        remote_static: &[u8; 32],
        h_final: &[u8; 32],
    ) -> Result<Vec<u8>, PeerCode> {
        if !self.limiter.admit(remote_static, self.clock.monotonic()) {
            return Err(PeerCode::Busy);
        }
        if constant_time_eq(remote_static, self.identity.public()) {
            return Err(PeerCode::Unauthorized);
        }
        match request {
            Request::Claim { offer_id, secret } => {
                self.claim(offer_id, secret.expose(), remote_static, h_final)
            }
            Request::PairStatus(pending_id) => self.pair_status(pending_id, remote_static),
            Request::GrantStatus(grant_id) => self.grant_status(grant_id, remote_static),
        }
    }

    fn claim(
        &self,
        offer_id: [u8; 16],
        secret: &[u8; 32],
        initiator: &[u8; 32],
        h_final: &[u8; 32],
    ) -> Result<Vec<u8>, PeerCode> {
        // Every store error on this surface goes through this one map.
        let (pending_id, expires_at) = self
            .commit_claim(offer_id, secret, initiator, h_final)
            .map_err(claim_error_code)?;
        encode(&PairClaimResponse {
            expires_at,
            pending_id: hex_encode(&pending_id),
            protocol: PROTOCOL,
        })
    }

    /// The claim transition. Returns the pending ID and expiry only once the
    /// commit is durable.
    fn commit_claim(
        &self,
        offer_id: [u8; 16],
        secret: &[u8; 32],
        initiator: &[u8; 32],
        h_final: &[u8; 32],
    ) -> Result<([u8; 16], i64), StorageError> {
        let responder = *self.identity.public();
        // The presented secret, not anything looked up in state.
        let secret_hash = offer_secret_hash(&offer_id, secret, &responder);
        let pending_id = derive_pending_id(&secret_hash, h_final);
        let sas_code = pair_sas(PROTOCOL, &offer_id, &responder, initiator, h_final);
        let os_now = self.clock.os_now_seconds()?;
        let mut claimed = None;
        #[cfg(test)]
        seams::before_claim_transition();
        self.store.transition(|state| {
            // Inside the closure, so a disable committed after any
            // earlier read still refuses the claim.
            if !state.sharing_enabled {
                return Err(SecurityError::Unauthorized);
            }
            let claim = OfferClaim {
                offer_id,
                secret: *secret,
                responder_static: responder,
                pending_id,
                initiator_static: *initiator,
                sas_code,
                sas_generation: SAS_GENERATION,
            };
            let (next, pending_id, _) = state.claim_offer(claim, os_now)?;
            let expires_at = next
                .pending
                .iter()
                .find(|pending| pending.pending_id == pending_id)
                .map(|pending| pending.expires_at_ms)
                .ok_or(SecurityError::Invalid)?;
            claimed = Some((pending_id, expires_at));
            Ok(next)
        })?;
        // Reached only when the commit is durable.
        claimed.ok_or(StorageError::Refused(SecurityError::Invalid))
    }

    fn pair_status(&self, pending_id: [u8; 16], initiator: &[u8; 32]) -> Result<Vec<u8>, PeerCode> {
        let state = self.store.state().map_err(storage_error_code)?;
        let reference = &state.reference;
        if !reference.sharing_enabled {
            return Err(PeerCode::Unauthorized);
        }
        let pending = reference
            .pending
            .iter()
            .find(|pending| pending.pending_id == pending_id)
            .filter(|pending| constant_time_eq(&pending.initiator_static, initiator))
            .ok_or(PeerCode::Unauthorized)?;
        let waiting = |state| {
            encode(&PairStatusPending {
                protocol: PROTOCOL,
                state,
            })
        };
        match pending.state {
            // Only `awaitingApproval` needs the clock, and it is read after
            // the binding, so only the bound static can see `busy`.
            PendingState::AwaitingApproval => match self.clock_of(reference) {
                Ok(clock) if clock.anomaly => Err(PeerCode::Busy),
                Ok(clock) if effective_ms(clock)? >= pending.expires_at_ms => {
                    waiting(WaitingState::Expired)
                }
                Ok(_) => waiting(WaitingState::Awaiting),
                Err(error) => Err(storage_error_code(error)),
            },
            PendingState::Rejected => waiting(WaitingState::Rejected),
            PendingState::Expired => waiting(WaitingState::Expired),
            // Answered whether or not the pending has since expired (F-8),
            // from the grant as it is now.
            PendingState::Approved => {
                let grant_id = derive_grant_id(&pending_id);
                match reference
                    .grants
                    .iter()
                    .find(|grant| grant.grant_id == grant_id)
                {
                    // Unreachable under the frozen transitions; fail closed.
                    None => waiting(WaitingState::Expired),
                    Some(grant) => encode(&PairStatusApproved {
                        auth_epoch: grant.auth_epoch,
                        expires_at: grant.expires_at_ms,
                        grant_id: hex_encode(&grant.grant_id),
                        protocol: PROTOCOL,
                        source_scope_generation: grant.source_scope_generation,
                        state: ApprovedState::Approved,
                    }),
                }
            }
        }
    }

    /// Advisory only: admits nothing. Answers the bound static even while
    /// sharing is off, so a receiver learns `revoked` explicitly (F-5). An
    /// unreadable OS clock is handled like an anomaly: what needs no clock
    /// is still answered.
    fn grant_status(&self, grant_id: [u8; 16], initiator: &[u8; 32]) -> Result<Vec<u8>, PeerCode> {
        let state = self.store.state().map_err(storage_error_code)?;
        let reference = &state.reference;
        let grant = reference
            .grants
            .iter()
            .find(|grant| grant.grant_id == grant_id)
            .filter(|grant| constant_time_eq(&grant.initiator_static, initiator))
            .ok_or(PeerCode::Unauthorized)?;
        let status = grant_status_of(grant, reference, self.clock_of(reference))?;
        encode(&GrantStatusResponse {
            auth_epoch: grant.auth_epoch,
            expires_at: grant.expires_at_ms,
            grant_id: hex_encode(&grant.grant_id),
            protocol: PROTOCOL,
            source_scope_generation: grant.source_scope_generation,
            state: status,
        })
    }

    /// The frozen clock status, or the OS clock error for the caller to
    /// weigh against answers that need no clock.
    pub(crate) fn clock_of(&self, reference: &ReferenceState) -> Result<ClockStatus, StorageError> {
        self.clock
            .os_now_seconds()
            .map(|os_now| clock_status(os_now, reference.last_accepted_wall_unix_seconds()))
    }
}

/// The Grant status `state` of `grant`, from the grant's own fields and the
/// state's counters, never from a request's fields. The report path decides
/// its codes 3 and 4 with this same function. `Err` is `busy` (clock
/// anomaly) or the OS clock error, when no clock-free answer applies.
pub(crate) fn grant_status_of(
    grant: &Grant,
    reference: &ReferenceState,
    clock: Result<ClockStatus, StorageError>,
) -> Result<GrantStatus, PeerCode> {
    // None of these needs a clock.
    let revoked = grant.state == GrantState::Revoked
        || !reference.sharing_enabled
        || grant.auth_epoch <= reference.deny_floor
        || grant.source_scope_generation != reference.source_scope_generation;
    let expired = grant.state == GrantState::Expired;
    Ok(match clock {
        // Expiry first, deliberately (`spec/pairing-v1.md`).
        Ok(clock) if !clock.anomaly => {
            if expired || effective_ms(clock)? >= grant.expires_at_ms {
                GrantStatus::Expired
            } else if revoked {
                GrantStatus::Revoked
            } else {
                GrantStatus::Active
            }
        }
        _ if revoked => GrantStatus::Revoked,
        _ if expired => GrantStatus::Expired,
        Ok(_) => return Err(PeerCode::Busy),
        Err(error) => return Err(storage_error_code(error)),
    })
}

fn effective_ms(clock: ClockStatus) -> Result<i64, PeerCode> {
    clock
        .effective_now
        .checked_mul(1_000)
        .ok_or(PeerCode::Internal)
}

/// One error frame; `code` is a pairing [`PeerCode`] or a report-path code.
pub(crate) fn error_frame(request_id: [u8; 16], code: u16) -> Frame {
    let payload = CanonicalJsonV1::encode(&PeerErrorPayload {
        code,
        protocol: PROTOCOL,
    })
    .unwrap_or_default();
    Frame {
        kind: FrameKind::Error,
        final_chunk: true,
        request_id,
        chunk_index: 0,
        chunk_count: 1,
        payload,
    }
}

/// Owner approval of `pending_id` (the control command is `SA-2B2c`).
/// `responderStatic` is this agent's identity from one snapshot; the grant
/// ID is derived from the pending ID; the grant lasts 30 days from the
/// effective now. Returns the grant ID.
pub fn approve(
    store: &StateStore,
    pending_id: [u8; 16],
    sas_generation: u64,
    disclosure_exact: bool,
    os_now_seconds: i64,
) -> Result<[u8; 16], StorageError> {
    let responder_static = store.state()?.identity_public()?;
    let grant_id = derive_grant_id(&pending_id);
    store.transition(|state| {
        let effective =
            clock_status(os_now_seconds, state.last_accepted_wall_unix_seconds()).effective_now;
        let grant_expires_at_ms = effective
            .checked_mul(1_000)
            .and_then(|ms| ms.checked_add(GRANT_LIFETIME_MS))
            .ok_or(SecurityError::Bounds)?;
        state.approve_pending(
            PendingApproval {
                pending_id,
                sas_generation,
                grant_id,
                responder_static,
                grant_expires_at_ms,
                disclosure_exact,
            },
            os_now_seconds,
        )
    })?;
    Ok(grant_id)
}

// ------------------------------------------------------------- receiver ---

/// Errors the receiver client reports. None carries peer bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    /// The offer names this device's own static key.
    SelfPairing,
    /// The Pair URL was refused by the frozen `parse_pair_url` (malformed,
    /// not canonical, or outside its lifetime). Nothing was sent.
    InvalidOffer,
    /// Pair claim answered `unauthorized`. The cause is not inferred.
    OfferUnusable,
    /// A claim succeeded with a pending ID that neither a kept record nor
    /// this connection derived.
    LostAttempt,
    /// The producer answered with this error code. From `claim`,
    /// `Code(Busy)` means [`CLAIM_BUSY_MAX`] `busy` answers in one call;
    /// none of them left a record, but records kept by earlier calls stay,
    /// so the caller must keep its [`ClaimAttempts`]. `Code(Internal)` ends
    /// the call at once and keeps the record its connection created (the
    /// request may have been committed); the UI must not retry it
    /// automatically.
    Code(PeerCode),
    Rejected,
    Expired,
    Revoked,
    /// The reply broke the protocol; the client stopped.
    Aborted,
    /// The poll window or the request cap ran out.
    PollLimit,
    /// Connect, handshake, transport, deadline or memory failure. From
    /// `claim`, a failure after the handshake ends the call at once and
    /// keeps the record its connection created.
    Transport(NoiseError),
}

impl ClientError {
    /// Text for the person pairing.
    pub fn message(self) -> &'static str {
        match self {
            Self::OfferUnusable => {
                "This offer cannot be used. If the owner's device shows a pending request for this offer, ask the owner to reject it."
            }
            Self::LostAttempt => {
                "This device lost track of an earlier attempt. Ask the owner to reject the request and create a new offer."
            }
            Self::Code(PeerCode::Busy) => {
                "The other device cannot answer right now. Try again later."
            }
            Self::SelfPairing => "This offer was created on this device.",
            Self::InvalidOffer => "This offer is not valid.",
            Self::Rejected => "The owner rejected the request.",
            Self::Expired => "The request expired.",
            Self::Revoked => "The grant was revoked.",
            Self::Code(_) | Self::Aborted | Self::PollLimit | Self::Transport(_) => {
                "Pairing did not complete."
            }
        }
    }
}

/// One attempt that completed its handshake: the pending ID and SAS it
/// derived, recorded before the request was written.
#[derive(Clone, Debug)]
struct Attempt {
    pending_id: [u8; 16],
    sas: String,
}

/// Claim attempts, per offer, at most [`CLAIM_ATTEMPTS_MAX`]. A retry
/// against the frozen claim returns the ID of the first attempt whose claim
/// was committed, so a record is kept while it may still be answered.
///
/// Record rule: a record is created after the handshake (a pending ID
/// exists only from `hFinal` on) and before the request is written, unless
/// the offer already has [`CLAIM_ATTEMPTS_MAX`] records: then the
/// connection still goes ahead, without a record. Only the record this
/// connection itself created is ever removed, and only when (a) an
/// authenticated `busy`, `unauthorized`, `invalid` or `incompatible`
/// answers it (all are sent before any commit), or (b) a success names an
/// *earlier* record's pending ID (that earlier attempt consumed the offer).
/// It is kept for `internal`, for a transport failure after the handshake
/// (both end the call), for a protocol violation, and for a success that
/// matches itself. A connection that created no record removes nothing. A
/// new attempt or another offer clears only what is displayed, never this.
#[derive(Clone, Debug, Default)]
pub struct ClaimAttempts {
    records: BTreeMap<[u8; 16], Vec<Attempt>>,
}

impl ClaimAttempts {
    /// Attempt slots used for `offer_id`.
    pub fn used(&self, offer_id: &[u8; 16]) -> usize {
        self.records.get(offer_id).map_or(0, Vec::len)
    }
}

/// A claim whose pending ID matched one of this device's attempts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claimed {
    pub offer_id: [u8; 16],
    pub responder_static: [u8; 32],
    pub host: String,
    pub port: u16,
    pub pending_id: [u8; 16],
    /// The SAS of the attempt that created the pending claim.
    pub sas: String,
    /// Producer wall clock; display only.
    pub expires_at_ms: i64,
    /// Receiver monotonic time of the successful claim. Process-local: it
    /// has an arbitrary origin and must never be persisted.
    pub claimed_at: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairStatus {
    Awaiting,
    Rejected,
    Expired,
    Approved {
        grant_id: [u8; 16],
        auth_epoch: u64,
        source_scope_generation: u64,
        expires_at_ms: i64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantAnswer {
    pub state: GrantStatus,
    pub auth_epoch: u64,
    pub source_scope_generation: u64,
    pub expires_at_ms: i64,
}

/// A grant Grant status confirmed `active`. Returned, not stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedGrant {
    pub grant_id: [u8; 16],
    pub auth_epoch: u64,
    pub source_scope_generation: u64,
    pub expires_at_ms: i64,
    pub responder_static: [u8; 32],
    pub initiator_static: [u8; 32],
    pub pending_id: [u8; 16],
    /// Where the claimed offer pointed (the Pair URL's `host` and `port`),
    /// carried from [`Claimed`] by [`PairingClient::poll`].
    pub host: String,
    pub port: u16,
}

/// The receiver side of the pairing wire.
pub struct PairingClient<'a> {
    pub identity: &'a StaticKey,
    pub ledger: &'a MemoryLedger,
    pub clock: &'a dyn Clock,
}

impl fmt::Debug for PairingClient<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingClient { .. }")
    }
}

/// A reply frame, typed by the request that was sent and the frame kind.
#[derive(Debug)]
enum Reply {
    Body(Received),
    Code(PeerCode),
}

impl PairingClient<'_> {
    /// Pair claim from a Pair URL. The URL goes through the frozen
    /// `parse_pair_url` at `effective_now_ms`, which owns the whole offer
    /// validation; anything it refuses is [`ClientError::InvalidOffer`]
    /// before any connection. The URL and the parsed offer, which holds the
    /// secret, are never formatted, logged or returned.
    ///
    /// Attempt records follow the record rule of [`ClaimAttempts`].
    /// Within one call, `busy` and connect or handshake failures are
    /// retried at least [`CLAIM_RETRY_INTERVAL`] apart; after
    /// [`CLAIM_BUSY_MAX`] `busy` answers the call returns `Code(Busy)`, and
    /// after [`CLAIM_CONNECT_FAILURES_MAX`] connect or handshake failures
    /// [`ClientError::Transport`]. `internal` and a transport failure after
    /// the handshake end the call at once. A later call may try again.
    pub fn claim(
        &self,
        pair_url: &str,
        effective_now_ms: i64,
        attempts: &mut ClaimAttempts,
    ) -> Result<Claimed, ClientError> {
        let offer =
            parse_pair_url(pair_url, effective_now_ms).map_err(|_| ClientError::InvalidOffer)?;
        let offer_id =
            decode_fixed_hex::<16>(&offer.offer_id).map_err(|_| ClientError::InvalidOffer)?;
        let responder_static = decode_fixed_hex::<32>(&offer.responder_static)
            .map_err(|_| ClientError::InvalidOffer)?;
        let secret = crate::state_store::Secret32::new(
            decode_fixed_hex::<32>(&offer.secret).map_err(|_| ClientError::InvalidOffer)?,
        );
        let (host, port) = (offer.host, offer.port);
        if constant_time_eq(&responder_static, self.identity.public()) {
            return Err(ClientError::SelfPairing);
        }
        let secret_hash = offer_secret_hash(&offer_id, secret.expose(), &responder_static);
        let payload = CanonicalJsonV1::encode(&PairClaimRequest {
            offer_id: hex_encode(&offer_id),
            protocol: PROTOCOL,
            secret: WireSecret(secret),
        })
        .map_err(|_| ClientError::InvalidOffer)?;
        let tries = attempts.records.entry(offer_id).or_default();
        let mut connect_failures = 0;
        let mut busy = 0;
        let mut retry = false;
        loop {
            if retry {
                self.clock.sleep(CLAIM_RETRY_INTERVAL);
            }
            retry = true;
            let mut session = match noise::connect(&host, port, self.identity, &responder_static) {
                Ok(session) => session,
                Err(error) => {
                    connect_failures += 1;
                    if connect_failures >= CLAIM_CONNECT_FAILURES_MAX {
                        return Err(ClientError::Transport(error));
                    }
                    continue;
                }
            };
            let h_final = session.h_final();
            let own = Attempt {
                pending_id: derive_pending_id(&secret_hash, h_final),
                sas: pair_sas(
                    PROTOCOL,
                    &offer_id,
                    &responder_static,
                    self.identity.public(),
                    h_final,
                ),
            };
            // With every slot used the connection still goes ahead, but
            // without a record: a reply naming this connection's own ID
            // still succeeds below, and a lost one cannot be recovered.
            let created = tries.len() < CLAIM_ATTEMPTS_MAX;
            if created {
                tries.push(own.clone());
            }
            // Removes only the record this connection created, which is
            // the last one; a connection that created none removes nothing.
            let drop_own = |tries: &mut Vec<Attempt>| {
                if created {
                    tries.pop();
                }
            };
            match self.exchange(&mut session, payload.clone()) {
                Ok(Reply::Body(received)) => {
                    let response: PairClaimResponse =
                        CanonicalJsonV1::decode(&received.frame().payload)
                            .map_err(|_| ClientError::Aborted)?;
                    if response.protocol != PROTOCOL {
                        return Err(ClientError::Aborted);
                    }
                    let pending_id = decode_fixed_hex::<16>(&response.pending_id)
                        .map_err(|_| ClientError::Aborted)?;
                    let sas = match tries
                        .iter()
                        .find(|attempt| attempt.pending_id == pending_id)
                    {
                        Some(attempt) => attempt.sas.clone(),
                        None if pending_id == own.pending_id => own.sas.clone(),
                        None => return Err(ClientError::LostAttempt),
                    };
                    // Rule (b): an earlier attempt consumed the offer, so the
                    // ID this connection derived is never answered.
                    if pending_id != own.pending_id {
                        drop_own(tries);
                    }
                    return Ok(Claimed {
                        offer_id,
                        responder_static,
                        host,
                        port,
                        pending_id,
                        sas,
                        expires_at_ms: response.expires_at,
                        claimed_at: self.clock.monotonic(),
                    });
                }
                // Rule (a): every one of these is sent before any commit
                // (on Pair claim a store `Busy` is sent as `internal`), so
                // this connection's ID can never be answered.
                Ok(Reply::Code(PeerCode::Unauthorized)) => {
                    drop_own(tries);
                    return Err(ClientError::OfferUnusable);
                }
                Ok(Reply::Code(code @ (PeerCode::Invalid | PeerCode::Incompatible))) => {
                    drop_own(tries);
                    return Err(ClientError::Code(code));
                }
                Ok(Reply::Code(PeerCode::Busy)) => {
                    drop_own(tries);
                    busy += 1;
                    if busy >= CLAIM_BUSY_MAX {
                        return Err(ClientError::Code(PeerCode::Busy));
                    }
                }
                // The request may have been committed: the record stays,
                // and the call ends so each retry is the caller's choice.
                Ok(Reply::Code(PeerCode::Internal)) => {
                    return Err(ClientError::Code(PeerCode::Internal));
                }
                // The request may have reached the producer and been
                // committed: the record stays, and the call ends, as for
                // `internal`. A protocol violation keeps it too.
                Err(error) => return Err(error),
            }
        }
    }

    /// One Pair status request.
    pub fn pair_status(&self, claimed: &Claimed) -> Result<PairStatus, ClientError> {
        let payload = CanonicalJsonV1::encode(&PairStatusRequest {
            pending_id: hex_encode(&claimed.pending_id),
            protocol: PROTOCOL,
        })
        .map_err(|_| ClientError::Aborted)?;
        let received = self.request(claimed, payload)?;
        let body = &received.frame().payload;
        let value = CanonicalJsonV1::decode_value(body).map_err(|_| ClientError::Aborted)?;
        // Shape chosen by the `state` value, never by the key set.
        if value.get("state").and_then(Value::as_str) == Some("approved") {
            let response: PairStatusApproved =
                CanonicalJsonV1::decode(body).map_err(|_| ClientError::Aborted)?;
            let grant_id =
                decode_fixed_hex::<16>(&response.grant_id).map_err(|_| ClientError::Aborted)?;
            if response.protocol != PROTOCOL || grant_id != derive_grant_id(&claimed.pending_id) {
                return Err(ClientError::Aborted);
            }
            return Ok(PairStatus::Approved {
                grant_id,
                auth_epoch: response.auth_epoch,
                source_scope_generation: response.source_scope_generation,
                expires_at_ms: response.expires_at,
            });
        }
        let response: PairStatusPending =
            CanonicalJsonV1::decode(body).map_err(|_| ClientError::Aborted)?;
        if response.protocol != PROTOCOL {
            return Err(ClientError::Aborted);
        }
        Ok(match response.state {
            WaitingState::Awaiting => PairStatus::Awaiting,
            WaitingState::Rejected => PairStatus::Rejected,
            WaitingState::Expired => PairStatus::Expired,
        })
    }

    /// One Grant status request.
    pub fn grant_status(
        &self,
        claimed: &Claimed,
        grant_id: [u8; 16],
    ) -> Result<GrantAnswer, ClientError> {
        let payload = CanonicalJsonV1::encode(&GrantStatusRequest {
            grant_id: hex_encode(&grant_id),
            protocol: PROTOCOL,
        })
        .map_err(|_| ClientError::Aborted)?;
        let received = self.request(claimed, payload)?;
        let response: GrantStatusResponse =
            CanonicalJsonV1::decode(&received.frame().payload).map_err(|_| ClientError::Aborted)?;
        if response.protocol != PROTOCOL
            || decode_fixed_hex::<16>(&response.grant_id) != Ok(grant_id)
        {
            return Err(ClientError::Aborted);
        }
        Ok(GrantAnswer {
            state: response.state,
            auth_epoch: response.auth_epoch,
            source_scope_generation: response.source_scope_generation,
            expires_at_ms: response.expires_at,
        })
    }

    /// Polls Pair status, then Grant status, one request at a time at least
    /// [`POLL_INTERVAL`] apart, for at most [`POLL_WINDOW`] of receiver
    /// monotonic time after the claim and [`POLL_REQUESTS_MAX`] requests.
    /// `busy`, `internal`, transport errors and timeouts count and continue;
    /// every other answer stops.
    pub fn poll(&self, claimed: &Claimed) -> Result<ConfirmedGrant, ClientError> {
        let mut requests = 0;
        let mut last = claimed.claimed_at;
        let mut approved: Option<[u8; 16]> = None;
        loop {
            let due = last + POLL_INTERVAL;
            let now = self.clock.monotonic();
            if now < due {
                self.clock.sleep(due - now);
            }
            let now = self.clock.monotonic();
            if requests >= POLL_REQUESTS_MAX
                || now.saturating_sub(claimed.claimed_at) >= POLL_WINDOW
            {
                return Err(ClientError::PollLimit);
            }
            requests += 1;
            last = now;
            let outcome = match approved {
                None => match self.pair_status(claimed) {
                    Ok(PairStatus::Approved { grant_id, .. }) => {
                        approved = Some(grant_id);
                        Ok(None)
                    }
                    Ok(PairStatus::Awaiting) => Ok(None),
                    Ok(PairStatus::Rejected) => Ok(Some(Err(ClientError::Rejected))),
                    Ok(PairStatus::Expired) => Ok(Some(Err(ClientError::Expired))),
                    Err(error) => Err(error),
                },
                Some(grant_id) => self.grant_status(claimed, grant_id).map(|answer| {
                    Some(match answer.state {
                        GrantStatus::Active => Ok(ConfirmedGrant {
                            grant_id,
                            auth_epoch: answer.auth_epoch,
                            source_scope_generation: answer.source_scope_generation,
                            expires_at_ms: answer.expires_at_ms,
                            responder_static: claimed.responder_static,
                            initiator_static: *self.identity.public(),
                            pending_id: claimed.pending_id,
                            host: claimed.host.clone(),
                            port: claimed.port,
                        }),
                        GrantStatus::Revoked => Err(ClientError::Revoked),
                        GrantStatus::Expired => Err(ClientError::Expired),
                    })
                }),
            };
            match outcome {
                Ok(Some(done)) => return done,
                Ok(None)
                | Err(
                    ClientError::Code(PeerCode::Busy | PeerCode::Internal)
                    | ClientError::Transport(_),
                ) => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn request(&self, claimed: &Claimed, payload: Vec<u8>) -> Result<Received, ClientError> {
        let mut session = noise::connect(
            &claimed.host,
            claimed.port,
            self.identity,
            &claimed.responder_static,
        )
        .map_err(ClientError::Transport)?;
        match self.exchange(&mut session, payload)? {
            Reply::Body(received) => Ok(received),
            Reply::Code(code) => Err(ClientError::Code(code)),
        }
    }

    /// Sends one request frame and checks the reply frame against it.
    fn exchange(&self, session: &mut Session, payload: Vec<u8>) -> Result<Reply, ClientError> {
        let request_id =
            random::<16>().map_err(|_| ClientError::Transport(NoiseError::Unavailable))?;
        let request = Frame {
            kind: FrameKind::Request,
            final_chunk: true,
            request_id,
            chunk_index: 0,
            chunk_count: 1,
            payload,
        };
        session
            .send(&request, Deadline::after(INITIATOR_WRITE_TIMEOUT))
            .map_err(ClientError::Transport)?;
        drop(request);
        let received = session
            .receive(self.ledger, Deadline::after(INITIATOR_READ_TIMEOUT))
            .map_err(ClientError::Transport)?;
        let frame = received.frame();
        if frame.request_id != request_id
            || frame.chunk_count != 1
            || frame.chunk_index != 0
            || !frame.final_chunk
        {
            return Err(ClientError::Aborted);
        }
        match frame.kind {
            FrameKind::Response => Ok(Reply::Body(received)),
            FrameKind::Error => {
                let error: PeerErrorPayload =
                    CanonicalJsonV1::decode(&frame.payload).map_err(|_| ClientError::Aborted)?;
                if error.protocol != PROTOCOL {
                    return Err(ClientError::Aborted);
                }
                PeerCode::from_wire(error.code)
                    .map(Reply::Code)
                    .ok_or(ClientError::Aborted)
            }
            FrameKind::Request => Err(ClientError::Aborted),
        }
    }
}

#[cfg(test)]
mod seams {
    use std::cell::RefCell;

    type Hook = Box<dyn FnOnce()>;

    thread_local! {
        static BEFORE_CLAIM_TRANSITION: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    /// Used only by the store-backed tests, which need a secure root.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn set_before_claim_transition(hook: Option<Hook>) {
        BEFORE_CLAIM_TRANSITION.with(|cell| *cell.borrow_mut() = hook);
    }

    pub(super) fn before_claim_transition() {
        if let Some(hook) = BEFORE_CLAIM_TRANSITION.with(|cell| cell.borrow_mut().take()) {
            hook();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acceptance (10): every store and transition error maps to one
    /// peer code, and every peer code is in {1, 2, 5, 6, 8}.
    #[test]
    fn every_storage_and_security_error_maps_to_its_peer_code() {
        let cases = [
            (StorageError::UnsafeState, 8),
            (StorageError::Busy, 5),
            (StorageError::Unknown, 8),
            (StorageError::Incompatible, 8),
            (StorageError::Corrupt, 8),
            (StorageError::Unavailable, 8),
            (StorageError::Refused(SecurityError::Bounds), 8),
            (StorageError::Refused(SecurityError::Canonical), 8),
            (StorageError::Refused(SecurityError::Conflict), 8),
            (StorageError::Refused(SecurityError::Expired), 8),
            (StorageError::Refused(SecurityError::Invalid), 8),
            (StorageError::Refused(SecurityError::Unauthorized), 2),
        ];
        for (error, code) in cases {
            let mapped = storage_error_code(error).wire();
            assert_eq!(mapped, code, "{error:?}");
            assert!([1, 2, 5, 6, 8].contains(&mapped), "{error:?}");
        }
        for code in [
            PeerCode::Invalid,
            PeerCode::Unauthorized,
            PeerCode::Busy,
            PeerCode::Incompatible,
            PeerCode::Internal,
        ] {
            assert_eq!(PeerCode::from_wire(code.wire()), Some(code));
        }
        for code in [0, 3, 4, 7, 9, u16::MAX] {
            assert_eq!(PeerCode::from_wire(code), None, "{code}");
        }
    }

    /// D3: Pair claim sends a store `Busy` as `internal`, so its `busy` can
    /// only be the rate limiter's; every other store error maps as the
    /// total map does.
    #[test]
    fn the_claim_map_sends_a_store_busy_as_internal() {
        assert_eq!(claim_error_code(StorageError::Busy), PeerCode::Internal);
        // Control: the total map, used by the status surfaces, keeps `busy`.
        assert_eq!(storage_error_code(StorageError::Busy), PeerCode::Busy);
        for error in [
            StorageError::UnsafeState,
            StorageError::Unknown,
            StorageError::Incompatible,
            StorageError::Corrupt,
            StorageError::Unavailable,
            StorageError::Refused(SecurityError::Bounds),
            StorageError::Refused(SecurityError::Canonical),
            StorageError::Refused(SecurityError::Conflict),
            StorageError::Refused(SecurityError::Expired),
            StorageError::Refused(SecurityError::Invalid),
            StorageError::Refused(SecurityError::Unauthorized),
        ] {
            assert_eq!(
                claim_error_code(error),
                storage_error_code(error),
                "{error:?}"
            );
        }
    }

    /// Acceptance (11), internal types: the request types that hold the
    /// secret never show it.
    #[test]
    fn internal_request_types_redact_the_secret() {
        let secret = [0xa7; 32];
        let payload = CanonicalJsonV1::encode(&PairClaimRequest {
            offer_id: hex_encode(&[0x11; 16]),
            protocol: PROTOCOL,
            secret: WireSecret(crate::state_store::Secret32::new(secret)),
        })
        .unwrap();
        assert!(
            String::from_utf8_lossy(&payload).contains(&hex_encode(&secret)),
            "control: the request payload does carry the secret"
        );
        let decoded: PairClaimRequest = CanonicalJsonV1::decode(&payload).unwrap();
        let request = parse_request(&payload).unwrap();
        assert!(matches!(request, Parsed::Pairing(Request::Claim { .. })));
        for shown in [format!("{decoded:?}"), format!("{request:?}")] {
            assert!(shown.contains("Secret32(redacted)"), "{shown}");
            assert!(!shown.contains(&hex_encode(&secret)), "{shown}");
            assert!(!shown.contains("167, 167"), "{shown}");
        }
        // A bad secret is refused without echoing it.
        let bad = br#"{"offerId":"11111111111111111111111111111111","protocol":1,"secret":"NOT-A-SECRET-VALUE"}"#;
        let error = serde_json::from_slice::<PairClaimRequest>(bad)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("NOT-A-SECRET-VALUE"), "{error}");
        assert_eq!(parse_request(bad).err(), Some(PeerCode::Invalid));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    mod disk {
        use std::sync::{
            Arc,
            atomic::{AtomicI64, Ordering},
        };

        use super::*;
        use crate::{
            secure_fs::{
                SecureRoot, Step,
                seams::{self as fs_seams, Reset as FsReset},
                test_support::{SUFFIX, TempHome, retry_busy},
            },
            security::{Offer, OfferState},
        };

        const NOW: i64 = 1_700_000_000;

        struct FixedClock(AtomicI64);

        impl Clock for FixedClock {
            fn monotonic(&self) -> Duration {
                Duration::from_secs(self.0.load(Ordering::SeqCst) as u64)
            }
            fn os_now_seconds(&self) -> Result<i64, StorageError> {
                Ok(self.0.load(Ordering::SeqCst))
            }
            fn sleep(&self, duration: Duration) {
                self.0
                    .fetch_add(duration.as_secs() as i64, Ordering::SeqCst);
            }
        }

        struct Node {
            _home: TempHome,
            store: Arc<StateStore>,
            key: StaticKey,
            ledger: MemoryLedger,
            limiter: RateLimiter,
            clock: FixedClock,
            reports: Reports,
        }

        const OFFER: [u8; 16] = [0x0f; 16];
        const SECRET: [u8; 32] = [0x5e; 32];
        const INITIATOR: [u8; 32] = [0xb2; 32];

        fn node() -> Node {
            let home = TempHome::new();
            let store =
                retry_busy(|| StateStore::open(SecureRoot::open_under(&home.path, SUFFIX)?, NOW))
                    .unwrap();
            let key = StaticKey::from_state(&store.state().unwrap()).unwrap();
            let responder = *key.public();
            store
                .transition(|state| {
                    state.enable_sharing()?.create_offer(
                        Offer {
                            offer_id: OFFER,
                            secret_hash: offer_secret_hash(&OFFER, &SECRET, &responder),
                            created_at_ms: NOW * 1_000,
                            expires_at_ms: NOW * 1_000 + 600_000,
                            state: OfferState::Active,
                        },
                        NOW,
                    )
                })
                .unwrap();
            Node {
                _home: home,
                store: Arc::new(store),
                key,
                ledger: MemoryLedger::default(),
                limiter: RateLimiter::default(),
                clock: FixedClock(AtomicI64::new(NOW)),
                reports: Reports::new(Arc::new(crate::report_peer::NoSource)),
            }
        }

        impl Node {
            fn producer(&self) -> Producer<'_> {
                Producer {
                    store: &self.store,
                    identity: &self.key,
                    ledger: &self.ledger,
                    limiter: &self.limiter,
                    clock: &self.clock,
                    reports: &self.reports,
                }
            }

            /// A claim answered in this thread, so thread-local seams apply.
            fn claim(&self) -> Result<Vec<u8>, PeerCode> {
                self.clock.sleep(RATE_INTERVAL);
                answer_claim(&self.producer())
            }
        }

        /// Producer steps (2)–(5) for [`claim_frame`].
        fn answer_claim(producer: &Producer<'_>) -> Result<Vec<u8>, PeerCode> {
            match parse_frame(&claim_frame())? {
                Parsed::Pairing(request) => producer.answer(request, &INITIATOR, &[0x44; 32]),
                Parsed::Report(_) => panic!("a claim frame parsed as a Peer request"),
            }
        }

        fn claim_frame() -> Frame {
            let payload = CanonicalJsonV1::encode(&PairClaimRequest {
                offer_id: hex_encode(&OFFER),
                protocol: PROTOCOL,
                secret: WireSecret(crate::state_store::Secret32::new(SECRET)),
            })
            .unwrap();
            Frame {
                kind: FrameKind::Request,
                final_chunk: true,
                request_id: [0x33; 16],
                chunk_index: 0,
                chunk_count: 1,
                payload,
            }
        }

        /// D3: a store `Busy` while serving Pair claim answers `internal`,
        /// never `busy`. The OS clock read stands in for the store: every
        /// store error of this surface goes through one map.
        #[test]
        fn a_store_busy_during_a_claim_answers_internal() {
            struct BusyClock;
            impl Clock for BusyClock {
                fn monotonic(&self) -> Duration {
                    Duration::ZERO
                }
                fn os_now_seconds(&self) -> Result<i64, StorageError> {
                    Err(StorageError::Busy)
                }
                fn sleep(&self, _: Duration) {}
            }
            let node = node();
            let producer = Producer {
                clock: &BusyClock,
                ..node.producer()
            };
            assert_eq!(answer_claim(&producer), Err(PeerCode::Internal));
            assert!(node.store.state().unwrap().reference.pending.is_empty());
        }

        /// Acceptance (10): a claim whose commit fails answers `internal`
        /// and sends no claim response; the store is then sticky-unknown
        /// and the next claim is `internal` too.
        #[test]
        fn a_claim_whose_commit_fails_answers_internal_and_never_the_pending_id() {
            let node = node();
            let _reset = FsReset;
            fs_seams::set_hook(Some(Box::new(|step| {
                if step == Step::Rename {
                    Err(std::io::Error::other("injected"))
                } else {
                    Ok(())
                }
            })));
            assert_eq!(node.claim(), Err(PeerCode::Internal));
            fs_seams::set_hook(None);
            assert_eq!(node.store.state().err(), Some(StorageError::Unknown));
            assert_eq!(node.claim(), Err(PeerCode::Internal));
        }

        /// Control for the test above: the same claim without the injected
        /// failure answers the pending ID.
        #[test]
        fn control_the_same_claim_commits_and_answers() {
            let node = node();
            let body = node.claim().unwrap();
            let response: PairClaimResponse = CanonicalJsonV1::decode(&body).unwrap();
            let pending = &node.store.state().unwrap().reference.pending[0];
            assert_eq!(response.pending_id, hex_encode(&pending.pending_id));
        }

        /// Acceptance (16): a disable committed after the handler started
        /// but before its transition still refuses the claim, because the
        /// sharing check is inside the transition closure.
        #[test]
        fn a_disable_between_snapshot_and_transition_refuses_the_claim() {
            let node = node();
            let store = Arc::clone(&node.store);
            seams::set_before_claim_transition(Some(Box::new(move || {
                store.disable(NOW * 1_000).unwrap();
            })));
            let answer = node.claim();
            seams::set_before_claim_transition(None);
            assert_eq!(answer, Err(PeerCode::Unauthorized));
            let state = node.store.state().unwrap();
            assert!(!state.reference.sharing_enabled);
            assert!(state.reference.pending.is_empty());
        }
    }
}
