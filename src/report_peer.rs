//! Peer report transport (`spec/report-peer-v1.md`): one Peer request
//! frame answered with 1–274 response chunks, or one error frame.
//!
//! Producer side: admission is the frozen nine-conjunct predicate through
//! [`StateStore::authorize`], after the static binding; every chunk is
//! authorized again through [`StateStore::authorize_then`], which holds the
//! store's read lock while the chunk is written. The body comes from an
//! injected [`ReportSource`] and is never decoded there.
//!
//! Receiver side: [`fetch`] asks one paired producer for one report. The
//! producer is untrusted for framing, size and content: every chunk is
//! checked, the body is reserved on the ledger before it is kept, and the
//! frozen decoder runs only after a non-allocating pass ([`scan`]) has
//! refused the shapes it would refuse anyway and the decoder's allocations
//! have been reserved ([`decode_reservation`]).

use std::{
    collections::HashMap,
    fmt,
    mem::size_of,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    canonical::{CanonicalJsonV1, constant_time_eq},
    noise::{self, Deadline, NoiseError, RESPONDER_WRITE_TIMEOUT, Session, StaticKey},
    pairing::{GrantStatus, PeerCode, Producer, error_frame, grant_status_of, storage_error_code},
    peer_store::{PeerRecord, usable},
    report::{
        AgentsRecord, Endpoint, GraphRecord, HourlyRecord, ModelsRecord, ReportRecord,
        ReportRequest, decode_response,
    },
    secure_fs::StorageError,
    security::{
        AGGREGATION_REVISION, FRAME_PAYLOAD_MAX, Frame, FrameKind, Grant, GrantState,
        LOGICAL_BODY_MAX, MemoryLedger, MemoryReservation, PEER_PROTOCOL_VERSION,
        REPORT_SCHEMA_VERSION, ReferenceState, TZDB_REVISION, clock_status, decode_fixed_hex,
        hex_encode,
    },
    state_store::{AuthorizationQuery, StateStore, random},
};

/// How long the source may take, on the producer's monotonic clock. The
/// source keeps to it; a result returned later is discarded.
pub const COMPUTE_DEADLINE: Duration = Duration::from_secs(120);
/// Each chunk's write, so a revoke waits for at most one chunk.
pub const CHUNK_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// The whole response, from the first chunk on.
pub const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(15);
/// Requests one grant may make at once after being idle.
pub const GRANT_BURST: u64 = 2;
/// One more request is allowed per this much monotonic time.
pub const GRANT_REFILL: Duration = Duration::from_secs(60);

/// The error codes the report path sends. 3 and 4 only after the static
/// binding, and only from the grant's own fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ReportCode {
    Invalid = 1,
    Unauthorized = 2,
    Expired = 3,
    Revoked = 4,
    Busy = 5,
    Incompatible = 6,
    Internal = 8,
}

impl ReportCode {
    pub fn wire(self) -> u16 {
        self as u16
    }
}

impl From<PeerCode> for ReportCode {
    fn from(code: PeerCode) -> Self {
        match code {
            PeerCode::Invalid => Self::Invalid,
            PeerCode::Unauthorized => Self::Unauthorized,
            PeerCode::Busy => Self::Busy,
            PeerCode::Incompatible => Self::Incompatible,
            PeerCode::Internal => Self::Internal,
        }
    }
}

/// The source failed; the request is answered `internal`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceError;

/// Where report bodies come from (the real source is `SA-2B3`).
pub trait ReportSource: Send + Sync {
    /// The canonical `ReportResponse` body for `request`'s endpoint. The
    /// producer checks only its length. The source should return by
    /// `deadline`; nothing interrupts it if it does not.
    fn report(&self, request: &ReportRequest, deadline: Instant) -> Result<Vec<u8>, SourceError>;
}

/// No source yet: every authorized report request is answered `internal`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSource;

impl ReportSource for NoSource {
    fn report(&self, _: &ReportRequest, _: Instant) -> Result<Vec<u8>, SourceError> {
        Err(SourceError)
    }
}

/// What the report path shares across connections: the source, the
/// per-grant limit and the compute slot. One per process (the listener's).
pub struct Reports {
    source: Arc<dyn ReportSource>,
    grants: Mutex<HashMap<[u8; 16], Bucket>>,
    computing: AtomicBool,
}

impl fmt::Debug for Reports {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Reports { .. }")
    }
}

impl Reports {
    pub fn new(source: Arc<dyn ReportSource>) -> Self {
        Self {
            source,
            grants: Mutex::new(HashMap::new()),
            computing: AtomicBool::new(false),
        }
    }

    /// Step (5): one request in flight per grant, and a token bucket of
    /// [`GRANT_BURST`] refilled one per [`GRANT_REFILL`]. A refusal takes no
    /// token. Buckets that are full and idle are dropped, so the table holds
    /// only grants that used it recently.
    fn admit(&self, grant_id: [u8; 16], now: Duration) -> Option<InFlight<'_>> {
        let mut grants = lock(&self.grants);
        grants.retain(|_, bucket| {
            bucket.refill(now);
            bucket.in_flight || bucket.tokens < GRANT_BURST
        });
        let bucket = grants.entry(grant_id).or_insert(Bucket {
            tokens: GRANT_BURST,
            at: now,
            in_flight: false,
        });
        if bucket.in_flight || bucket.tokens == 0 {
            return None;
        }
        bucket.tokens -= 1;
        bucket.in_flight = true;
        Some(InFlight(self, grant_id))
    }

    /// Step (6): one computation per process, no queue.
    fn compute_slot(&self) -> Option<ComputeSlot<'_>> {
        self.computing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| ComputeSlot(&self.computing))
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: u64,
    /// Monotonic time the last whole token was added (or the bucket filled).
    at: Duration,
    in_flight: bool,
}

impl Bucket {
    fn refill(&mut self, now: Duration) {
        let gained = now.saturating_sub(self.at).as_secs() / GRANT_REFILL.as_secs();
        self.tokens = self.tokens.saturating_add(gained).min(GRANT_BURST);
        if self.tokens == GRANT_BURST {
            self.at = now;
        } else {
            // `gained < GRANT_BURST` here, so this cannot overflow.
            self.at += GRANT_REFILL * gained as u32;
        }
    }
}

/// Clears the grant's in-flight mark when the response ends, on every path.
struct InFlight<'a>(&'a Reports, [u8; 16]);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if let Some(bucket) = lock(&self.0.grants).get_mut(&self.1) {
            bucket.in_flight = false;
        }
    }
}

/// Frees the compute slot. Dropped only after the source has returned.
struct ComputeSlot<'a>(&'a AtomicBool);

impl Drop for ComputeSlot<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// An admitted request: everything the chunk loop needs.
struct Admitted<'a> {
    grant_id: [u8; 16],
    body: Vec<u8>,
    _reservation: MemoryReservation,
    _in_flight: InFlight<'a>,
}

/// Serves one parsed Peer request (step (1) done by the caller): an error
/// frame, or the body in chunks. Writes no log.
pub(crate) fn serve(
    producer: &Producer<'_>,
    mut session: Session,
    request_id: [u8; 16],
    request: &ReportRequest,
) {
    match admit(producer, session.remote_static(), request) {
        Ok(admitted) => send_chunks(producer, &mut session, request_id, request, admitted),
        Err(code) => {
            let _ = session.send(
                &error_frame(request_id, code.wire()),
                Deadline::after(RESPONDER_WRITE_TIMEOUT),
            );
        }
    }
}

/// Steps (2)–(7).
fn admit<'a>(
    producer: &Producer<'a>,
    remote_static: &[u8; 32],
    request: &ReportRequest,
) -> Result<Admitted<'a>, ReportCode> {
    let store = producer.store;
    // (2) The static binding, from one snapshot. An unknown grant and a
    // foreign static are the same `unauthorized`.
    let state = store
        .state()
        .map_err(|error| ReportCode::from(storage_error_code(error)))?;
    let reference = &state.reference;
    let grant_id =
        decode_fixed_hex::<16>(&request.grant_id).map_err(|_| ReportCode::Unauthorized)?;
    let grant = reference
        .grants
        .iter()
        .find(|grant| grant.grant_id == grant_id)
        .filter(|grant| constant_time_eq(&grant.initiator_static, remote_static))
        .ok_or(ReportCode::Unauthorized)?;
    // (3) Authorization, against the current durable state.
    let os_now = producer.clock.os_now_seconds();
    let authorized = os_now.is_ok_and(|now| store.authorize(&query(grant_id, request, now)));
    if !authorized {
        return Err(refusal(producer, grant, reference, os_now));
    }
    // (4)
    request.validate().map_err(|_| ReportCode::Invalid)?;
    // (5)
    let reports = producer.reports;
    let in_flight = reports
        .admit(grant_id, producer.clock.monotonic())
        .ok_or(ReportCode::Busy)?;
    // (6) and (7). The slot is freed only once the source has returned.
    let slot = reports.compute_slot().ok_or(ReportCode::Busy)?;
    let started = producer.clock.monotonic();
    let body = reports
        .source
        .report(request, Instant::now() + COMPUTE_DEADLINE);
    let late = producer.clock.monotonic().saturating_sub(started) >= COMPUTE_DEADLINE;
    drop(slot);
    let body = body
        .ok()
        .filter(|body| !late && (1..=LOGICAL_BODY_MAX).contains(&body.len()))
        .ok_or(ReportCode::Internal)?;
    let reservation = producer
        .ledger
        .reserve(body.len())
        .ok_or(ReportCode::Busy)?;
    Ok(Admitted {
        grant_id,
        body,
        _reservation: reservation,
        _in_flight: in_flight,
    })
}

fn query(grant_id: [u8; 16], request: &ReportRequest, os_now: i64) -> AuthorizationQuery {
    AuthorizationQuery {
        grant_id,
        auth_epoch: request.auth_epoch,
        source_scope_generation: request.source_scope_generation,
        endpoint: request.endpoint,
        os_now_unix_seconds: os_now,
    }
}

/// Why an authorization failed, for the bound static only: by the same
/// function Grant status uses, from the grant's own fields and the
/// counters, never from the request. Anything but `expired` or `revoked`
/// (a stale `authEpoch`, another `sourceScopeGeneration`, an endpoint out
/// of scope, a clock anomaly) is `unauthorized`.
fn refusal(
    producer: &Producer<'_>,
    grant: &Grant,
    reference: &ReferenceState,
    os_now: Result<i64, StorageError>,
) -> ReportCode {
    let clock = os_now.map(|now| clock_status(now, reference.last_accepted_wall_unix_seconds()));
    match grant_status_of(grant, reference, clock) {
        Ok(GrantStatus::Expired) => {
            // Persist the expiry, so a clock moved back later cannot
            // make the grant look merely anomalous. A failure changes
            // nothing in the answer.
            if grant.state == GrantState::Active {
                if let Some(now_ms) = clock
                    .ok()
                    .and_then(|clock| clock.effective_now.checked_mul(1_000))
                {
                    let _ = producer
                        .store
                        .transition(|state| state.expire_one(grant.grant_id, now_ms));
                }
            }
            ReportCode::Expired
        }
        Ok(GrantStatus::Revoked) => ReportCode::Revoked,
        Ok(GrantStatus::Active) | Err(_) => ReportCode::Unauthorized,
    }
}

/// Step (8). Each chunk is authorized again and written while the store's
/// read lock is held, so once a revoke commit holds the write lock no
/// chunk write starts. A failed authorization or write closes the
/// connection without an error frame.
fn send_chunks(
    producer: &Producer<'_>,
    session: &mut Session,
    request_id: [u8; 16],
    request: &ReportRequest,
    admitted: Admitted<'_>,
) {
    // At most 274: the body is at most `LOGICAL_BODY_MAX`.
    let count = admitted.body.len().div_ceil(FRAME_PAYLOAD_MAX) as u32;
    let end = Instant::now() + RESPONSE_WRITE_TIMEOUT;
    for (index, chunk) in admitted.body.chunks(FRAME_PAYLOAD_MAX).enumerate() {
        let index = index as u32;
        let frame = Frame {
            kind: FrameKind::Response,
            final_chunk: index + 1 == count,
            request_id,
            chunk_index: index,
            chunk_count: count,
            payload: chunk.to_vec(),
        };
        let Ok(os_now) = producer.clock.os_now_seconds() else {
            return;
        };
        // `f` takes no store lock: with a writer waiting it would deadlock.
        let sent =
            producer
                .store
                .authorize_then(&query(admitted.grant_id, request, os_now), || {
                    let left = end.saturating_duration_since(Instant::now());
                    let deadline = Deadline::after(left.min(CHUNK_WRITE_TIMEOUT));
                    #[cfg(test)]
                    seams::event(request_id, seams::Event::Start(index));
                    let sent = session.send(&frame, deadline);
                    #[cfg(test)]
                    seams::event(request_id, seams::Event::Returned(index));
                    sent
                });
        if sent != Some(Ok(())) {
            return;
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ------------------------------------------------------------- receiver ---

/// The whole exchange after the handshake, on the receiver's monotonic
/// clock: the producer's compute deadline (120 s) plus its response
/// deadline (15 s). Absolute: progress never extends it.
pub const FETCH_DEADLINE: Duration = Duration::from_secs(135);
/// Fetches running at once per [`FetchLimiter`].
pub const MAX_FETCHES: usize = 2;
/// Most `records` a body may hold.
pub const RECORDS_MAX: usize = 262_144;
/// Most decoded bytes of all value strings together; keys are not counted
/// here (they are in the reservation).
pub const VALUE_STRINGS_MAX: usize = 8 * 1024 * 1024;
/// Longest string, key or value, in decoded bytes. No valid response holds
/// a longer one (`report::MAX_TEXT_BYTES`; dates and IDs are shorter).
pub const STRING_MAX: usize = crate::report::MAX_TEXT_BYTES;
/// Fixed allowance on top of the counted decode cost: the scratch and NFC
/// buffers of strings at most [`STRING_MAX`] long, the `clients` vectors,
/// the request copy `validate` makes, and error text.
pub const DECODE_SLACK: usize = 64 * 1024;

/// What to ask for. The rest of the Peer request comes from the peer
/// record and the protocol constants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportQuery {
    pub endpoint: Endpoint,
    pub start_date: String,
    pub end_date_exclusive: String,
    pub timezone: String,
    /// Sorted, unique; empty means every client.
    pub clients: Vec<String>,
}

/// The decoded records, typed by the endpoint that was asked for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Records {
    Graph(Vec<GraphRecord>),
    Models(Vec<ModelsRecord>),
    Hourly(Vec<HourlyRecord>),
    Agents(Vec<AgentsRecord>),
}

/// A report the frozen decoder accepted against the request that was sent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fetched {
    /// The canonical response body, exactly as received.
    pub body: Vec<u8>,
    pub records: Records,
    pub saturated: bool,
}

/// Why a fetch failed. None carries bytes from the producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchError {
    /// The query fails `ReportRequest::validate`. Nothing was sent.
    InvalidQuery,
    /// The record is not usable (`peer_store::usable`). Nothing was sent.
    Unusable,
    /// [`MAX_FETCHES`] fetches are running. Nothing was sent.
    TooMany,
    /// Error code 3.
    Expired,
    /// Error code 4.
    Revoked,
    /// Error code 2. The grant may be fine and the record only stale (a
    /// revocation of another grant renumbers `authEpoch`): ask Grant
    /// status, then `PeerStore::update_grant`.
    CheckGrantStatus,
    /// Error code 5. The producer may already have spent one of the
    /// grant's rate tokens: do not retry before [`GRANT_REFILL`] (60 s).
    Busy,
    /// Error code 8.
    Internal,
    /// Error code 1 or 6.
    Rejected,
    /// Connect, handshake or transport failure.
    Transport(NoiseError),
    /// [`FETCH_DEADLINE`] passed.
    Timeout,
    /// The reply broke the frame or chunk rules, or its error frame is not
    /// a valid peer error.
    Protocol,
    /// The body was refused, by the shape gate or by the frozen decoder
    /// and `validate` against the request that was sent.
    Invalid,
    /// The memory ledger refused a reservation. A later fetch may fit.
    Memory,
    /// The body's decode cost is more than the whole ledger
    /// ([`REMOTE_MEMORY_MAX`]): no later fetch of the same report can fit.
    TooLarge,
}

/// At most [`MAX_FETCHES`] fetches at once. Share one per process.
#[derive(Debug, Default)]
pub struct FetchLimiter(AtomicUsize);

impl FetchLimiter {
    fn acquire(&self) -> Option<FetchSlot<'_>> {
        let mut running = self.0.load(Ordering::Acquire);
        while running < MAX_FETCHES {
            match self.0.compare_exchange_weak(
                running,
                running + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(FetchSlot(&self.0)),
                Err(observed) => running = observed,
            }
        }
        None
    }
}

struct FetchSlot<'a>(&'a AtomicUsize);

impl Drop for FetchSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Asks the producer of `peer` for one report: (1) `ReportRequest::validate`
/// on the request built from `peer` and `query`; (2) `usable`; (3) a
/// [`FetchLimiter`] slot; nothing is sent unless all three pass. Then a
/// handshake pinned to `peer.responder_static`, one request, and the reply
/// within [`FETCH_DEADLINE`], checked and decoded as `spec/report-peer-v1.md`
/// ("Receiver") says. No retry, no polling, no cache.
///
/// A caller that updates `peers.json` from the outcome names the record by
/// `peer.responder_static` and `peer.grant_id`, never by bytes of the reply.
pub fn fetch(
    peer: &PeerRecord,
    query: &ReportQuery,
    store: &StateStore,
    ledger: &MemoryLedger,
    limiter: &FetchLimiter,
) -> Result<Fetched, FetchError> {
    let request_id = random::<16>().map_err(|_| FetchError::Transport(NoiseError::Unavailable))?;
    let request = ReportRequest {
        aggregation_revision: AGGREGATION_REVISION,
        auth_epoch: peer.auth_epoch,
        clients: query.clients.clone(),
        end_date_exclusive: query.end_date_exclusive.clone(),
        endpoint: query.endpoint.into(),
        grant_id: hex_encode(&peer.grant_id),
        protocol: PEER_PROTOCOL_VERSION,
        report_schema: REPORT_SCHEMA_VERSION,
        request_id: hex_encode(&request_id),
        source_scope_generation: peer.source_scope_generation,
        start_date: query.start_date.clone(),
        timezone: query.timezone.clone(),
        tzdb_revision: TZDB_REVISION.into(),
    };
    request.validate().map_err(|_| FetchError::InvalidQuery)?;
    // A query can pass `validate` and still not fit one request frame
    // (128 clients of 255 escaped bytes). Refuse it here, before anything
    // is sent, not as a frame error after the handshake.
    if CanonicalJsonV1::encode(&request).map_or(true, |bytes| bytes.len() > FRAME_PAYLOAD_MAX) {
        return Err(FetchError::InvalidQuery);
    }
    if !usable(peer, store) {
        return Err(FetchError::Unusable);
    }
    // `usable` read its own snapshot: a reset since then must not send
    // under an identity the record is not bound to.
    let identity = store
        .state()
        .and_then(|state| StaticKey::from_state(&state))
        .map_err(|_| FetchError::Unusable)?;
    if *identity.public() != peer.initiator_static {
        return Err(FetchError::Unusable);
    }
    let _slot = limiter.acquire().ok_or(FetchError::TooMany)?;
    let mut session = noise::connect(&peer.host, peer.port, &identity, &peer.responder_static)
        .map_err(FetchError::Transport)?;
    exchange(
        &mut session,
        request_id,
        &request,
        query.endpoint,
        ledger,
        Deadline::after(FETCH_DEADLINE),
    )
}

/// One request on an established session, then the reply: one error frame,
/// or 1–274 chunks checked one by one and reserved before they are kept,
/// then [`decode_reservation`] reserved before the frozen decoder runs.
/// Every reservation is returned when this returns.
fn exchange(
    session: &mut Session,
    request_id: [u8; 16],
    request: &ReportRequest,
    endpoint: Endpoint,
    ledger: &MemoryLedger,
    deadline: Deadline,
) -> Result<Fetched, FetchError> {
    let payload = CanonicalJsonV1::encode(request).map_err(|_| FetchError::InvalidQuery)?;
    session
        .send(
            &Frame {
                kind: FrameKind::Request,
                final_chunk: true,
                request_id,
                chunk_index: 0,
                chunk_count: 1,
                payload,
            },
            deadline,
        )
        .map_err(transport)?;
    let first = session.receive(ledger, deadline).map_err(transport)?;
    let frame = first.frame();
    if frame.request_id != request_id {
        return Err(FetchError::Protocol);
    }
    match frame.kind {
        FrameKind::Error => return Err(error_code(&frame.payload)),
        FrameKind::Request => return Err(FetchError::Protocol),
        FrameKind::Response if frame.chunk_index != 0 => return Err(FetchError::Protocol),
        FrameKind::Response => {}
    }
    // `Frame::decode` holds `chunkCount` to 1..=274 and `final` to the last
    // index, on every chunk.
    let count = frame.chunk_count;
    let capacity = count as usize * FRAME_PAYLOAD_MAX;
    let _body_reservation = ledger.reserve(capacity).ok_or(FetchError::Memory)?;
    // One allocation: every chunk is at most `FRAME_PAYLOAD_MAX`.
    let mut body = Vec::with_capacity(capacity);
    body.extend_from_slice(&frame.payload);
    drop(first);
    for index in 1..count {
        let received = session.receive(ledger, deadline).map_err(transport)?;
        let frame = received.frame();
        if frame.kind != FrameKind::Response
            || frame.request_id != request_id
            || frame.chunk_count != count
            || frame.chunk_index != index
            || body.len() + frame.payload.len() > LOGICAL_BODY_MAX
        {
            return Err(FetchError::Protocol);
        }
        body.extend_from_slice(&frame.payload);
    }
    let cost = decode_reservation(&body, endpoint).map_err(|_| FetchError::Invalid)?;
    // More than the whole ledger: no retry can ever fit it.
    if cost > crate::security::REMOTE_MEMORY_MAX {
        return Err(FetchError::TooLarge);
    }
    let _decode_reservation = ledger.reserve(cost).ok_or(FetchError::Memory)?;
    #[cfg(test)]
    receive_seams::before_decode();
    let (records, saturated) = match endpoint {
        Endpoint::Graph => decode::<GraphRecord>(&body, request, Records::Graph),
        Endpoint::Models => decode::<ModelsRecord>(&body, request, Records::Models),
        Endpoint::Hourly => decode::<HourlyRecord>(&body, request, Records::Hourly),
        Endpoint::Agents => decode::<AgentsRecord>(&body, request, Records::Agents),
    }?;
    // The buffer was sized for `chunkCount` full chunks; the caller gets
    // one sized for the body.
    body.shrink_to_fit();
    Ok(Fetched {
        body,
        records,
        saturated,
    })
}

/// The frozen decoder and `validate`, against the request that was sent.
fn decode<R: ReportRecord>(
    body: &[u8],
    request: &ReportRequest,
    wrap: fn(Vec<R>) -> Records,
) -> Result<(Records, bool), FetchError> {
    let response = decode_response::<R>(body, Some(request)).map_err(|_| FetchError::Invalid)?;
    Ok((wrap(response.records), response.saturated))
}

fn transport(error: NoiseError) -> FetchError {
    match error {
        NoiseError::Timeout => FetchError::Timeout,
        NoiseError::Memory => FetchError::Memory,
        NoiseError::Framing | NoiseError::Frame => FetchError::Protocol,
        other => FetchError::Transport(other),
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ErrorPayload {
    code: u16,
    protocol: u16,
}

/// An error frame's payload (at most 4 KiB; its decode is not charged).
fn error_code(payload: &[u8]) -> FetchError {
    match CanonicalJsonV1::decode::<ErrorPayload>(payload) {
        Ok(ErrorPayload {
            code,
            protocol: PEER_PROTOCOL_VERSION,
        }) => match code {
            1 | 6 => FetchError::Rejected,
            2 => FetchError::CheckGrantStatus,
            3 => FetchError::Expired,
            4 => FetchError::Revoked,
            5 => FetchError::Busy,
            8 => FetchError::Internal,
            _ => FetchError::Protocol,
        },
        _ => FetchError::Protocol,
    }
}

// ------------------------------------------------- receiver: before decode ---

/// The response keys, in CanonicalJsonV1 order.
const RESPONSE_KEYS: [&str; 15] = [
    "aggregationRevision",
    "authEpoch",
    "clients",
    "endDateExclusive",
    "endpoint",
    "grantId",
    "protocol",
    "records",
    "reportSchema",
    "requestId",
    "saturated",
    "sourceScopeGeneration",
    "startDate",
    "timezone",
    "tzdbRevision",
];

const GRAPH_KEYS: &[&str] = &[
    "cacheReadTokens",
    "cacheWriteTokens",
    "client",
    "costNanoUsd",
    "date",
    "inputTokens",
    "messageCount",
    "model",
    "outputTokens",
    "provider",
    "reasoningTokens",
    "totalTokens",
    "turnCount",
];

const MODELS_KEYS: &[&str] = &[
    "cacheReadTokens",
    "cacheWriteTokens",
    "client",
    "costNanoUsd",
    "durationMillis",
    "inputTokens",
    "messageCount",
    "model",
    "outputTokens",
    "provider",
    "reasoningTokens",
    "sampleCount",
    "timedTokens",
    "totalTokens",
    "turnCount",
];

const HOURLY_KEYS: &[&str] = &[
    "bucketStartUnixMs",
    "cacheReadTokens",
    "cacheWriteTokens",
    "client",
    "costNanoUsd",
    "inputTokens",
    "messageCount",
    "model",
    "outputTokens",
    "provider",
    "reasoningTokens",
    "totalTokens",
    "turnCount",
    "utcOffsetSeconds",
];

const AGENTS_KEYS: &[&str] = &[
    "agent",
    "cacheReadTokens",
    "cacheWriteTokens",
    "client",
    "costNanoUsd",
    "inputTokens",
    "messageCount",
    "model",
    "outputTokens",
    "provider",
    "reasoningTokens",
    "totalTokens",
    "turnCount",
];

/// The record keys and the typed record size of `endpoint`.
fn record_shape(endpoint: Endpoint) -> (&'static [&'static str], usize) {
    match endpoint {
        Endpoint::Graph => (GRAPH_KEYS, size_of::<GraphRecord>()),
        Endpoint::Models => (MODELS_KEYS, size_of::<ModelsRecord>()),
        Endpoint::Hourly => (HOURLY_KEYS, size_of::<HourlyRecord>()),
        Endpoint::Agents => (AGENTS_KEYS, size_of::<AgentsRecord>()),
    }
}

/// The shape gate refused a body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanError {
    /// Not the response shape: syntax, whitespace, a key set or key order,
    /// an array or object where none belongs, a value of a refused type, or
    /// more than 128 `clients`.
    Shape,
    /// A string longer than [`STRING_MAX`] decoded bytes.
    String,
    /// More than [`RECORDS_MAX`] records.
    Records,
    /// More than [`VALUE_STRINGS_MAX`] bytes of value strings.
    StringBytes,
}

/// What the frozen decoder builds from a body, counted without allocating.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    /// JSON objects: the top level and each record.
    pub objects: usize,
    /// Object entries, one key each.
    pub keys: usize,
    /// Decoded bytes of all keys.
    pub key_bytes: usize,
    /// Value strings (`clients` elements included).
    pub strings: usize,
    /// Decoded bytes of all value strings.
    pub string_bytes: usize,
    /// Every JSON value, the top-level object included.
    pub values: usize,
    /// Array elements (`clients` and `records`).
    pub elements: usize,
    pub records: usize,
}

/// One pass over `body`, allocating nothing, that refuses what the typed
/// decode of `endpoint`'s response would refuse anyway, plus the two
/// receiver limits [`RECORDS_MAX`] and [`VALUE_STRINGS_MAX`] (spec
/// "Receiver", the shape gate), and counts what the decoder will allocate.
/// It replaces none of the frozen decoder's checks.
pub fn scan(body: &[u8], endpoint: Endpoint) -> Result<Counts, ScanError> {
    let (record_keys, _) = record_shape(endpoint);
    let mut scanner = Scanner {
        bytes: body,
        at: 0,
        counts: Counts::default(),
    };
    scanner.counts.values += 1;
    scanner.object(&RESPONSE_KEYS, &mut |scanner, key| match key {
        "clients" => scanner.array(
            crate::report::MAX_CLIENTS,
            ScanError::Shape,
            &mut |scanner| {
                scanner.counts.values += 1;
                scanner.value_string()
            },
        ),
        "records" => scanner.array(RECORDS_MAX, ScanError::Records, &mut |scanner| {
            scanner.counts.values += 1;
            scanner.counts.records += 1;
            scanner.object(record_keys, &mut |scanner, _| scanner.scalar(false))
        }),
        _ => scanner.scalar(true),
    })?;
    if scanner.at != body.len() {
        return Err(ScanError::Shape);
    }
    Ok(scanner.counts)
}

/// Bytes to reserve before the frozen `decode_response` runs on `body`: an
/// upper bound on what it holds at once beyond the body itself (spec
/// "Receiver memory"). Refuses what [`scan`] refuses.
pub fn decode_reservation(body: &[u8], endpoint: Endpoint) -> Result<usize, ScanError> {
    let counts = scan(body, endpoint)?;
    let (record_keys, record_size) = record_shape(endpoint);
    decode_cost(&counts, body.len(), record_keys.len(), record_size).ok_or(ScanError::Shape)
}

/// Allocation granularity charged per allocation.
const ALLOC_ROUND: usize = 16;
/// B-tree node capacity of `std`'s `BTreeMap` (`B = 6`).
const NODE_CAPACITY: usize = 11;
/// A `BTreeMap<String, Value>` leaf: parent pointer, index and length (16
/// with padding), then the keys and values in place.
const LEAF_BYTES: usize = round_up(16 + NODE_CAPACITY * (size_of::<String>() + size_of::<Value>()));
/// An internal node: a leaf plus `NODE_CAPACITY + 1` edges.
const INTERNAL_BYTES: usize = round_up(LEAF_BYTES + (NODE_CAPACITY + 1) * size_of::<usize>());

const fn round_up(bytes: usize) -> usize {
    (bytes + ALLOC_ROUND - 1) & !(ALLOC_ROUND - 1)
}

/// Node bytes of one object with `entries` keys. Up to 11 fit one leaf.
/// From 12 the root splits into two leaves under one internal node, and
/// neither leaf can split again before 18 entries (each holds at least 5
/// after the split and at most 11), whether the map is built by insertion
/// (the decoder's second DOM) or in bulk (its first). The gate admits only
/// 13 to 15.
fn object_nodes(entries: usize) -> Option<usize> {
    match entries {
        0 => Some(0),
        1..=NODE_CAPACITY => Some(LEAF_BYTES),
        12..=17 => Some(2 * LEAF_BYTES + INTERNAL_BYTES),
        _ => None,
    }
}

/// `count` strings of `bytes` decoded bytes in all, each its own
/// allocation rounded up to [`ALLOC_ROUND`] (an empty one allocates
/// nothing, so the bound holds).
fn strings_cost(bytes: usize, count: usize) -> Option<usize> {
    count.checked_mul(ALLOC_ROUND - 1)?.checked_add(bytes)
}

/// The decode cost, one term per allocation class, checked arithmetic:
///
/// - one DOM: the object nodes, every key and value string, and a `Value`
///   slot for the root and for each array element, twice over for `Vec`
///   growth (map values live inside the nodes);
/// - the DOM twice: the decoder builds one to read the body and another
///   when it re-encodes the typed value;
/// - the typed records, twice over for `Vec` growth;
/// - the re-encoding buffer, three times the body (doubling growth and the
///   copy while it grows);
/// - [`DECODE_SLACK`].
fn decode_cost(
    counts: &Counts,
    body_len: usize,
    record_entries: usize,
    record_size: usize,
) -> Option<usize> {
    let nodes = object_nodes(RESPONSE_KEYS.len())?
        .checked_add(counts.records.checked_mul(object_nodes(record_entries)?)?)?;
    let strings = strings_cost(counts.key_bytes, counts.keys)?
        .checked_add(strings_cost(counts.string_bytes, counts.strings)?)?;
    let slots = counts
        .elements
        .checked_mul(2)?
        .checked_add(1)?
        .checked_mul(size_of::<Value>())?;
    let dom = nodes.checked_add(strings)?.checked_add(slots)?;
    let typed = counts.records.checked_mul(2)?.checked_mul(record_size)?;
    dom.checked_mul(2)?
        .checked_add(typed)?
        .checked_add(body_len.checked_mul(3)?)?
        .checked_add(DECODE_SLACK)
}

/// The gate's cursor. No whitespace is accepted: CanonicalJsonV1 has none.
struct Scanner<'a> {
    bytes: &'a [u8],
    at: usize,
    counts: Counts,
}

type Member<'m, 'a> = dyn FnMut(&mut Scanner<'a>, &'static str) -> Result<(), ScanError> + 'm;
type Element<'m, 'a> = dyn FnMut(&mut Scanner<'a>) -> Result<(), ScanError> + 'm;

impl<'a> Scanner<'a> {
    fn next(&mut self) -> Result<u8, ScanError> {
        let byte = *self.bytes.get(self.at).ok_or(ScanError::Shape)?;
        self.at += 1;
        Ok(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn eat(&mut self, expected: u8) -> Result<(), ScanError> {
        if self.next()? == expected {
            Ok(())
        } else {
            Err(ScanError::Shape)
        }
    }

    /// An object whose keys are exactly `keys`, in that (canonical) order.
    /// A key must be written without escapes: none of these names needs
    /// one, and the canonical encoding writes none.
    fn object(
        &mut self,
        keys: &[&'static str],
        member: &mut Member<'_, 'a>,
    ) -> Result<(), ScanError> {
        self.counts.objects += 1;
        self.eat(b'{')?;
        for (index, key) in keys.iter().enumerate() {
            if index > 0 {
                self.eat(b',')?;
            }
            let (length, raw) = self.string()?;
            if raw != key.as_bytes() {
                return Err(ScanError::Shape);
            }
            self.counts.keys += 1;
            self.counts.key_bytes += length;
            self.eat(b':')?;
            member(self, key)?;
        }
        self.eat(b'}')
    }

    /// An array of at most `limit` elements; one more is `over`.
    fn array(
        &mut self,
        limit: usize,
        over: ScanError,
        element: &mut Element<'_, 'a>,
    ) -> Result<(), ScanError> {
        self.counts.values += 1;
        self.eat(b'[')?;
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(());
        }
        let mut count = 0;
        loop {
            count += 1;
            if count > limit {
                return Err(over);
            }
            self.counts.elements += 1;
            element(self)?;
            match self.next()? {
                b',' => {}
                b']' => return Ok(()),
                _ => return Err(ScanError::Shape),
            }
        }
    }

    /// A string, a number or `null`; `true` and `false` only where
    /// `boolean` allows (no record field is a boolean).
    fn scalar(&mut self, boolean: bool) -> Result<(), ScanError> {
        self.counts.values += 1;
        match self.peek() {
            Some(b'"') => self.value_string(),
            Some(b'n') => self.literal(b"null"),
            Some(b't') if boolean => self.literal(b"true"),
            Some(b'f') if boolean => self.literal(b"false"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(ScanError::Shape),
        }
    }

    fn value_string(&mut self) -> Result<(), ScanError> {
        let (length, _) = self.string()?;
        self.counts.strings += 1;
        self.counts.string_bytes += length;
        if self.counts.string_bytes > VALUE_STRINGS_MAX {
            return Err(ScanError::StringBytes);
        }
        Ok(())
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), ScanError> {
        if self.bytes[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(())
        } else {
            Err(ScanError::Shape)
        }
    }

    /// An integer of at most 20 digits. A fraction or exponent stops here
    /// and fails at the next delimiter: the decoder refuses floats, and
    /// every integer it accepts fits in 20 digits.
    fn number(&mut self) -> Result<(), ScanError> {
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        let start = self.at;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        if (1..=20).contains(&(self.at - start)) {
            Ok(())
        } else {
            Err(ScanError::Shape)
        }
    }

    /// A string: its decoded length in bytes, as `serde_json` decodes it,
    /// and its raw bytes between the quotes. Refuses what `serde_json`
    /// refuses (a control character, an unknown escape, an unpaired
    /// surrogate) and anything longer than [`STRING_MAX`].
    fn string(&mut self) -> Result<(usize, &'a [u8]), ScanError> {
        self.eat(b'"')?;
        let start = self.at;
        let mut length = 0_usize;
        loop {
            length += match self.next()? {
                b'"' => break,
                b'\\' => match self.next()? {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => 1,
                    b'u' => match self.hex4()? {
                        0xd800..=0xdbff => {
                            self.eat(b'\\')?;
                            self.eat(b'u')?;
                            if !(0xdc00..=0xdfff).contains(&self.hex4()?) {
                                return Err(ScanError::Shape);
                            }
                            4
                        }
                        0xdc00..=0xdfff => return Err(ScanError::Shape),
                        0..=0x7f => 1,
                        0x80..=0x7ff => 2,
                        _ => 3,
                    },
                    _ => return Err(ScanError::Shape),
                },
                0x00..=0x1f => return Err(ScanError::Shape),
                _ => 1,
            };
            if length > STRING_MAX {
                return Err(ScanError::String);
            }
        }
        Ok((length, &self.bytes[start..self.at - 1]))
    }

    fn hex4(&mut self) -> Result<u16, ScanError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = char::from(self.next()?)
                .to_digit(16)
                .ok_or(ScanError::Shape)?;
            value = (value << 4) | digit as u16;
        }
        Ok(value)
    }
}

/// Counts decodes on this thread, and runs a hook just before one. Absent
/// from non-test builds.
#[cfg(test)]
mod receive_seams {
    use std::cell::{Cell, RefCell};

    type Hook = Box<dyn FnOnce()>;

    thread_local! {
        static DECODES: Cell<usize> = const { Cell::new(0) };
        static BEFORE_DECODE: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    pub(super) fn before_decode() {
        DECODES.with(|decodes| decodes.set(decodes.get() + 1));
        if let Some(hook) = BEFORE_DECODE.with(|cell| cell.borrow_mut().take()) {
            hook();
        }
    }

    pub(super) fn decodes() -> usize {
        DECODES.with(Cell::get)
    }

    pub(super) fn set_before_decode(hook: Hook) {
        BEFORE_DECODE.with(|cell| *cell.borrow_mut() = Some(hook));
    }
}

/// A hook around each chunk write, for one request ID only, so other
/// tests running at the same time never reach it. Absent from non-test
/// builds.
#[cfg(test)]
mod seams {
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum Event {
        Start(u32),
        Returned(u32),
    }

    type Hook = Arc<dyn Fn(Event) + Send + Sync>;

    static HOOK: Mutex<Option<([u8; 16], Hook)>> = Mutex::new(None);

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn set(request_id: [u8; 16], hook: Option<Hook>) {
        *HOOK.lock().unwrap() = hook.map(|hook| (request_id, hook));
    }

    /// Runs the hook outside the seam's own lock, so it may block.
    pub(super) fn event(request_id: [u8; 16], event: Event) {
        let hook = HOOK
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(id, _)| *id == request_id)
            .map(|(_, hook)| Arc::clone(hook));
        if let Some(hook) = hook {
            hook(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acceptance (8), the bucket itself: two at once, then one per minute;
    /// a refusal takes no token; one in flight per grant.
    #[test]
    fn the_grant_limit_allows_a_burst_of_two_then_one_a_minute() {
        let reports = Reports::new(Arc::new(NoSource));
        let (a, b) = ([0xa; 16], [0xb; 16]);
        let t = Duration::from_secs(1_000);
        drop(reports.admit(a, t).unwrap());
        drop(reports.admit(a, t).unwrap());
        assert!(reports.admit(a, t).is_none(), "third at once");
        assert!(reports.admit(a, t + Duration::from_secs(59)).is_none());
        // Another grant has its own bucket.
        drop(reports.admit(b, t).unwrap());
        drop(reports.admit(a, t + GRANT_REFILL).unwrap());
        assert!(reports.admit(a, t + GRANT_REFILL).is_none());
        // Ten idle minutes refill only up to the burst.
        let later = t + GRANT_REFILL * 11;
        drop(reports.admit(a, later).unwrap());
        drop(reports.admit(a, later).unwrap());
        assert!(reports.admit(a, later).is_none());
        // In flight: a second request of the same grant waits for none.
        let idle = later + GRANT_REFILL * 5;
        let first = reports.admit(a, idle).unwrap();
        assert!(reports.admit(a, idle).is_none(), "in flight");
        drop(first);
        drop(reports.admit(a, idle).unwrap());
    }

    #[test]
    fn the_compute_slot_admits_one_at_a_time() {
        let reports = Reports::new(Arc::new(NoSource));
        let slot = reports.compute_slot().unwrap();
        assert!(reports.compute_slot().is_none());
        drop(slot);
        assert!(reports.compute_slot().is_some());
    }

    #[test]
    fn report_codes_are_the_control_numbering() {
        let codes = [
            (ReportCode::Invalid, 1),
            (ReportCode::Unauthorized, 2),
            (ReportCode::Expired, 3),
            (ReportCode::Revoked, 4),
            (ReportCode::Busy, 5),
            (ReportCode::Incompatible, 6),
            (ReportCode::Internal, 8),
        ];
        for (code, wire) in codes {
            assert_eq!(code.wire(), wire, "{code:?}");
        }
    }

    /// Acceptance (6), through the product listener: chunk 1 is held
    /// inside `authorize_then` for 500 ms; a revoke started then returns
    /// within 5 s, after every chunk write that started has returned, and
    /// no chunk write starts after it. The client gets an incomplete
    /// response. The body is larger than any loopback socket buffer.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_revoke_during_a_response_stops_it_after_the_chunk_in_flight() {
        use std::{sync::mpsc, thread};

        use crate::{
            listener::Listener,
            noise::{self, StaticKey},
            pairing::{Clock, RateLimiter, SystemClock, approve},
            report::Endpoint,
            secure_fs::{
                SecureRoot,
                test_support::{SUFFIX, TempHome, retry_busy},
            },
            security::{
                MemoryLedger, Offer, OfferClaim, OfferState, hex_encode, offer_secret_hash,
            },
            state_store::StateStore,
        };

        struct Fixed(Vec<u8>);
        impl ReportSource for Fixed {
            fn report(&self, _: &ReportRequest, _: Instant) -> Result<Vec<u8>, SourceError> {
                Ok(self.0.clone())
            }
        }

        const BODY: usize = 8 * 1024 * 1024;
        const REQUEST_ID: [u8; 16] = [0x6e; 16];
        let now = SystemClock.os_now_seconds().unwrap();
        let home = TempHome::new();
        let store = Arc::new(
            retry_busy(|| StateStore::open(SecureRoot::open_under(&home.path, SUFFIX)?, now))
                .unwrap(),
        );
        store
            .set_listen_config(
                Some("127.0.0.1".into()),
                {
                    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                    probe.local_addr().unwrap().port()
                },
                None,
            )
            .unwrap();
        let responder = StaticKey::from_state(&store.state().unwrap()).unwrap();
        let receiver = StaticKey::generate().unwrap();
        let (offer_id, secret, pending_id) = ([1; 16], [2; 32], [3; 16]);
        store
            .transition(|state| {
                state
                    .enable_sharing()?
                    .create_offer(
                        Offer {
                            offer_id,
                            secret_hash: offer_secret_hash(&offer_id, &secret, responder.public()),
                            created_at_ms: now * 1_000,
                            expires_at_ms: now * 1_000 + 600_000,
                            state: OfferState::Active,
                        },
                        now,
                    )?
                    .claim_offer(
                        OfferClaim {
                            offer_id,
                            secret,
                            responder_static: *responder.public(),
                            pending_id,
                            initiator_static: *receiver.public(),
                            sas_code: "0A1B-2C3D".into(),
                            sas_generation: 1,
                        },
                        now,
                    )
                    .map(|(next, _, _)| next)
            })
            .unwrap();
        let grant_id = approve(&store, pending_id, 1, true, now).unwrap();
        let mut listener = Listener::start(
            Arc::clone(&store),
            MemoryLedger::default(),
            Arc::new(RateLimiter::default()),
            Arc::new(SystemClock),
            Arc::new(Reports::new(Arc::new(Fixed(vec![b'x'; BODY])))),
        )
        .unwrap();

        // The seam: record every chunk write; hold chunk 1 and tell the test.
        let events = Arc::new(Mutex::new(Vec::<(seams::Event, Instant)>::new()));
        let (held_tx, held_rx) = mpsc::channel::<()>();
        let held_tx = Mutex::new(held_tx);
        let record = Arc::clone(&events);
        seams::set(
            REQUEST_ID,
            Some(Arc::new(move |event| {
                record.lock().unwrap().push((event, Instant::now()));
                if event == seams::Event::Start(1) {
                    held_tx.lock().unwrap().send(()).unwrap();
                    thread::sleep(Duration::from_millis(500));
                }
            })),
        );

        let request = ReportRequest {
            aggregation_revision: 1,
            auth_epoch: 1,
            clients: Vec::new(),
            end_date_exclusive: "2025-02-01".into(),
            endpoint: Endpoint::Graph as u16,
            grant_id: hex_encode(&grant_id),
            protocol: 1,
            report_schema: 1,
            request_id: hex_encode(&REQUEST_ID),
            source_scope_generation: 1,
            start_date: "2025-01-01".into(),
            timezone: "UTC".into(),
            tzdb_revision: "2026c".into(),
        };
        let port = listener.local_addr().port();
        let client = thread::spawn(move || {
            let mut session =
                noise::connect("127.0.0.1", port, &receiver, responder.public()).unwrap();
            let payload = crate::canonical::CanonicalJsonV1::encode(&request).unwrap();
            session
                .send(
                    &Frame {
                        kind: FrameKind::Request,
                        final_chunk: true,
                        request_id: REQUEST_ID,
                        chunk_index: 0,
                        chunk_count: 1,
                        payload,
                    },
                    Deadline::after(Duration::from_secs(10)),
                )
                .unwrap();
            let ledger = MemoryLedger::default();
            let mut frames = Vec::new();
            while let Ok(received) =
                session.receive(&ledger, Deadline::after(Duration::from_secs(15)))
            {
                frames.push(received.frame().clone());
            }
            frames
        });

        held_rx.recv_timeout(Duration::from_secs(20)).unwrap();
        let revoke_started = Instant::now();
        store
            .transition(|state| state.revoke_commit(grant_id, now * 1_000))
            .unwrap();
        let revoked = Instant::now();
        let frames = client.join().unwrap();
        seams::set(REQUEST_ID, None);
        listener.stop();

        assert!(revoked - revoke_started < Duration::from_secs(5));
        let events = events.lock().unwrap().clone();
        for (event, at) in &events {
            match event {
                seams::Event::Returned(_) => assert!(*at < revoked, "{event:?} after the revoke"),
                seams::Event::Start(_) => assert!(*at < revoked, "{event:?} after the revoke"),
            }
        }
        let count = BODY.div_ceil(FRAME_PAYLOAD_MAX) as u32;
        assert!(frames.len() < count as usize, "{} of {count}", frames.len());
        assert!(
            frames.len() >= 2,
            "chunks 0 and 1 were written: {}",
            frames.len()
        );
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(frame.kind, FrameKind::Response);
            assert_eq!(frame.chunk_index, index as u32);
            assert_eq!(frame.chunk_count, count);
        }
    }
}

/// Receiver acceptance that needs no secure root, so it runs on every
/// platform: `exchange` against a scripted producer that completes a real
/// IK handshake and then writes whatever its script says, valid frames or
/// not; the shape gate, the counts and the key lists.
#[cfg(test)]
mod receiver_tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        thread,
    };

    use serde_json::json;

    use super::*;
    use crate::{
        report::{ReportResponse, encode_response},
        security::{NOISE_PROLOGUE, NOISE_SUITE, REMOTE_MEMORY_MAX, encode_outer},
    };

    const REQUEST_ID: [u8; 16] = [0x42; 16];
    const SHORT: Duration = Duration::from_secs(10);

    /// The producer end after the handshake.
    struct Scripted {
        stream: TcpStream,
        transport: snow::TransportState,
    }

    impl Scripted {
        /// Encrypts and writes any plaintext. False once the receiver is
        /// gone.
        fn write(&mut self, plaintext: &[u8]) -> bool {
            let mut ciphertext = vec![0; plaintext.len() + 16];
            let length = self
                .transport
                .write_message(plaintext, &mut ciphertext)
                .unwrap();
            ciphertext.truncate(length);
            self.stream
                .write_all(&encode_outer(&ciphertext).unwrap())
                .is_ok()
        }

        fn frame(&mut self, frame: &Frame) -> bool {
            self.write(&frame.encode().unwrap())
        }

        fn frames(&mut self, frames: &[Frame]) -> bool {
            frames.iter().all(|frame| self.frame(frame))
        }
    }

    type Script = Box<dyn FnOnce(&mut Scripted, [u8; 16], ReportRequest) + Send>;

    /// A producer on 127.0.0.1 for one connection: the IK responder
    /// handshake, one request read and parsed, then `script`.
    fn producer(script: Script) -> (u16, [u8; 32], thread::JoinHandle<()>) {
        let keys = snow::Builder::new(NOISE_SUITE.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let public = keys.public.as_slice().try_into().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut handshake = snow::Builder::new(NOISE_SUITE.parse().unwrap())
                .local_private_key(&keys.private)
                .and_then(|builder| builder.prologue(NOISE_PROLOGUE))
                .and_then(snow::Builder::build_responder)
                .unwrap();
            let mut message1 = [0; 4 + noise::MESSAGE1_LEN];
            stream.read_exact(&mut message1).unwrap();
            handshake
                .read_message(&message1[4..], &mut [0; noise::MESSAGE1_LEN])
                .unwrap();
            let mut message2 = [0; noise::MESSAGE2_LEN];
            handshake.write_message(&[], &mut message2).unwrap();
            stream
                .write_all(&(noise::MESSAGE2_LEN as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&message2).unwrap();
            let mut transport = handshake.into_transport_mode().unwrap();
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).unwrap();
            let mut ciphertext = vec![0; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut ciphertext).unwrap();
            let mut plaintext = vec![0; ciphertext.len()];
            let length = transport.read_message(&ciphertext, &mut plaintext).unwrap();
            plaintext.truncate(length);
            let frame = Frame::decode(&plaintext).unwrap();
            let request = CanonicalJsonV1::decode(&frame.payload).unwrap();
            script(
                &mut Scripted { stream, transport },
                frame.request_id,
                request,
            );
        });
        (port, public, handle)
    }

    /// The request a fetch of `endpoint` sends (fixed request ID).
    fn request(endpoint: Endpoint) -> ReportRequest {
        ReportRequest {
            aggregation_revision: 1,
            auth_epoch: 3,
            clients: Vec::new(),
            end_date_exclusive: "2025-02-01".into(),
            endpoint: endpoint.into(),
            grant_id: hex_encode(&[0x11; 16]),
            protocol: 1,
            report_schema: 1,
            request_id: hex_encode(&REQUEST_ID),
            source_scope_generation: 1,
            start_date: "2025-01-01".into(),
            timezone: "UTC".into(),
            tzdb_revision: "2026c".into(),
        }
    }

    /// `exchange` for `endpoint` against `script`, within `within`, then
    /// waits for the producer to finish. Returns the result and how long
    /// `exchange` took.
    fn run_within(
        endpoint: Endpoint,
        ledger: &MemoryLedger,
        within: Duration,
        script: Script,
    ) -> (Result<Fetched, FetchError>, Duration) {
        let (port, responder, handle) = producer(script);
        let identity = StaticKey::generate().unwrap();
        let mut session = noise::connect("127.0.0.1", port, &identity, &responder).unwrap();
        let started = Instant::now();
        let result = exchange(
            &mut session,
            REQUEST_ID,
            &request(endpoint),
            endpoint,
            ledger,
            Deadline::after(within),
        );
        let elapsed = started.elapsed();
        drop(session);
        handle.join().unwrap();
        (result, elapsed)
    }

    fn run(
        endpoint: Endpoint,
        ledger: &MemoryLedger,
        script: Script,
    ) -> Result<Fetched, FetchError> {
        run_within(endpoint, ledger, SHORT, script).0
    }

    fn graph(n: usize) -> GraphRecord {
        GraphRecord {
            date: "2025-01-02".into(),
            client: format!("{n:06}"),
            model: Some("model".into()),
            provider: None,
            input_tokens: n as u64,
            output_tokens: 1,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            total_tokens: n as u64 + 1,
            message_count: 1,
            turn_count: 1,
            cost_nano_usd: 7,
        }
    }

    fn agents(n: usize) -> AgentsRecord {
        AgentsRecord {
            agent: format!("{n:06}"),
            client: "c".into(),
            model: None,
            provider: None,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            total_tokens: 0,
            message_count: 0,
            turn_count: 0,
            cost_nano_usd: 0,
        }
    }

    fn body_of<R: ReportRecord>(request: &ReportRequest, records: Vec<R>) -> Vec<u8> {
        encode_response(&ReportResponse::from_request(request, records, false)).unwrap()
    }

    /// `count` graph records echoing `request`.
    fn graph_body(request: &ReportRequest, count: usize) -> Vec<u8> {
        body_of(request, (0..count).map(graph).collect())
    }

    fn chunks(request_id: [u8; 16], body: &[u8]) -> Vec<Frame> {
        let count = body.len().div_ceil(FRAME_PAYLOAD_MAX).max(1) as u32;
        let mut frames: Vec<Frame> = body
            .chunks(FRAME_PAYLOAD_MAX)
            .enumerate()
            .map(|(index, chunk)| Frame {
                kind: FrameKind::Response,
                final_chunk: index as u32 + 1 == count,
                request_id,
                chunk_index: index as u32,
                chunk_count: count,
                payload: chunk.to_vec(),
            })
            .collect();
        if frames.is_empty() {
            frames.push(Frame {
                kind: FrameKind::Response,
                final_chunk: true,
                request_id,
                chunk_index: 0,
                chunk_count: 1,
                payload: Vec::new(),
            });
        }
        frames
    }

    /// A script that answers with `body` in chunks.
    fn serve(body: Vec<u8>) -> Script {
        Box::new(move |producer, id, _| {
            producer.frames(&chunks(id, &body));
        })
    }

    fn error_frame_of(request_id: [u8; 16], payload: serde_json::Value) -> Frame {
        Frame {
            kind: FrameKind::Error,
            final_chunk: true,
            request_id,
            chunk_index: 0,
            chunk_count: 1,
            payload: CanonicalJsonV1::encode(&payload).unwrap(),
        }
    }

    /// Acceptance (1) without a store: a multi-chunk body echoing the
    /// request decodes to its records, and every reservation is returned.
    #[test]
    fn a_multi_chunk_reply_decodes_to_the_producers_records() {
        let ledger = MemoryLedger::default();
        let body = graph_body(&request(Endpoint::Graph), 1_000);
        assert!(body.len() > FRAME_PAYLOAD_MAX);
        let before = receive_seams::decodes();
        let fetched = run(Endpoint::Graph, &ledger, serve(body.clone())).unwrap();
        assert_eq!(fetched.body, body);
        assert_eq!(
            fetched.records,
            Records::Graph((0..1_000).map(graph).collect())
        );
        assert!(!fetched.saturated);
        assert_eq!(receive_seams::decodes(), before + 1);
        assert_eq!(ledger.used(), 0);
    }

    /// Acceptance (3): each hostile framing is refused, and the ledger is
    /// back at its baseline afterwards.
    #[test]
    fn hostile_framing_is_refused_and_the_ledger_returns_to_baseline() {
        let ledger = MemoryLedger::default();
        let three = graph_body(&request(Endpoint::Graph), 700);
        assert_eq!(
            three.len().div_ceil(FRAME_PAYLOAD_MAX),
            3,
            "{}",
            three.len()
        );
        let patched = |count: u32, index: u32, last: bool| -> Script {
            Box::new(move |producer, id, _| {
                let mut bytes = Frame {
                    kind: FrameKind::Response,
                    final_chunk: true,
                    request_id: id,
                    chunk_index: 0,
                    chunk_count: 1,
                    payload: b"{}".to_vec(),
                }
                .encode()
                .unwrap();
                bytes[7] = u8::from(last);
                bytes[24..28].copy_from_slice(&index.to_be_bytes());
                bytes[28..32].copy_from_slice(&count.to_be_bytes());
                producer.write(&bytes);
            })
        };
        let altered = |body: Vec<u8>, alter: fn(&mut Vec<Frame>)| -> Script {
            Box::new(move |producer, id, _| {
                let mut frames = chunks(id, &body);
                alter(&mut frames);
                producer.frames(&frames);
            })
        };
        let cases: Vec<(&str, Script, FetchError)> = vec![
            ("chunkCount 0", patched(0, 0, true), FetchError::Protocol),
            (
                "chunkCount 275",
                patched(275, 0, false),
                FetchError::Protocol,
            ),
            (
                "final on chunk 0 of 2",
                patched(2, 0, true),
                FetchError::Protocol,
            ),
            (
                "index skipped",
                altered(three.clone(), |frames| {
                    frames.remove(1);
                }),
                FetchError::Protocol,
            ),
            (
                "requestId changed mid-way",
                altered(three.clone(), |frames| frames[1].request_id = [0x43; 16]),
                FetchError::Protocol,
            ),
            (
                "chunkCount changed mid-way",
                altered(three.clone(), |frames| {
                    frames[1].chunk_count = 4;
                }),
                FetchError::Protocol,
            ),
            (
                "first frame is a Request",
                Box::new(|producer, id, _| {
                    producer.frame(&Frame {
                        kind: FrameKind::Request,
                        final_chunk: true,
                        request_id: id,
                        chunk_index: 0,
                        chunk_count: 1,
                        payload: b"{}".to_vec(),
                    });
                }),
                FetchError::Protocol,
            ),
            (
                "first frame names another request",
                altered(three.clone(), |frames| frames[0].request_id = [0x43; 16]),
                FetchError::Protocol,
            ),
            (
                "error code 7",
                Box::new(|producer, id, _| {
                    producer.frame(&error_frame_of(id, json!({"code": 7, "protocol": 1})));
                }),
                FetchError::Protocol,
            ),
            (
                "error protocol 2",
                Box::new(|producer, id, _| {
                    producer.frame(&error_frame_of(id, json!({"code": 4, "protocol": 2})));
                }),
                FetchError::Protocol,
            ),
            (
                "total over 16 MiB",
                Box::new(|producer, id, _| {
                    let payload = vec![b' '; FRAME_PAYLOAD_MAX];
                    let count = crate::security::RESPONSE_CHUNKS_MAX;
                    for index in 0..count {
                        let sent = producer.frame(&Frame {
                            kind: FrameKind::Response,
                            final_chunk: index + 1 == count,
                            request_id: id,
                            chunk_index: index,
                            chunk_count: count,
                            payload: payload.clone(),
                        });
                        if !sent {
                            break;
                        }
                    }
                }),
                FetchError::Protocol,
            ),
        ];
        for (label, script, expected) in cases {
            let before = receive_seams::decodes();
            assert_eq!(
                run(Endpoint::Graph, &ledger, script).err(),
                Some(expected),
                "{label}"
            );
            assert_eq!(receive_seams::decodes(), before, "{label}");
            assert_eq!(ledger.used(), 0, "{label}");
        }
        // Control: the same three chunks unaltered decode.
        run(Endpoint::Graph, &ledger, serve(three)).unwrap();
        assert_eq!(ledger.used(), 0);
    }

    /// Error mapping: each code the producer may send has its variant.
    #[test]
    fn error_codes_map_to_their_variants() {
        let ledger = MemoryLedger::default();
        for (code, expected) in [
            (1, FetchError::Rejected),
            (2, FetchError::CheckGrantStatus),
            (3, FetchError::Expired),
            (4, FetchError::Revoked),
            (5, FetchError::Busy),
            (6, FetchError::Rejected),
            (8, FetchError::Internal),
        ] {
            let script: Script = Box::new(move |producer, id, _| {
                producer.frame(&error_frame_of(id, json!({"code": code, "protocol": 1})));
            });
            assert_eq!(
                run(Endpoint::Graph, &ledger, script).err(),
                Some(expected),
                "{code}"
            );
        }
        assert_eq!(ledger.used(), 0);
    }

    /// Acceptance (4): a valid body for another grant, other dates or
    /// another endpoint fails validation against the request that was
    /// sent; the same body for the right request decodes (control).
    #[test]
    fn a_body_echoing_another_request_is_invalid() {
        let ledger = MemoryLedger::default();
        type Change = fn(&mut ReportRequest);
        let changes: [(&str, Change); 4] = [
            ("grantId", |r| r.grant_id = hex_encode(&[0x99; 16])),
            ("startDate", |r| r.start_date = "2025-01-02".into()),
            ("endDateExclusive", |r| {
                r.end_date_exclusive = "2025-02-02".into()
            }),
            ("authEpoch", |r| r.auth_epoch += 1),
        ];
        for (label, change) in changes {
            let script: Script = Box::new(move |producer, id, mut asked| {
                change(&mut asked);
                producer.frames(&chunks(id, &graph_body(&asked, 3)));
            });
            assert_eq!(
                run(Endpoint::Graph, &ledger, script).err(),
                Some(FetchError::Invalid),
                "{label}"
            );
        }
        // Another endpoint: a models body (no records) for a graph request.
        let script: Script = Box::new(|producer, id, mut asked| {
            asked.endpoint = Endpoint::Models.into();
            producer.frames(&chunks(id, &body_of::<ModelsRecord>(&asked, Vec::new())));
        });
        assert_eq!(
            run(Endpoint::Graph, &ledger, script).err(),
            Some(FetchError::Invalid)
        );
        // Control: the echo of the request itself.
        let script: Script = Box::new(|producer, id, asked| {
            producer.frames(&chunks(id, &graph_body(&asked, 3)));
        });
        run(Endpoint::Graph, &ledger, script).unwrap();
        assert_eq!(ledger.used(), 0);
    }

    /// The canonical empty graph body for the test request, as text, to
    /// splice hostile pieces into.
    fn empty_graph_text() -> String {
        String::from_utf8(graph_body(&request(Endpoint::Graph), 0)).unwrap()
    }

    /// One graph record's text, to splice into `"records":[...]`.
    fn record_text() -> String {
        let value = serde_json::to_value(graph(1)).unwrap();
        String::from_utf8(CanonicalJsonV1::encode(&value).unwrap()).unwrap()
    }

    fn with_records(records: &str) -> Vec<u8> {
        empty_graph_text()
            .replace(r#""records":[]"#, &format!(r#""records":[{records}]"#))
            .into_bytes()
    }

    /// Acceptance (5), the gate: each hostile shape is refused before the
    /// decode reservation and before the frozen decoder (the decode seam
    /// does not fire), and the ledger is back at its baseline.
    #[test]
    fn the_shape_gate_refuses_before_reserving_or_decoding() {
        let ledger = MemoryLedger::default();
        let empty = empty_graph_text();
        let record = record_text();
        let flood = vec![r#"{"":0}"#; 100_000].join(",");
        let nested = vec!["[0]"; 300_000].join(",");
        let zeros = {
            let count = (LOGICAL_BODY_MAX - 2).div_ceil(2);
            let mut text = "0,".repeat(count);
            text.pop();
            format!("[{text}]")
        };
        assert!(zeros.len() <= LOGICAL_BODY_MAX && zeros.len() > LOGICAL_BODY_MAX - 2);
        let combining = format!("e{}", "\u{301}".repeat(128));
        assert!(combining.len() >= 256);
        let long_strings = {
            let text = |n: usize, tag: &str| format!("{tag}{}{n:06}", "x".repeat(248));
            let records: Vec<AgentsRecord> = (0..8_300)
                .map(|n| AgentsRecord {
                    agent: text(n, "a"),
                    client: text(n, "c"),
                    model: Some(text(n, "m")),
                    provider: Some(text(n, "p")),
                    ..agents(n)
                })
                .collect();
            body_of(&request(Endpoint::Agents), records)
        };
        let cases: Vec<(&str, Endpoint, Vec<u8>)> = vec![
            (
                r#"{"":0} flood in clients"#,
                Endpoint::Graph,
                empty
                    .replace(r#""clients":[]"#, &format!(r#""clients":[{flood}]"#))
                    .into_bytes(),
            ),
            (
                "[[0],[0],...]",
                Endpoint::Graph,
                format!("[{nested}]").into_bytes(),
            ),
            ("16 MiB of [0,0,...]", Endpoint::Graph, zeros.into_bytes()),
            (
                "an object inside a record",
                Endpoint::Graph,
                with_records(&record.replace(r#""model":"model""#, r#""model":{"a":1}"#)),
            ),
            (
                "an array inside a record",
                Endpoint::Graph,
                with_records(&record.replace(r#""model":"model""#, r#""model":[1]"#)),
            ),
            (
                "a record with an extra key",
                Endpoint::Graph,
                with_records(&record.replace(r#""turnCount":1}"#, r#""turnCount":1,"zzz":0}"#)),
            ),
            (
                "a record missing a key",
                Endpoint::Graph,
                with_records(&record.replace(r#","turnCount":1}"#, "}")),
            ),
            (
                "a 257-byte string of combining marks",
                Endpoint::Graph,
                with_records(&record.replace(
                    r#""client":"000001""#,
                    &format!(r#""client":"{combining}""#),
                )),
            ),
            ("value strings over 8 MiB", Endpoint::Agents, long_strings),
        ];
        for (label, endpoint, body) in cases {
            assert!(body.len() <= LOGICAL_BODY_MAX, "{label}");
            let before = receive_seams::decodes();
            assert_eq!(
                run(endpoint, &ledger, serve(body)).err(),
                Some(FetchError::Invalid),
                "{label}"
            );
            assert_eq!(receive_seams::decodes(), before, "{label}: decoded");
            assert_eq!(ledger.used(), 0, "{label}");
        }
        // Control: the unaltered record passes the gate and decodes.
        let before = receive_seams::decodes();
        run(Endpoint::Graph, &ledger, serve(with_records(&record))).unwrap();
        assert_eq!(receive_seams::decodes(), before + 1);
    }

    /// Acceptance (5), the gate's reasons and limits, on the scanner
    /// itself (the records limit needs a body larger than 16 MiB, which no
    /// fetch can deliver).
    #[test]
    fn the_scanner_limits_records_strings_and_clients() {
        // 262,144 records pass; one more is `Records`.
        let record = record_text();
        let records = |count: usize| {
            let mut text = format!("{record},").repeat(count);
            text.pop();
            with_records(&text)
        };
        let at = records(RECORDS_MAX);
        assert_eq!(scan(&at, Endpoint::Graph).unwrap().records, RECORDS_MAX);
        drop(at);
        assert_eq!(
            scan(&records(RECORDS_MAX + 1), Endpoint::Graph),
            Err(ScanError::Records)
        );
        // Value strings: exactly 8 MiB passes, one byte more does not.
        // Records with a 255-byte `client` (plus "2025-01-02" and "model")
        // fill up to just below the limit; one more record, with a `null`
        // model, lands on it exactly or one byte past it.
        let empty = empty_graph_text();
        let base = scan(empty.as_bytes(), Endpoint::Graph)
            .unwrap()
            .string_bytes;
        let per = STRING_MAX + "2025-01-02".len() + "model".len();
        let full = (VALUE_STRINGS_MAX - base) / per;
        let mut text: Vec<String> = (0..full)
            .map(|n| {
                record.replace(
                    r#""client":"000001""#,
                    &format!(r#""client":"{}{n:06}""#, "c".repeat(STRING_MAX - 6)),
                )
            })
            .collect();
        let fixed = base + full * per;
        assert_eq!(
            scan(&with_records(&text.join(",")), Endpoint::Graph)
                .unwrap()
                .string_bytes,
            fixed
        );
        let room = VALUE_STRINGS_MAX - fixed;
        assert!(room > 10 && room - 9 <= STRING_MAX, "{room}");
        text.push(String::new());
        let mut top_up = |bytes: usize| {
            *text.last_mut().unwrap() = record
                .replace(r#""model":"model""#, r#""model":null"#)
                .replace(
                    r#""client":"000001""#,
                    &format!(r#""client":"{}""#, "z".repeat(bytes - "2025-01-02".len())),
                );
            with_records(&text.join(","))
        };
        assert_eq!(
            scan(&top_up(room), Endpoint::Graph).unwrap().string_bytes,
            VALUE_STRINGS_MAX
        );
        assert_eq!(
            scan(&top_up(room + 1), Endpoint::Graph),
            Err(ScanError::StringBytes)
        );
        // Strings: 255 decoded bytes pass, 256 do not; escapes count once.
        let one = |text: &str| with_records(&record.replace(r#""000001""#, text));
        assert!(scan(&one(&format!(r#""{}""#, "a".repeat(255))), Endpoint::Graph).is_ok());
        assert_eq!(
            scan(&one(&format!(r#""{}""#, "a".repeat(256))), Endpoint::Graph),
            Err(ScanError::String)
        );
        assert!(
            scan(
                &one(&format!(r#""{}""#, r"\n".repeat(255))),
                Endpoint::Graph
            )
            .is_ok()
        );
        // 128 clients pass, 129 do not.
        let named = |count: usize| {
            let names: Vec<String> = (0..count).map(|n| format!(r#""c{n:03}""#)).collect();
            empty
                .replace(
                    r#""clients":[]"#,
                    &format!(r#""clients":[{}]"#, names.join(",")),
                )
                .into_bytes()
        };
        assert!(scan(&named(128), Endpoint::Graph).is_ok());
        assert_eq!(scan(&named(129), Endpoint::Graph), Err(ScanError::Shape));
        // Whitespace, a float, a trailing byte and a bool in a record.
        for (label, bytes) in [
            ("whitespace", empty.replacen(':', ": ", 1).into_bytes()),
            (
                "float",
                empty
                    .replace(r#""authEpoch":3"#, r#""authEpoch":3.0"#)
                    .into_bytes(),
            ),
            ("trailing", format!("{empty} ").into_bytes()),
            (
                "bool in a record",
                with_records(&record.replace(r#""costNanoUsd":7"#, r#""costNanoUsd":true"#)),
            ),
        ] {
            assert_eq!(
                scan(&bytes, Endpoint::Graph),
                Err(ScanError::Shape),
                "{label}"
            );
        }
    }

    /// The counts of `value` as `serde_json` built it.
    fn counted(value: &Value) -> Counts {
        fn walk(value: &Value, counts: &mut Counts) {
            counts.values += 1;
            match value {
                Value::String(text) => {
                    counts.strings += 1;
                    counts.string_bytes += text.len();
                }
                Value::Array(items) => {
                    counts.elements += items.len();
                    items.iter().for_each(|item| walk(item, counts));
                }
                Value::Object(map) => {
                    counts.objects += 1;
                    for (key, item) in map {
                        counts.keys += 1;
                        counts.key_bytes += key.len();
                        walk(item, counts);
                    }
                }
                _ => {}
            }
        }
        let mut counts = Counts::default();
        walk(value, &mut counts);
        counts.records = value["records"].as_array().unwrap().len();
        counts
    }

    /// Acceptance (5), differential: the scanner's counts equal what
    /// `serde_json` decodes from the same bytes, with escapes, `\"`, raw
    /// multi-byte UTF-8 and `\u` escapes (a surrogate pair included).
    #[test]
    fn scanner_counts_equal_what_serde_json_decodes() {
        let mut asked = request(Endpoint::Graph);
        asked.clients = vec![
            "\u{1}x".into(),
            "a\"b".into(),
            "tab\there".into(),
            "é😀".into(),
        ];
        asked.timezone = "back\\slash/".into();
        let records: Vec<GraphRecord> = asked
            .clients
            .iter()
            .enumerate()
            .map(|(n, client)| GraphRecord {
                client: client.clone(),
                model: (n % 2 == 0).then(|| "m\"\n".into()),
                provider: Some(String::new()),
                ..graph(n)
            })
            .collect();
        let mut records = records;
        records.sort_by(|a, b| a.cmp_identity(b));
        let canonical = body_of(&asked, records);
        let escaped = String::from_utf8(canonical.clone())
            .unwrap()
            .replace(r#""m\"\n""#, r#""é😀\/A""#)
            .into_bytes();
        assert_ne!(canonical, escaped);
        for bytes in [
            canonical,
            escaped,
            graph_body(&request(Endpoint::Graph), 50),
        ] {
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(scan(&bytes, Endpoint::Graph).unwrap(), counted(&value));
        }
    }

    /// The key lists the gate holds are the typed structs' keys, in
    /// CanonicalJsonV1 order.
    #[test]
    fn the_gate_key_lists_are_the_typed_keys() {
        fn keys<T: Serialize>(value: &T) -> Vec<String> {
            serde_json::to_value(value)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect()
        }
        let hourly = HourlyRecord {
            bucket_start_unix_ms: 0,
            utc_offset_seconds: 0,
            client: "c".into(),
            model: None,
            provider: None,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            total_tokens: 0,
            message_count: 0,
            turn_count: 0,
            cost_nano_usd: 0,
        };
        let models = ModelsRecord {
            client: "c".into(),
            model: None,
            provider: None,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            total_tokens: 0,
            message_count: 0,
            turn_count: 0,
            cost_nano_usd: 0,
            duration_millis: 0,
            timed_tokens: 0,
            sample_count: 0,
        };
        assert_eq!(keys(&graph(0)), record_shape(Endpoint::Graph).0);
        assert_eq!(keys(&models), record_shape(Endpoint::Models).0);
        assert_eq!(keys(&hourly), record_shape(Endpoint::Hourly).0);
        assert_eq!(keys(&agents(0)), record_shape(Endpoint::Agents).0);
        let response = ReportResponse::<GraphRecord>::from_request(
            &request(Endpoint::Graph),
            Vec::new(),
            false,
        );
        assert_eq!(keys(&response), RESPONSE_KEYS);
    }

    /// Acceptance (5): with the ledger too full for `chunkCount ×
    /// FRAME_PAYLOAD_MAX`, the fetch fails at the first chunk and reads no
    /// other: the producer holds the rest back for 3 s, and the fetch
    /// returns well before that.
    #[test]
    fn a_full_ledger_stops_the_fetch_at_the_first_chunk() {
        let ledger = MemoryLedger::default();
        let held = ledger.reserve(REMOTE_MEMORY_MAX - 200_000).unwrap();
        let body = graph_body(&request(Endpoint::Graph), 6_000);
        let count = body.len().div_ceil(FRAME_PAYLOAD_MAX);
        assert!(count * FRAME_PAYLOAD_MAX > 200_000, "{count}");
        let script: Script = Box::new(move |producer, id, _| {
            let frames = chunks(id, &body);
            producer.frame(&frames[0]);
            thread::sleep(Duration::from_secs(3));
            producer.frames(&frames[1..]);
        });
        let before = receive_seams::decodes();
        let (result, elapsed) = run_within(Endpoint::Graph, &ledger, SHORT, script);
        assert_eq!(result.err(), Some(FetchError::Memory));
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        assert_eq!(receive_seams::decodes(), before);
        drop(held);
        assert_eq!(ledger.used(), 0);
    }

    /// A body whose decode cost exceeds the whole ledger is `TooLarge`, not
    /// `Memory`: retrying cannot help. The decoder never runs.
    ///
    /// The body is several megabytes sent through Noise over loopback; on a
    /// loaded CI runner that took longer than [`SHORT`] and the fetch ended
    /// `Timeout` (PR #25, Ubuntu). This test's own deadline is therefore
    /// [`FETCH_DEADLINE`]: the outcome under test does not depend on time.
    #[test]
    fn a_body_costing_more_than_the_whole_ledger_is_too_large() {
        let ledger = MemoryLedger::default();
        let body = graph_body(&request(Endpoint::Graph), 70_000);
        assert!(
            body.len() <= crate::security::LOGICAL_BODY_MAX,
            "{}",
            body.len()
        );
        let cost = decode_reservation(&body, Endpoint::Graph).unwrap();
        assert!(cost > REMOTE_MEMORY_MAX, "{cost}");
        let before = receive_seams::decodes();
        assert_eq!(
            run_within(Endpoint::Graph, &ledger, FETCH_DEADLINE, serve(body))
                .0
                .err(),
            Some(FetchError::TooLarge)
        );
        assert_eq!(receive_seams::decodes(), before);
        assert_eq!(ledger.used(), 0);
    }

    /// Acceptance (5): the decode reservation comes before the decoder.
    /// With room for the chunks but not for the decode cost, the fetch is
    /// `Memory` and the decoder never runs.
    #[test]
    fn the_decode_cost_is_reserved_before_the_decoder_runs() {
        let ledger = MemoryLedger::default();
        let body = graph_body(&request(Endpoint::Graph), 1_500);
        let count = body.len().div_ceil(FRAME_PAYLOAD_MAX);
        let receive = 3 * crate::security::FRAME_CIPHERTEXT_MAX;
        let room = receive + count * FRAME_PAYLOAD_MAX + 10_000;
        let cost = decode_reservation(&body, Endpoint::Graph).unwrap();
        assert!(cost > receive + 10_000, "{cost}");
        let held = ledger.reserve(REMOTE_MEMORY_MAX - room).unwrap();
        let before = receive_seams::decodes();
        assert_eq!(
            run(Endpoint::Graph, &ledger, serve(body.clone())).err(),
            Some(FetchError::Memory)
        );
        assert_eq!(
            receive_seams::decodes(),
            before,
            "decoded without a reservation"
        );
        drop(held);
        // Control: with room, the same body decodes.
        run(Endpoint::Graph, &ledger, serve(body)).unwrap();
        assert_eq!(receive_seams::decodes(), before + 1);
        assert_eq!(ledger.used(), 0);
    }

    /// Acceptance (5): two large pulls at once on one ledger. The first
    /// holds its body and decode reservations (stopped by the seam just
    /// before its decoder); the second is refused `Memory` without
    /// decoding; once released, the first completes and the ledger returns
    /// to its baseline. The body is the largest smallest-record agents body
    /// whose reservation still fits the ledger once (see the report: a
    /// 16 MiB body of the smallest records does not fit even alone).
    #[test]
    fn two_large_pulls_at_once_the_second_is_refused_by_the_ledger() {
        let asked = request(Endpoint::Agents);
        let body = body_of(&asked, (0..38_000).map(agents).collect());
        let needs = body.len().div_ceil(FRAME_PAYLOAD_MAX) * FRAME_PAYLOAD_MAX
            + decode_reservation(&body, Endpoint::Agents).unwrap();
        eprintln!(
            "two large pulls: body {} B, body + decode reservation {needs} B",
            body.len()
        );
        assert!(needs < REMOTE_MEMORY_MAX && 2 * needs > REMOTE_MEMORY_MAX);
        let ledger = MemoryLedger::default();
        let (reserved_tx, reserved_rx) = mpsc::channel::<()>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let first = {
            let ledger = ledger.clone();
            let body = body.clone();
            thread::spawn(move || {
                receive_seams::set_before_decode(Box::new(move || {
                    reserved_tx.send(()).unwrap();
                    go_rx.recv_timeout(Duration::from_secs(60)).unwrap();
                }));
                run_within(
                    Endpoint::Agents,
                    &ledger,
                    Duration::from_secs(120),
                    serve(body),
                )
                .0
            })
        };
        reserved_rx.recv_timeout(Duration::from_secs(120)).unwrap();
        assert!(ledger.used() >= needs, "{}", ledger.used());
        let before = receive_seams::decodes();
        assert_eq!(
            run_within(
                Endpoint::Agents,
                &ledger,
                Duration::from_secs(120),
                serve(body)
            )
            .0
            .err(),
            Some(FetchError::Memory)
        );
        assert_eq!(receive_seams::decodes(), before);
        go_tx.send(()).unwrap();
        let fetched = first.join().unwrap().unwrap();
        assert!(matches!(fetched.records, Records::Agents(ref records) if records.len() == 38_000));
        assert_eq!(ledger.used(), 0);
    }

    /// Acceptance (8): the deadline is absolute. A producer silent after
    /// the handshake times out at the deadline; so does one that sends a
    /// chunk every 300 ms, each gap far inside the deadline, when the
    /// chunks together take longer than it.
    #[test]
    fn the_fetch_deadline_is_absolute() {
        let ledger = MemoryLedger::default();
        let within = Duration::from_secs(1);
        let silent: Script = Box::new(|_, _, _| thread::sleep(Duration::from_millis(2_500)));
        let (result, elapsed) = run_within(Endpoint::Graph, &ledger, within, silent);
        assert_eq!(result.err(), Some(FetchError::Timeout));
        assert!(elapsed >= within && elapsed < within * 2, "{elapsed:?}");

        let body = graph_body(&request(Endpoint::Graph), 4_000);
        let count = body.len().div_ceil(FRAME_PAYLOAD_MAX);
        assert!(count >= 5, "{count}");
        let trickle: Script = Box::new(move |producer, id, _| {
            for frame in chunks(id, &body) {
                thread::sleep(Duration::from_millis(300));
                if !producer.frame(&frame) {
                    return;
                }
            }
        });
        let (result, elapsed) = run_within(Endpoint::Graph, &ledger, within, trickle);
        assert_eq!(result.err(), Some(FetchError::Timeout));
        assert!(elapsed >= within && elapsed < within * 2, "{elapsed:?}");
        assert_eq!(ledger.used(), 0);
    }

    /// Acceptance (6), the limiter itself: two slots, the third refused,
    /// a slot back on drop.
    #[test]
    fn the_fetch_limiter_admits_two_at_once() {
        let limiter = FetchLimiter::default();
        let first = limiter.acquire().unwrap();
        let second = limiter.acquire().unwrap();
        assert!(limiter.acquire().is_none());
        drop(first);
        let third = limiter.acquire().unwrap();
        assert!(limiter.acquire().is_none());
        drop((second, third));
        assert_eq!(limiter.0.load(Ordering::Acquire), 0);
    }
}
