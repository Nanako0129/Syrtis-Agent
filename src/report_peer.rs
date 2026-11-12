//! Peer report transport, producer side (`spec/report-peer-v1.md`): one
//! Peer request frame answered with 1–274 response chunks, or one error
//! frame.
//!
//! Admission is the frozen nine-conjunct predicate through
//! [`StateStore::authorize`], after the static binding; every chunk is
//! authorized again through [`StateStore::authorize_then`], which holds the
//! store's read lock while the chunk is written. The body comes from an
//! injected [`ReportSource`] and is never decoded here.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{
    canonical::constant_time_eq,
    noise::{Deadline, RESPONDER_WRITE_TIMEOUT, Session},
    pairing::{GrantStatus, PeerCode, Producer, error_frame, grant_status_of, storage_error_code},
    report::ReportRequest,
    secure_fs::StorageError,
    security::{
        FRAME_PAYLOAD_MAX, Frame, FrameKind, Grant, GrantState, LOGICAL_BODY_MAX,
        MemoryReservation, ReferenceState, clock_status, decode_fixed_hex,
    },
    state_store::AuthorizationQuery,
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
