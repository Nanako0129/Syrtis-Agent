//! SA-2B2a1 acceptance: Noise IK transport and the pairing wire, driven over
//! loopback TCP through the public API.
//!
//! The loopback `TcpListener` here is a test harness, not the product
//! listener (`SA-2B2a2`). Pure transport tests run on every platform; tests
//! that need a secure root run on macOS and Linux only, because Windows
//! fails closed (`tests/runtime_storage_v1.rs`). Negative controls that need
//! test-only seams live in the unit tests of `src/pairing.rs` and
//! `src/noise.rs`.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use serde_json::{Value, json};
use syrtis_agent::{
    canonical::CanonicalJsonV1,
    noise::{self, Deadline, MESSAGE1_LEN, MESSAGE2_LEN, NoiseError, Session, StaticKey},
    pairing::{
        ClaimAttempts, Claimed, ClientError, Clock, PairingClient, PeerCode, RATE_INTERVAL,
        RATE_TABLE_MAX, RateLimiter, SystemClock, derive_grant_id, derive_pending_id,
    },
    secure_fs::StorageError,
    security::{
        FRAME_CIPHERTEXT_MAX, Frame, FrameKind, MemoryLedger, PairOffer, REMOTE_MEMORY_MAX,
        hex_encode, offer_secret_hash, pair_sas,
    },
};

fn loopback() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// Reads until EOF or error; returns what arrived.
fn drain(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    bytes
}

/// A handshake, one request frame and one response frame; the receiving
/// side holds exactly 3x the declared ciphertext length on its ledger while
/// it holds the frame, and returns to zero after.
#[test]
fn a_frame_round_trip_reserves_three_times_the_declared_length() {
    let responder = StaticKey::generate().unwrap();
    let initiator = StaticKey::generate().unwrap();
    let (listener, port) = loopback();
    let ledger = MemoryLedger::default();
    let payload = b"{\"x\":1}".to_vec();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            let mut session = noise::accept(stream, &responder).unwrap();
            let received = session
                .receive(&ledger, noise::Deadline::after(Duration::from_secs(10)))
                .unwrap();
            // 38-byte header + payload + 16-byte tag, three times.
            assert_eq!(ledger.used(), 3 * (38 + payload.len() + 16));
            let mut reply = received.frame().clone();
            drop(received);
            assert_eq!(ledger.used(), 0);
            reply.kind = FrameKind::Response;
            session
                .send(&reply, noise::Deadline::after(Duration::from_secs(10)))
                .unwrap();
            (*session.h_final(), *session.remote_static())
        });
        let mut session =
            noise::connect("127.0.0.1", port, &initiator, responder.public()).unwrap();
        let request = Frame {
            kind: FrameKind::Request,
            final_chunk: true,
            request_id: [9; 16],
            chunk_index: 0,
            chunk_count: 1,
            payload: payload.clone(),
        };
        session
            .send(&request, noise::Deadline::after(Duration::from_secs(10)))
            .unwrap();
        let reply = session
            .receive(
                &MemoryLedger::default(),
                noise::Deadline::after(Duration::from_secs(10)),
            )
            .unwrap();
        assert_eq!(reply.frame().payload, payload);
        assert_eq!(reply.frame().request_id, [9; 16]);
        let (h_final, remote) = server.join().unwrap();
        assert_eq!(&h_final, session.h_final());
        assert_eq!(&remote, initiator.public());
        assert_eq!(session.remote_static(), responder.public());
    });
}

/// Acceptance (8), transport half: a message 1 prefix of 97 or 95 is
/// refused at once (the body is never awaited) and nothing is written back.
#[test]
fn a_message_1_prefix_other_than_96_closes_without_reading_or_writing() {
    let responder = StaticKey::generate().unwrap();
    for prefix in [97_u32, 95] {
        let (listener, port) = loopback();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let (stream, _) = listener.accept().unwrap();
                let started = std::time::Instant::now();
                let result = noise::accept(stream, &responder).map(|_| ());
                (result, started.elapsed())
            });
            let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
            client.write_all(&prefix.to_be_bytes()).unwrap();
            let (result, elapsed) = server.join().unwrap();
            assert_eq!(result, Err(NoiseError::Framing), "{prefix}");
            // No body was sent; waiting for one would have taken the
            // 10-second handshake deadline.
            assert!(elapsed < Duration::from_secs(5), "{prefix}: {elapsed:?}");
            assert!(drain(&mut client).is_empty(), "{prefix}");
        });
    }
}

/// Acceptance (8): a message 2 prefix other than 48 fails the initiator,
/// which then writes nothing more.
#[test]
fn a_message_2_prefix_other_than_48_fails_the_initiator_and_sends_no_frame() {
    let responder = StaticKey::generate().unwrap();
    let initiator = StaticKey::generate().unwrap();
    for prefix in [49_u32, 47] {
        let (listener, port) = loopback();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let (mut stream, _) = listener.accept().unwrap();
                let mut message1 = [0; 4 + MESSAGE1_LEN];
                stream.read_exact(&mut message1).unwrap();
                assert_eq!(message1[..4], (MESSAGE1_LEN as u32).to_be_bytes());
                let mut reply = prefix.to_be_bytes().to_vec();
                reply.resize(4 + prefix as usize, 0x77);
                stream.write_all(&reply).unwrap();
                drain(&mut stream)
            });
            let result = noise::connect("127.0.0.1", port, &initiator, responder.public());
            assert_eq!(result.err(), Some(NoiseError::Framing), "{prefix}");
            assert!(server.join().unwrap().is_empty(), "{prefix}");
        });
    }
    assert_eq!(MESSAGE2_LEN, 48);
}

/// The handshake deadline is absolute: a peer that trickles message 1 one
/// byte at a time, each well inside any per-read timeout, is still cut off
/// 10 s after the handshake began.
#[test]
fn partial_bytes_do_not_extend_the_handshake_deadline() {
    use syrtis_agent::security::{NOISE_PROLOGUE, NOISE_SUITE};
    let responder = StaticKey::generate().unwrap();
    let builder = || snow::Builder::new(NOISE_SUITE.parse().unwrap());
    let initiator = builder().generate_keypair().unwrap();
    let mut state = builder()
        .local_private_key(&initiator.private)
        .unwrap()
        .remote_public_key(responder.public())
        .unwrap()
        .prologue(NOISE_PROLOGUE)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut message = (MESSAGE1_LEN as u32).to_be_bytes().to_vec();
    let mut message1 = [0; MESSAGE1_LEN];
    state.write_message(&[], &mut message1).unwrap();
    message.extend_from_slice(&message1);
    let (listener, port) = loopback();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            let started = std::time::Instant::now();
            let result = noise::accept(stream, &responder).map(|_| ());
            (result, started.elapsed())
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_nodelay(true).unwrap();
        // 100 bytes at 110 ms each: about 11 s in all.
        for byte in &message {
            if stream.write_all(&[*byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(110));
        }
        let (result, elapsed) = server.join().unwrap();
        assert_eq!(result, Err(NoiseError::Timeout));
        assert!(elapsed >= Duration::from_secs(10), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(11), "{elapsed:?}");
    });
}

/// A transport length prefix above the frozen ciphertext maximum is refused
/// before anything is reserved or read: the body is never awaited (B9). The
/// ledger is filled so that reserving 3x that length would fail: refusing
/// the length first gives `Framing`, reserving first would give `Memory`.
#[test]
fn a_transport_length_over_the_maximum_is_refused_before_reserving() {
    use syrtis_agent::security::{NOISE_PROLOGUE, NOISE_SUITE};
    let responder = StaticKey::generate().unwrap();
    let builder = || snow::Builder::new(NOISE_SUITE.parse().unwrap());
    let initiator = builder().generate_keypair().unwrap();
    let (listener, port) = loopback();
    let ledger = MemoryLedger::default();
    let level = REMOTE_MEMORY_MAX - 3 * (FRAME_CIPHERTEXT_MAX + 1) + 1;
    let _fill = ledger.reserve(level).unwrap();
    assert!(ledger.reserve(3 * (FRAME_CIPHERTEXT_MAX + 1)).is_none());
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            let mut session = noise::accept(stream, &responder).unwrap();
            let result = session
                .receive(&ledger, noise::Deadline::after(Duration::from_secs(3)))
                .map(|_| ());
            (result, ledger.used())
        });
        let mut state = builder()
            .local_private_key(&initiator.private)
            .unwrap()
            .remote_public_key(responder.public())
            .unwrap()
            .prologue(NOISE_PROLOGUE)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut message1 = [0; MESSAGE1_LEN];
        state.write_message(&[], &mut message1).unwrap();
        stream
            .write_all(&(MESSAGE1_LEN as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&message1).unwrap();
        let mut message2 = [0; 4 + MESSAGE2_LEN];
        stream.read_exact(&mut message2).unwrap();
        stream
            .write_all(&(FRAME_CIPHERTEXT_MAX as u32 + 1).to_be_bytes())
            .unwrap();
        let (result, used) = server.join().unwrap();
        // Waiting for the body would have ended in `Timeout`.
        assert_eq!(result, Err(NoiseError::Framing));
        assert_eq!(used, level);
    });
}

/// Acceptance (12), the table rules: a static admitted less than a second
/// ago is refused and the refusal does not move its time; a full table
/// refuses a new static until entries age out.
#[test]
fn the_rate_limiter_admits_once_per_second_and_caps_the_table() {
    let limiter = RateLimiter::default();
    let base = Duration::from_secs(100);
    let key = [1; 32];
    assert!(limiter.admit(&key, base));
    assert!(!limiter.admit(&key, base + Duration::from_millis(999)));
    // `busy` did not store 999 ms, so 1 s after the admission is allowed.
    assert!(limiter.admit(&key, base + RATE_INTERVAL));

    let limiter = RateLimiter::default();
    for n in 0..RATE_TABLE_MAX {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&(n as u64).to_be_bytes());
        assert!(limiter.admit(&key, base), "{n}");
    }
    let newcomer = [0xff; 32];
    assert!(!limiter.admit(&newcomer, base + Duration::from_millis(500)));
    // Once the table's entries are a second old they are dropped.
    assert!(limiter.admit(&newcomer, base + RATE_INTERVAL));
}

/// The derivations are exactly the formulas in `spec/pairing-v1.md`.
#[test]
fn the_pending_and_grant_ids_follow_the_specified_formulas() {
    use sha2::{Digest, Sha256};
    let secret_hash = [0x12; 32];
    let h_final = [0x34; 32];
    let digest = Sha256::new()
        .chain_update(b"syrtis-pair-pending-v1\0")
        .chain_update(secret_hash)
        .chain_update(h_final)
        .finalize();
    let pending = derive_pending_id(&secret_hash, &h_final);
    assert_eq!(pending[..], digest[..16]);
    let digest = Sha256::new()
        .chain_update(b"syrtis-pair-grant-v1\0")
        .chain_update(pending)
        .finalize();
    assert_eq!(derive_grant_id(&pending)[..], digest[..16]);
}

// ------------------------------------------------------- shared harness

const NOW: i64 = 1_700_000_000;
const LONG: Duration = Duration::from_secs(15);

type Hook<'a> = Box<dyn FnMut(Duration) + Send + 'a>;

/// Shared fake time. `sleep` advances it (unless frozen) and then runs
/// the hook, so a test can act "while the client waits".
struct FakeClock<'a> {
    elapsed: &'a Mutex<Duration>,
    /// Added to the monotonic reading and to the wall clock.
    offset: Duration,
    /// Added to the wall clock only.
    skew: AtomicI64,
    frozen: bool,
    /// When set, the OS wall clock cannot be read.
    wall_fails: AtomicBool,
    hook: Mutex<Hook<'a>>,
}

impl<'a> FakeClock<'a> {
    fn new(elapsed: &'a Mutex<Duration>) -> Self {
        Self {
            elapsed,
            offset: Duration::ZERO,
            skew: AtomicI64::new(0),
            frozen: false,
            wall_fails: AtomicBool::new(false),
            hook: Mutex::new(Box::new(|_| {})),
        }
    }
}

impl Clock for FakeClock<'_> {
    fn monotonic(&self) -> Duration {
        *self.elapsed.lock().unwrap() + self.offset
    }

    fn os_now_seconds(&self) -> Result<i64, StorageError> {
        if self.wall_fails.load(Ordering::SeqCst) {
            return Err(StorageError::Unavailable);
        }
        Ok(NOW + self.skew.load(Ordering::SeqCst) + self.monotonic().as_secs() as i64)
    }

    fn sleep(&self, duration: Duration) {
        let now = {
            let mut elapsed = self.elapsed.lock().unwrap();
            if !self.frozen {
                *elapsed += duration;
            }
            *elapsed
        };
        (self.hook.lock().unwrap())(now);
    }
}

fn secret(n: u8) -> [u8; 32] {
    std::array::from_fn(|i| (n.wrapping_mul(37)).wrapping_add(i as u8) ^ 0xa5)
}

fn offer_id(n: u8) -> [u8; 16] {
    [n; 16]
}

/// A scripted responder: for connection `n` (0-based), `reply` gets the
/// request and the session's `hFinal` and returns the frame to send,
/// or `None` to hold the connection open without answering.
fn fake<R>(
    key: &StaticKey,
    reply: impl FnMut(usize, &Frame, &[u8; 32]) -> Option<Frame> + Send,
    body: impl FnOnce(u16) -> R,
) -> (R, usize) {
    let (listener, port) = loopback();
    let stop = AtomicBool::new(false);
    let count = AtomicUsize::new(0);
    let mut reply = reply;
    let result = thread::scope(|scope| {
        scope.spawn(|| {
            let mut held: Vec<Session> = Vec::new();
            for stream in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let n = count.fetch_add(1, Ordering::SeqCst);
                let Ok(mut session) = noise::accept(stream, key) else {
                    continue;
                };
                let Ok(received) = session.receive(&MemoryLedger::default(), Deadline::after(LONG))
                else {
                    continue;
                };
                match reply(n, received.frame(), session.h_final()) {
                    Some(frame) => {
                        let _ = session.send(&frame, Deadline::after(LONG));
                    }
                    None => held.push(session),
                }
            }
        });
        let result = catch_unwind(AssertUnwindSafe(|| body(port)));
        stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", port));
        result
    });
    let result = result.unwrap_or_else(|panic| resume_unwind(panic));
    (result, count.into_inner())
}

fn json_bytes(value: Value) -> Vec<u8> {
    CanonicalJsonV1::encode(&value).unwrap()
}

fn error_payload(code: u16) -> Vec<u8> {
    format!("{{\"code\":{code},\"protocol\":1}}").into_bytes()
}

fn frame(kind: FrameKind, request_id: [u8; 16], payload: Vec<u8>) -> Frame {
    Frame {
        kind,
        final_chunk: true,
        request_id,
        chunk_index: 0,
        chunk_count: 1,
        payload,
    }
}

fn claimed_for(key: &StaticKey, port: u16, pending_id: [u8; 16]) -> Claimed {
    Claimed {
        offer_id: offer_id(1),
        responder_static: *key.public(),
        host: "127.0.0.1".into(),
        port,
        pending_id,
        sas: "0000-0000".into(),
        expires_at_ms: 0,
        claimed_at: Duration::ZERO,
    }
}

fn fake_offer(key: &StaticKey, port: u16) -> PairOffer {
    PairOffer {
        expires_at: 0,
        host: "127.0.0.1".into(),
        offer_id: hex_encode(&offer_id(1)),
        port,
        responder_static: hex_encode(key.public()),
        secret: hex_encode(&secret(1)),
        version: 1,
    }
}

// ------------------------------------------------- tests on every OS

/// A loopback port with nothing listening: connecting to it is refused.
fn refused_port() -> u16 {
    loopback().1
}

/// B2: a connect failure takes no attempt record. Five refused connects
/// end this claim with a transport error and no record; a later claim of
/// the same offer (same offer ID, same records) still connects and
/// succeeds.
#[test]
fn refused_connects_take_no_attempt_record() {
    let fake_key = StaticKey::generate().unwrap();
    let receiver = StaticKey::generate().unwrap();
    let time = Mutex::new(Duration::ZERO);
    let clock = FakeClock::new(&time);
    let ledger = MemoryLedger::default();
    let client = PairingClient {
        identity: &receiver,
        ledger: &ledger,
        clock: &clock,
    };
    let mut attempts = ClaimAttempts::default();
    let result = client.claim(&fake_offer(&fake_key, refused_port()), &mut attempts);
    assert_eq!(result, Err(ClientError::Transport(NoiseError::Io)));
    assert_eq!(attempts.used(&offer_id(1)), 0);
    // Four waits between five connects, all on the injected clock.
    assert_eq!(*time.lock().unwrap(), 4 * Duration::from_secs(1));

    let secret_hash = offer_secret_hash(&offer_id(1), &secret(1), fake_key.public());
    let (result, count) = fake(
        &fake_key,
        |_, request, h_final| {
            Some(frame(
                FrameKind::Response,
                request.request_id,
                json_bytes(json!({
                    "expiresAt": 1,
                    "pendingId": hex_encode(&derive_pending_id(&secret_hash, h_final)),
                    "protocol": 1,
                })),
            ))
        },
        |port| client.claim(&fake_offer(&fake_key, port), &mut attempts),
    );
    assert_eq!(count, 1);
    assert_eq!(result.map(|claimed| claimed.offer_id), Ok(offer_id(1)));
    assert_eq!(attempts.used(&offer_id(1)), 1);
}

/// B7: an offer with another `version` or a port below 1024 is refused
/// before any connection.
#[test]
fn an_offer_with_a_bad_version_or_port_is_refused_without_connecting() {
    let fake_key = StaticKey::generate().unwrap();
    let receiver = StaticKey::generate().unwrap();
    let time = Mutex::new(Duration::ZERO);
    let clock = FakeClock::new(&time);
    let ledger = MemoryLedger::default();
    let client = PairingClient {
        identity: &receiver,
        ledger: &ledger,
        clock: &clock,
    };
    let unauthorized =
        |request: &Frame| frame(FrameKind::Error, request.request_id, error_payload(2));
    let (results, count) = fake(
        &fake_key,
        |_, request, _| Some(unauthorized(request)),
        |port| {
            let mut attempts = ClaimAttempts::default();
            let version = PairOffer {
                version: 2,
                ..fake_offer(&fake_key, port)
            };
            let low_port = PairOffer {
                port: 1023,
                ..fake_offer(&fake_key, port)
            };
            [
                client.claim(&version, &mut attempts),
                client.claim(&low_port, &mut attempts),
            ]
        },
    );
    assert_eq!(
        results,
        [
            Err(ClientError::InvalidOffer),
            Err(ClientError::InvalidOffer)
        ]
    );
    assert_eq!(count, 0, "no connection was made");
    // Control: the same offer with version 1 and its real port connects.
    let (result, count) = fake(
        &fake_key,
        |_, request, _| Some(unauthorized(request)),
        |port| client.claim(&fake_offer(&fake_key, port), &mut ClaimAttempts::default()),
    );
    assert_eq!((result, count), (Err(ClientError::OfferUnusable), 1));
}

/// B10: `unauthorized`, `invalid` and `incompatible` stop both the claim
/// and the poll on the first answer.
#[test]
fn a_refusing_answer_stops_claim_and_poll_at_once() {
    let fake_key = StaticKey::generate().unwrap();
    let receiver = StaticKey::generate().unwrap();
    let time = Mutex::new(Duration::ZERO);
    let clock = FakeClock::new(&time);
    let ledger = MemoryLedger::default();
    let client = PairingClient {
        identity: &receiver,
        ledger: &ledger,
        clock: &clock,
    };
    for (code, claim_error, poll_error) in [
        (
            2,
            ClientError::OfferUnusable,
            ClientError::Code(PeerCode::Unauthorized),
        ),
        (
            1,
            ClientError::Code(PeerCode::Invalid),
            ClientError::Code(PeerCode::Invalid),
        ),
        (
            6,
            ClientError::Code(PeerCode::Incompatible),
            ClientError::Code(PeerCode::Incompatible),
        ),
    ] {
        let answer =
            |request: &Frame| frame(FrameKind::Error, request.request_id, error_payload(code));
        let mut attempts = ClaimAttempts::default();
        let (result, count) = fake(
            &fake_key,
            |_, request, _| Some(answer(request)),
            |port| client.claim(&fake_offer(&fake_key, port), &mut attempts),
        );
        assert_eq!((result, count), (Err(claim_error), 1), "claim {code}");
        let (result, count) = fake(
            &fake_key,
            |_, request, _| Some(answer(request)),
            |port| client.poll(&claimed_for(&fake_key, port, [0x21; 16])),
        );
        assert_eq!((result, count), (Err(poll_error), 1), "poll {code}");
    }
}

/// B4: every `SystemClock` reads one process-wide monotonic origin, so a
/// reading from an instance made later is never behind an earlier one.
#[test]
fn system_clock_instances_share_one_origin() {
    let first = SystemClock;
    thread::sleep(Duration::from_millis(50));
    let second = SystemClock;
    let early = first.monotonic();
    let late = second.monotonic();
    assert!(late >= early, "{late:?} < {early:?}");
}

/// A claim response for the connection with this `hFinal`.
fn claim_reply(request: &Frame, secret_hash: &[u8; 32], h_final: &[u8; 32]) -> Frame {
    frame(
        FrameKind::Response,
        request.request_id,
        json_bytes(json!({
            "expiresAt": 1,
            "pendingId": hex_encode(&derive_pending_id(secret_hash, h_final)),
            "protocol": 1,
        })),
    )
}

/// Acceptance (14): five transport failures after the handshake use the
/// five attempt records, and the sixth try ends as a lost attempt without
/// connecting; an answer naming the first attempt's pending ID on the
/// fifth try is still matched, so no record is ever evicted. Each failure
/// is a lost reply (the receiver's ledger cannot hold it): the request
/// reached the producer and may have been committed, so its record stays.
/// (A `busy` answer drops its record, C1, so it cannot fill them.)
#[test]
fn claim_attempts_are_capped_at_five_and_never_evicted() {
    let fake_key = StaticKey::generate().unwrap();
    let receiver = StaticKey::generate().unwrap();
    let time = Mutex::new(Duration::ZERO);
    let clock = FakeClock::new(&time);
    let ledger = MemoryLedger::default();
    let client = PairingClient {
        identity: &receiver,
        ledger: &ledger,
        clock: &clock,
    };
    let secret_hash = offer_secret_hash(&offer_id(1), &secret(1), fake_key.public());

    // Every reply would match its own attempt, but none can be read.
    let fill = ledger.reserve(REMOTE_MEMORY_MAX).unwrap();
    let mut attempts = ClaimAttempts::default();
    let (result, count) = fake(
        &fake_key,
        |_, request, h_final| Some(claim_reply(request, &secret_hash, h_final)),
        |port| client.claim(&fake_offer(&fake_key, port), &mut attempts),
    );
    assert_eq!((result, count), (Err(ClientError::LostAttempt), 5));
    assert_eq!(attempts.used(&offer_id(1)), 5);
    let (result, count) = fake(
        &fake_key,
        |_, request, h_final| Some(claim_reply(request, &secret_hash, h_final)),
        |port| client.claim(&fake_offer(&fake_key, port), &mut attempts),
    );
    assert_eq!((result, count), (Err(ClientError::LostAttempt), 0));
    drop(fill);
    assert_eq!(ledger.used(), 0);

    // Four replies are lost; the fifth, readable again, names the pending
    // ID the first try derived.
    let fill = Mutex::new(Some(ledger.reserve(REMOTE_MEMORY_MAX).unwrap()));
    let mut first: Option<[u8; 32]> = None;
    let mut attempts = ClaimAttempts::default();
    let (result, count) = fake(
        &fake_key,
        |n, request, h_final| {
            let first = *first.get_or_insert(*h_final);
            if n < 4 {
                return Some(claim_reply(request, &secret_hash, h_final));
            }
            // Released before the reply is written, so the client can read it.
            fill.lock().unwrap().take();
            Some(claim_reply(request, &secret_hash, &first))
        },
        |port| client.claim(&fake_offer(&fake_key, port), &mut attempts),
    );
    assert_eq!(count, 5);
    let claimed = result.unwrap();
    assert_eq!(attempts.used(&offer_id(1)), 5);
    let h_first = first.unwrap();
    assert_eq!(
        claimed.sas,
        pair_sas(
            1,
            &offer_id(1),
            fake_key.public(),
            receiver.public(),
            &h_first
        )
    );
    assert_eq!(
        claimed.pending_id,
        derive_pending_id(&secret_hash, &h_first)
    );
    assert_eq!(ledger.used(), 0);
}

/// C1: on Pair claim `busy` comes only from the rate limiter, before any
/// state is read, so an authenticated `busy` drops its attempt record.
/// Five `busy` answers end the call with `Busy` and no record; a later
/// claim of the same offer succeeds with its own connection's SAS. Claim
/// calls stay a second apart: a claim right after a finished one first
/// waits out the interval, and takes one more record only.
#[test]
fn busy_claims_keep_no_record_and_claim_calls_stay_a_second_apart() {
    let fake_key = StaticKey::generate().unwrap();
    let receiver = StaticKey::generate().unwrap();
    let time = Mutex::new(Duration::ZERO);
    let clock = FakeClock::new(&time);
    let ledger = MemoryLedger::default();
    let client = PairingClient {
        identity: &receiver,
        ledger: &ledger,
        clock: &clock,
    };
    let secret_hash = offer_secret_hash(&offer_id(1), &secret(1), fake_key.public());
    let h_finals = Mutex::new(Vec::new());
    let mut attempts = ClaimAttempts::default();
    let (outcomes, count) = fake(
        &fake_key,
        |n, request, h_final| {
            h_finals.lock().unwrap().push(*h_final);
            Some(if n < 5 {
                frame(FrameKind::Error, request.request_id, error_payload(5))
            } else {
                claim_reply(request, &secret_hash, h_final)
            })
        },
        |port| {
            let offer = fake_offer(&fake_key, port);
            (0..3)
                .map(|_| {
                    let result = client.claim(&offer, &mut attempts);
                    (result, attempts.used(&offer_id(1)), *time.lock().unwrap())
                })
                .collect::<Vec<_>>()
        },
    );
    assert_eq!(count, 7);
    let h_finals = h_finals.into_inner().unwrap();
    let sas = |n: usize| {
        pair_sas(
            1,
            &offer_id(1),
            fake_key.public(),
            receiver.public(),
            &h_finals[n],
        )
    };
    // Five `busy` answers, four 1 s waits between them, no record.
    assert_eq!(outcomes[0].0, Err(ClientError::Busy));
    assert_eq!((outcomes[0].1, outcomes[0].2), (0, Duration::from_secs(4)));
    // The next call waits a second after the last exchange, then succeeds.
    let claimed = outcomes[1].0.clone().unwrap();
    assert_eq!(claimed.sas, sas(5));
    assert_eq!(
        claimed.pending_id,
        derive_pending_id(&secret_hash, &h_finals[5])
    );
    assert_eq!((outcomes[1].1, outcomes[1].2), (1, Duration::from_secs(5)));
    // Called again at once: it waits a second first and adds one record.
    let claimed = outcomes[2].0.clone().unwrap();
    assert_eq!(claimed.sas, sas(6));
    assert_eq!((outcomes[2].1, outcomes[2].2), (2, Duration::from_secs(6)));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod disk {
    use std::{
        net::Shutdown, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Instant,
    };

    use syrtis_agent::{
        pairing::{ConfirmedGrant, GrantStatus, PairStatus, Producer, approve},
        secure_fs::SecureRoot,
        security::{NOISE_PROLOGUE, NOISE_SUITE, Offer, OfferState, PendingState},
        state_store::StateStore,
    };

    use super::*;

    const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];

    // Used only by the store-backed tests.
    impl<'a> FakeClock<'a> {
        fn hook(self, hook: impl FnMut(Duration) + Send + 'a) -> Self {
            *self.hook.lock().unwrap() = Box::new(hook);
            self
        }

        fn skew(&self, seconds: i64) {
            self.skew.store(seconds, Ordering::SeqCst);
        }

        /// Moves time on by a second, so the next request from the same
        /// static is admitted by the producer's rate limiter.
        fn tick(&self) {
            *self.elapsed.lock().unwrap() += RATE_INTERVAL;
        }
    }
    const REQUEST_ID: [u8; 16] = [0x5a; 16];

    // ------------------------------------------------------------ harness

    /// A temporary home. Only directories this helper created are removed.
    struct TempHome {
        path: PathBuf,
    }

    impl TempHome {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "syrtis-agent-pair-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// A producer agent on its own secure root, sharing on.
    struct Node {
        home: TempHome,
        store: StateStore,
        key: StaticKey,
        ledger: MemoryLedger,
        limiter: RateLimiter,
    }

    impl Node {
        fn new() -> Self {
            let home = TempHome::new();
            let store =
                retry_busy(|| StateStore::open(SecureRoot::open_under(&home.path, SUFFIX)?, NOW))
                    .unwrap();
            store.transition(|state| state.enable_sharing()).unwrap();
            let key = StaticKey::from_state(&store.state().unwrap()).unwrap();
            Self {
                home,
                store,
                key,
                ledger: MemoryLedger::default(),
                limiter: RateLimiter::default(),
            }
        }

        fn producer<'a>(&'a self, clock: &'a dyn Clock) -> Producer<'a> {
            Producer {
                store: &self.store,
                identity: &self.key,
                ledger: &self.ledger,
                limiter: &self.limiter,
                clock,
            }
        }

        /// Creates offer `n`, created at `os_now`, through the frozen transition.
        fn offer(&self, n: u8, lifetime_ms: i64, os_now: i64) {
            let responder = *self.key.public();
            self.store
                .transition(|state| {
                    state.create_offer(
                        Offer {
                            offer_id: offer_id(n),
                            secret_hash: offer_secret_hash(&offer_id(n), &secret(n), &responder),
                            created_at_ms: os_now * 1_000,
                            expires_at_ms: os_now * 1_000 + lifetime_ms,
                            state: OfferState::Active,
                        },
                        os_now,
                    )
                })
                .unwrap();
        }

        fn pair_offer(&self, n: u8, port: u16) -> PairOffer {
            let state = self.store.state().unwrap();
            let offer = state
                .reference
                .offers
                .iter()
                .find(|offer| offer.offer_id == offer_id(n))
                .unwrap();
            PairOffer {
                expires_at: offer.expires_at_ms,
                host: "127.0.0.1".into(),
                offer_id: hex_encode(&offer_id(n)),
                port,
                responder_static: hex_encode(self.key.public()),
                secret: hex_encode(&secret(n)),
                version: 1,
            }
        }

        fn state_file(&self) -> Vec<u8> {
            let path = SUFFIX
                .iter()
                .fold(self.home.path.clone(), |path, part| path.join(part))
                .join("state.json");
            std::fs::read(path).unwrap()
        }
    }

    fn retry_busy<T>(mut f: impl FnMut() -> Result<T, StorageError>) -> Result<T, StorageError> {
        for _ in 0..200 {
            match f() {
                Err(StorageError::Busy) => thread::sleep(Duration::from_millis(10)),
                other => return other,
            }
        }
        f()
    }

    /// Serves connections with `producer` on a loopback port while `body`
    /// runs; returns `body`'s result and the producer's monotonic time at
    /// each accepted connection.
    fn serve<R>(producer: &Producer<'_>, body: impl FnOnce(u16) -> R) -> (R, Vec<Duration>) {
        let (listener, port) = loopback();
        let stop = AtomicBool::new(false);
        let accepted = Mutex::new(Vec::new());
        let result = thread::scope(|scope| {
            scope.spawn(|| {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    accepted.lock().unwrap().push(producer.clock.monotonic());
                    producer.serve(stream);
                }
            });
            let result = catch_unwind(AssertUnwindSafe(|| body(port)));
            stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(("127.0.0.1", port));
            result
        });
        let result = result.unwrap_or_else(|panic| resume_unwind(panic));
        (result, accepted.into_inner().unwrap())
    }

    fn claim_json(n: u8, secret: &[u8; 32]) -> Vec<u8> {
        json_bytes(json!({
            "offerId": hex_encode(&offer_id(n)),
            "protocol": 1,
            "secret": hex_encode(secret),
        }))
    }

    fn pair_status_json(pending_id: &[u8; 16]) -> Vec<u8> {
        json_bytes(json!({"pendingId": hex_encode(pending_id), "protocol": 1}))
    }

    fn grant_status_json(grant_id: &[u8; 16]) -> Vec<u8> {
        json_bytes(json!({"grantId": hex_encode(grant_id), "protocol": 1}))
    }

    /// One raw request over a real handshake: the reply frame and `hFinal`.
    fn raw_kind(
        port: u16,
        key: &StaticKey,
        responder: &[u8; 32],
        kind: FrameKind,
        payload: Vec<u8>,
    ) -> (Frame, [u8; 32]) {
        let mut session = noise::connect("127.0.0.1", port, key, responder).unwrap();
        session
            .send(&frame(kind, REQUEST_ID, payload), Deadline::after(LONG))
            .unwrap();
        let received = session
            .receive(&MemoryLedger::default(), Deadline::after(LONG))
            .unwrap();
        assert_eq!(received.frame().request_id, REQUEST_ID);
        (received.frame().clone(), *session.h_final())
    }

    fn raw(port: u16, key: &StaticKey, responder: &[u8; 32], payload: Vec<u8>) -> Frame {
        raw_kind(port, key, responder, FrameKind::Request, payload).0
    }

    fn body_of(frame: &Frame) -> Value {
        assert_eq!(frame.kind, FrameKind::Response, "{:?}", frame.payload);
        CanonicalJsonV1::decode_value(&frame.payload).unwrap()
    }

    fn pending_of(value: &Value) -> [u8; 16] {
        syrtis_agent::security::decode_fixed_hex(value["pendingId"].as_str().unwrap()).unwrap()
    }

    /// Records both directions of one proxied connection.
    struct Tap {
        port: u16,
        up: Arc<Mutex<Vec<u8>>>,
        down: Arc<Mutex<Vec<u8>>>,
    }

    fn tap(target: u16) -> Tap {
        let (listener, port) = loopback();
        let up = Arc::new(Mutex::new(Vec::new()));
        let down = Arc::new(Mutex::new(Vec::new()));
        let (up_log, down_log) = (Arc::clone(&up), Arc::clone(&down));
        thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            let server = TcpStream::connect(("127.0.0.1", target)).unwrap();
            pump(
                client.try_clone().unwrap(),
                server.try_clone().unwrap(),
                up_log,
            );
            pump(server, client, down_log);
        });
        Tap { port, up, down }
    }

    fn pump(mut from: TcpStream, mut to: TcpStream, log: Arc<Mutex<Vec<u8>>>) {
        thread::spawn(move || {
            let mut buffer = [0; 4096];
            loop {
                match from.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        log.lock().unwrap().extend_from_slice(&buffer[..read]);
                        if to.write_all(&buffer[..read]).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = to.shutdown(Shutdown::Write);
        });
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// The secret as raw bytes, lowercase and uppercase hex, and as `Debug`
    /// renders a byte array.
    fn secret_forms(secret: &[u8; 32]) -> Vec<Vec<u8>> {
        let hex = hex_encode(secret);
        // `Debug` of a byte vector, as a `Frame` payload would print: of
        // the raw secret, and of its hex text.
        let bytes_debug = format!("{secret:?}");
        let hex_debug = format!("{:?}", hex.as_bytes());
        vec![
            secret.to_vec(),
            hex.clone().into_bytes(),
            hex.to_ascii_uppercase().into_bytes(),
            bytes_debug.trim_matches(['[', ']']).as_bytes().to_vec(),
            hex_debug.trim_matches(['[', ']']).as_bytes().to_vec(),
        ]
    }

    fn assert_no_secret(label: &str, bytes: &[u8], secrets: &[[u8; 32]]) {
        for form in secrets.iter().flat_map(secret_forms) {
            assert!(!contains(bytes, &form), "{label} carries the secret");
        }
    }

    /// A client, a pending claim and an approval through the store, all
    /// through real loopback connections; returns the client's confirmed
    /// grant and the store's pending ID.
    fn paired(node: &Node, port: u16, key: &StaticKey, n: u8, clock: &FakeClock<'_>) -> [u8; 16] {
        node.offer(n, 600_000, clock.os_now_seconds().unwrap());
        clock.tick();
        let body = body_of(&raw(
            port,
            key,
            node.key.public(),
            claim_json(n, &secret(n)),
        ));
        let pending_id = pending_of(&body);
        approve(
            &node.store,
            pending_id,
            1,
            true,
            clock.os_now_seconds().unwrap(),
        )
        .unwrap();
        pending_id
    }

    fn state_of(frame: &Frame) -> String {
        body_of(frame)["state"].as_str().unwrap().to_owned()
    }

    // ------------------------------------------------------------- tests

    /// Acceptance (1) and (15, clock): offer, claim, equal SAS on both
    /// sides, owner approval while the client polls, Pair status
    /// `approved`, Grant status `active`, rate limiting on, polls at least
    /// 3 s apart. The receiver clock running an hour ahead of the producer
    /// changes nothing: the client bounds polling by its own monotonic time
    /// and never compares the producer's `expiresAt` with its own clock.
    #[test]
    fn two_nodes_pair_end_to_end_and_agree_on_the_sas() {
        for receiver_ahead in [0_i64, 3_600] {
            let node = Node::new();
            node.offer(1, 600_000, NOW);
            let time = Mutex::new(Duration::ZERO);
            let producer_clock = FakeClock::new(&time);
            let sleeps = AtomicUsize::new(0);
            let mut receiver_clock = FakeClock::new(&time).hook(|elapsed| {
                // The owner approves while the client waits for its 2nd poll.
                if sleeps.fetch_add(1, Ordering::SeqCst) == 1 {
                    let pending = node.store.state().unwrap().reference.pending[0].clone();
                    approve(
                        &node.store,
                        pending.pending_id,
                        pending.sas_generation,
                        true,
                        NOW + elapsed.as_secs() as i64,
                    )
                    .unwrap();
                }
            });
            receiver_clock.offset = Duration::from_secs(receiver_ahead as u64);
            receiver_clock.skew(receiver_ahead);
            let receiver = StaticKey::generate().unwrap();
            let ledger = MemoryLedger::default();
            let client = PairingClient {
                identity: &receiver,
                ledger: &ledger,
                clock: &receiver_clock,
            };
            let producer = node.producer(&producer_clock);
            let ((claimed, confirmed), accepted) = serve(&producer, |port| {
                let mut attempts = ClaimAttempts::default();
                let claimed = client
                    .claim(&node.pair_offer(1, port), &mut attempts)
                    .unwrap();
                (claimed.clone(), client.poll(&claimed))
            });
            let state = node.store.state().unwrap();
            let pending = &state.reference.pending[0];
            let grant = &state.reference.grants[0];
            assert_eq!(claimed.sas, pending.sas_code, "receiver and producer SAS");
            assert_eq!(claimed.pending_id, pending.pending_id);
            assert_eq!(pending.state, PendingState::Approved);
            assert_eq!(pending.initiator_static, *receiver.public());
            assert_eq!(
                confirmed,
                Ok(ConfirmedGrant {
                    grant_id: derive_grant_id(&pending.pending_id),
                    auth_epoch: grant.auth_epoch,
                    source_scope_generation: grant.source_scope_generation,
                    expires_at_ms: grant.expires_at_ms,
                    responder_static: *node.key.public(),
                    initiator_static: *receiver.public(),
                    pending_id: pending.pending_id,
                })
            );
            assert_eq!(grant.grant_id, derive_grant_id(&pending.pending_id));
            assert_eq!(grant.responder_static, *node.key.public());
            assert_eq!(
                grant.expires_at_ms - grant.created_at_ms,
                30 * 86_400_000,
                "30-day grant"
            );
            // Claim, Pair status x2 (awaiting, approved), Grant status.
            assert_eq!(accepted.len(), 4, "{accepted:?}");
            for pair in accepted.windows(2) {
                assert!(pair[1] - pair[0] >= Duration::from_secs(3), "{accepted:?}");
            }
            assert_eq!(ledger.used(), 0);
            assert_eq!(node.ledger.used(), 0);
        }
    }

    /// Acceptance (2): a wrong secret is `unauthorized`, leaves the offer
    /// active and writes nothing.
    #[test]
    fn a_wrong_secret_is_unauthorized_and_changes_nothing() {
        let node = Node::new();
        node.offer(1, 600_000, NOW);
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let receiver = StaticKey::generate().unwrap();
        let before = node.state_file();
        let (reply, _) = serve(&node.producer(&clock), |port| {
            raw(
                port,
                &receiver,
                node.key.public(),
                claim_json(1, &[0x01; 32]),
            )
        });
        assert_eq!(reply.kind, FrameKind::Error);
        assert_eq!(reply.payload, error_payload(2));
        assert_eq!(node.state_file(), before);
        assert_eq!(
            node.store.state().unwrap().reference.offers[0].state,
            OfferState::Active
        );
    }

    /// Acceptance (3): eight refusals, one payload. Wrong secret, unknown
    /// offer, an offer that expired unclaimed, an offer someone else
    /// consumed, unknown pending ID, unknown grant ID, and a Pair status or
    /// Grant status from a static the record is not bound to.
    #[test]
    fn eight_unauthorized_causes_send_byte_identical_payloads() {
        let node = Node::new();
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let alice = StaticKey::generate().unwrap();
        let mallory = StaticKey::generate().unwrap();
        node.offer(1, 600_000, NOW);
        node.offer(2, 1_000, NOW);
        let responder = *node.key.public();
        let (payloads, _) = serve(&node.producer(&clock), |port| {
            let pending_id = paired(&node, port, &alice, 3, &clock);
            let grant_id = derive_grant_id(&pending_id);
            node.offer(4, 600_000, clock.os_now_seconds().unwrap());
            clock.tick();
            body_of(&raw(port, &alice, &responder, claim_json(4, &secret(4))));
            let ask = |key: &StaticKey, payload: Vec<u8>| {
                clock.tick();
                raw(port, key, &responder, payload).payload
            };
            vec![
                ("wrong secret", ask(&mallory, claim_json(1, &[0x01; 32]))),
                ("unknown offer", ask(&mallory, claim_json(9, &secret(9)))),
                // Offer 2 lived 1 s and is now past expiry, never claimed.
                ("expired offer", ask(&mallory, claim_json(2, &secret(2)))),
                ("consumed offer", ask(&mallory, claim_json(4, &secret(4)))),
                (
                    "unknown pending",
                    ask(&alice, pair_status_json(&[0xee; 16])),
                ),
                ("unknown grant", ask(&alice, grant_status_json(&[0xee; 16]))),
                (
                    "pair status static",
                    ask(&mallory, pair_status_json(&pending_id)),
                ),
                (
                    "grant status static",
                    ask(&mallory, grant_status_json(&grant_id)),
                ),
                // Control: the bound static gets an answer.
                ("control", ask(&alice, grant_status_json(&grant_id))),
            ]
        });
        let (control, refusals) = payloads.split_last().unwrap();
        for (label, payload) in refusals {
            assert_eq!(*payload, error_payload(2), "{label}");
        }
        assert_ne!(control.1, error_payload(2));
    }

    /// Acceptance (4): the claim response is lost (the receiver's ledger
    /// cannot hold it), the client retries on a new connection, the frozen
    /// claim returns the first pending ID, and the client shows the SAS of
    /// that first attempt, which the owner can approve as generation 1.
    #[test]
    fn a_lost_claim_response_is_recovered_with_the_first_sas() {
        let node = Node::new();
        node.offer(1, 600_000, NOW);
        let time = Mutex::new(Duration::ZERO);
        let producer_clock = FakeClock::new(&time);
        let ledger = MemoryLedger::default();
        let fill = Mutex::new(ledger.reserve(REMOTE_MEMORY_MAX));
        let receiver_clock = FakeClock::new(&time).hook(|_| {
            fill.lock().unwrap().take();
        });
        let receiver = StaticKey::generate().unwrap();
        let client = PairingClient {
            identity: &receiver,
            ledger: &ledger,
            clock: &receiver_clock,
        };
        let mut attempts = ClaimAttempts::default();
        let (claimed, accepted) = serve(&node.producer(&producer_clock), |port| {
            client.claim(&node.pair_offer(1, port), &mut attempts)
        });
        let claimed = claimed.unwrap();
        assert_eq!(accepted.len(), 2, "first response lost, one retry");
        assert_eq!(attempts.used(&offer_id(1)), 2);
        let state = node.store.state().unwrap();
        assert_eq!(state.reference.pending.len(), 1);
        let pending = &state.reference.pending[0];
        assert_eq!(claimed.pending_id, pending.pending_id);
        assert_eq!(claimed.sas, pending.sas_code, "the first attempt's SAS");
        approve(&node.store, claimed.pending_id, 1, true, NOW + 2).unwrap();
        assert_eq!(ledger.used(), 0);
    }

    /// Acceptance (5): an observer with the transcript and
    /// `responderStatic` recomputes `hFinal`, but not the pending ID; with
    /// the Pair URL it can.
    #[test]
    fn a_handshake_observer_recomputes_h_final_but_not_the_pending_id() {
        use blake2::{Blake2s256, Digest as _};
        let node = Node::new();
        node.offer(1, 600_000, NOW);
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let receiver = StaticKey::generate().unwrap();
        let responder = *node.key.public();
        let ((reply, h_final, up, down), _) = serve(&node.producer(&clock), |port| {
            let tap = tap(port);
            let (reply, h_final) = raw_kind(
                tap.port,
                &receiver,
                &responder,
                FrameKind::Request,
                claim_json(1, &secret(1)),
            );
            let up = tap.up.lock().unwrap().clone();
            let down = tap.down.lock().unwrap().clone();
            (reply, h_final, up, down)
        });
        let pending_id = pending_of(&body_of(&reply));
        assert_eq!(up[..4], 96_u32.to_be_bytes());
        assert_eq!(down[..4], 48_u32.to_be_bytes());
        let (message1, message2) = (&up[4..100], &down[4..52]);

        let hash = |parts: &[&[u8]]| -> [u8; 32] {
            let mut hasher = Blake2s256::new();
            for part in parts {
                hasher.update(part);
            }
            hasher.finalize().into()
        };
        let mut h = hash(&[NOISE_SUITE.as_bytes()]);
        for part in [
            NOISE_PROLOGUE,
            &responder[..],
            &message1[..32],
            &message1[32..80],
            &message1[80..],
            &message2[..32],
            &message2[32..],
        ] {
            h = hash(&[&h[..], part]);
        }
        assert_eq!(h, h_final, "the handshake hash is public");

        let sha = |parts: &[&[u8]]| -> [u8; 16] {
            let mut hasher = sha2::Sha256::new();
            for part in parts {
                sha2::Digest::update(&mut hasher, part);
            }
            sha2::Digest::finalize(hasher)[..16].try_into().unwrap()
        };
        // The observer's guesses: the tag with hFinal alone, or with a
        // secret hash under a guessed secret.
        assert_ne!(sha(&[&b"syrtis-pair-pending-v1\0"[..], &h[..]]), pending_id);
        let guessed = offer_secret_hash(&offer_id(1), &[0; 32], &responder);
        assert_ne!(derive_pending_id(&guessed, &h), pending_id);
        // Positive control: the holder of this Pair URL can.
        let known = offer_secret_hash(&offer_id(1), &secret(1), &responder);
        assert_eq!(derive_pending_id(&known, &h), pending_id);
    }

    /// Acceptance (6): `awaiting` is the exact wire value; `rejected`;
    /// `expired` by effective now with no sweep; `approved` still answered
    /// after the pending's own expiry.
    #[test]
    fn pair_status_reports_awaiting_rejected_expired_and_late_approved() {
        let node = Node::new();
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let alice = StaticKey::generate().unwrap();
        let mallory = StaticKey::generate().unwrap();
        let responder = *node.key.public();
        serve(&node.producer(&clock), |port| {
            let claim = |n: u8| {
                node.offer(n, 600_000, clock.os_now_seconds().unwrap());
                clock.tick();
                pending_of(&body_of(&raw(
                    port,
                    &alice,
                    &responder,
                    claim_json(n, &secret(n)),
                )))
            };
            let awaiting = claim(1);
            let rejected = claim(2);
            let late = claim(3);
            let status = |pending_id: &[u8; 16]| {
                clock.tick();
                raw(port, &alice, &responder, pair_status_json(pending_id))
            };
            assert_eq!(
                status(&awaiting).payload,
                br#"{"protocol":1,"state":"awaiting"}"#
            );
            node.store
                .transition(|state| state.reject_pending(rejected, 1, NOW * 1_000))
                .unwrap();
            assert_eq!(
                status(&rejected).payload,
                br#"{"protocol":1,"state":"rejected"}"#
            );
            approve(&node.store, late, 1, true, clock.os_now_seconds().unwrap()).unwrap();

            // Past every pending's expiry (600 s), no sweep has run.
            clock.skew(700);
            assert_eq!(
                status(&awaiting).payload,
                br#"{"protocol":1,"state":"expired"}"#
            );
            assert_eq!(
                node.store.state().unwrap().reference.pending[0].state,
                PendingState::AwaitingApproval,
                "no sweep"
            );
            let approved = body_of(&status(&late));
            let grant = node.store.state().unwrap().reference.grants[0].clone();
            assert_eq!(
                approved,
                json!({
                    "authEpoch": grant.auth_epoch,
                    "expiresAt": grant.expires_at_ms,
                    "grantId": hex_encode(&derive_grant_id(&late)),
                    "protocol": 1,
                    "sourceScopeGeneration": grant.source_scope_generation,
                    "state": "approved",
                })
            );

            // Clock anomaly, checked after the binding: the bound static
            // sees `busy`, any other static still `unauthorized`.
            clock.skew(200_000);
            assert_eq!(status(&awaiting).payload, error_payload(5));
            clock.tick();
            let other = raw(port, &mallory, &responder, pair_status_json(&awaiting));
            assert_eq!(other.payload, error_payload(2));
        });
    }

    /// Acceptance (7): active; revoked after revoke, after a source change
    /// and after disable (still answered); expired by state and by effective
    /// now; under a clock anomaly an active grant is `busy`, a revoked one
    /// `revoked`, and an unbound static still `unauthorized`.
    #[test]
    fn grant_status_reports_every_state_and_respects_the_clock_order() {
        let node = Node::new();
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let alice = StaticKey::generate().unwrap();
        let mallory = StaticKey::generate().unwrap();
        let responder = *node.key.public();
        serve(&node.producer(&clock), |port| {
            let grants: Vec<[u8; 16]> = (1..=5)
                .map(|n| derive_grant_id(&paired(&node, port, &alice, n, &clock)))
                .collect();
            let status = |key: &StaticKey, grant_id: &[u8; 16]| {
                clock.tick();
                raw(port, key, &responder, grant_status_json(grant_id))
            };
            assert_eq!(state_of(&status(&alice, &grants[0])), "active");
            let body = body_of(&status(&alice, &grants[0]));
            assert_eq!(body["grantId"], hex_encode(&grants[0]));

            node.store
                .transition(|state| state.revoke_commit(grants[0], NOW * 1_000))
                .unwrap();
            assert_eq!(state_of(&status(&alice, &grants[0])), "revoked");
            assert_eq!(state_of(&status(&alice, &grants[1])), "active");

            let expires = node.store.state().unwrap().reference.grants[2].expires_at_ms;
            node.store
                .transition(|state| state.expire_one(grants[2], expires))
                .unwrap();
            assert_eq!(state_of(&status(&alice, &grants[2])), "expired");

            // Clock anomaly: forward by more than a day.
            clock.skew(200_000);
            assert_eq!(status(&alice, &grants[1]).payload, error_payload(5));
            assert_eq!(state_of(&status(&alice, &grants[0])), "revoked");
            assert_eq!(state_of(&status(&alice, &grants[2])), "expired");
            assert_eq!(status(&mallory, &grants[1]).payload, error_payload(2));
            clock.skew(0);

            node.store
                .transition(|state| state.source_change_commit())
                .unwrap();
            assert_eq!(state_of(&status(&alice, &grants[1])), "revoked");
        });

        // Expiry by effective now: walk the durable wall forward a day at a
        // time (a single 30-day step is a clock anomaly), then ask.
        let node = Node::new();
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        serve(&node.producer(&clock), |port| {
            let grant_id = derive_grant_id(&paired(&node, port, &alice, 1, &clock));
            let expires = node.store.state().unwrap().reference.grants[0].expires_at_ms;
            for day in 1..=30 {
                node.store.checkpoint(NOW + day * 86_400).unwrap();
            }
            clock.skew(expires / 1_000 - NOW);
            clock.tick();
            let reply = raw(
                port,
                &alice,
                node.key.public(),
                grant_status_json(&grant_id),
            );
            assert_eq!(state_of(&reply), "expired");
            assert_eq!(
                node.store.state().unwrap().reference.grants[0].state,
                syrtis_agent::security::GrantState::Active,
                "expired by effective now, not by a sweep"
            );
        });

        // Disable: Grant status still answers the bound static, `revoked`.
        let node = Node::new();
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        serve(&node.producer(&clock), |port| {
            let grant_id = derive_grant_id(&paired(&node, port, &alice, 1, &clock));
            node.store.disable(NOW * 1_000).unwrap();
            clock.tick();
            let reply = raw(
                port,
                &alice,
                node.key.public(),
                grant_status_json(&grant_id),
            );
            assert_eq!(state_of(&reply), "revoked");
        });
    }

    /// B5: with the OS wall clock unreadable, Grant status still answers
    /// what needs no clock: a revoked grant `revoked`, an expired one
    /// `expired`; an active one gets the error map's `internal`.
    #[test]
    fn grant_status_without_a_wall_clock_still_reports_revoked_and_expired() {
        let node = Node::new();
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let alice = StaticKey::generate().unwrap();
        let responder = *node.key.public();
        serve(&node.producer(&clock), |port| {
            let grants: Vec<[u8; 16]> = (1..=3)
                .map(|n| derive_grant_id(&paired(&node, port, &alice, n, &clock)))
                .collect();
            node.store
                .transition(|state| state.revoke_commit(grants[0], NOW * 1_000))
                .unwrap();
            let expires = node.store.state().unwrap().reference.grants[1].expires_at_ms;
            node.store
                .transition(|state| state.expire_one(grants[1], expires))
                .unwrap();
            clock.wall_fails.store(true, Ordering::SeqCst);
            let status = |grant_id: &[u8; 16]| {
                clock.tick();
                raw(port, &alice, &responder, grant_status_json(grant_id))
            };
            assert_eq!(state_of(&status(&grants[0])), "revoked");
            assert_eq!(state_of(&status(&grants[1])), "expired");
            assert_eq!(status(&grants[2]).payload, error_payload(8));
            // Control: with the clock back, the active grant is `active`.
            clock.wall_fails.store(false, Ordering::SeqCst);
            assert_eq!(state_of(&status(&grants[2])), "active");
        });
    }

    /// C2: with the OS wall clock unreadable or anomalous, Pair status
    /// still answers the stored states that need no clock (`rejected`,
    /// `approved`). Only `awaitingApproval` needs it: `internal` when it
    /// cannot be read, `busy` under an anomaly.
    #[test]
    fn pair_status_without_a_sane_clock_still_reports_terminal_states() {
        let node = Node::new();
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let alice = StaticKey::generate().unwrap();
        let responder = *node.key.public();
        serve(&node.producer(&clock), |port| {
            let claim = |n: u8| {
                node.offer(n, 600_000, clock.os_now_seconds().unwrap());
                clock.tick();
                pending_of(&body_of(&raw(
                    port,
                    &alice,
                    &responder,
                    claim_json(n, &secret(n)),
                )))
            };
            let awaiting = claim(1);
            let rejected = claim(2);
            let approved = claim(3);
            node.store
                .transition(|state| state.reject_pending(rejected, 1, NOW * 1_000))
                .unwrap();
            approve(
                &node.store,
                approved,
                1,
                true,
                clock.os_now_seconds().unwrap(),
            )
            .unwrap();
            let status = |pending_id: &[u8; 16]| {
                clock.tick();
                raw(port, &alice, &responder, pair_status_json(pending_id))
            };
            let rejected_body = br#"{"protocol":1,"state":"rejected"}"#;

            clock.wall_fails.store(true, Ordering::SeqCst);
            assert_eq!(status(&rejected).payload, rejected_body);
            assert_eq!(state_of(&status(&approved)), "approved");
            assert_eq!(status(&awaiting).payload, error_payload(8));
            clock.wall_fails.store(false, Ordering::SeqCst);

            clock.skew(200_000);
            assert_eq!(status(&rejected).payload, rejected_body);
            assert_eq!(state_of(&status(&approved)), "approved");
            assert_eq!(status(&awaiting).payload, error_payload(5));

            // Control: with a sane clock the awaiting pending is answered.
            clock.skew(0);
            assert_eq!(
                status(&awaiting).payload,
                br#"{"protocol":1,"state":"awaiting"}"#
            );
        });
    }

    /// Acceptance (8), producer half: a bad message 1 prefix closes with
    /// nothing written; a replay of a recorded connection (message 1 and the
    /// request ciphertext) reaches no state.
    #[test]
    fn bad_prefixes_and_replayed_message_1_leave_state_and_ledger_untouched() {
        let node = Node::new();
        node.offer(1, 600_000, NOW);
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let receiver = StaticKey::generate().unwrap();
        let responder = *node.key.public();
        serve(&node.producer(&clock), |port| {
            let before = node.state_file();
            for prefix in [97_u32, 95] {
                let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
                client.write_all(&prefix.to_be_bytes()).unwrap();
                assert!(drain(&mut client).is_empty(), "{prefix}");
                assert_eq!(node.ledger.used(), 0);
            }
            assert_eq!(node.state_file(), before);

            // A real claim, recorded.
            let tap = tap(port);
            let reply = raw(tap.port, &receiver, &responder, claim_json(1, &secret(1)));
            body_of(&reply);
            let recorded = tap.up.lock().unwrap().clone();
            let after_claim = node.state_file();
            // Time moves on, so a claim retry that got through would
            // advance the durable wall and change the file.
            clock.tick();
            *time.lock().unwrap() += Duration::from_secs(5);
            let mut replay = TcpStream::connect(("127.0.0.1", port)).unwrap();
            replay.write_all(&recorded).unwrap();
            let answer = drain(&mut replay);
            assert_eq!(answer.len(), 4 + MESSAGE2_LEN, "message 2 only, no frame");
            assert_eq!(node.state_file(), after_claim);
            assert_eq!(node.ledger.used(), 0);
        });
    }

    /// Acceptance (9): unknown key set, the Peer request key set, a frame
    /// that is not a request and a 4,097-byte payload are `invalid`;
    /// `protocol: 2` is `incompatible`. The 4,097-byte payload is canonical
    /// with the Pair status key set and `protocol: 2` (B8), so only the size
    /// cap makes it `invalid`; without the cap it would be `incompatible`.
    #[test]
    fn malformed_requests_are_invalid_and_another_protocol_is_incompatible() {
        let node = Node::new();
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let alice = StaticKey::generate().unwrap();
        let responder = *node.key.public();
        let id = hex_encode(&[0x11; 16]);
        let padded = |size: usize| {
            let base = json_bytes(json!({"pendingId": "", "protocol": 2})).len();
            let bytes = json_bytes(json!({"pendingId": "a".repeat(size - base), "protocol": 2}));
            assert_eq!(bytes.len(), size);
            bytes
        };
        let peer_request = json!({
            "aggregationRevision": 1, "authEpoch": 1, "clients": [],
            "endDateExclusive": "2026-01-02", "endpoint": 1, "grantId": id,
            "protocol": 1, "reportSchema": 1, "requestId": id,
            "sourceScopeGeneration": 1, "startDate": "2026-01-01",
            "timezone": "UTC", "tzdbRevision": "2026c",
        });
        serve(&node.producer(&clock), |port| {
            let ask = |kind: FrameKind, payload: Vec<u8>| {
                clock.tick();
                raw_kind(port, &alice, &responder, kind, payload).0.payload
            };
            let request = FrameKind::Request;
            let cases = [
                (
                    "unknown keys",
                    request,
                    json_bytes(json!({"pendingId": id, "protocol": 1, "x": 1})),
                ),
                ("peer request", request, json_bytes(peer_request)),
                (
                    "response kind",
                    FrameKind::Response,
                    pair_status_json(&[0x11; 16]),
                ),
                ("4097 bytes", request, padded(4_097)),
                ("not canonical", request, b"{ \"pendingId\":1}".to_vec()),
            ];
            for (label, kind, payload) in cases {
                assert_eq!(ask(kind, payload), error_payload(1), "{label}");
            }
            assert_eq!(
                ask(request, json_bytes(json!({"pendingId": id, "protocol": 2}))),
                error_payload(6)
            );
            // Control for the cap: at 4,096 bytes the same payload passes
            // every other check and reaches `incompatible`.
            assert_eq!(ask(request, padded(4_096)), error_payload(6));
            // Control: protocol 1 reaches the surface.
            assert_eq!(
                ask(request, json_bytes(json!({"pendingId": id, "protocol": 1}))),
                error_payload(2)
            );
        });
    }

    /// Acceptance (11): the secret appears in no handshake message, no
    /// response or error payload, and no `Debug` output of the public types.
    #[test]
    fn the_secret_never_leaves_the_claim_request() {
        let node = Node::new();
        node.offer(1, 600_000, NOW);
        let the_secret = secret(1);
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let receiver = StaticKey::generate().unwrap();
        let ledger = MemoryLedger::default();
        let client = PairingClient {
            identity: &receiver,
            ledger: &ledger,
            clock: &clock,
        };
        let responder = *node.key.public();
        let producer = node.producer(&clock);
        let mut debug = vec![format!("{producer:?}"), format!("{client:?}")];
        let secrets = [the_secret, secret(2)];
        node.offer(2, 600_000, NOW);
        let (payloads, _) = serve(&producer, |port| {
            let claim_response =
                raw(port, &receiver, &responder, claim_json(2, &secret(2))).payload;
            assert_no_secret("claim response", &claim_response, &secrets);
            clock.tick();
            let tap = tap(port);
            let mut attempts = ClaimAttempts::default();
            let claimed = client
                .claim(&node.pair_offer(1, tap.port), &mut attempts)
                .unwrap();
            let (up, down) = (
                tap.up.lock().unwrap().clone(),
                tap.down.lock().unwrap().clone(),
            );
            let claimed = Claimed { port, ..claimed };
            clock.tick();
            let awaiting = client.pair_status(&claimed).unwrap();
            approve(&node.store, claimed.pending_id, 1, true, NOW + 1).unwrap();
            clock.tick();
            let approved = client.pair_status(&claimed).unwrap();
            let PairStatus::Approved { grant_id, .. } = approved else {
                panic!("{approved:?}")
            };
            clock.tick();
            let answer = client.grant_status(&claimed, grant_id).unwrap();
            clock.tick();
            let confirmed = client.poll(&claimed).unwrap();
            debug.extend([
                format!("{confirmed:?}"),
                format!("{attempts:?}"),
                format!("{claimed:?}"),
                format!("{awaiting:?}"),
                format!("{approved:?}"),
                format!("{answer:?}"),
                format!("{:?}", answer.state),
                format!("{:?}", ClientError::OfferUnusable),
                format!("{:?}", PeerCode::Unauthorized),
                format!("{:?}", node.limiter),
                format!("{:?}", node.key),
                format!("{receiver:?}"),
                format!("{:?}", SystemClock),
                format!("{:?}", Deadline::after(LONG)),
                format!("{:?}", NoiseError::Io),
            ]);
            // A live session and a received request frame, which holds
            // the secret in its payload.
            let (listener, probe) = loopback();
            thread::scope(|scope| {
                let server = scope.spawn(|| {
                    let mut session =
                        noise::accept(listener.accept().unwrap().0, &node.key).unwrap();
                    let received = session
                        .receive(&MemoryLedger::default(), Deadline::after(LONG))
                        .unwrap();
                    assert!(contains(
                        &received.frame().payload,
                        hex_encode(&the_secret).as_bytes()
                    ));
                    (format!("{session:?}"), format!("{received:?}"))
                });
                let mut session =
                    noise::connect("127.0.0.1", probe, &receiver, &responder).unwrap();
                session
                    .send(
                        &frame(FrameKind::Request, REQUEST_ID, claim_json(1, &the_secret)),
                        Deadline::after(LONG),
                    )
                    .unwrap();
                let (session_debug, received_debug) = server.join().unwrap();
                debug.extend([format!("{session:?}"), session_debug, received_debug]);
            });
            let mut payloads = vec![
                ("message 1", up[..4 + MESSAGE1_LEN].to_vec()),
                ("message 2", down[..4 + MESSAGE2_LEN].to_vec()),
            ];
            let ask = |key: &StaticKey, payload: Vec<u8>| {
                clock.tick();
                raw(port, key, &responder, payload).payload
            };
            payloads.push(("grant active", ask(&receiver, grant_status_json(&grant_id))));
            // `busy`: the same static again without a tick, right after an
            // admitted request.
            payloads.push((
                "busy",
                raw(port, &receiver, &responder, claim_json(1, &the_secret)).payload,
            ));
            payloads.push((
                "claim unauthorized",
                ask(&receiver, claim_json(1, &the_secret)),
            ));
            payloads.push(("invalid", ask(&receiver, b"{}".to_vec())));
            payloads.push((
                "incompatible",
                ask(
                    &receiver,
                    json_bytes(json!({"grantId": hex_encode(&grant_id), "protocol": 2})),
                ),
            ));
            payloads.push(("claim response", claim_response));
            node.store
                .transition(|state| state.revoke_commit(grant_id, NOW * 1_000))
                .unwrap();
            payloads.push((
                "grant revoked",
                ask(&receiver, grant_status_json(&grant_id)),
            ));
            payloads
        });
        let labels: Vec<&str> = payloads.iter().map(|(label, _)| *label).collect();
        assert_eq!(
            labels,
            [
                "message 1",
                "message 2",
                "grant active",
                "busy",
                "claim unauthorized",
                "invalid",
                "incompatible",
                "claim response",
                "grant revoked"
            ]
        );
        for (label, payload) in &payloads {
            assert_no_secret(label, payload, &secrets);
        }
        assert_eq!(payloads[3].1, error_payload(5));
        for shown in &debug {
            assert_no_secret(shown, shown.as_bytes(), &secrets);
        }
    }

    /// Acceptance (12), on the wire: the same static within a second is
    /// `busy` and commits nothing; a second later the same claim commits.
    #[test]
    fn a_second_request_within_a_second_is_busy_and_commits_nothing() {
        let node = Node::new();
        node.offer(1, 600_000, NOW);
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let alice = StaticKey::generate().unwrap();
        let responder = *node.key.public();
        serve(&node.producer(&clock), |port| {
            let first = raw(port, &alice, &responder, pair_status_json(&[0xee; 16]));
            assert_eq!(first.payload, error_payload(2));
            let before = node.state_file();
            let busy = raw(port, &alice, &responder, claim_json(1, &secret(1)));
            assert_eq!(busy.payload, error_payload(5));
            assert_eq!(node.state_file(), before);
            clock.tick();
            body_of(&raw(port, &alice, &responder, claim_json(1, &secret(1))));
            assert_ne!(node.state_file(), before);
        });
    }

    /// Acceptance (13): both ends refuse pairing with themselves.
    #[test]
    fn self_pairing_is_refused_at_both_ends() {
        let node = Node::new();
        node.offer(1, 600_000, NOW);
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let ledger = MemoryLedger::default();
        let itself = PairingClient {
            identity: &node.key,
            ledger: &ledger,
            clock: &clock,
        };
        let responder = *node.key.public();
        let ((client, producer), accepted) = serve(&node.producer(&clock), |port| {
            let mut attempts = ClaimAttempts::default();
            let client = itself.claim(&node.pair_offer(1, port), &mut attempts);
            let producer = raw(port, &node.key, &responder, claim_json(1, &secret(1)));
            (client, producer)
        });
        assert_eq!(client, Err(ClientError::SelfPairing));
        assert_eq!(accepted.len(), 1, "the client never connected");
        assert_eq!(producer.payload, error_payload(2));
        assert!(node.store.state().unwrap().reference.pending.is_empty());
    }

    /// Acceptance (14): every mismatch in a reply frame stops the client.
    #[test]
    fn a_reply_that_breaks_the_protocol_aborts_the_client() {
        let fake_key = StaticKey::generate().unwrap();
        let receiver = StaticKey::generate().unwrap();
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let ledger = MemoryLedger::default();
        let client = PairingClient {
            identity: &receiver,
            ledger: &ledger,
            clock: &clock,
        };
        let pending_id = [0x21; 16];
        let grant_id = derive_grant_id(&pending_id);
        let awaiting = br#"{"protocol":1,"state":"awaiting"}"#.to_vec();
        let approved = |grant: &[u8; 16]| {
            json_bytes(json!({
                "authEpoch": 1, "expiresAt": 1, "grantId": hex_encode(grant),
                "protocol": 1, "sourceScopeGeneration": 1, "state": "approved",
            }))
        };
        let active = |grant: &[u8; 16]| {
            json_bytes(json!({
                "authEpoch": 1, "expiresAt": 1, "grantId": hex_encode(grant),
                "protocol": 1, "sourceScopeGeneration": 1, "state": "active",
            }))
        };
        type Reply = Box<dyn Fn(&Frame) -> Frame + Send + Sync>;
        let respond = |payload: Vec<u8>| -> Reply {
            Box::new(move |request: &Frame| {
                frame(FrameKind::Response, request.request_id, payload.clone())
            })
        };
        let error = |code: u16, protocol: u16| -> Reply {
            Box::new(move |request: &Frame| {
                frame(
                    FrameKind::Error,
                    request.request_id,
                    json_bytes(json!({"code": code, "protocol": protocol})),
                )
            })
        };
        let cases: Vec<(&str, bool, Reply)> = vec![
            (
                "request id",
                false,
                Box::new(|_: &Frame| {
                    frame(
                        FrameKind::Response,
                        [0; 16],
                        br#"{"protocol":1,"state":"awaiting"}"#.to_vec(),
                    )
                }),
            ),
            (
                "chunk count",
                false,
                Box::new(|request: &Frame| Frame {
                    kind: FrameKind::Response,
                    final_chunk: false,
                    request_id: request.request_id,
                    chunk_index: 0,
                    chunk_count: 2,
                    payload: br#"{"protocol":1,"state":"awaiting"}"#.to_vec(),
                }),
            ),
            ("approved grant id", false, respond(approved(&[0x99; 16]))),
            ("grant status grant id", true, respond(active(&[0x99; 16]))),
            ("pair status says active", false, respond(active(&grant_id))),
            (
                "grant status says approved",
                true,
                respond(approved(&grant_id)),
            ),
            ("code 3", false, error(3, 1)),
            ("code 4", false, error(4, 1)),
            ("code 7", false, error(7, 1)),
            ("error protocol", false, error(2, 2)),
            (
                "error request id",
                false,
                Box::new(|_: &Frame| frame(FrameKind::Error, [0; 16], error_payload(2))),
            ),
            (
                "request kind",
                false,
                Box::new(|request: &Frame| {
                    frame(
                        FrameKind::Request,
                        request.request_id,
                        br#"{"protocol":1,"state":"awaiting"}"#.to_vec(),
                    )
                }),
            ),
        ];
        for (label, grant, reply) in &cases {
            let (result, _) = fake(
                &fake_key,
                |_, request, _| Some(reply(request)),
                |port| {
                    let claimed = claimed_for(&fake_key, port, pending_id);
                    if *grant {
                        client.grant_status(&claimed, grant_id).map(|_| ())
                    } else {
                        client.pair_status(&claimed).map(|_| ())
                    }
                },
            );
            assert_eq!(result, Err(ClientError::Aborted), "{label}");
        }
        // Controls: well-formed replies are accepted.
        for (grant, reply) in [
            (false, respond(approved(&grant_id))),
            (true, respond(active(&grant_id))),
            (false, respond(awaiting.clone())),
        ] {
            let (result, _) = fake(
                &fake_key,
                |_, request, _| Some(reply(request)),
                |port| {
                    let claimed = claimed_for(&fake_key, port, pending_id);
                    if grant {
                        client.grant_status(&claimed, grant_id).map(|_| ())
                    } else {
                        client.pair_status(&claimed).map(|_| ())
                    }
                },
            );
            assert_eq!(result, Ok(()));
        }
        // A code outside {1,2,5,6,8} stops a poll too, after one request.
        let (result, count) = fake(
            &fake_key,
            |_, request, _| Some(error(7, 1)(request)),
            |port| client.poll(&claimed_for(&fake_key, port, pending_id)),
        );
        assert_eq!((result, count), (Err(ClientError::Aborted), 1));
    }

    /// Acceptance (15): a producer that keeps answering `awaiting` is
    /// polled 3 s apart until the 960 s window closes: 319 requests after
    /// the claim. (A real producer would answer `expired` once the offer's
    /// 900 s are up, so a scripted one holds the answer.) With a clock that
    /// never advances, the request cap stops polling at exactly 320.
    #[test]
    fn polling_stops_at_the_window_or_the_request_cap() {
        let fake_key = StaticKey::generate().unwrap();
        let receiver = StaticKey::generate().unwrap();
        let ledger = MemoryLedger::default();
        let awaiting = |request: &Frame| {
            frame(
                FrameKind::Response,
                request.request_id,
                br#"{"protocol":1,"state":"awaiting"}"#.to_vec(),
            )
        };

        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let client = PairingClient {
            identity: &receiver,
            ledger: &ledger,
            clock: &clock,
        };
        let (result, count) = fake(
            &fake_key,
            |_, request, _| Some(awaiting(request)),
            |port| client.poll(&claimed_for(&fake_key, port, [0x21; 16])),
        );
        assert_eq!((result, count), (Err(ClientError::PollLimit), 319));
        assert_eq!(*time.lock().unwrap(), Duration::from_secs(960));

        let time = Mutex::new(Duration::ZERO);
        let sleeps = AtomicUsize::new(0);
        let mut frozen = FakeClock::new(&time).hook(|_| {
            // Guard against a missing cap looping forever.
            assert!(
                sleeps.fetch_add(1, Ordering::SeqCst) < 400,
                "no request cap"
            );
        });
        frozen.frozen = true;
        let client = PairingClient {
            identity: &receiver,
            ledger: &ledger,
            clock: &frozen,
        };
        let (result, count) = fake(
            &fake_key,
            |_, request, _| Some(awaiting(request)),
            |port| client.poll(&claimed_for(&fake_key, port, [0x21; 16])),
        );
        assert_eq!((result, count), (Err(ClientError::PollLimit), 320));
        assert_eq!(*time.lock().unwrap(), Duration::ZERO);
    }

    /// Acceptance (15): a producer that never answers costs one poll its
    /// 15 s read deadline; the poll counts it and carries on.
    #[test]
    fn a_stuck_producer_times_out_one_poll_at_15_seconds() {
        let fake_key = StaticKey::generate().unwrap();
        let receiver = StaticKey::generate().unwrap();
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let ledger = MemoryLedger::default();
        let client = PairingClient {
            identity: &receiver,
            ledger: &ledger,
            clock: &clock,
        };
        let started = Instant::now();
        let (result, count) = fake(
            &fake_key,
            |n, request, _| {
                (n > 0).then(|| {
                    frame(
                        FrameKind::Response,
                        request.request_id,
                        br#"{"protocol":1,"state":"rejected"}"#.to_vec(),
                    )
                })
            },
            |port| client.poll(&claimed_for(&fake_key, port, [0x21; 16])),
        );
        let elapsed = started.elapsed();
        assert_eq!((result, count), (Err(ClientError::Rejected), 2));
        assert!(elapsed >= Duration::from_secs(15), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(25), "{elapsed:?}");
    }

    /// Acceptance (16): with sharing off, Pair claim and Pair status are
    /// `unauthorized` and no pending is created.
    #[test]
    fn with_sharing_off_claim_and_pair_status_are_unauthorized() {
        let node = Node::new();
        node.offer(1, 600_000, NOW);
        node.offer(2, 600_000, NOW);
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let alice = StaticKey::generate().unwrap();
        let responder = *node.key.public();
        serve(&node.producer(&clock), |port| {
            let pending_id = pending_of(&body_of(&raw(
                port,
                &alice,
                &responder,
                claim_json(1, &secret(1)),
            )));
            node.store.disable(NOW * 1_000).unwrap();
            clock.tick();
            let claim = raw(port, &alice, &responder, claim_json(2, &secret(2)));
            clock.tick();
            let status = raw(port, &alice, &responder, pair_status_json(&pending_id));
            assert_eq!(claim.payload, error_payload(2));
            assert_eq!(status.payload, error_payload(2));
            assert_eq!(node.store.state().unwrap().reference.pending.len(), 1);
        });
    }

    /// Acceptance (17): with the producer's ledger full, reading the
    /// request closes the connection with no frame; with the receiver's
    /// ledger full, the client reports a memory error. Both ledgers return
    /// to zero.
    #[test]
    fn a_full_ledger_closes_or_fails_and_returns_to_baseline() {
        let node = Node::new();
        let time = Mutex::new(Duration::ZERO);
        let clock = FakeClock::new(&time);
        let receiver = StaticKey::generate().unwrap();
        let ledger = MemoryLedger::default();
        let client = PairingClient {
            identity: &receiver,
            ledger: &ledger,
            clock: &clock,
        };
        serve(&node.producer(&clock), |port| {
            let claimed = claimed_for(&node.key, port, [0x21; 16]);
            let fill = node.ledger.reserve(REMOTE_MEMORY_MAX).unwrap();
            assert_eq!(
                client.pair_status(&claimed),
                Err(ClientError::Transport(NoiseError::Io))
            );
            assert_eq!(node.ledger.used(), REMOTE_MEMORY_MAX);
            drop(fill);
            assert_eq!(node.ledger.used(), 0);

            clock.tick();
            let fill = ledger.reserve(REMOTE_MEMORY_MAX).unwrap();
            assert_eq!(
                client.pair_status(&claimed),
                Err(ClientError::Transport(NoiseError::Memory))
            );
            drop(fill);
            assert_eq!(ledger.used(), 0);
            assert_eq!(node.ledger.used(), 0);

            // Control: with room, the same request is answered.
            clock.tick();
            assert_eq!(
                client.pair_status(&claimed),
                Err(ClientError::Code(PeerCode::Unauthorized))
            );
        });
    }

    #[test]
    fn grant_status_values_decode_only_from_their_wire_names() {
        for (name, state) in [
            ("active", GrantStatus::Active),
            ("revoked", GrantStatus::Revoked),
            ("expired", GrantStatus::Expired),
        ] {
            assert_eq!(
                serde_json::from_value::<GrantStatus>(json!(name)).unwrap(),
                state
            );
        }
        assert!(serde_json::from_value::<GrantStatus>(json!("approved")).is_err());
    }
}
