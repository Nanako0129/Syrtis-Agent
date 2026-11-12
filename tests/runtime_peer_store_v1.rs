//! SA-2B2a2 acceptance: the receiver peer store (`peers.json`) through the
//! public API.
//!
//! Codec and load-rule tests run on every platform. Tests that need a secure
//! root run on macOS and Linux only, because Windows fails closed
//! (`tests/runtime_storage_v1.rs`). The commit-failure test needs test-only
//! seams and lives in the unit tests of `src/peer_store.rs`.

use std::collections::BTreeSet;

use serde_json::Value;
use syrtis_agent::{
    canonical::CanonicalJsonV1,
    peer_store::{PEERS_MAX, PeerRecord, PeerState, decode_peers, encode_peers},
    secure_fs::StorageError,
};

const SPEC_V1: &str = include_str!("../spec/v1.md");

fn spec_fields(surface: &str) -> BTreeSet<&'static str> {
    let prefix = format!("| {surface} |");
    let row = SPEC_V1
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("spec/v1.md has no row {surface}"));
    row.split('|')
        .nth(2)
        .unwrap()
        .trim()
        .trim_matches('`')
        .split(',')
        .collect()
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

/// The `peers.json` key sets equal the two frozen `spec/v1.md` rows.
fn assert_frozen_keys(bytes: &[u8]) {
    let value = CanonicalJsonV1::decode_value(bytes).unwrap();
    assert_eq!(keys(&value), spec_fields("Receiver peer store top level"));
    let peers = value["peers"].as_array().unwrap();
    assert!(!peers.is_empty());
    for peer in peers {
        assert_eq!(keys(peer), spec_fields("Receiver peer record"));
    }
}

/// Producer `n` (its `responderStatic` is `[n; 32]`).
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

fn base() -> Value {
    let bytes = encode_peers(&[record(1), record(2)]).unwrap();
    CanonicalJsonV1::decode_value(&bytes).unwrap()
}

fn bytes_of(value: &Value) -> Vec<u8> {
    CanonicalJsonV1::encode(value).unwrap()
}

/// Every value encoding, and the key sets of `spec/v1.md`.
#[test]
fn the_codec_matches_the_spec_and_round_trips() {
    let peers = vec![
        PeerRecord {
            node_label: Some("studio-mac".into()),
            state: PeerState::Revoked,
            ..record(1)
        },
        PeerRecord {
            host: "nas.local".into(),
            state: PeerState::Expired,
            ..record(2)
        },
        record(3),
    ];
    let bytes = encode_peers(&peers).unwrap();
    assert_frozen_keys(&bytes);
    let value = CanonicalJsonV1::decode_value(&bytes).unwrap();
    assert_eq!(value["schema"], 1);
    assert_eq!(value["peers"][0]["responderStatic"], "01".repeat(32));
    assert_eq!(value["peers"][0]["grantId"], "01".repeat(16));
    assert_eq!(value["peers"][0]["pendingId"], "81".repeat(16));
    assert_eq!(value["peers"][0]["initiatorStatic"], "b2".repeat(32));
    assert_eq!(value["peers"][0]["createdAt"], 1_700_000_000_000_i64);
    assert_eq!(value["peers"][0]["nodeLabel"], "studio-mac");
    assert_eq!(value["peers"][1]["nodeLabel"], Value::Null);
    let states: Vec<&str> = (0..3)
        .map(|i| value["peers"][i]["state"].as_str().unwrap())
        .collect();
    assert_eq!(states, ["revoked", "expired", "active"]);
    assert!(!bytes.ends_with(b"\n"));
    assert_eq!(decode_peers(&bytes).unwrap(), peers);
    assert_eq!(decode_peers(br#"{"peers":[],"schema":1}"#).unwrap(), vec![]);
}

type Mutation = Box<dyn Fn(&mut Value)>;

fn set(path: &'static [&'static str], to: Value) -> Mutation {
    Box::new(move |value: &mut Value| {
        let mut at = value;
        for part in path {
            at = match part.parse::<usize>() {
                Ok(index) => &mut at[index],
                Err(_) => &mut at[*part],
            };
        }
        *at = to.clone();
    })
}

fn peers_of(n: usize) -> Mutation {
    Box::new(move |value: &mut Value| {
        let encoded = encode_peers(&(1..=n as u8).map(record).collect::<Vec<_>>()).unwrap();
        *value = CanonicalJsonV1::decode_value(&encoded).unwrap();
    })
}

/// Acceptance (2): each load rule refuses one file that breaks only it,
/// with the specified error, and accepts a control that differs from that
/// file only in the broken point.
#[test]
fn every_load_rule_fails_closed_and_its_control_loads() {
    use StorageError::{Corrupt, Incompatible};
    let hex = |byte: &str, len: usize| Value::from(byte.repeat(len));
    let cases: Vec<(&str, StorageError, Mutation, Mutation)> = vec![
        (
            "schema 2",
            Incompatible,
            set(&["schema"], 2.into()),
            set(&["schema"], 1.into()),
        ),
        (
            "schema 0",
            Incompatible,
            set(&["schema"], 0.into()),
            set(&["schema"], 1.into()),
        ),
        (
            "schema not an integer",
            Corrupt,
            set(&["schema"], "1".into()),
            set(&["schema"], 1.into()),
        ),
        (
            "unknown top-level key",
            Corrupt,
            Box::new(|v| {
                v["zzz"] = 1.into();
            }),
            Box::new(|_| {}),
        ),
        (
            "unknown record key",
            Corrupt,
            Box::new(|v| {
                v["peers"][0]["zzz"] = 1.into();
            }),
            Box::new(|_| {}),
        ),
        (
            "missing record key",
            Corrupt,
            Box::new(|v| {
                v["peers"][0].as_object_mut().unwrap().remove("nodeLabel");
            }),
            set(&["peers", "0", "nodeLabel"], Value::Null),
        ),
        (
            "missing schema",
            Corrupt,
            Box::new(|v| {
                v.as_object_mut().unwrap().remove("schema");
            }),
            Box::new(|_| {}),
        ),
        (
            "null required field",
            Corrupt,
            set(&["peers", "0", "authEpoch"], Value::Null),
            set(&["peers", "0", "authEpoch"], 7.into()),
        ),
        (
            "17 peers",
            Corrupt,
            peers_of(PEERS_MAX + 1),
            peers_of(PEERS_MAX),
        ),
        (
            "duplicate responderStatic",
            Corrupt,
            set(&["peers", "1", "responderStatic"], hex("01", 32)),
            set(&["peers", "1", "responderStatic"], hex("02", 32)),
        ),
        (
            "unsorted responderStatic",
            Corrupt,
            set(&["peers", "0", "responderStatic"], hex("03", 32)),
            set(&["peers", "1", "responderStatic"], hex("03", 32)),
        ),
        (
            "short responderStatic",
            Corrupt,
            set(&["peers", "0", "responderStatic"], hex("01", 31)),
            set(&["peers", "0", "responderStatic"], hex("01", 32)),
        ),
        (
            "long initiatorStatic",
            Corrupt,
            set(&["peers", "0", "initiatorStatic"], hex("b2", 33)),
            set(&["peers", "0", "initiatorStatic"], hex("b2", 32)),
        ),
        (
            "short grantId",
            Corrupt,
            set(&["peers", "0", "grantId"], hex("01", 15)),
            set(&["peers", "0", "grantId"], hex("01", 16)),
        ),
        (
            "uppercase pendingId",
            Corrupt,
            set(&["peers", "0", "pendingId"], hex("AB", 16)),
            set(&["peers", "0", "pendingId"], hex("ab", 16)),
        ),
        (
            "uppercase host",
            Corrupt,
            set(&["peers", "0", "host"], "Studio.local".into()),
            set(&["peers", "0", "host"], "studio.local".into()),
        ),
        (
            "non-canonical IPv4 host",
            Corrupt,
            set(&["peers", "0", "host"], "127.0.0.01".into()),
            set(&["peers", "0", "host"], "127.0.0.1".into()),
        ),
        (
            "non-canonical IPv6 host",
            Corrupt,
            set(&["peers", "0", "host"], "0:0:0:0:0:0:0:1".into()),
            set(&["peers", "0", "host"], "::1".into()),
        ),
        (
            "empty host",
            Corrupt,
            set(&["peers", "0", "host"], "".into()),
            set(&["peers", "0", "host"], "a".into()),
        ),
        (
            "port 1023",
            Corrupt,
            set(&["peers", "0", "port"], 1023.into()),
            set(&["peers", "0", "port"], 1024.into()),
        ),
        (
            "port above 65535",
            Corrupt,
            set(&["peers", "0", "port"], 65_536.into()),
            set(&["peers", "0", "port"], 65_535.into()),
        ),
        (
            "nodeLabel 129 bytes",
            Corrupt,
            set(&["peers", "0", "nodeLabel"], "x".repeat(129).into()),
            set(&["peers", "0", "nodeLabel"], "x".repeat(128).into()),
        ),
        (
            "state outside the three",
            Corrupt,
            set(&["peers", "0", "state"], "approved".into()),
            set(&["peers", "0", "state"], "expired".into()),
        ),
    ];
    for (label, error, bad, control) in &cases {
        let mut value = base();
        bad(&mut value);
        assert_eq!(decode_peers(&bytes_of(&value)), Err(*error), "{label}");
        let mut value = base();
        control(&mut value);
        assert!(decode_peers(&bytes_of(&value)).is_ok(), "control {label}");
    }

    // Byte-level rules: CanonicalJsonV1 form and NFC.
    let canonical = bytes_of(&base());
    let mut spaced = canonical.clone();
    spaced.insert(1, b' ');
    assert_eq!(decode_peers(&spaced), Err(Corrupt), "whitespace");
    let mut newline = canonical.clone();
    newline.push(b'\n');
    assert_eq!(decode_peers(&newline), Err(Corrupt), "trailing newline");
    assert!(decode_peers(&canonical).is_ok(), "control canonical");
    let label = |text: &str| {
        let mut value = base();
        value["peers"][0]["nodeLabel"] = text.into();
        serde_json::to_vec(&value).unwrap()
    };
    assert_eq!(decode_peers(&label("e\u{301}")), Err(Corrupt), "non-NFC");
    assert!(decode_peers(&label("\u{e9}")).is_ok(), "control NFC");
    // The read bound, also applied by the decoder.
    assert_eq!(decode_peers(&vec![b' '; 1024 * 1024 + 1]), Err(Corrupt));
    // `expiresAt` is the producer's clock, `createdAt` the receiver's: an
    // expiry before the creation is not compared, so it loads.
    let mut value = base();
    value["peers"][0]["expiresAt"] = 1.into();
    assert!(decode_peers(&bytes_of(&value)).is_ok());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod disk {
    use std::{
        net::{TcpListener, TcpStream},
        os::unix::fs::PermissionsExt,
        panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
        path::{Path, PathBuf},
        process::Command,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    use syrtis_agent::{
        noise::StaticKey,
        pairing::{
            ClaimAttempts, Clock, ConfirmedGrant, PairingClient, Producer, RateLimiter, approve,
        },
        peer_store::{PeerStore, usable},
        report_peer::{NoSource, Reports},
        secure_fs::SecureRoot,
        security::{
            MemoryLedger, Offer, OfferState, PairOffer, hex_encode, offer_secret_hash, pair_url,
        },
        state_store::StateStore,
    };

    use super::*;

    const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];
    const NOW: i64 = 1_700_000_000;
    const OFFER: [u8; 16] = [0x0f; 16];
    const SECRET: [u8; 32] = [0x5e; 32];

    struct TempHome {
        path: PathBuf,
    }

    impl TempHome {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "syrtis-agent-peers-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }

        fn peers_file(&self) -> PathBuf {
            SUFFIX
                .iter()
                .fold(self.path.clone(), |path, part| path.join(part))
                .join("peers.json")
        }

        fn read_peers(&self) -> Vec<u8> {
            std::fs::read(self.peers_file()).unwrap()
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Retries only `Busy`, for about 2 s: a fork-to-exec child of this
    /// binary can still hold a lock this process just released.
    fn retry_busy<T>(mut f: impl FnMut() -> Result<T, StorageError>) -> Result<T, StorageError> {
        for _ in 0..200 {
            match f() {
                Err(StorageError::Busy) => thread::sleep(Duration::from_millis(10)),
                other => return other,
            }
        }
        f()
    }

    fn open_state(home: &Path) -> StateStore {
        retry_busy(|| StateStore::open(SecureRoot::open_under(home, SUFFIX)?, NOW)).unwrap()
    }

    /// The state store and the peer store on one root.
    fn open_both(home: &Path) -> (StateStore, PeerStore) {
        let state = open_state(home);
        let peers = PeerStore::open(state.root()).unwrap();
        (state, peers)
    }

    /// Re-runs this binary as a separate process that tries to take the
    /// root's lock once, and returns what it printed.
    fn child_lock(home: &Path) -> String {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "disk::child_process_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SYRTIS_PEERS_CHILD", "lock")
            .env("SYRTIS_PEERS_HOME", home)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(output.status.success(), "{stdout}");
        let start = stdout.find("LOCK:").unwrap_or_else(|| panic!("{stdout}")) + 5;
        stdout[start..].lines().next().unwrap_or("").to_owned()
    }

    /// The child side of `child_lock`. A no-op in a normal test run.
    #[test]
    fn child_process_entry() {
        let Ok(mode) = std::env::var("SYRTIS_PEERS_CHILD") else {
            return;
        };
        let home = PathBuf::from(std::env::var("SYRTIS_PEERS_HOME").unwrap());
        assert_eq!(mode, "lock");
        let result = SecureRoot::open_under(&home, SUFFIX).map(|_| ());
        println!("LOCK:{result:?}");
    }

    /// Fake time shared by both ends: `sleep` advances it.
    struct FakeClock(Mutex<Duration>);

    impl Clock for FakeClock {
        fn monotonic(&self) -> Duration {
            *self.0.lock().unwrap()
        }
        fn os_now_seconds(&self) -> Result<i64, StorageError> {
            Ok(NOW + self.monotonic().as_secs() as i64)
        }
        fn sleep(&self, duration: Duration) {
            *self.0.lock().unwrap() += duration;
        }
    }

    /// Serves connections with `producer` on a loopback port while `body`
    /// runs.
    fn serve<R>(producer: &Producer<'_>, body: impl FnOnce(u16) -> R) -> R {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = AtomicBool::new(false);
        let result = thread::scope(|scope| {
            scope.spawn(|| {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        producer.serve(stream);
                    }
                }
            });
            let result = catch_unwind(AssertUnwindSafe(|| body(port)));
            stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(("127.0.0.1", port));
            result
        });
        result.unwrap_or_else(|panic| resume_unwind(panic))
    }

    /// Two agents on two temp roots pair over loopback: the producer
    /// creates an offer, the receiver claims it from the Pair URL, the
    /// owner approves, and the receiver polls to a confirmed grant.
    /// Returns the receiver's confirmed grant and the claimed host and port.
    fn pair(producer_home: &Path, receiver: &StateStore) -> (ConfirmedGrant, String, u16) {
        let producer_store = open_state(producer_home);
        producer_store
            .transition(|state| state.enable_sharing())
            .unwrap();
        let producer_key = StaticKey::from_state(&producer_store.state().unwrap()).unwrap();
        let responder = *producer_key.public();
        let expires_at = NOW * 1_000 + 600_000;
        producer_store
            .transition(|state| {
                state.create_offer(
                    Offer {
                        offer_id: OFFER,
                        secret_hash: offer_secret_hash(&OFFER, &SECRET, &responder),
                        created_at_ms: NOW * 1_000,
                        expires_at_ms: expires_at,
                        state: OfferState::Active,
                    },
                    NOW,
                )
            })
            .unwrap();
        let clock = FakeClock(Mutex::new(Duration::ZERO));
        let (ledger, receiver_ledger) = (MemoryLedger::default(), MemoryLedger::default());
        let limiter = RateLimiter::default();
        let reports = Reports::new(Arc::new(NoSource));
        let producer = Producer {
            store: &producer_store,
            identity: &producer_key,
            ledger: &ledger,
            limiter: &limiter,
            clock: &clock,
            reports: &reports,
        };
        let receiver_key = StaticKey::from_state(&receiver.state().unwrap()).unwrap();
        let client = PairingClient {
            identity: &receiver_key,
            ledger: &receiver_ledger,
            clock: &clock,
        };
        serve(&producer, |port| {
            let url = pair_url(&PairOffer {
                expires_at,
                host: "127.0.0.1".into(),
                offer_id: hex_encode(&OFFER),
                port,
                responder_static: hex_encode(&responder),
                secret: hex_encode(&SECRET),
                version: 1,
            })
            .unwrap();
            let mut attempts = ClaimAttempts::default();
            let claimed = client.claim(&url, NOW * 1_000, &mut attempts).unwrap();
            approve(
                &producer_store,
                claimed.pending_id,
                1,
                true,
                clock.os_now_seconds().unwrap(),
            )
            .unwrap();
            let confirmed = client.poll(&claimed).unwrap();
            (confirmed, claimed.host, claimed.port)
        })
    }

    /// Acceptance (1): pairing two temp-root agents, then `upsert` from the
    /// confirmed grant, writes one `active` record whose keys equal the two
    /// `spec/v1.md` rows; reopening the root and the store reads back the
    /// same record, and its encoding is bit-identical to the file.
    #[test]
    fn a_confirmed_grant_is_stored_and_reads_back_bit_for_bit() {
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let (store, peers) = open_both(&receiver_home.path);
        assert_eq!(peers.peers().unwrap(), vec![]);
        assert!(!receiver_home.peers_file().exists(), "absent until a write");
        let (confirmed, host, port) = pair(&producer_home.path, &store);
        let record = PeerRecord::from_confirmed(
            &confirmed,
            host,
            port,
            Some("studio-mac".into()),
            NOW * 1_000 + 9,
        );
        assert_eq!(record.state, PeerState::Active);
        assert_eq!(record.grant_id, confirmed.grant_id);
        assert_eq!(record.responder_static, confirmed.responder_static);
        assert_eq!(record.initiator_static, confirmed.initiator_static);
        peers.upsert(record.clone()).unwrap();
        let file = receiver_home.read_peers();
        assert_frozen_keys(&file);
        let mode = std::fs::metadata(receiver_home.peers_file())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        drop((store, peers));

        let (store, peers) = open_both(&receiver_home.path);
        let read = peers.peers().unwrap();
        assert_eq!(read, vec![record]);
        assert_eq!(encode_peers(&read).unwrap(), file);
        assert!(usable(&read[0], &store));
    }

    /// Acceptance (2), on disk: a file load refuses fails `open` closed
    /// (`Corrupt`, `Incompatible`), and a stale temp file is removed.
    #[test]
    fn an_unreadable_peers_file_fails_open_closed() {
        let home = TempHome::new();
        drop(open_state(&home.path));
        for (bytes, error) in [
            (
                br#"{"peers":[],"schema":2}"#.to_vec(),
                StorageError::Incompatible,
            ),
            (
                br#"{"peers":[], "schema":1}"#.to_vec(),
                StorageError::Corrupt,
            ),
            (b"[]".to_vec(), StorageError::Corrupt),
        ] {
            std::fs::write(home.peers_file(), &bytes).unwrap();
            std::fs::set_permissions(home.peers_file(), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            let state = open_state(&home.path);
            assert_eq!(PeerStore::open(state.root()).err(), Some(error));
        }
        // Control: the canonical empty list loads; a stale temp goes.
        std::fs::write(home.peers_file(), br#"{"peers":[],"schema":1}"#).unwrap();
        let temp = home.peers_file().with_file_name(".peers.json.tmp");
        std::fs::write(&temp, b"partial").unwrap();
        let (_state, peers) = open_both(&home.path);
        assert_eq!(peers.peers().unwrap(), vec![]);
        assert!(!temp.exists());
    }

    /// Acceptance (3): a 17th producer is `Refused(Bounds)`; a record load
    /// would refuse is `Refused(Invalid)`; both leave the file bit-identical
    /// and the store still reopens. The same producer again replaces its
    /// record. `set_state` and `remove` change only their producer.
    #[test]
    fn refused_writes_change_nothing_and_a_repairing_replaces() {
        use syrtis_agent::security::SecurityError::{Bounds, Invalid};
        let home = TempHome::new();
        let (_state, peers) = open_both(&home.path);
        for n in 1..=PEERS_MAX as u8 {
            peers.upsert(record(n)).unwrap();
        }
        let full = home.read_peers();
        let refusals = [
            (record(17), Bounds),
            (
                PeerRecord {
                    node_label: Some("x".repeat(129)),
                    ..record(1)
                },
                Invalid,
            ),
            (
                PeerRecord {
                    node_label: Some("e\u{301}".into()),
                    ..record(1)
                },
                Invalid,
            ),
            (
                PeerRecord {
                    host: "Studio.local".into(),
                    ..record(1)
                },
                Invalid,
            ),
            (
                PeerRecord {
                    port: 1023,
                    ..record(1)
                },
                Invalid,
            ),
            (
                PeerRecord {
                    state: PeerState::Revoked,
                    ..record(1)
                },
                Invalid,
            ),
        ];
        for (refused, error) in refusals {
            let label = format!("{refused:?}");
            assert_eq!(
                peers.upsert(refused),
                Err(StorageError::Refused(error)),
                "{label}"
            );
            assert_eq!(home.read_peers(), full, "{label}");
            // Not sticky: the store still reads.
            assert_eq!(peers.peers().unwrap().len(), PEERS_MAX, "{label}");
        }
        assert_eq!(
            peers.set_state(&[1; 32], PeerState::Active),
            Err(StorageError::Refused(Invalid))
        );
        assert_eq!(
            peers.set_state(&[99; 32], PeerState::Revoked),
            Err(StorageError::Refused(Invalid))
        );
        assert_eq!(home.read_peers(), full);

        // The same producer re-paired: replaced, still 16.
        let repaired = PeerRecord {
            auth_epoch: 5,
            grant_id: [0xee; 16],
            node_label: Some("x".repeat(128)),
            ..record(1)
        };
        peers.upsert(repaired.clone()).unwrap();
        let now = peers.peers().unwrap();
        assert_eq!(now.len(), PEERS_MAX);
        assert_eq!(now[0], repaired);
        assert_eq!(
            now[1..],
            (2..=PEERS_MAX as u8).map(record).collect::<Vec<_>>()[..]
        );

        peers.set_state(&[2; 32], PeerState::Revoked).unwrap();
        peers.set_state(&[3; 32], PeerState::Expired).unwrap();
        peers.remove(&[4; 32]).unwrap();
        peers.remove(&[4; 32]).unwrap();
        drop((_state, peers));
        let (_state, peers) = open_both(&home.path);
        let reread = peers.peers().unwrap();
        assert_eq!(reread.len(), PEERS_MAX - 1);
        assert_eq!(reread[0], repaired);
        assert_eq!(reread[1].state, PeerState::Revoked);
        assert_eq!(reread[2].state, PeerState::Expired);
        assert_eq!(reread[3], record(5));
    }

    /// Acceptance (5): `usable` is false for `revoked` and `expired`, and
    /// false after the receiver's reset, because it reads the identity
    /// from the state store on every call.
    #[test]
    fn usable_needs_active_and_the_current_identity() {
        let (producer_home, receiver_home) = (TempHome::new(), TempHome::new());
        let (store, peers) = open_both(&receiver_home.path);
        let (confirmed, host, port) = pair(&producer_home.path, &store);
        let record = PeerRecord::from_confirmed(&confirmed, host, port, None, NOW * 1_000);
        peers.upsert(record.clone()).unwrap();
        assert!(usable(&record, &store), "control: active and bound");
        for state in [PeerState::Revoked, PeerState::Expired] {
            assert!(!usable(
                &PeerRecord {
                    state,
                    ..record.clone()
                },
                &store
            ));
        }
        store.reset(NOW + 10, (NOW + 10) * 1_000).unwrap();
        let after = peers.peers().unwrap();
        assert_eq!(after, vec![record.clone()], "reset leaves peers.json alone");
        assert!(!usable(&after[0], &store), "the identity changed");
        // Control: a record bound to the new identity is usable.
        let new_identity = store.state().unwrap().identity_public().unwrap();
        let rebound = PeerRecord {
            initiator_static: new_identity,
            ..record
        };
        assert!(usable(&rebound, &store));
    }

    /// Acceptance (6): `peers.json` sits under the same owner lock as
    /// `state.json`. While either store holds the root (the peer store
    /// alone keeps it open after the state store is dropped), a second
    /// process gets `Busy`; once both are dropped it can take the lock.
    #[test]
    fn the_peer_store_shares_the_state_store_lock() {
        let home = TempHome::new();
        let (state, peers) = open_both(&home.path);
        peers.upsert(record(1)).unwrap();
        assert_eq!(child_lock(&home.path), "Err(Busy)");
        drop(state);
        assert_eq!(
            child_lock(&home.path),
            "Err(Busy)",
            "the peer store holds it"
        );
        drop(peers);
        let free = retry_busy(|| SecureRoot::open_under(&home.path, SUFFIX).map(|_| ()));
        assert_eq!(free, Ok(()), "control: the lock is free once both are gone");
    }
}
