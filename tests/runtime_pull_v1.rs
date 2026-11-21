//! SA-2B3b acceptance: the receiver side of the runtime (`Runtime::pull`,
//! `Runtime::last_good`, the receiver cache in housekeeping) and the
//! listener items (`spec/runtime-v1.md`), through the public API with two
//! runtimes paired over loopback in temp roots.
//!
//! macOS, Linux and Windows (`W3b`; a secure root is needed). Control
//! commands go over the control socket on macOS and Linux and through
//! `Runtime::control` on Windows, which has no socket. The symlinked cache
//! file test stays Unix-only. Acceptance (3c) needs a failure seam and is a
//! unit test in `src/runtime.rs`.

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
mod support;

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
mod disk {
    #[cfg(not(windows))]
    use std::os::unix::fs::symlink;
    use std::{
        fs,
        io::{ErrorKind, Read},
        net::{TcpListener, TcpStream},
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicI64, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use serde_json::{Value, json};
    #[cfg(not(windows))]
    use syrtis_agent::{control::Client, state_store::Secret32};
    use syrtis_agent::{
        control::{Command, LISTEN_CONFIGURE, OFFER_CREATE, OK, REVOKE},
        noise::StaticKey,
        pairing::{ClaimAttempts, Clock, PairingClient, approve, derive_grant_id},
        peer_store::{PeerRecord, PeerState},
        report::{AgentsRecord, Endpoint, ReportRequest, ReportResponse, encode_response},
        report_peer::{FetchError, ReportQuery, ReportSource, SourceError},
        runtime::{Options, PullError, Runtime, RuntimeError},
        secure_fs::{SecureRoot, StorageError},
        security::{MemoryLedger, PendingApproval, hex_encode},
    };

    const NOW: i64 = 1_700_000_000;
    const NOW_MS: i64 = NOW * 1_000;
    const SUFFIX: &[&str] = &["r"];
    const LOOPBACK: &str = "127.0.0.1";
    /// A housekeeping period short enough to drive rounds from a test.
    const FAST: Duration = Duration::from_millis(50);
    const SLOW: Duration = Duration::from_secs(60);

    /// Injected time; `sleep` advances both clocks at once.
    struct TestClock {
        os: AtomicI64,
        mono: Mutex<Duration>,
    }

    impl TestClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                os: AtomicI64::new(NOW),
                mono: Mutex::new(Duration::ZERO),
            })
        }

        fn set_os(&self, seconds: i64) {
            self.os.store(seconds, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn monotonic(&self) -> Duration {
            *self.mono.lock().unwrap()
        }

        fn os_now_seconds(&self) -> Result<i64, StorageError> {
            Ok(self.os.load(Ordering::SeqCst))
        }

        fn sleep(&self, duration: Duration) {
            *self.mono.lock().unwrap() += duration;
            self.os
                .fetch_add(duration.as_secs() as i64, Ordering::SeqCst);
        }
    }

    /// A short temporary home (`support::new_home`); only what this helper
    /// created is removed.
    struct TempHome(PathBuf);

    impl TempHome {
        fn new() -> Self {
            Self(super::support::new_home("sp"))
        }

        fn root(&self) -> PathBuf {
            self.0.join(SUFFIX[0])
        }

        /// The receiver cache files in the root.
        fn rcache(&self) -> Vec<PathBuf> {
            let mut files: Vec<_> = fs::read_dir(self.root())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("rcache-")
                })
                .collect();
            files.sort();
            files
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// An agents report with the fixture's records, echoing the request,
    /// with the label the producer passes (as `EngineSource` does).
    struct Stub;

    impl ReportSource for Stub {
        fn report(
            &self,
            request: &ReportRequest,
            node_label: Option<&str>,
            _: Instant,
        ) -> Result<Vec<u8>, SourceError> {
            let bytes: &[u8] = include_bytes!("fixtures/v1/report/agents.json");
            let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
            let records = syrtis_agent::report::decode_response::<AgentsRecord>(bytes, None)
                .map_err(|_| SourceError)?
                .records;
            encode_response(&ReportResponse {
                node_label: node_label.map(str::to_owned),
                ..ReportResponse::from_request(request, records, false)
            })
            .map_err(|_| SourceError)
        }
    }

    /// A runtime on its own home. Field order is drop order.
    struct Node {
        runtime: Runtime,
        clock: Arc<TestClock>,
        home: TempHome,
    }

    impl Node {
        fn new(period: Duration) -> Self {
            Self::start(TempHome::new(), TestClock::new(), period).unwrap()
        }

        fn start(
            home: TempHome,
            clock: Arc<TestClock>,
            period: Duration,
        ) -> Result<Self, RuntimeError> {
            let options = Options {
                clock: Arc::clone(&clock) as Arc<dyn Clock>,
                housekeeping_period: period,
            };
            let mut tries = 0;
            let runtime = loop {
                let root = SecureRoot::open_under(&home.0, SUFFIX).map_err(RuntimeError::Store);
                match root.and_then(|root| Runtime::start(root, Arc::new(Stub), options.clone())) {
                    // A reopen can briefly see the lock (`secure_fs`).
                    Err(RuntimeError::Store(StorageError::Busy)) if tries < 200 => {
                        tries += 1;
                        thread::sleep(Duration::from_millis(10));
                    }
                    other => break other?,
                }
            };
            Ok(Self {
                runtime,
                clock,
                home,
            })
        }

        /// Stops the runtime and starts a new one on the same home.
        fn restart(self, period: Duration) -> Self {
            let Self {
                runtime,
                clock,
                home,
            } = self;
            drop(runtime);
            Self::start(home, clock, period).unwrap()
        }

        /// A control command: over the socket, or in-process on Windows.
        fn call(&self, id: u16, body: Value) -> Value {
            #[cfg(not(windows))]
            let reply = {
                let token = *self.runtime.store().state().unwrap().control_token.expose();
                Client::new(
                    Secret32::new(token),
                    self.runtime.socket_path().to_path_buf(),
                )
                .call(&Command { id, body })
                .unwrap()
            };
            #[cfg(windows)]
            let reply = self.runtime.control(&Command { id, body }).unwrap();
            assert_eq!(reply.code, OK);
            reply.data
        }

        fn configure(&self, port: u16) {
            self.call(
                LISTEN_CONFIGURE,
                json!({"bindHost": LOOPBACK, "bindPort": port}),
            );
        }
    }

    /// A paired producer and receiver.
    struct Pair {
        receiver: Node,
        producer: Node,
        producer_static: [u8; 32],
        grant_id: [u8; 16],
    }

    /// Pairs a fresh receiver with a fresh producer over loopback. With
    /// `grant_expires_at_ms` the producer approves directly with that
    /// expiry; otherwise through the normal approval (100 years).
    fn pair(grant_expires_at_ms: Option<i64>, receiver_period: Duration) -> Pair {
        let producer = Node::new(SLOW);
        producer.configure(free_port());
        producer.runtime.enable_sharing().unwrap();
        let url = producer.call(OFFER_CREATE, json!({"ttlSeconds": 600}))["pairUrl"]
            .as_str()
            .unwrap()
            .to_owned();
        let receiver = Node::new(receiver_period);
        let identity = StaticKey::from_state(&receiver.runtime.store().state().unwrap()).unwrap();
        let ledger = MemoryLedger::default();
        let client = PairingClient {
            identity: &identity,
            ledger: &ledger,
            clock: &*producer.clock,
        };
        let claimed = client
            .claim(&url, NOW_MS, &mut ClaimAttempts::default())
            .unwrap();
        let store = producer.runtime.store();
        match grant_expires_at_ms {
            None => {
                approve(store, claimed.pending_id, 1, true, NOW).unwrap();
            }
            Some(expires_at_ms) => {
                let responder = store.state().unwrap().identity_public().unwrap();
                store
                    .transition(|state| {
                        state.approve_pending(
                            PendingApproval {
                                pending_id: claimed.pending_id,
                                sas_generation: 1,
                                grant_id: derive_grant_id(&claimed.pending_id),
                                responder_static: responder,
                                grant_expires_at_ms: expires_at_ms,
                                disclosure_exact: true,
                            },
                            NOW,
                        )
                    })
                    .unwrap();
            }
        }
        let confirmed = client.poll(&claimed).unwrap();
        receiver
            .runtime
            .peers()
            .upsert(PeerRecord::from_confirmed(&confirmed, None, NOW_MS))
            .unwrap();
        Pair {
            producer_static: confirmed.responder_static,
            grant_id: confirmed.grant_id,
            receiver,
            producer,
        }
    }

    impl Pair {
        fn pull(&self) -> Result<Vec<u8>, PullError> {
            self.receiver
                .runtime
                .pull(&self.producer_static, &query())
                .map(|fetched| fetched.body)
        }

        fn last_good(&self) -> Option<Vec<u8>> {
            self.receiver
                .runtime
                .last_good(&self.producer_static, &query())
                .unwrap()
                .map(|cached| cached.body().to_vec())
        }

        fn peer_state(&self) -> PeerState {
            self.receiver.runtime.peers().peers().unwrap()[0].state
        }
    }

    fn query() -> ReportQuery {
        ReportQuery {
            endpoint: Endpoint::Agents,
            start_date: "2025-01-01".into(),
            end_date_exclusive: "2025-02-01".into(),
            timezone: "America/Los_Angeles".into(),
            clients: vec!["claude".into(), "codex".into()],
        }
    }

    fn free_port() -> u16 {
        TcpListener::bind((LOOPBACK, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// Polls `check` every 10 ms for up to 5 s.
    fn eventually(what: &str, mut check: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !check() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    // ------------------------------------------------------------- tests

    /// Acceptance (1): `pull` returns the report and writes one receiver
    /// cache entry; with the producer gone, `last_good` returns the same
    /// bytes.
    #[test]
    fn a_pulled_report_is_the_last_good_after_the_producer_stops() {
        let pair = pair(None, SLOW);
        let body = pair.pull().unwrap();
        assert_eq!(pair.receiver.home.rcache().len(), 1);
        let Pair {
            receiver,
            producer,
            producer_static,
            ..
        } = pair;
        drop(producer);
        let cached = receiver
            .runtime
            .last_good(&producer_static, &query())
            .unwrap()
            .unwrap();
        assert_eq!(cached.body(), body.as_slice());
    }

    /// DR-2b: a successful pull carries the producer's stored label and
    /// `costIncomplete`, stores the label on the peer record (and only on a
    /// change: the same label leaves `peers.json` unreplaced), and from then
    /// on `ever_answered` is true. A label the producer clears is cleared.
    /// Removing the producer ends `ever_answered`.
    #[test]
    fn a_pull_stores_the_producers_label_and_marks_it_answered() {
        let pair = pair(None, SLOW);
        let runtime = &pair.receiver.runtime;
        let label = |label: Option<&str>| {
            let store = pair.producer.runtime.store();
            let config = store.state().unwrap().config;
            store
                .set_listen_config(config.bind_host, config.bind_port, label.map(str::to_owned))
                .unwrap();
        };
        let record = || runtime.peers().peers().unwrap()[0].clone();
        // Which file `peers.json` is: its inode; Windows, where std has
        // no stable file ID, its last write time (a replace writes a new
        // temp file and renames it over the name).
        let peers_file = || {
            let metadata = fs::metadata(pair.receiver.home.root().join("peers.json")).unwrap();
            #[cfg(not(windows))]
            return std::os::unix::fs::MetadataExt::ino(&metadata) as u128;
            #[cfg(windows)]
            return std::os::windows::fs::MetadataExt::last_write_time(&metadata) as u128;
        };
        assert!(!runtime.ever_answered(&pair.producer_static));
        let before = record();

        label(Some("Studio Mac"));
        let fetched = runtime.pull(&pair.producer_static, &query()).unwrap();
        assert_eq!(fetched.node_label.as_deref(), Some("Studio Mac"));
        assert!(!fetched.cost_incomplete);
        assert_eq!(
            record(),
            PeerRecord {
                node_label: Some("Studio Mac".into()),
                ..before.clone()
            }
        );
        assert!(runtime.ever_answered(&pair.producer_static));
        assert!(!runtime.ever_answered(&[0x5a; 32]));

        // The same label: nothing written. (The producer's rate tokens
        // refill on its monotonic clock.)
        let file = peers_file();
        pair.producer.clock.sleep(Duration::from_secs(60));
        runtime.pull(&pair.producer_static, &query()).unwrap();
        assert_eq!(peers_file(), file, "an unchanged label rewrote peers.json");

        label(None);
        pair.producer.clock.sleep(Duration::from_secs(60));
        let fetched = runtime.pull(&pair.producer_static, &query()).unwrap();
        assert_eq!(fetched.node_label, None);
        assert_eq!(record(), before);

        runtime.remove_peer(&pair.producer_static).unwrap();
        assert!(!runtime.ever_answered(&pair.producer_static));
    }

    /// `SA-3e`: `remove_peer` deletes the producer's record and its cache
    /// file at once, not at expiry.
    #[test]
    fn remove_peer_deletes_the_record_and_its_cache() {
        let pair = pair(None, SLOW);
        pair.pull().unwrap();
        assert_eq!(pair.receiver.home.rcache().len(), 1);
        pair.receiver
            .runtime
            .remove_peer(&pair.producer_static)
            .unwrap();
        assert!(pair.receiver.home.rcache().is_empty());
        assert!(pair.receiver.runtime.peers().peers().unwrap().is_empty());
        assert_eq!(pair.last_good(), None);
    }

    /// `SA-3e`: removing a producer that is not there is `Ok` and leaves
    /// another producer's entry; entries left under a key whose record is
    /// already gone are still deleted.
    #[test]
    fn removing_an_absent_peer_leaves_other_entries() {
        let pair = pair(None, SLOW);
        pair.pull().unwrap();
        let files = pair.receiver.home.rcache();
        assert_eq!(files.len(), 1);
        pair.receiver.runtime.remove_peer(&[0x5a; 32]).unwrap();
        assert_eq!(pair.receiver.home.rcache(), files);
        assert_eq!(pair.receiver.runtime.peers().peers().unwrap().len(), 1);
        // Orphan: the record goes through `PeerStore` alone, the file stays.
        pair.receiver
            .runtime
            .peers()
            .remove(&pair.producer_static)
            .unwrap();
        assert_eq!(pair.receiver.home.rcache(), files);
        pair.receiver
            .runtime
            .remove_peer(&pair.producer_static)
            .unwrap();
        assert!(pair.receiver.home.rcache().is_empty());
    }

    /// Acceptance (2): after the producer revokes the grant, `pull` is
    /// `Revoked`, every cache file of that producer is gone, `peers.json`
    /// says `revoked`, and `last_good` is `None`.
    #[test]
    fn a_revoked_pull_marks_the_peer_and_removes_its_cache() {
        let pair = pair(None, SLOW);
        pair.pull().unwrap();
        assert_eq!(pair.receiver.home.rcache().len(), 1);
        pair.producer
            .call(REVOKE, json!({"grantId": hex_encode(&pair.grant_id)}));
        assert_eq!(pair.pull(), Err(PullError::Fetch(FetchError::Revoked)));
        assert!(pair.receiver.home.rcache().is_empty());
        assert_eq!(pair.peer_state(), PeerState::Revoked);
        assert_eq!(pair.last_good(), None);
        // Durable: a restart reads `revoked` from `peers.json`.
        let Pair { receiver, .. } = pair;
        let receiver = receiver.restart(SLOW);
        assert_eq!(
            receiver.runtime.peers().peers().unwrap()[0].state,
            PeerState::Revoked
        );
    }

    /// Acceptance (2b): a record that is no longer usable does not read a
    /// cache entry that is still on disk.
    #[test]
    fn an_unusable_record_does_not_read_its_cache_entry() {
        let pair = pair(None, SLOW);
        let body = pair.pull().unwrap();
        assert_eq!(pair.last_good(), Some(body));
        pair.receiver
            .runtime
            .peers()
            .set_state(&pair.producer_static, &pair.grant_id, PeerState::Revoked)
            .unwrap();
        assert_eq!(pair.last_good(), None);
        assert_eq!(pair.receiver.home.rcache().len(), 1);
    }

    /// Acceptance (3): a grant past its expiry: `pull` is `Expired`, the
    /// cache files are gone, `peers.json` says `expired`, `last_good` is
    /// `None`.
    #[test]
    fn an_expired_pull_marks_the_peer_and_removes_its_cache() {
        let pair = pair(Some(NOW_MS + 120_000), SLOW);
        pair.pull().unwrap();
        assert_eq!(pair.receiver.home.rcache().len(), 1);
        pair.producer.clock.set_os(NOW + 130);
        assert_eq!(pair.pull(), Err(PullError::Fetch(FetchError::Expired)));
        assert!(pair.receiver.home.rcache().is_empty());
        assert_eq!(pair.peer_state(), PeerState::Expired);
        assert_eq!(pair.last_good(), None);
    }

    /// Acceptance (3b): an entry lives no longer than the grant. With the
    /// producer gone (nothing marks the record), `last_good` is `Some`
    /// before the grant's `expiresAt` and `None` after it.
    #[test]
    fn an_entry_does_not_outlive_the_grant() {
        let pair = pair(Some(NOW_MS + 120_000), SLOW);
        let body = pair.pull().unwrap();
        let Pair {
            receiver,
            producer,
            producer_static,
            ..
        } = pair;
        drop(producer);
        let last_good = || {
            receiver
                .runtime
                .last_good(&producer_static, &query())
                .unwrap()
                .map(|cached| cached.body().to_vec())
        };
        receiver.clock.set_os(NOW + 100);
        assert_eq!(last_good(), Some(body));
        receiver.clock.set_os(NOW + 130);
        assert_eq!(last_good(), None);
    }

    /// A clock anomaly (here rolled back past the 300 s tolerance) neither
    /// reads nor deletes the entry: `last_good` is `None` while it lasts and
    /// the same body is back once the clock is sane again.
    #[test]
    fn a_clock_anomaly_does_not_read_or_delete_the_cache() {
        let pair = pair(Some(NOW_MS + 120_000), SLOW);
        let body = pair.pull().unwrap();
        let Pair {
            receiver,
            producer,
            producer_static,
            ..
        } = pair;
        drop(producer);
        let last_good = || {
            receiver
                .runtime
                .last_good(&producer_static, &query())
                .unwrap()
                .map(|cached| cached.body().to_vec())
        };
        receiver.clock.set_os(NOW - 1_000);
        assert_eq!(last_good(), None);
        assert_eq!(receiver.home.rcache().len(), 1);
        receiver.clock.set_os(NOW + 100);
        assert_eq!(last_good(), Some(body));
    }

    /// Acceptance (4): `Busy` (the grant's rate tokens spent) and a
    /// connect failure (the producer gone) leave the cache alone.
    #[test]
    fn busy_and_disconnect_leave_the_cache_alone() {
        let pair = pair(None, SLOW);
        pair.pull().unwrap();
        // GRANT_BURST is 2 and the producer's monotonic clock stands still.
        // The second pull replaces the entry (another `requestId`).
        let body = pair.pull().unwrap();
        assert_eq!(pair.pull(), Err(PullError::Fetch(FetchError::Busy)));
        let files = pair.receiver.home.rcache();
        assert_eq!(files.len(), 1);
        assert_eq!(pair.last_good(), Some(body.clone()));

        let Pair {
            receiver,
            producer,
            producer_static,
            ..
        } = pair;
        drop(producer);
        assert!(matches!(
            receiver.runtime.pull(&producer_static, &query()),
            Err(PullError::Fetch(FetchError::Transport(_)))
        ));
        assert_eq!(receiver.home.rcache(), files);
        let cached = receiver
            .runtime
            .last_good(&producer_static, &query())
            .unwrap()
            .unwrap();
        assert_eq!(cached.body(), body.as_slice());
    }

    /// Acceptance (5): a cache file swapped for a symlink: the runtime
    /// still starts (without a cache), `pull` succeeds, `last_good` is
    /// `None`, and the symlink's target is untouched.
    #[cfg(not(windows))]
    #[test]
    fn a_symlinked_cache_file_leaves_the_runtime_without_a_cache() {
        let pair = pair(None, SLOW);
        pair.pull().unwrap();
        let Pair {
            receiver,
            producer,
            producer_static,
            ..
        } = pair;
        let receiver = {
            let file = receiver.home.rcache().remove(0);
            let target = receiver.home.0.join("target");
            fs::write(&target, b"not a cache entry").unwrap();
            // Swapped while the runtime is down.
            let Node {
                runtime,
                clock,
                home,
            } = receiver;
            drop(runtime);
            fs::remove_file(&file).unwrap();
            symlink(&target, &file).unwrap();
            Node::start(home, clock, SLOW).unwrap()
        };
        let body = receiver
            .runtime
            .pull(&producer_static, &query())
            .unwrap()
            .body;
        assert!(!body.is_empty());
        assert!(
            receiver
                .runtime
                .last_good(&producer_static, &query())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fs::read(receiver.home.0.join("target")).unwrap(),
            b"not a cache entry"
        );
        drop(producer);
    }

    /// Acceptance (6): housekeeping deletes an entry once the effective
    /// now reaches its `expiresAt`, with no `last_good` call.
    #[test]
    fn housekeeping_purges_expired_entries() {
        let pair = pair(Some(NOW_MS + 120_000), FAST);
        pair.pull().unwrap();
        assert_eq!(pair.receiver.home.rcache().len(), 1);
        pair.receiver.clock.set_os(NOW + 130);
        eventually("the expired entry was purged", || {
            pair.receiver.home.rcache().is_empty()
        });
    }

    /// Acceptance (7): `listenConfigure` with the address already bound
    /// does not restart the listener: the port and a connection in flight
    /// stay.
    #[test]
    fn listen_configure_to_the_bound_address_keeps_the_listener() {
        let node = Node::new(SLOW);
        let port = free_port();
        node.configure(port);
        let mut stream = TcpStream::connect((LOOPBACK, port)).unwrap();
        // Past the listener's 50 ms accept poll: the connection is admitted.
        thread::sleep(Duration::from_millis(300));
        node.configure(port);
        assert_eq!(node.runtime.listener_addr().unwrap().port(), port);
        stream
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut byte = [0u8; 1];
        let read = stream.read(&mut byte);
        assert!(
            matches!(&read, Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)),
            "the connection was closed: {read:?}"
        );
    }

    /// Acceptance (8): with the stored port taken at start there is no
    /// listener; once the port is free, a housekeeping round starts one
    /// and the node pairs.
    #[test]
    fn housekeeping_retries_a_listener_that_did_not_bind() {
        let taken = TcpListener::bind((LOOPBACK, 0)).unwrap();
        let port = taken.local_addr().unwrap().port();
        let home = TempHome::new();
        {
            let store = syrtis_agent::state_store::StateStore::open(
                SecureRoot::open_under(&home.0, SUFFIX).unwrap(),
                NOW,
            )
            .unwrap();
            store
                .set_listen_config(Some(LOOPBACK.into()), port, None)
                .unwrap();
        }
        let node = Node::start(home, TestClock::new(), FAST).unwrap();
        assert_eq!(node.runtime.listener_addr(), None);
        drop(taken);
        eventually("a round started the listener", || {
            node.runtime.listener_addr().map(|address| address.port()) == Some(port)
        });

        node.runtime.enable_sharing().unwrap();
        let url = node.call(OFFER_CREATE, json!({"ttlSeconds": 600}))["pairUrl"]
            .as_str()
            .unwrap()
            .to_owned();
        let receiver = Node::new(SLOW);
        let identity = StaticKey::from_state(&receiver.runtime.store().state().unwrap()).unwrap();
        let ledger = MemoryLedger::default();
        PairingClient {
            identity: &identity,
            ledger: &ledger,
            clock: &*node.clock,
        }
        .claim(&url, NOW_MS, &mut ClaimAttempts::default())
        .unwrap();
    }
}
