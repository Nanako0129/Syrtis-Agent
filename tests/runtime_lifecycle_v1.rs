//! SA-2B2c2 acceptance: the runtime (`src/runtime.rs`,
//! `spec/runtime-v1.md`) through the public API, over real Unix domain
//! sockets and loopback TCP.
//!
//! Every test needs a secure root, so they run on macOS and Linux only:
//! Windows fails closed (`tests/runtime_storage_v1.rs`). Homes live in
//! `/tmp` with short names so the control socket path fits `sun_path`.
//! Listeners bind 127.0.0.1 only. Acceptance (6b), first half (`stop()`
//! while a `listenConfigure` hook is held), needs a test-only gate and is a
//! unit test in `src/runtime.rs`.

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod disk {
    use std::{
        fs,
        net::{TcpListener, TcpStream},
        os::unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::UnixStream,
        },
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicI64, AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use serde_json::{Value, json};
    use syrtis_agent::{
        control::{
            APPROVE, Client, Command, LISTEN_CONFIGURE, OFFER_CREATE, OK, PENDING_LIST, Response,
            SHUTDOWN, STATUS, UNAUTHORIZED,
        },
        noise::StaticKey,
        pairing::{ClaimAttempts, ClientError, Clock, PairingClient},
        peer_store::{PeerRecord, PeerStore},
        report::{
            AgentsRecord, Endpoint, ReportRequest, ReportResponse, decode_response, encode_response,
        },
        report_peer::{FetchLimiter, Records, ReportQuery, ReportSource, SourceError, fetch},
        runtime::{Options, Runtime, RuntimeError},
        secure_fs::{SecureRoot, StorageError},
        security::{
            GrantState, MemoryLedger, OfferClaim, OfferState, PendingApproval, PendingState,
            ReferenceState, SecurityError, Terminal, TerminalKind, decode_fixed_hex, hex_encode,
            parse_pair_url,
        },
        state_store::{Secret32, StateStore, encode_state},
    };

    const NOW: i64 = 1_700_000_000;
    const NOW_MS: i64 = NOW * 1_000;
    const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];
    const LOOPBACK: &str = "127.0.0.1";
    const NINETY_DAYS_MS: i64 = 90 * 86_400_000;
    /// A housekeeping period short enough to drive rounds from a test.
    const FAST: Duration = Duration::from_millis(50);

    /// Injected time. `sleep` advances both clocks at once; `os` counts
    /// its reads, which in an idle runtime are the housekeeping rounds.
    struct TestClock {
        os: AtomicI64,
        mono: Mutex<Duration>,
        reads: AtomicUsize,
    }

    impl TestClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                os: AtomicI64::new(NOW),
                mono: Mutex::new(Duration::ZERO),
                reads: AtomicUsize::new(0),
            })
        }

        fn os(&self) -> i64 {
            self.os.load(Ordering::SeqCst)
        }

        fn set_os(&self, seconds: i64) {
            self.os.store(seconds, Ordering::SeqCst);
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl Clock for TestClock {
        fn monotonic(&self) -> Duration {
            *self.mono.lock().unwrap()
        }

        fn os_now_seconds(&self) -> Result<i64, StorageError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.os())
        }

        fn sleep(&self, duration: Duration) {
            *self.mono.lock().unwrap() += duration;
            self.os
                .fetch_add(duration.as_secs() as i64, Ordering::SeqCst);
        }
    }

    /// A temporary home in `/tmp`, short so the socket path fits
    /// `sun_path`. Only directories this helper created are removed.
    struct TempHome(PathBuf);

    impl TempHome {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = PathBuf::from(format!(
                "/tmp/sl-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn root(&self) -> PathBuf {
            SUFFIX
                .iter()
                .fold(self.0.clone(), |path, part| path.join(part))
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::set_permissions(self.root(), fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The stub report source: the agents fixture, echoing the request.
    struct Stub;

    impl ReportSource for Stub {
        fn report(&self, request: &ReportRequest, _: Instant) -> Result<Vec<u8>, SourceError> {
            encode_response(&ReportResponse::from_request(request, agents(), false))
                .map_err(|_| SourceError)
        }
    }

    fn agents() -> Vec<AgentsRecord> {
        let bytes: &[u8] = include_bytes!("fixtures/v1/report/agents.json");
        let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        decode_response::<AgentsRecord>(bytes, None)
            .unwrap()
            .records
    }

    /// A running runtime on its own home. Field order is drop order: the
    /// runtime stops before its home is removed.
    struct Node {
        runtime: Runtime,
        clock: Arc<TestClock>,
        home: TempHome,
    }

    impl Node {
        fn new(period: Duration) -> Self {
            Self::start(TempHome::new(), period).unwrap()
        }

        fn start(home: TempHome, period: Duration) -> Result<Self, RuntimeError> {
            let clock = TestClock::new();
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

        fn store(&self) -> &StateStore {
            self.runtime.store()
        }

        fn reference(&self) -> ReferenceState {
            self.store().state().unwrap().reference
        }

        fn wall(&self) -> i64 {
            self.reference().last_accepted_wall_unix_seconds()
        }

        fn client(&self) -> Client {
            let token = *self.store().state().unwrap().control_token.expose();
            Client::new(
                Secret32::new(token),
                self.runtime.socket_path().to_path_buf(),
            )
        }

        fn call(&self, id: u16, body: Value) -> Response {
            self.client().call(&Command { id, body }).unwrap()
        }

        fn configure(&self, port: u16) {
            let response = self.call(
                LISTEN_CONFIGURE,
                json!({"bindHost": LOOPBACK, "bindPort": port}),
            );
            assert_eq!(response.code, OK);
        }

        /// `offerCreate` through control; returns `(offerId, Pair URL)`.
        fn offer(&self, ttl_seconds: u64) -> ([u8; 16], String) {
            let response = self.call(OFFER_CREATE, json!({"ttlSeconds": ttl_seconds}));
            assert_eq!(response.code, OK);
            let offer_id = decode_fixed_hex(response.data["offerId"].as_str().unwrap()).unwrap();
            (offer_id, response.data["pairUrl"].as_str().unwrap().into())
        }

        /// Claims the offer of `url` straight through the store (the
        /// frozen `claim_offer`, as the producer would), at the clock's
        /// now, with the secret from the URL. `issued_ms` is when the URL
        /// was made: the frozen `parse_pair_url` refuses one with more than
        /// 900 s left, or none.
        fn claim_direct(&self, url: &str, issued_ms: i64, n: u8) -> Result<[u8; 16], StorageError> {
            let offer = parse_pair_url(url, issued_ms).unwrap();
            let pending_id = [n; 16];
            let os_now = self.clock.os();
            self.store()
                .transition(|state| {
                    state
                        .claim_offer(
                            OfferClaim {
                                offer_id: decode_fixed_hex(&offer.offer_id).unwrap(),
                                secret: decode_fixed_hex(&offer.secret).unwrap(),
                                responder_static: decode_fixed_hex(&offer.responder_static)
                                    .unwrap(),
                                pending_id,
                                initiator_static: [n; 32],
                                sas_code: "ABCD-0123".into(),
                                sas_generation: 1,
                            },
                            os_now,
                        )
                        .map(|(next, _, _)| next)
                })
                .map(|()| pending_id)
        }

        fn offer_state(&self, offer_id: [u8; 16]) -> OfferState {
            self.reference()
                .offers
                .iter()
                .find(|offer| offer.offer_id == offer_id)
                .unwrap()
                .state
        }

        fn pending_state(&self, pending_id: [u8; 16]) -> PendingState {
            self.reference()
                .pending
                .iter()
                .find(|pending| pending.pending_id == pending_id)
                .unwrap()
                .state
        }

        fn grant_state(&self, grant_id: [u8; 16]) -> GrantState {
            self.reference()
                .grants
                .iter()
                .find(|grant| grant.grant_id == grant_id)
                .unwrap()
                .state
        }

        fn state_bytes(&self) -> Vec<u8> {
            encode_state(&self.store().state().unwrap()).unwrap()
        }

        /// Fills the record table to exactly `MAX_RECORDS` (256) with
        /// filler terminal records, written by one `StateStore::transition`
        /// whose closure pushes them onto `terminal` directly. Each filler
        /// is `cleanup_complete` with `terminal_at = compactable_at_ms -
        /// 90 days`, so the frozen `compact_terminals` (the checkpoint)
        /// removes them all once the effective now reaches
        /// `compactable_at_ms`, and none before.
        fn fill_record_table(&self, compactable_at_ms: i64) {
            self.store()
                .transition(|state| {
                    let mut next = state.clone();
                    let used = next.offers.len()
                        + next.pending.len()
                        + next.grants.len()
                        + next.terminal.len();
                    for n in 0..(256 - used) {
                        let mut record_id = [0xee; 16];
                        record_id[..8].copy_from_slice(&(n as u64).to_be_bytes());
                        next.terminal.push(Terminal {
                            record_id,
                            kind: TerminalKind::Offer,
                            auth_epoch: 0,
                            terminal_at_ms: compactable_at_ms - NINETY_DAYS_MS,
                            cleanup_complete: true,
                        });
                    }
                    Ok(next)
                })
                .unwrap();
            assert_eq!(record_count(&self.reference()), 256);
        }
    }

    fn record_count(state: &ReferenceState) -> usize {
        state.offers.len() + state.pending.len() + state.grants.len() + state.terminal.len()
    }

    /// A receiver agent on its own temp root.
    struct Receiver {
        store: StateStore,
        peers: PeerStore,
        key: StaticKey,
        ledger: MemoryLedger,
        limiter: FetchLimiter,
        _home: TempHome,
    }

    impl Receiver {
        fn new() -> Self {
            let home = TempHome::new();
            let store =
                StateStore::open(SecureRoot::open_under(&home.0, SUFFIX).unwrap(), NOW).unwrap();
            let peers = PeerStore::open(store.root()).unwrap();
            let key = StaticKey::from_state(&store.state().unwrap()).unwrap();
            Self {
                store,
                peers,
                key,
                ledger: MemoryLedger::default(),
                limiter: FetchLimiter::default(),
                _home: home,
            }
        }

        fn client<'a>(&'a self, clock: &'a TestClock) -> PairingClient<'a> {
            PairingClient {
                identity: &self.key,
                ledger: &self.ledger,
                clock,
            }
        }
    }

    /// A loopback port nothing listens on.
    fn free_port() -> u16 {
        TcpListener::bind((LOOPBACK, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn listening(port: u16) -> bool {
        TcpStream::connect((LOOPBACK, port)).is_ok()
    }

    /// Polls `check` every 10 ms for up to 5 s.
    fn eventually(what: &str, mut check: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !check() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Waits until at least `rounds` more housekeeping rounds (clock
    /// reads, in an idle runtime) have run.
    fn rounds(node: &Node, rounds: usize) {
        let start = node.clock.reads();
        eventually("housekeeping rounds", || {
            node.clock.reads() >= start + rounds
        });
    }

    /// Runs `f` on another thread; `Some` if it returns within `within`.
    fn within<T: Send + 'static>(
        within: Duration,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(within).ok()
    }

    // ------------------------------------------------------------- tests

    /// Acceptance (1): start → `listenConfigure` and `offerCreate` over
    /// control → another node claims over the wire, the owner approves
    /// over control, the receiver confirms and pulls a report from the
    /// stub source → the `shutdown` command ends the runtime.
    #[test]
    fn the_runtime_pairs_serves_a_report_and_shuts_down_by_command() {
        let node = Arc::new(Node::new(Duration::from_secs(60)));
        assert_eq!(node.runtime.listener_addr(), None);
        let port = free_port();
        node.configure(port);
        assert_eq!(node.runtime.listener_addr().unwrap().port(), port);
        node.runtime.enable_sharing().unwrap();
        let (_, url) = node.offer(600);

        let receiver = Receiver::new();
        let pairing = receiver.client(&node.clock);
        let claimed = pairing
            .claim(&url, NOW_MS, &mut ClaimAttempts::default())
            .unwrap();
        let list = node.call(PENDING_LIST, json!({}));
        assert_eq!(list.data[0]["pendingId"], hex_encode(&claimed.pending_id));
        let approve = node.call(
            APPROVE,
            json!({"pendingId": hex_encode(&claimed.pending_id), "sasGeneration": 1}),
        );
        assert_eq!(approve.code, OK);
        let confirmed = pairing.poll(&claimed).unwrap();
        let record = PeerRecord::from_confirmed(&confirmed, None, node.clock.os() * 1_000);
        receiver.peers.upsert(record.clone()).unwrap();

        let fetched = fetch(
            &record,
            &ReportQuery {
                endpoint: Endpoint::Agents,
                start_date: "2025-01-01".into(),
                end_date_exclusive: "2025-02-01".into(),
                timezone: "America/Los_Angeles".into(),
                clients: vec!["claude".into(), "codex".into()],
            },
            &receiver.store,
            &receiver.ledger,
            &receiver.limiter,
        )
        .unwrap();
        assert_eq!(fetched.records, Records::Agents(agents()));

        let waiter = Arc::clone(&node);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            waiter.runtime.wait();
            let _ = tx.send(());
        });
        assert_eq!(node.call(SHUTDOWN, json!({})).code, OK);
        assert!(
            rx.recv_timeout(Duration::from_secs(3)).is_ok(),
            "wait() did not return after shutdown"
        );
        node.runtime.stop();
        assert!(!listening(port));
    }

    /// Acceptance (2): after `shutdown` its reply arrives (the hook does
    /// not stop the server on the connection thread), `wait()` returns,
    /// `stop()` finishes within 3 s, the socket file stays but accepts no
    /// connection, and the peer port is closed.
    #[test]
    fn shutdown_returns_wait_and_stop_closes_the_socket_and_the_port() {
        let node = Arc::new(Node::new(Duration::from_secs(60)));
        let port = free_port();
        node.configure(port);
        assert!(listening(port));
        let waiter = Arc::clone(&node);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            waiter.runtime.wait();
            let _ = tx.send(());
        });
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());

        let reply = node.client().call(&Command {
            id: SHUTDOWN,
            body: json!({}),
        });
        assert_eq!(reply.map(|response| response.code), Ok(OK));
        assert!(
            rx.recv_timeout(Duration::from_secs(3)).is_ok(),
            "wait() did not return after shutdown"
        );
        let stopper = Arc::clone(&node);
        let started = Instant::now();
        assert!(
            within(Duration::from_secs(3), move || stopper.runtime.stop()).is_some(),
            "stop() took more than 3 s"
        );
        assert!(started.elapsed() < Duration::from_secs(3));

        let socket = node.runtime.socket_path();
        assert!(
            fs::symlink_metadata(socket)
                .unwrap()
                .file_type()
                .is_socket()
        );
        assert!(UnixStream::connect(socket).is_err());
        assert!(!listening(port));
        // `stop()` again is a no-op.
        node.runtime.stop();
    }

    /// Acceptance (3): `listenConfigure` to a new port closes the old one
    /// and the new one pairs; an address that does not bind leaves no
    /// listener (no fallback) and `status` still answers.
    #[test]
    fn listen_configure_moves_the_listener_and_an_unbindable_address_stops_it() {
        let node = Node::new(Duration::from_secs(60));
        let (first, second) = (free_port(), free_port());
        node.configure(first);
        assert!(listening(first));
        node.configure(second);
        assert!(!listening(first), "the old port still accepts");
        assert_eq!(node.runtime.listener_addr().unwrap().port(), second);

        node.runtime.enable_sharing().unwrap();
        let (_, url) = node.offer(600);
        let receiver = Receiver::new();
        receiver
            .client(&node.clock)
            .claim(&url, NOW_MS, &mut ClaimAttempts::default())
            .unwrap();

        // Held by this test, so the bind fails with the address in use.
        let taken = TcpListener::bind((LOOPBACK, 0)).unwrap();
        node.configure(taken.local_addr().unwrap().port());
        assert_eq!(node.runtime.listener_addr(), None);
        assert!(!listening(second), "fell back to the old listener");
        let status = node.call(STATUS, json!({}));
        assert_eq!(status.code, OK);
        assert_eq!(status.data["bindPort"], taken.local_addr().unwrap().port());
    }

    /// Acceptance (4), F-7: an offer, an awaiting pending and an active
    /// grant → `disable_sharing` → the pending is rejected, the offer
    /// cancelled, the grant revoked → `enable_sharing` → the old Pair URL
    /// is refused over the wire (`unauthorized`) and the old pending
    /// cannot be approved.
    #[test]
    fn disable_rejects_cancels_and_revokes_and_nothing_old_works_after_enable() {
        let node = Node::new(Duration::from_secs(60));
        let port = free_port();
        node.configure(port);
        node.runtime.enable_sharing().unwrap();
        let receiver = Receiver::new();
        let pairing = receiver.client(&node.clock);

        let (_, granted_url) = node.offer(600);
        let granted = pairing
            .claim(&granted_url, NOW_MS, &mut ClaimAttempts::default())
            .unwrap();
        assert_eq!(
            node.call(
                APPROVE,
                json!({"pendingId": hex_encode(&granted.pending_id), "sasGeneration": 1}),
            )
            .code,
            OK
        );
        let grant_id = pairing.poll(&granted).unwrap().grant_id;
        let (open_offer, open_url) = node.offer(600);
        let (_, pending_url) = node.offer(600);
        let waiting = pairing
            .claim(&pending_url, NOW_MS, &mut ClaimAttempts::default())
            .unwrap();
        assert_eq!(
            node.pending_state(waiting.pending_id),
            PendingState::AwaitingApproval
        );

        node.runtime.disable_sharing().unwrap();
        let state = node.reference();
        assert!(!state.sharing_enabled);
        assert_eq!(
            node.pending_state(waiting.pending_id),
            PendingState::Rejected
        );
        assert_eq!(node.offer_state(open_offer), OfferState::Cancelled);
        assert_eq!(node.grant_state(grant_id), GrantState::Revoked);
        assert!(
            state
                .grants
                .iter()
                .all(|grant| grant.state != GrantState::Active)
        );

        node.runtime.enable_sharing().unwrap();
        assert!(node.reference().sharing_enabled);
        assert_eq!(
            pairing
                .claim(&open_url, NOW_MS, &mut ClaimAttempts::default())
                .unwrap_err(),
            ClientError::OfferUnusable
        );
        let approve = node.call(
            APPROVE,
            json!({"pendingId": hex_encode(&waiting.pending_id), "sasGeneration": 1}),
        );
        assert_eq!(approve.code, UNAUTHORIZED);
        assert_eq!(
            node.pending_state(waiting.pending_id),
            PendingState::Rejected
        );
    }

    /// Acceptance (5), the enable gate. The record table is full, so
    /// `disable_sharing` cannot cancel the offer (`Bounds`): it still
    /// succeeds, rejects the pending, and leaves the offer active. Enable
    /// is refused (`Busy`, nothing written) until a checkpoint pushes the
    /// wall past the offer's expiry; then it succeeds with the offer still
    /// active, and the old Pair URL cannot be claimed even once the table
    /// has room again.
    #[test]
    fn with_a_full_record_table_enable_waits_until_the_wall_passes_the_stranded_offer() {
        let node = Node::new(Duration::from_secs(60));
        node.configure(free_port());
        node.runtime.enable_sharing().unwrap();
        let (stranded, stranded_url) = node.offer(600);
        let (_, pending_url) = node.offer(600);
        let pending = node.claim_direct(&pending_url, NOW_MS, 0x51).unwrap();
        // Fillers leave at the checkpoint at NOW + 700 s, not before.
        node.fill_record_table((NOW + 700) * 1_000);

        assert_eq!(
            node.runtime.disable_sharing(),
            Ok(()),
            "a full table failed the disable"
        );
        assert!(!node.reference().sharing_enabled);
        assert_eq!(node.pending_state(pending), PendingState::Rejected);
        assert_eq!(node.offer_state(stranded), OfferState::Active);

        let before = node.state_bytes();
        assert_eq!(node.runtime.enable_sharing(), Err(StorageError::Busy));
        assert_eq!(node.state_bytes(), before, "a refused enable wrote");
        assert!(!node.reference().sharing_enabled);

        // The offer expires at NOW + 600 s; the wall passes it.
        node.clock.set_os(NOW + 601);
        node.store().checkpoint(NOW + 601).unwrap();
        assert_eq!(node.wall(), NOW + 601);
        assert_eq!(record_count(&node.reference()), 258, "fillers left early");
        assert_eq!(node.runtime.enable_sharing(), Ok(()));
        assert!(node.reference().sharing_enabled);
        assert_eq!(node.offer_state(stranded), OfferState::Active);

        // Room again (the fillers are compacted), so a refusal below is the
        // offer's expiry, not the table.
        node.clock.set_os(NOW + 700);
        node.store().checkpoint(NOW + 700).unwrap();
        assert!(record_count(&node.reference()) < 16);
        assert_eq!(
            node.claim_direct(&stranded_url, NOW_MS, 0x52),
            Err(StorageError::Refused(SecurityError::Unauthorized))
        );
        let (_, fresh_url) = node.offer(600);
        node.claim_direct(&fresh_url, (NOW + 700) * 1_000, 0x53)
            .unwrap();
    }

    /// The enable gate's second cancel: an offer the disable could not
    /// cancel (`Bounds`) is cancelled by `enable_sharing` once the table
    /// has room again, so enable does not wait for its expiry.
    #[test]
    fn enable_cancels_a_stranded_offer_once_the_table_has_room() {
        let node = Node::new(Duration::from_secs(60));
        node.configure(free_port());
        node.runtime.enable_sharing().unwrap();
        let (stranded, _) = node.offer(600);
        node.fill_record_table((NOW + 100) * 1_000);
        node.runtime.disable_sharing().unwrap();
        assert_eq!(node.offer_state(stranded), OfferState::Active);

        node.clock.set_os(NOW + 100);
        node.store().checkpoint(NOW + 100).unwrap();
        assert!(record_count(&node.reference()) < 16);
        assert_eq!(node.runtime.enable_sharing(), Ok(()));
        assert_eq!(node.offer_state(stranded), OfferState::Cancelled);
    }

    /// Acceptance (6): after disable and enable, a new offer pairs and is
    /// approved; after a reset whose old wall a fast clock had pushed
    /// ahead, enable, a new offer and a claim all succeed.
    #[test]
    fn after_disable_and_enable_and_after_a_reset_new_offers_pair() {
        let node = Node::new(Duration::from_secs(60));
        node.configure(free_port());
        node.runtime.enable_sharing().unwrap();
        node.runtime.disable_sharing().unwrap();
        node.runtime.enable_sharing().unwrap();
        let receiver = Receiver::new();
        let pairing = receiver.client(&node.clock);
        let (_, url) = node.offer(600);
        let claimed = pairing
            .claim(&url, NOW_MS, &mut ClaimAttempts::default())
            .unwrap();
        let approve = node.call(
            APPROVE,
            json!({"pendingId": hex_encode(&claimed.pending_id), "sasGeneration": 1}),
        );
        assert_eq!(approve.code, OK);
        pairing.poll(&claimed).unwrap();

        // A fast clock pushes the wall an hour ahead; the clock comes back
        // (an anomaly), and the owner resets.
        let ahead = node.clock.os() + 3_600;
        node.clock.set_os(ahead);
        node.store().checkpoint(ahead).unwrap();
        let back = ahead - 3_500;
        node.clock.set_os(back);
        node.store().reset(back, back * 1_000).unwrap();
        assert_eq!(node.wall(), back);

        node.runtime.enable_sharing().unwrap();
        let (_, url) = node.offer(600);
        let claimed = pairing
            .claim(&url, back * 1_000, &mut ClaimAttempts::default())
            .unwrap();
        assert_eq!(
            node.pending_state(claimed.pending_id),
            PendingState::AwaitingApproval
        );
    }

    /// Acceptance (6b), second half: two `listenConfigure` commands at once
    /// end with the listener bound to the address the store holds.
    #[test]
    fn concurrent_listen_configures_end_bound_to_the_stored_address() {
        let node = Arc::new(Node::new(Duration::from_secs(60)));
        for _ in 0..10 {
            let ports = [free_port(), free_port()];
            let handles: Vec<_> = ports
                .iter()
                .map(|&port| {
                    let node = Arc::clone(&node);
                    thread::spawn(move || node.configure(port))
                })
                .collect();
            for handle in handles {
                handle.join().unwrap();
            }
            let stored = node.store().state().unwrap().config.bind_port;
            assert!(ports.contains(&stored));
            assert_eq!(
                node.runtime.listener_addr().map(|address| address.port()),
                Some(stored),
                "the listener is not on the stored port"
            );
            assert!(listening(stored));
            let other = if ports[0] == stored {
                ports[1]
            } else {
                ports[0]
            };
            assert!(!listening(other), "a listener on the other port survived");
        }
    }

    /// Acceptance (7): with only the injected clock moving (no control or
    /// peer request), housekeeping stores an offer, a pending and a grant
    /// as expired once the effective now reaches their `expiresAt`, and
    /// advances the durable wall.
    #[test]
    fn housekeeping_expires_offers_pending_and_grants_and_advances_the_wall() {
        let node = Node::new(FAST);
        node.configure(free_port());
        node.runtime.enable_sharing().unwrap();
        let (offer, _) = node.offer(60);
        let (_, pending_url) = node.offer(90);
        let pending = node.claim_direct(&pending_url, NOW_MS, 0x61).unwrap();
        let (_, grant_url) = node.offer(600);
        let granting = node.claim_direct(&grant_url, NOW_MS, 0x62).unwrap();
        let grant_id = [0x63; 16];
        let responder = node.store().state().unwrap().identity_public().unwrap();
        node.store()
            .transition(|state| {
                state.approve_pending(
                    PendingApproval {
                        pending_id: granting,
                        sas_generation: 1,
                        grant_id,
                        responder_static: responder,
                        grant_expires_at_ms: NOW_MS + 120_000,
                        disclosure_exact: true,
                    },
                    NOW,
                )
            })
            .unwrap();

        node.clock.set_os(NOW + 100);
        eventually("offer and pending expired", || {
            node.offer_state(offer) == OfferState::Expired
                && node.pending_state(pending) == PendingState::Expired
        });
        assert_eq!(node.grant_state(grant_id), GrantState::Active);
        eventually("wall advanced", || node.wall() == NOW + 100);

        node.clock.set_os(NOW + 130);
        eventually("grant expired", || {
            node.grant_state(grant_id) == GrantState::Expired
        });
        eventually("wall advanced", || node.wall() == NOW + 130);
    }

    /// Acceptance (8), clock: a round with an anomalous clock (a day and a
    /// half ahead of the wall) writes nothing, and the next sane round
    /// expires what is due.
    #[test]
    fn an_anomalous_round_is_skipped_and_the_next_sane_one_sweeps() {
        let node = Node::new(FAST);
        node.configure(free_port());
        node.runtime.enable_sharing().unwrap();
        let (offer, _) = node.offer(600);
        rounds(&node, 1);
        let before = node.state_bytes();

        node.clock.set_os(NOW + 129_600);
        rounds(&node, 4);
        assert_eq!(node.offer_state(offer), OfferState::Active);
        assert_eq!(node.wall(), NOW);
        assert_eq!(node.state_bytes(), before);

        node.clock.set_os(NOW + 700);
        eventually("offer expired after the clock recovered", || {
            node.offer_state(offer) == OfferState::Expired
        });
        assert_eq!(node.wall(), NOW + 700);
    }

    /// Acceptance (8), store: once a commit fails (the root is made
    /// read-only, so the next checkpoint cannot stage) the store is sticky
    /// unknown; housekeeping keeps running (no panic) at its period (no
    /// spin), and `stop()` still returns.
    #[test]
    fn a_sticky_store_neither_stops_nor_spins_housekeeping() {
        let node = Node::new(FAST);
        rounds(&node, 1);
        let root = node.home.root();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
        if fs::File::create(root.join("probe")).is_ok() {
            // Privileged: the mode does not stop a write here.
            let _ = fs::remove_file(root.join("probe"));
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            eprintln!("skipped: a read-only root is writable by this user");
            return;
        }
        eventually("the store went sticky", || node.store().state().is_err());
        assert_eq!(node.store().state().err(), Some(StorageError::Unknown));
        let start = node.clock.reads();
        thread::sleep(Duration::from_secs(1));
        let reads = node.clock.reads() - start;
        // A 50 ms period is ~20 rounds a second.
        assert!(reads >= 5, "housekeeping stopped: {reads} rounds in 1 s");
        assert!(reads <= 60, "housekeeping spins: {reads} rounds in 1 s");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let node = Arc::new(node);
        let stopper = Arc::clone(&node);
        assert!(
            within(Duration::from_secs(3), move || stopper.runtime.stop()).is_some(),
            "stop() hung on a sticky store"
        );
    }

    /// Acceptance (9): `stop()` takes a final checkpoint.
    #[test]
    fn stop_takes_a_final_checkpoint() {
        let node = Node::new(Duration::from_secs(60));
        // One read opened the store, the next is the first round's; the
        // next round is 60 s away.
        eventually("first round", || node.clock.reads() >= 2);
        node.clock.set_os(NOW + 30);
        node.runtime.stop();
        assert_eq!(node.wall(), NOW + 30);
    }

    /// Acceptance (10): without a `bindHost`, and with one that does not
    /// bind, the runtime starts, control answers, and no listener runs.
    #[test]
    fn without_a_bindable_host_the_runtime_runs_control_without_a_listener() {
        let node = Node::new(Duration::from_secs(60));
        assert_eq!(node.runtime.listener_addr(), None);
        let status = node.call(STATUS, json!({}));
        assert_eq!(status.code, OK);
        assert_eq!(status.data["bindHost"], Value::Null);

        let taken = TcpListener::bind((LOOPBACK, 0)).unwrap();
        let home = TempHome::new();
        {
            let store =
                StateStore::open(SecureRoot::open_under(&home.0, SUFFIX).unwrap(), NOW).unwrap();
            store
                .set_listen_config(
                    Some(LOOPBACK.into()),
                    taken.local_addr().unwrap().port(),
                    None,
                )
                .unwrap();
        }
        let started = Node::start(home, Duration::from_secs(60));
        assert!(
            started.is_ok(),
            "an unbindable address failed the start: {:?}",
            started.as_ref().err()
        );
        let node = started.unwrap();
        assert_eq!(node.runtime.listener_addr(), None);
        assert_eq!(node.call(STATUS, json!({})).code, OK);
    }

    /// Control `status` and `pendingList` leave out offers and pending
    /// records past `expiresAt` by the effective now, before housekeeping
    /// has stored them as expired (PR #18 CR-1).
    #[test]
    fn status_and_pending_list_leave_out_what_has_expired() {
        let node = Node::new(Duration::from_secs(60));
        node.configure(free_port());
        node.runtime.enable_sharing().unwrap();
        node.offer(60);
        let (_, pending_url) = node.offer(120);
        node.claim_direct(&pending_url, NOW_MS, 0x71).unwrap();
        let status = node.call(STATUS, json!({}));
        assert_eq!(status.data["activeOfferCount"], 1);
        assert_eq!(status.data["pendingCount"], 1);
        assert_eq!(
            node.call(PENDING_LIST, json!({}))
                .data
                .as_array()
                .unwrap()
                .len(),
            1
        );

        node.clock.set_os(NOW + 60);
        let status = node.call(STATUS, json!({}));
        assert_eq!(status.data["activeOfferCount"], 0);
        assert_eq!(status.data["pendingCount"], 1);

        node.clock.set_os(NOW + 120);
        let status = node.call(STATUS, json!({}));
        assert_eq!(status.data["pendingCount"], 0);
        assert_eq!(node.call(PENDING_LIST, json!({})).data, json!([]));
        // Still stored as active: only the views filtered them.
        assert_eq!(
            node.reference()
                .offers
                .iter()
                .filter(|offer| offer.state == OfferState::Active)
                .count(),
            1
        );
    }
}
