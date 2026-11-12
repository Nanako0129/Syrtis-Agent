//! SA-2B2a3 acceptance: the producer's product TCP listener
//! (`src/listener.rs`, `spec/pairing-v1.md` "Listener"), over real loopback
//! sockets through the public API.
//!
//! Every test here needs a secure root, so they run on macOS and Linux
//! only: Windows fails closed (`tests/runtime_storage_v1.rs`). The bind
//! re-validation (acceptance 3, unit half) and the low-order static check
//! (acceptance 8) are unit tests in `src/listener.rs` and `src/noise.rs`,
//! which run on all three platforms. Every listener binds 127.0.0.1 only.

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod disk {
    use std::{
        io::{ErrorKind, Read},
        net::{SocketAddr, TcpListener, TcpStream},
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use syrtis_agent::{
        listener::{Listener, ListenerError, MAX_CONNECTIONS},
        noise::{self, StaticKey},
        pairing::{ClaimAttempts, Clock, PairingClient, RateLimiter, approve},
        report_peer::{NoSource, Reports},
        secure_fs::{SecureRoot, StorageError},
        security::{
            MemoryLedger, Offer, OfferState, PairOffer, hex_encode, offer_secret_hash, pair_url,
        },
        state_store::StateStore,
    };

    const NOW: i64 = 1_700_000_000;
    const NOW_MS: i64 = NOW * 1_000;
    const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];
    const LOOPBACK: &str = "127.0.0.1";

    /// Fake time: `sleep` advances it at once, so polling takes no real time.
    #[derive(Default)]
    struct TestClock(Mutex<Duration>);

    impl Clock for TestClock {
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

    /// A temporary home. Only directories this helper created are removed.
    struct TempHome(PathBuf);

    impl TempHome {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "syrtis-agent-listen-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A producer agent on its own secure root, sharing on.
    struct Node {
        // Dropped after the store, which holds the root open.
        store: Arc<StateStore>,
        _home: TempHome,
    }

    impl Node {
        fn new() -> Self {
            let home = TempHome::new();
            let store =
                retry_busy(|| StateStore::open(SecureRoot::open_under(&home.0, SUFFIX)?, NOW))
                    .unwrap();
            store.transition(|state| state.enable_sharing()).unwrap();
            Self {
                store: Arc::new(store),
                _home: home,
            }
        }

        /// The identity as the store holds it right now.
        fn key(&self) -> StaticKey {
            StaticKey::from_state(&self.store.state().unwrap()).unwrap()
        }

        fn configure(&self, host: &str, port: u16) -> Result<(), StorageError> {
            self.store.set_listen_config(Some(host.into()), port, None)
        }

        fn start(&self, clock: Arc<TestClock>) -> Result<Listener, ListenerError> {
            Listener::start(
                Arc::clone(&self.store),
                MemoryLedger::default(),
                Arc::new(RateLimiter::default()),
                clock,
                Arc::new(Reports::new(Arc::new(NoSource))),
            )
        }

        /// Offer 1, created at `NOW`, and its Pair URL for `port`.
        fn offer_url(&self, port: u16) -> String {
            let (offer_id, secret) = ([1; 16], [0x5c; 32]);
            let responder = *self.key().public();
            self.store
                .transition(|state| {
                    state.create_offer(
                        Offer {
                            offer_id,
                            secret_hash: offer_secret_hash(&offer_id, &secret, &responder),
                            created_at_ms: NOW_MS,
                            expires_at_ms: NOW_MS + 600_000,
                            state: OfferState::Active,
                        },
                        NOW,
                    )
                })
                .unwrap();
            pair_url(&PairOffer {
                expires_at: NOW_MS + 600_000,
                host: LOOPBACK.into(),
                offer_id: hex_encode(&offer_id),
                port,
                responder_static: hex_encode(&responder),
                secret: hex_encode(&secret),
                version: 1,
            })
            .unwrap()
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

    /// A loopback port nothing listens on (bound once, then released).
    fn free_port() -> u16 {
        TcpListener::bind((LOOPBACK, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn refused(port: u16) -> bool {
        TcpStream::connect((LOOPBACK, port))
            .is_err_and(|error| error.kind() == ErrorKind::ConnectionRefused)
    }

    /// True when the peer closes `stream` within `within`; false when the
    /// read is still waiting then. Sends nothing.
    fn closed_within(stream: &mut TcpStream, within: Duration) -> bool {
        stream.set_read_timeout(Some(within)).unwrap();
        match stream.read(&mut [0; 1]) {
            Ok(0) => true,
            Ok(read) => panic!("the producer sent {read} bytes before any handshake byte"),
            Err(error) => !matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
        }
    }

    /// Opens `n` connections that send nothing, so each sits in the
    /// producer's handshake read, and gives the accept loop time to take
    /// them all.
    fn stalled(address: SocketAddr, n: usize) -> Vec<TcpStream> {
        let streams = (0..n)
            .map(|_| TcpStream::connect(address).unwrap())
            .collect();
        thread::sleep(Duration::from_millis(300));
        streams
    }

    /// Acceptance (1): a receiver pairs end to end, through the Pair URL,
    /// with a listener bound from the stored config: claim, approve, poll,
    /// confirmed grant.
    #[test]
    fn a_receiver_pairs_through_the_listener_end_to_end() {
        let node = Node::new();
        let port = free_port();
        node.configure(LOOPBACK, port).unwrap();
        let clock = Arc::new(TestClock::default());
        let mut listener = node.start(Arc::clone(&clock)).unwrap();
        assert_eq!(
            listener.local_addr(),
            SocketAddr::from(([127, 0, 0, 1], port))
        );

        let receiver = StaticKey::generate().unwrap();
        let ledger = MemoryLedger::default();
        let client = PairingClient {
            identity: &receiver,
            ledger: &ledger,
            clock: &*clock,
        };
        let mut attempts = ClaimAttempts::default();
        let claimed = client
            .claim(&node.offer_url(port), NOW_MS, &mut attempts)
            .unwrap();
        approve(
            &node.store,
            claimed.pending_id,
            1,
            true,
            clock.os_now_seconds().unwrap(),
        )
        .unwrap();
        let confirmed = client.poll(&claimed).unwrap();
        listener.stop();

        let state = node.store.state().unwrap();
        let pending = &state.reference.pending[0];
        assert_eq!(claimed.sas, pending.sas_code);
        assert_eq!(confirmed.pending_id, pending.pending_id);
        assert_eq!(confirmed.grant_id, state.reference.grants[0].grant_id);
        assert_eq!(confirmed.responder_static, *node.key().public());
        assert_eq!(confirmed.initiator_static, *receiver.public());
    }

    /// Acceptance (2): a null `bindHost` (the initial state) is an error
    /// and nothing listens on the stored port.
    #[test]
    fn a_null_bind_host_binds_nothing() {
        let node = Node::new();
        let config = node.store.state().unwrap().config;
        assert_eq!(config.bind_host, None);
        assert_eq!(
            node.start(Arc::default()).err(),
            Some(ListenerError::NotConfigured)
        );
        assert!(refused(config.bind_port));
    }

    /// Acceptance (3), end to end: `0x0` and `localhost` are accepted by
    /// the store, but the listener refuses them and binds nothing (handed
    /// to the OS resolver as a string, `0x0` would bind every interface).
    #[test]
    fn a_stored_0x0_or_hostname_is_refused_before_binding() {
        for host in ["0x0", "localhost"] {
            let node = Node::new();
            let port = free_port();
            node.configure(host, port).unwrap();
            assert_eq!(
                node.store.state().unwrap().config.bind_host.as_deref(),
                Some(host)
            );
            assert_eq!(
                node.start(Arc::default()).err(),
                Some(ListenerError::InvalidAddress),
                "{host}"
            );
            assert!(refused(port), "{host}");
        }
    }

    /// Acceptance (4): a port in use is an error; no other port is tried.
    #[test]
    fn a_port_in_use_is_an_error_without_fallback() {
        let node = Node::new();
        let occupied = TcpListener::bind((LOOPBACK, 0)).unwrap();
        let port = occupied.local_addr().unwrap().port();
        node.configure(LOOPBACK, port).unwrap();
        assert_eq!(node.start(Arc::default()).err(), Some(ListenerError::Bind));
        drop(occupied);
    }

    /// Acceptance (5): with 8 connections stalled in the handshake, a 9th
    /// is closed at once while the 8 stay open; once one of them closes,
    /// a new connection is admitted.
    #[test]
    fn a_ninth_concurrent_connection_is_closed_and_a_freed_slot_is_reused() {
        let node = Node::new();
        node.configure(LOOPBACK, free_port()).unwrap();
        let mut listener = node.start(Arc::default()).unwrap();
        let address = listener.local_addr();
        let mut held = stalled(address, MAX_CONNECTIONS);
        assert_eq!(MAX_CONNECTIONS, 8);

        let started = Instant::now();
        let mut ninth = TcpStream::connect(address).unwrap();
        assert!(closed_within(&mut ninth, Duration::from_secs(3)));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );

        // The 8 are still open well into their 10 s handshake deadline.
        thread::sleep(Duration::from_secs(1));
        for (n, stream) in held.iter_mut().enumerate() {
            assert!(!closed_within(stream, Duration::from_millis(100)), "{n}");
        }

        drop(held.remove(0));
        let admitted = (0..20).any(|_| {
            let mut stream = TcpStream::connect(address).unwrap();
            !closed_within(&mut stream, Duration::from_millis(300))
        });
        assert!(admitted, "the freed slot was never reused");
        listener.stop();
    }

    /// Acceptance (6): each connection reads the identity as it is then.
    /// After a reset, the next handshake pinned to the new key succeeds and
    /// one pinned to the old key fails.
    #[test]
    fn the_connection_after_a_reset_uses_the_new_identity() {
        let node = Node::new();
        node.configure(LOOPBACK, free_port()).unwrap();
        let mut listener = node.start(Arc::default()).unwrap();
        let port = listener.local_addr().port();
        let receiver = StaticKey::generate().unwrap();
        let old = *node.key().public();
        assert!(noise::connect(LOOPBACK, port, &receiver, &old).is_ok());

        node.store.reset(NOW + 10, (NOW + 10) * 1_000).unwrap();
        let new = *node.key().public();
        assert_ne!(new, old);
        assert!(noise::connect(LOOPBACK, port, &receiver, &new).is_ok());
        assert!(noise::connect(LOOPBACK, port, &receiver, &old).is_err());
        listener.stop();
    }

    /// Acceptance (7): `stop` with 8 connections stalled in the handshake
    /// returns within 1 s, closes them, and the port refuses afterwards.
    #[test]
    fn stop_closes_stalled_handshakes_and_returns_within_a_second() {
        let node = Node::new();
        node.configure(LOOPBACK, free_port()).unwrap();
        let mut listener = node.start(Arc::default()).unwrap();
        let address = listener.local_addr();
        let mut held = stalled(address, MAX_CONNECTIONS);

        let started = Instant::now();
        listener.stop();
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        for (n, stream) in held.iter_mut().enumerate() {
            assert!(closed_within(stream, Duration::from_millis(500)), "{n}");
        }
        assert!(refused(address.port()));
    }
}
