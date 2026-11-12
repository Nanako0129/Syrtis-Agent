//! SA-2B2b1 acceptance: the producer's peer report service
//! (`src/report_peer.rs`, `spec/report-peer-v1.md`), end to end through the
//! product `Listener` over real loopback sockets. The test client is
//! written by hand over `noise::connect` and frames; the receiver's
//! `fetch` is `SA-2B2b2`.
//!
//! Every test here needs a secure root, so they run on macOS and Linux
//! only: Windows fails closed (`tests/runtime_storage_v1.rs`). The
//! per-grant limit, the compute slot and the code numbering have unit
//! tests in `src/report_peer.rs` that run on all three platforms; so does
//! nothing else, because the report path reads the store. Acceptance (6),
//! which needs a test-only seam inside `authorize_then`, is a unit test
//! there too. Every listener binds 127.0.0.1 only.

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod disk {
    use std::{
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicI64, AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use serde_json::json;
    use syrtis_agent::{
        canonical::CanonicalJsonV1,
        listener::Listener,
        noise::{self, Deadline, StaticKey},
        pairing::{Claimed, Clock, PairingClient, RateLimiter, approve},
        report::{
            AgentsRecord, GraphRecord, HourlyRecord, ModelsRecord, ReportRecord, ReportRequest,
            ReportResponse, decode_response, encode_response,
        },
        report_peer::{GRANT_REFILL, ReportSource, Reports, SourceError},
        secure_fs::{SecureRoot, StorageError},
        security::{
            FRAME_PAYLOAD_MAX, Frame, FrameKind, GrantState, LOGICAL_BODY_MAX, MemoryLedger, Offer,
            OfferClaim, OfferState, REMOTE_MEMORY_MAX, assemble_response, hex_encode,
            offer_secret_hash,
        },
        state_store::{AuthorizationQuery, StateStore},
    };

    const NOW: i64 = 1_700_000_000;
    const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];
    const LOOPBACK: &str = "127.0.0.1";
    const REQUEST_ID: [u8; 16] = [0x5a; 16];
    const LONG: Duration = Duration::from_secs(20);

    // ------------------------------------------------------------ harness

    /// Injected time: monotonic and OS wall clock set by the test.
    struct TestClock {
        mono: Mutex<Duration>,
        os: AtomicI64,
    }

    impl TestClock {
        fn advance(&self, by: Duration) {
            *self.mono.lock().unwrap() += by;
        }

        fn set_os(&self, seconds: i64) {
            self.os.store(seconds, Ordering::SeqCst);
        }

        fn os(&self) -> i64 {
            self.os.load(Ordering::SeqCst)
        }
    }

    impl Clock for TestClock {
        fn monotonic(&self) -> Duration {
            *self.mono.lock().unwrap()
        }

        fn os_now_seconds(&self) -> Result<i64, StorageError> {
            Ok(self.os())
        }

        fn sleep(&self, duration: Duration) {
            self.advance(duration);
        }
    }

    type SourceFn = dyn Fn(&ReportRequest) -> Result<Vec<u8>, SourceError> + Send + Sync;

    struct FnSource(Box<SourceFn>);

    impl ReportSource for FnSource {
        fn report(&self, request: &ReportRequest, _: Instant) -> Result<Vec<u8>, SourceError> {
            (self.0)(request)
        }
    }

    /// A temporary home. Only directories this helper created are removed.
    struct TempHome(PathBuf);

    impl TempHome {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "syrtis-agent-report-{}-{}",
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

    /// A producer agent, sharing on, served by the product listener on
    /// 127.0.0.1 with `source`.
    struct Node {
        listener: Listener,
        store: Arc<StateStore>,
        clock: Arc<TestClock>,
        ledger: MemoryLedger,
        responder: [u8; 32],
        _home: TempHome,
    }

    /// One grant this node issued to `key`.
    #[derive(Clone, Copy)]
    struct Granted {
        grant_id: [u8; 16],
        pending_id: [u8; 16],
        auth_epoch: u64,
        source_scope_generation: u64,
        expires_at_ms: i64,
    }

    impl Node {
        fn new(
            source: impl Fn(&ReportRequest) -> Result<Vec<u8>, SourceError> + Send + Sync + 'static,
        ) -> Self {
            let home = TempHome::new();
            let store =
                retry_busy(|| StateStore::open(SecureRoot::open_under(&home.0, SUFFIX)?, NOW))
                    .unwrap();
            store.transition(|state| state.enable_sharing()).unwrap();
            let port = TcpListener::bind((LOOPBACK, 0))
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            store
                .set_listen_config(Some(LOOPBACK.into()), port, None)
                .unwrap();
            let store = Arc::new(store);
            let clock = Arc::new(TestClock {
                mono: Mutex::new(Duration::from_secs(1_000)),
                os: AtomicI64::new(NOW),
            });
            let ledger = MemoryLedger::default();
            let listener = Listener::start(
                Arc::clone(&store),
                ledger.clone(),
                Arc::new(RateLimiter::default()),
                Arc::clone(&clock) as Arc<dyn Clock>,
                Arc::new(Reports::new(Arc::new(FnSource(Box::new(source))))),
            )
            .unwrap();
            let responder = *StaticKey::from_state(&store.state().unwrap())
                .unwrap()
                .public();
            Self {
                listener,
                store,
                clock,
                ledger,
                responder,
                _home: home,
            }
        }

        fn port(&self) -> u16 {
            self.listener.local_addr().port()
        }

        /// Grant `n` to `key`, through the frozen offer, claim and approve
        /// transitions at the current OS clock.
        fn grant(&self, n: u8, key: &StaticKey) -> Granted {
            let os_now = self.clock.os();
            let (offer_id, secret, pending_id) = ([n; 16], [n; 32], [0x80 | n; 16]);
            let responder = self.responder;
            self.store
                .transition(|state| {
                    state
                        .create_offer(
                            Offer {
                                offer_id,
                                secret_hash: offer_secret_hash(&offer_id, &secret, &responder),
                                created_at_ms: os_now * 1_000,
                                expires_at_ms: os_now * 1_000 + 600_000,
                                state: OfferState::Active,
                            },
                            os_now,
                        )?
                        .claim_offer(
                            OfferClaim {
                                offer_id,
                                secret,
                                responder_static: responder,
                                pending_id,
                                initiator_static: *key.public(),
                                sas_code: "0A1B-2C3D".into(),
                                sas_generation: 1,
                            },
                            os_now,
                        )
                        .map(|(next, _, _)| next)
                })
                .unwrap();
            let grant_id = approve(&self.store, pending_id, 1, true, os_now).unwrap();
            self.granted(grant_id, pending_id)
        }

        /// The grant's fields as the store holds them now.
        fn granted(&self, grant_id: [u8; 16], pending_id: [u8; 16]) -> Granted {
            let grant = self.grant_state(grant_id);
            Granted {
                grant_id,
                pending_id,
                auth_epoch: grant.auth_epoch,
                source_scope_generation: grant.source_scope_generation,
                expires_at_ms: grant.expires_at_ms,
            }
        }

        fn grant_state(&self, grant_id: [u8; 16]) -> syrtis_agent::security::Grant {
            self.store
                .state()
                .unwrap()
                .reference
                .grants
                .into_iter()
                .find(|grant| grant.grant_id == grant_id)
                .unwrap()
        }

        fn fetch(&self, key: &StaticKey, request: &ReportRequest) -> Vec<Frame> {
            fetch_raw(
                self.port(),
                key,
                &self.responder,
                REQUEST_ID,
                CanonicalJsonV1::encode(request).unwrap(),
            )
        }

        /// Moves the OS clock and the durable wall to `target` through
        /// checkpoints of at most a day each, so no step is a clock anomaly.
        fn advance_wall_to(&self, target: i64) {
            let mut wall = self.clock.os();
            while wall < target {
                wall = (wall + 86_400).min(target);
                self.clock.set_os(wall);
                self.store.checkpoint(wall).unwrap();
            }
        }

        /// Waits until every connection has returned its reservation.
        fn ledger_at_baseline(&self) {
            let until = Instant::now() + LONG;
            while self.ledger.used() != 0 {
                assert!(
                    Instant::now() < until,
                    "ledger stuck at {}",
                    self.ledger.used()
                );
                thread::sleep(Duration::from_millis(10));
            }
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

    /// One request frame over a real handshake, then every frame until the
    /// producer closes (or 20 s pass).
    fn fetch_raw(
        port: u16,
        key: &StaticKey,
        responder: &[u8; 32],
        request_id: [u8; 16],
        payload: Vec<u8>,
    ) -> Vec<Frame> {
        let mut session = noise::connect(LOOPBACK, port, key, responder).unwrap();
        session
            .send(&request_frame(request_id, payload), Deadline::after(LONG))
            .unwrap();
        let ledger = MemoryLedger::default();
        let mut frames = Vec::new();
        while let Ok(received) = session.receive(&ledger, Deadline::after(LONG)) {
            frames.push(received.frame().clone());
        }
        frames
    }

    fn request_frame(request_id: [u8; 16], payload: Vec<u8>) -> Frame {
        Frame {
            kind: FrameKind::Request,
            final_chunk: true,
            request_id,
            chunk_index: 0,
            chunk_count: 1,
            payload,
        }
    }

    fn request(granted: &Granted, endpoint: u16) -> ReportRequest {
        ReportRequest {
            aggregation_revision: 1,
            auth_epoch: granted.auth_epoch,
            clients: vec!["claude".into(), "codex".into()],
            end_date_exclusive: "2025-02-01".into(),
            endpoint,
            grant_id: hex_encode(&granted.grant_id),
            protocol: 1,
            report_schema: 1,
            request_id: hex_encode(&REQUEST_ID),
            source_scope_generation: granted.source_scope_generation,
            start_date: "2025-01-01".into(),
            timezone: "America/Los_Angeles".into(),
            tzdb_revision: "2026c".into(),
        }
    }

    fn error_payload(code: u16) -> Vec<u8> {
        CanonicalJsonV1::encode(&json!({"code": code, "protocol": 1})).unwrap()
    }

    /// The one error frame of a refused request; its payload.
    fn refused(frames: &[Frame]) -> Vec<u8> {
        assert_eq!(frames.len(), 1, "{} frames", frames.len());
        assert_eq!(frames[0].kind, FrameKind::Error);
        assert_eq!(frames[0].request_id, REQUEST_ID);
        frames[0].payload.clone()
    }

    fn complete(frames: &[Frame]) -> Vec<u8> {
        assert!(!frames.is_empty());
        assert_eq!(
            frames[0].kind,
            FrameKind::Response,
            "{:?}",
            frames[0].payload
        );
        assemble_response(frames).unwrap()
    }

    // ------------------------------------------------------------- bodies

    fn fixture<R: ReportRecord>(bytes: &[u8]) -> Vec<R> {
        let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        decode_response::<R>(bytes, None).unwrap().records
    }

    /// 1,000 graph records: a body of several chunks.
    fn graph_records() -> Vec<GraphRecord> {
        (0..1_000_u64)
            .map(|n| GraphRecord {
                date: "2025-01-02".into(),
                client: "claude".into(),
                model: Some(format!("model-{n:05}")),
                provider: Some("anthropic".into()),
                input_tokens: n,
                output_tokens: n + 1,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                reasoning_tokens: 0,
                total_tokens: 2 * n + 1,
                message_count: 1,
                turn_count: 1,
                cost_nano_usd: n,
            })
            .collect()
    }

    fn models_records() -> Vec<ModelsRecord> {
        fixture(include_bytes!("fixtures/v1/report/models.json"))
    }

    fn hourly_records() -> Vec<HourlyRecord> {
        fixture(include_bytes!("fixtures/v1/report/hourly.json"))
    }

    fn agents_records() -> Vec<AgentsRecord> {
        fixture(include_bytes!("fixtures/v1/report/agents.json"))
    }

    fn body_for<R: ReportRecord>(request: &ReportRequest, records: Vec<R>) -> Vec<u8> {
        encode_response(&ReportResponse::from_request(request, records, false)).unwrap()
    }

    /// The stub: the canonical response for each endpoint, echoing the
    /// request.
    fn canonical(request: &ReportRequest) -> Result<Vec<u8>, SourceError> {
        Ok(match request.endpoint {
            1 => body_for(request, graph_records()),
            2 => body_for(request, models_records()),
            3 => body_for(request, hourly_records()),
            4 => body_for(request, agents_records()),
            _ => return Err(SourceError),
        })
    }

    // -------------------------------------------------------------- tests

    /// Acceptance (1): each of the four endpoints once; the graph body is
    /// larger than one frame. The client reassembles with the frozen
    /// `assemble_response` and decodes with the frozen `decode_response`
    /// against its own request.
    #[test]
    fn four_endpoints_are_served_and_decode_to_the_stub_records() {
        let node = Node::new(canonical);
        let key = StaticKey::generate().unwrap();
        let granted = node.grant(1, &key);

        fn check<R: ReportRecord>(node: &Node, key: &StaticKey, request: ReportRequest) -> usize {
            node.clock.advance(GRANT_REFILL);
            let frames = node.fetch(key, &request);
            let body = complete(&frames);
            let response = decode_response::<R>(&body, Some(&request)).unwrap();
            let expected: ReportResponse<R> =
                CanonicalJsonV1::decode(&canonical(&request).unwrap()).unwrap();
            assert_eq!(response.records, expected.records);
            assert!(frames.iter().all(|frame| frame.request_id == REQUEST_ID));
            body.len()
        }
        let graph = check::<GraphRecord>(&node, &key, request(&granted, 1));
        assert!(graph > FRAME_PAYLOAD_MAX, "{graph}");
        check::<ModelsRecord>(&node, &key, request(&granted, 2));
        check::<HourlyRecord>(&node, &key, request(&granted, 3));
        check::<AgentsRecord>(&node, &key, request(&granted, 4));
        node.ledger_at_baseline();
    }

    /// Acceptance (2): an unknown grant, a foreign static (another paired
    /// key with someone else's grant ID), a wrong `authEpoch`, a wrong
    /// `sourceScopeGeneration` and an endpoint out of scope all send the
    /// same `unauthorized` payload.
    #[test]
    fn five_unauthorized_causes_send_byte_identical_payloads() {
        let node = Node::new(canonical);
        let (alice, bob) = (
            StaticKey::generate().unwrap(),
            StaticKey::generate().unwrap(),
        );
        let a = node.grant(1, &alice);
        node.grant(2, &bob);
        let unknown = Granted {
            grant_id: [0x77; 16],
            ..a
        };
        let cases = [
            ("unknown grant", &alice, request(&unknown, 1)),
            ("foreign static", &bob, request(&a, 1)),
            (
                "authEpoch",
                &alice,
                request(
                    &Granted {
                        auth_epoch: a.auth_epoch + 1,
                        ..a
                    },
                    1,
                ),
            ),
            (
                "sourceScopeGeneration",
                &alice,
                request(
                    &Granted {
                        source_scope_generation: a.source_scope_generation + 1,
                        ..a
                    },
                    1,
                ),
            ),
            ("endpoint", &alice, request(&a, 5)),
        ];
        for (label, key, request) in cases {
            assert_eq!(
                refused(&node.fetch(key, &request)),
                error_payload(2),
                "{label}"
            );
        }
        // Control: the same grant, its own static and fields, is served.
        complete(&node.fetch(&alice, &request(&a, 1)));
    }

    /// Acceptance (3): a foreign static naming a revoked grant is
    /// `unauthorized`, while the bound static learns `revoked`.
    #[test]
    fn a_foreign_static_on_a_revoked_grant_is_unauthorized() {
        let node = Node::new(canonical);
        let (alice, bob) = (
            StaticKey::generate().unwrap(),
            StaticKey::generate().unwrap(),
        );
        let a = node.grant(1, &alice);
        node.grant(2, &bob);
        node.store
            .transition(|state| state.revoke_commit(a.grant_id, NOW * 1_000))
            .unwrap();
        assert_eq!(
            refused(&node.fetch(&bob, &request(&a, 1))),
            error_payload(2)
        );
        // Control: the bound static is told.
        assert_eq!(
            refused(&node.fetch(&alice, &request(&a, 1))),
            error_payload(4)
        );
    }

    /// Acceptance (4): after a revoke, a disable or a source change the
    /// bound static gets `revoked`; at expiry it gets `expired`, and the
    /// stored grant becomes `expired`.
    #[test]
    fn revoke_disable_and_source_change_are_revoked_and_expiry_is_expired() {
        type Change = fn(&Node, &Granted);
        let changes: [(&str, Change); 3] = [
            ("revoke", |node, granted| {
                node.store
                    .transition(|state| state.revoke_commit(granted.grant_id, NOW * 1_000))
                    .unwrap();
            }),
            ("disable", |node, _| {
                node.store.disable(NOW * 1_000).unwrap()
            }),
            ("source change", |node, _| {
                node.store
                    .transition(|state| state.source_change_commit())
                    .unwrap();
            }),
        ];
        for (label, change) in changes {
            let node = Node::new(canonical);
            let key = StaticKey::generate().unwrap();
            let granted = node.grant(1, &key);
            complete(&node.fetch(&key, &request(&granted, 1)));
            change(&node, &granted);
            assert_eq!(
                refused(&node.fetch(&key, &request(&granted, 1))),
                error_payload(4),
                "{label}"
            );
        }

        let node = Node::new(canonical);
        let key = StaticKey::generate().unwrap();
        let granted = node.grant(1, &key);
        node.advance_wall_to(granted.expires_at_ms / 1_000);
        assert_eq!(
            refused(&node.fetch(&key, &request(&granted, 1))),
            error_payload(3)
        );
        assert_eq!(
            node.grant_state(granted.grant_id).state,
            GrantState::Expired
        );
    }

    /// Acceptance (5): revoking A renumbers B. B's request with its old
    /// epoch is `unauthorized`, not `revoked`; after Grant status gives B
    /// its new epoch, B is served.
    #[test]
    fn revoking_another_grant_leaves_a_stale_epoch_unauthorized_not_revoked() {
        let node = Node::new(canonical);
        let (alice, bob) = (
            StaticKey::generate().unwrap(),
            StaticKey::generate().unwrap(),
        );
        let a = node.grant(1, &alice);
        let b = node.grant(2, &bob);
        node.store
            .transition(|state| state.revoke_commit(a.grant_id, NOW * 1_000))
            .unwrap();
        assert_eq!(
            refused(&node.fetch(&bob, &request(&b, 1))),
            error_payload(2)
        );

        let ledger = MemoryLedger::default();
        let client = PairingClient {
            identity: &bob,
            ledger: &ledger,
            clock: &*node.clock,
        };
        let claimed = Claimed {
            offer_id: [2; 16],
            responder_static: node.responder,
            host: LOOPBACK.into(),
            port: node.port(),
            pending_id: b.pending_id,
            sas: String::new(),
            expires_at_ms: 0,
            claimed_at: Duration::ZERO,
        };
        let answer = client.grant_status(&claimed, b.grant_id).unwrap();
        assert!(answer.auth_epoch > b.auth_epoch);
        let renewed = Granted {
            auth_epoch: answer.auth_epoch,
            source_scope_generation: answer.source_scope_generation,
            ..b
        };
        complete(&node.fetch(&bob, &request(&renewed, 1)));
    }

    /// Acceptance (7): a body near 16 MiB to a client that reads nothing.
    /// The producer gives up after one chunk's 2 s write deadline and
    /// closes; a revoke then returns at once. Prints the measured time.
    #[test]
    fn a_client_that_stops_reading_is_dropped_after_one_chunk_deadline() {
        const BODY: usize = LOGICAL_BODY_MAX - 1_000;
        let called = Arc::new(Mutex::new(None::<Instant>));
        let mark = Arc::clone(&called);
        let node = Node::new(move |_| {
            *mark.lock().unwrap() = Some(Instant::now());
            Ok(vec![b'x'; BODY])
        });
        let key = StaticKey::generate().unwrap();
        let granted = node.grant(1, &key);

        let mut session = noise::connect(LOOPBACK, node.port(), &key, &node.responder).unwrap();
        let payload = CanonicalJsonV1::encode(&request(&granted, 1)).unwrap();
        session
            .send(&request_frame(REQUEST_ID, payload), Deadline::after(LONG))
            .unwrap();
        let until = Instant::now() + LONG;
        while node.ledger.used() < BODY {
            assert!(Instant::now() < until, "the body was never reserved");
            thread::sleep(Duration::from_millis(1));
        }
        node.ledger_at_baseline();
        let dropped = Instant::now();
        let elapsed = dropped - called.lock().unwrap().unwrap();
        eprintln!("acceptance (7): producer closed {elapsed:?} after the source returned");
        assert!(elapsed >= Duration::from_secs(2), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");

        let started = Instant::now();
        node.store
            .transition(|state| state.revoke_commit(granted.grant_id, NOW * 1_000))
            .unwrap();
        let revoke = started.elapsed();
        eprintln!("acceptance (7): revoke afterwards took {revoke:?}");
        assert!(revoke < Duration::from_secs(1), "{revoke:?}");

        // What reached the client is an incomplete response.
        let ledger = MemoryLedger::default();
        let mut frames = 0;
        while session.receive(&ledger, Deadline::after(LONG)).is_ok() {
            frames += 1;
        }
        assert!(frames < BODY.div_ceil(FRAME_PAYLOAD_MAX), "{frames}");
    }

    /// Acceptance (8): a grant gets two requests at once, then one per
    /// 60 s of injected monotonic time; a second request of a grant whose
    /// first is still being sent is `busy`, while another grant is served.
    #[test]
    fn the_grant_limit_is_two_then_one_a_minute_and_one_in_flight() {
        const BIG: usize = LOGICAL_BODY_MAX - 1_000;
        let node = Node::new(|request| {
            if request.endpoint == 2 {
                Ok(vec![b'x'; BIG])
            } else {
                canonical(request)
            }
        });
        let key = StaticKey::generate().unwrap();
        let a = node.grant(1, &key);
        complete(&node.fetch(&key, &request(&a, 1)));
        complete(&node.fetch(&key, &request(&a, 1)));
        assert_eq!(
            refused(&node.fetch(&key, &request(&a, 1))),
            error_payload(5)
        );
        node.clock.advance(Duration::from_secs(59));
        assert_eq!(
            refused(&node.fetch(&key, &request(&a, 1))),
            error_payload(5)
        );
        node.clock.advance(Duration::from_secs(1));
        complete(&node.fetch(&key, &request(&a, 1)));

        // In flight: B's first response is stuck in a chunk write (the
        // client reads nothing); the compute slot is free again.
        let (bob, carol) = (
            StaticKey::generate().unwrap(),
            StaticKey::generate().unwrap(),
        );
        let b = node.grant(2, &bob);
        let c = node.grant(3, &carol);
        let mut stuck = noise::connect(LOOPBACK, node.port(), &bob, &node.responder).unwrap();
        stuck
            .send(
                &request_frame(
                    REQUEST_ID,
                    CanonicalJsonV1::encode(&request(&b, 2)).unwrap(),
                ),
                Deadline::after(LONG),
            )
            .unwrap();
        let until = Instant::now() + LONG;
        while node.ledger.used() < BIG {
            assert!(Instant::now() < until, "the body was never reserved");
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            refused(&node.fetch(&bob, &request(&b, 1))),
            error_payload(5)
        );
        // Control: another grant is served meanwhile.
        complete(&node.fetch(&carol, &request(&c, 1)));
        drop(stuck);
        node.ledger_at_baseline();
    }

    /// Acceptance (9): while the source computes, another grant is `busy`;
    /// past the 120 s deadline the slot is still held; when the source
    /// returns, its result is discarded as `internal` and the slot is free.
    #[test]
    fn the_compute_slot_is_held_until_the_source_returns() {
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let gate = Mutex::new((entered_tx, release_rx));
        let node = Node::new(move |request| {
            if request.endpoint == 2 {
                let gate = gate.lock().unwrap();
                gate.0.send(()).unwrap();
                // Bounded, so a failed assertion below (which drops the
                // listener, joining this thread) fails instead of hanging.
                let _ = gate.1.recv_timeout(LONG);
            }
            canonical(request)
        });
        let (alice, bob) = (
            StaticKey::generate().unwrap(),
            StaticKey::generate().unwrap(),
        );
        let a = node.grant(1, &alice);
        let b = node.grant(2, &bob);
        let (port, responder) = (node.port(), node.responder);
        let slow = thread::spawn(move || {
            let payload = CanonicalJsonV1::encode(&request(&a, 2)).unwrap();
            fetch_raw(port, &alice, &responder, REQUEST_ID, payload)
        });
        entered_rx.recv_timeout(LONG).unwrap();
        assert_eq!(
            refused(&node.fetch(&bob, &request(&b, 1))),
            error_payload(5)
        );
        node.clock.advance(Duration::from_secs(121));
        assert_eq!(
            refused(&node.fetch(&bob, &request(&b, 1))),
            error_payload(5)
        );
        release_tx.send(()).unwrap();
        assert_eq!(refused(&slow.join().unwrap()), error_payload(8));
        complete(&node.fetch(&bob, &request(&b, 1)));
        node.ledger_at_baseline();
    }

    /// Acceptance (10): a source error, an empty body and a body over
    /// 16 MiB are `internal` with no chunk; a full ledger is `busy`; every
    /// path returns the ledger to its baseline.
    #[test]
    fn source_failures_are_internal_and_a_full_ledger_is_busy() {
        #[derive(Clone, Copy)]
        enum Mode {
            Fail,
            Empty,
            Oversize,
            Large,
        }
        let mode = Arc::new(Mutex::new(Mode::Fail));
        let current = Arc::clone(&mode);
        let node = Node::new(move |_| match *current.lock().unwrap() {
            Mode::Fail => Err(SourceError),
            Mode::Empty => Ok(Vec::new()),
            Mode::Oversize => Ok(vec![b'x'; LOGICAL_BODY_MAX + 1]),
            Mode::Large => Ok(vec![b'x'; 2 * 1024 * 1024]),
        });
        let key = StaticKey::generate().unwrap();
        let granted = node.grant(1, &key);
        for (label, case) in [
            ("source error", Mode::Fail),
            ("empty", Mode::Empty),
            ("over 16 MiB", Mode::Oversize),
        ] {
            *mode.lock().unwrap() = case;
            node.clock.advance(GRANT_REFILL);
            assert_eq!(
                refused(&node.fetch(&key, &request(&granted, 1))),
                error_payload(8),
                "{label}"
            );
            node.ledger_at_baseline();
        }
        *mode.lock().unwrap() = Mode::Large;
        let held = node
            .ledger
            .reserve(REMOTE_MEMORY_MAX - 1024 * 1024)
            .unwrap();
        node.clock.advance(GRANT_REFILL);
        assert_eq!(
            refused(&node.fetch(&key, &request(&granted, 1))),
            error_payload(5)
        );
        drop(held);
        node.ledger_at_baseline();
        // Control: with room, the same body is sent.
        node.clock.advance(GRANT_REFILL);
        assert_eq!(
            complete(&node.fetch(&key, &request(&granted, 1))).len(),
            2 * 1024 * 1024
        );
        node.ledger_at_baseline();
    }

    /// Acceptance (11): a payload `requestId` other than the header's, and
    /// each reachable `ReportRequest::validate` rule, are `invalid`; a Peer
    /// request between 4,097 and 61,402 bytes reaches the report path,
    /// while each pairing surface at 4,097 bytes is still `invalid`.
    #[test]
    fn malformed_report_requests_are_invalid_and_only_pairing_is_capped_at_4096() {
        let node = Node::new(canonical);
        let key = StaticKey::generate().unwrap();
        let granted = node.grant(1, &key);
        let base = request(&granted, 1);

        let mut other_id = base.clone();
        other_id.request_id = hex_encode(&[0x11; 16]);
        assert_eq!(refused(&node.fetch(&key, &other_id)), error_payload(1));

        type Breach = fn(&mut ReportRequest);
        let breaches: [(&str, Breach); 11] = [
            ("aggregationRevision", |r| r.aggregation_revision = 2),
            ("reportSchema", |r| r.report_schema = 2),
            ("tzdbRevision", |r| r.tzdb_revision = "2026b".into()),
            ("startDate", |r| r.start_date = "2025-13-01".into()),
            ("endDateExclusive", |r| {
                r.end_date_exclusive = "2025-01-01".into()
            }),
            ("range over 370 days", |r| {
                r.end_date_exclusive = "2026-01-07".into()
            }),
            ("empty timezone", |r| r.timezone = String::new()),
            ("unsorted clients", |r| {
                r.clients = vec!["codex".into(), "claude".into()]
            }),
            ("duplicate clients", |r| {
                r.clients = vec!["claude".into(), "claude".into()]
            }),
            ("empty client", |r| r.clients = vec![String::new()]),
            ("129 clients", |r| {
                r.clients = (0..129).map(|n| format!("c{n:03}")).collect()
            }),
        ];
        for (label, breach) in breaches {
            let mut request = base.clone();
            breach(&mut request);
            assert_eq!(
                refused(&node.fetch(&key, &request)),
                error_payload(1),
                "{label}"
            );
        }
        // `protocol` is checked at dispatch: another integer is
        // `incompatible`.
        let mut other_protocol = base.clone();
        other_protocol.protocol = 2;
        assert_eq!(
            refused(&node.fetch(&key, &other_protocol)),
            error_payload(6)
        );

        // A Peer request over 4,096 bytes reaches the report path.
        let mut large = base.clone();
        // Sorted: digits sort before `claude`, the stub records' client.
        large.clients = (0..30)
            .map(|n| format!("{n:03}{}", "c".repeat(200)))
            .chain(["claude".to_owned()])
            .collect();
        let size = CanonicalJsonV1::encode(&large).unwrap().len();
        assert!((4_097..=FRAME_PAYLOAD_MAX).contains(&size), "{size}");
        complete(&node.fetch(&key, &large));

        // The three pairing surfaces keep the 4,096-byte cap. Each payload
        // is canonical with `protocol: 2`, so only the cap makes 4,097
        // bytes `invalid`; at 4,096 bytes it is `incompatible`.
        let padded = |keys: &[&str], size: usize| {
            let shape = |fill: &str| {
                // Only the first key carries the padding.
                let mut object = serde_json::Map::new();
                for (n, key) in keys.iter().enumerate() {
                    object.insert((*key).into(), if n == 0 { fill } else { "" }.into());
                }
                object.insert("protocol".into(), 2.into());
                CanonicalJsonV1::encode(&object).unwrap()
            };
            let pad = size - shape("").len();
            let bytes = shape(&"a".repeat(pad));
            assert_eq!(bytes.len(), size);
            bytes
        };
        let surfaces: [&[&str]; 3] = [&["offerId", "secret"], &["pendingId"], &["grantId"]];
        for keys in surfaces {
            for (size, code) in [(4_097, 1), (4_096, 6)] {
                // The pairing limiter admits a static once per second.
                node.clock.advance(Duration::from_secs(1));
                let frames = fetch_raw(
                    node.port(),
                    &key,
                    &node.responder,
                    REQUEST_ID,
                    padded(keys, size),
                );
                assert_eq!(refused(&frames), error_payload(code), "{keys:?} {size}");
            }
        }
    }

    /// Acceptance (12): `authorize_then` does not call `f` when the
    /// predicate is false; with two threads taking turns holding the read
    /// lock about 1 s each, a revoke still returns within one chunk's
    /// deadline plus margin.
    #[test]
    fn authorize_then_skips_a_refused_query_and_a_revoke_is_not_starved() {
        let node = Node::new(canonical);
        let key = StaticKey::generate().unwrap();
        let granted = node.grant(1, &key);
        let query = AuthorizationQuery {
            grant_id: granted.grant_id,
            auth_epoch: granted.auth_epoch,
            source_scope_generation: granted.source_scope_generation,
            endpoint: 1,
            os_now_unix_seconds: NOW,
        };
        let stale = AuthorizationQuery {
            auth_epoch: granted.auth_epoch + 1,
            ..query
        };
        let mut called = false;
        assert_eq!(node.store.authorize_then(&stale, || called = true), None);
        assert!(!called);
        assert_eq!(node.store.authorize_then(&query, || 7), Some(7));

        let readers: Vec<_> = (0..2_u64)
            .map(|n| {
                let store = Arc::clone(&node.store);
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(500 * n));
                    let until = Instant::now() + Duration::from_secs(10);
                    let mut held = 0;
                    while Instant::now() < until
                        && store
                            .authorize_then(&query, || thread::sleep(Duration::from_secs(1)))
                            .is_some()
                    {
                        held += 1;
                    }
                    held
                })
            })
            .collect();
        thread::sleep(Duration::from_millis(1_700));
        let started = Instant::now();
        node.store
            .transition(|state| state.revoke_commit(granted.grant_id, NOW * 1_000))
            .unwrap();
        let elapsed = started.elapsed();
        eprintln!("acceptance (12): revoke waited {elapsed:?}");
        let held: Vec<u32> = readers.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(held.iter().all(|held| *held >= 1), "{held:?}");
        assert!(
            elapsed < Duration::from_secs(3),
            "revoke waited {elapsed:?}"
        );
    }

    /// Acceptance (13): once a checkpoint has moved the durable wall past
    /// `expiresAt`, an OS clock moved back is still `expired`: within the
    /// rollback tolerance by the effective now, and beyond it (a clock
    /// anomaly) because the first answer persisted the expiry.
    #[test]
    fn after_expiry_a_clock_moved_back_is_still_expired() {
        let node = Node::new(canonical);
        let key = StaticKey::generate().unwrap();
        let granted = node.grant(1, &key);
        let target = granted.expires_at_ms / 1_000 + 10;
        node.advance_wall_to(target);
        // Earlier than `expiresAt`, within the 300 s rollback tolerance.
        node.clock.set_os(target - 110);
        assert_eq!(
            refused(&node.fetch(&key, &request(&granted, 1))),
            error_payload(3)
        );
        assert_eq!(
            node.grant_state(granted.grant_id).state,
            GrantState::Expired
        );
        // Far back: a clock anomaly. Still `expired`, from the stored state.
        node.clock.set_os(NOW);
        assert_eq!(
            refused(&node.fetch(&key, &request(&granted, 1))),
            error_payload(3)
        );
    }
}
