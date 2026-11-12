//! SA-2B2c1 acceptance: the local control wire (`src/control.rs`,
//! `spec/control-v1.md`) over real Unix domain sockets, through the public
//! API.
//!
//! Every test needs a secure root, so they run on macOS and Linux only:
//! Windows fails closed (`tests/runtime_storage_v1.rs`). Homes live in
//! `/tmp` with short names so the socket path fits `sun_path`. The other-UID
//! refusal (acceptance 5) is a unit test in `src/control.rs`; the real
//! cross-UID refusal is not observable here. TCP listeners bind 127.0.0.1.

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod disk {
    use std::{
        fs,
        io::{ErrorKind, Read, Write},
        net::TcpListener,
        os::unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
        path::{Path, PathBuf},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use serde_json::{Value, json};
    use syrtis_agent::{
        canonical::CanonicalJsonV1,
        control::{
            APPROVE, BUSY, Client, Command, ControlError, Hooks, INTERNAL, INVALID,
            LISTEN_CONFIGURE, OFFER_CANCEL, OFFER_CREATE, OK, PENDING_LIST, PRE_AUTH_CONNECTIONS,
            REJECT, REVOKE, Response, SCOPE_APPROVE, SHARING_SET, SHUTDOWN, SOCKET_NAME, STATUS,
            ScanStatus, Server, UNAUTHORIZED,
        },
        listener::Listener,
        pairing::{ClaimAttempts, Clock, PairingClient, RateLimiter},
        report_peer::{NoSource, Reports},
        runtime::{Options, Runtime, RuntimeError},
        secure_fs::{SecureRoot, StorageError},
        security::{
            MemoryLedger, Offer, OfferClaim, OfferState, Terminal, TerminalKind,
            control_command_mac, control_key, control_response_mac, control_server_mac,
            decode_fixed_hex, hex_encode, offer_secret_hash, parse_pair_url,
        },
        state_store::{Secret32, StateStore, encode_state},
    };

    const NOW: i64 = 1_700_000_000;
    const NOW_MS: i64 = NOW * 1_000;
    const SUFFIX: &[&str] = &["Library", "AppSupport", "agent"];
    const LOOPBACK: &str = "127.0.0.1";

    /// Fake time: `sleep` advances it at once.
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

    /// A temporary home in `/tmp`, short so the socket path fits
    /// `sun_path`. Only directories this helper created are removed.
    struct TempHome(PathBuf);

    impl TempHome {
        fn new() -> Self {
            Self::named("")
        }

        fn named(extra: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = PathBuf::from(format!(
                "/tmp/sc-{}-{}{extra}",
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
            let _ = fs::remove_dir_all(&self.0);
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

    fn open_store(home: &TempHome) -> Arc<StateStore> {
        Arc::new(
            retry_busy(|| StateStore::open(SecureRoot::open_under(&home.0, SUFFIX)?, NOW)).unwrap(),
        )
    }

    /// An agent with its control server running.
    struct Node {
        // Field order is drop order: the server stops before the store
        // closes the root, and the home goes last.
        server: Server,
        store: Arc<StateStore>,
        clock: Arc<TestClock>,
        shutdowns: Arc<AtomicUsize>,
        /// What the `sharingSet` and `scopeApprove` hooks were called with
        /// (`with_effect_hooks` only).
        effects: Arc<Mutex<Vec<String>>>,
        home: TempHome,
    }

    impl Node {
        /// `Server::start`: no `sharingSet` or `scopeApprove` hook.
        fn new(sharing: bool) -> Self {
            Self::build(sharing, false)
        }

        /// Recording `sharingSet` and `scopeApprove` hooks that succeed.
        fn with_effect_hooks() -> Self {
            Self::build(true, true)
        }

        fn build(sharing: bool, effect_hooks: bool) -> Self {
            let home = TempHome::new();
            let store = open_store(&home);
            if sharing {
                store.transition(|state| state.enable_sharing()).unwrap();
            }
            let clock = Arc::new(TestClock::default());
            let shutdowns = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&shutdowns);
            let on_shutdown = Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            });
            let effects = Arc::new(Mutex::new(Vec::new()));
            let server = if effect_hooks {
                let (sharing, scope) = (Arc::clone(&effects), Arc::clone(&effects));
                Server::start_with_all_hooks(
                    Arc::clone(&store),
                    Arc::clone(&clock) as Arc<dyn Clock>,
                    Hooks {
                        on_shutdown,
                        on_listen_configured: Arc::new(|| {}),
                        scan: Arc::new(ScanStatus::default),
                        scope: Arc::new(|_: &StateStore| false),
                        sharing: Some(Arc::new(move |enabled| {
                            sharing.lock().unwrap().push(format!("sharing {enabled}"));
                            Ok(())
                        })),
                        scope_approve: Some(Arc::new(move |_: &StateStore, digest: &str| {
                            scope.lock().unwrap().push(format!("scope {digest}"));
                            Ok(())
                        })),
                    },
                )
            } else {
                Server::start(
                    Arc::clone(&store),
                    Arc::clone(&clock) as Arc<dyn Clock>,
                    on_shutdown,
                )
            }
            .unwrap();
            Self {
                server,
                store,
                clock,
                shutdowns,
                effects,
                home,
            }
        }

        fn token(&self) -> [u8; 32] {
            *self.store.state().unwrap().control_token.expose()
        }

        fn client(&self) -> Client {
            self.client_with(self.token())
        }

        fn client_with(&self, token: [u8; 32]) -> Client {
            Client::new(
                Secret32::new(token),
                self.server.socket_path().to_path_buf(),
            )
        }

        fn call(&self, id: u16, body: Value) -> Response {
            self.client().call(&Command { id, body }).unwrap()
        }

        /// The durable state as bytes, to prove "unchanged".
        fn state_bytes(&self) -> Vec<u8> {
            encode_state(&self.store.state().unwrap()).unwrap()
        }

        fn identity(&self) -> [u8; 32] {
            self.store.state().unwrap().identity_public().unwrap()
        }

        fn configure(&self, port: u16) {
            let response = self.call(
                LISTEN_CONFIGURE,
                json!({"bindHost": LOOPBACK, "bindPort": port}),
            );
            assert_eq!(response.code, OK);
        }

        /// `offerCreate` through control; returns `(offerId, Pair URL)`.
        fn offer(&self) -> ([u8; 16], String) {
            let response = self.call(OFFER_CREATE, json!({"ttlSeconds": 600}));
            assert_eq!(response.code, OK);
            let offer_id = decode_fixed_hex(response.data["offerId"].as_str().unwrap()).unwrap();
            (offer_id, response.data["pairUrl"].as_str().unwrap().into())
        }

        /// Claims an offer straight through the store with the secret from
        /// its Pair URL; returns the pending ID.
        fn claim(&self, url: &str, n: u8) -> [u8; 16] {
            let offer = parse_pair_url(url, NOW_MS).unwrap();
            let pending_id = [n; 16];
            self.store
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
                            NOW,
                        )
                        .map(|(next, _, _)| next)
                })
                .unwrap();
            pending_id
        }

        /// An active grant: offer, claim, approve, all set up directly.
        fn grant(&self) -> [u8; 16] {
            let (offer_id, secret) = ([0x31; 16], [0x32; 32]);
            let responder = self.identity();
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
            self.store
                .transition(|state| {
                    state
                        .claim_offer(
                            OfferClaim {
                                offer_id,
                                secret,
                                responder_static: responder,
                                pending_id: [0x33; 16],
                                initiator_static: [0x34; 32],
                                sas_code: "1234-ABCD".into(),
                                sas_generation: 1,
                            },
                            NOW,
                        )
                        .map(|(next, _, _)| next)
                })
                .unwrap();
            syrtis_agent::pairing::approve(&self.store, [0x33; 16], 1, true, NOW).unwrap()
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

    /// True when the peer closes `stream` within `within` without sending
    /// a byte; false while it is still open. A byte from the peer panics.
    fn closed_within(stream: &mut UnixStream, within: Duration) -> bool {
        if stream.set_read_timeout(Some(within)).is_err() {
            // macOS refuses `setsockopt` once the peer has closed; a
            // non-blocking read then reports EOF (or a byte, which panics).
            stream.set_nonblocking(true).unwrap();
        }
        match stream.read(&mut [0; 1]) {
            Ok(0) => true,
            Ok(read) => panic!("the server sent {read} bytes"),
            Err(error) => !matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
        }
    }

    fn envelope(id: u16, request_id: &[u8; 16], body: Value) -> Vec<u8> {
        CanonicalJsonV1::encode(&json!({
            "body": body,
            "commandId": id,
            "controlVersion": 1,
            "requestId": hex_encode(request_id),
        }))
        .unwrap()
    }

    /// The client side of the wire by hand, from the frozen MAC functions,
    /// recording every byte it sends.
    struct Raw {
        stream: UnixStream,
        key: [u8; 32],
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        sent: Vec<u8>,
    }

    impl Raw {
        /// Connects, says hello and checks the server proof.
        fn open(path: &Path, token: &[u8; 32]) -> Self {
            static NONCE: AtomicUsize = AtomicUsize::new(1);
            let mut client_nonce = [0; 32];
            client_nonce[..8].copy_from_slice(&NONCE.fetch_add(1, Ordering::Relaxed).to_be_bytes());
            let mut raw = Self {
                stream: UnixStream::connect(path).unwrap(),
                key: control_key(token),
                client_nonce,
                server_nonce: [0; 32],
                sent: Vec::new(),
            };
            let mut hello = vec![0, 1];
            hello.extend_from_slice(&client_nonce);
            raw.send(&hello);
            let mut proof = [0; 64];
            raw.stream.read_exact(&mut proof).unwrap();
            raw.server_nonce.copy_from_slice(&proof[..32]);
            assert_eq!(
                proof[32..],
                control_server_mac(&raw.key, 1, &client_nonce, &raw.server_nonce)
            );
            raw
        }

        fn send(&mut self, bytes: &[u8]) {
            self.stream.write_all(bytes).unwrap();
            self.sent.extend_from_slice(bytes);
        }

        /// A complete command frame; `tamper` flips one MAC bit.
        fn frame(&self, id: u16, body: Value, tamper: bool) -> Vec<u8> {
            let request_id = [0x5a; 16];
            let json = envelope(id, &request_id, body);
            let mut mac = control_command_mac(
                &self.key,
                1,
                &self.client_nonce,
                &self.server_nonce,
                &request_id,
                id,
                &json,
            )
            .unwrap();
            if tamper {
                mac[0] ^= 1;
            }
            let mut frame = request_id.to_vec();
            frame.extend_from_slice(&id.to_be_bytes());
            frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
            frame.extend_from_slice(&json);
            frame.extend_from_slice(&mac);
            frame
        }

        /// Reads one response and returns its code (MAC not checked).
        fn response_code(&mut self) -> u16 {
            let mut header = [0; 6];
            self.stream.read_exact(&mut header).unwrap();
            let len = u32::from_be_bytes(header[2..].try_into().unwrap()) as usize;
            let mut rest = vec![0; len + 32];
            self.stream.read_exact(&mut rest).unwrap();
            u16::from_be_bytes([header[0], header[1]])
        }
    }

    /// Acceptance (1): status → listenConfigure → offerCreate → a receiver
    /// claims the Pair URL through the real listener → pendingList shows
    /// its SAS → approve → the receiver confirms the grant → revoke. Every
    /// response passed the frozen `verify_control_response` inside `call`.
    #[test]
    fn a_receiver_pairs_and_is_revoked_through_control_end_to_end() {
        let node = Node::new(true);
        let fresh = node.call(STATUS, json!({}));
        assert_eq!(fresh.code, OK);
        // SA-0F: unset host and label are null.
        assert_eq!(fresh.data["bindHost"], Value::Null);
        assert_eq!(fresh.data["nodeLabel"], Value::Null);
        assert_eq!(fresh.data["sharingEnabled"], true);
        assert_eq!(fresh.data["scanStatus"], "never");
        assert_eq!(fresh.data["sourceFamilies"], json!([]));

        let port = free_port();
        node.configure(port);
        let status = node.call(STATUS, json!({}));
        assert_eq!(status.data["bindHost"], LOOPBACK);
        assert_eq!(status.data["bindPort"], port);

        let mut listener = Listener::start(
            Arc::clone(&node.store),
            MemoryLedger::default(),
            Arc::new(RateLimiter::default()),
            Arc::clone(&node.clock) as Arc<dyn Clock>,
            Arc::new(Reports::new(Arc::new(NoSource))),
        )
        .unwrap();
        let (_, url) = node.offer();
        assert_eq!(node.call(STATUS, json!({})).data["activeOfferCount"], 1);

        let receiver = syrtis_agent::noise::StaticKey::generate().unwrap();
        let ledger = MemoryLedger::default();
        let pairing = PairingClient {
            identity: &receiver,
            ledger: &ledger,
            clock: &*node.clock,
        };
        let claimed = pairing
            .claim(&url, NOW_MS, &mut ClaimAttempts::default())
            .unwrap();

        let list = node.call(PENDING_LIST, json!({}));
        assert_eq!(list.code, OK);
        assert_eq!(
            list.data,
            json!([{
                "expiresAt": claimed.expires_at_ms,
                "pendingId": hex_encode(&claimed.pending_id),
                "sasCode": claimed.sas,
            }])
        );

        let approve = node.call(
            APPROVE,
            json!({"pendingId": hex_encode(&claimed.pending_id), "sasGeneration": 1}),
        );
        assert_eq!(approve.code, OK);
        let confirmed = pairing.poll(&claimed).unwrap();
        assert_eq!(confirmed.responder_static, node.identity());
        assert_eq!(node.call(STATUS, json!({})).data["activeGrantCount"], 1);

        let revoke = node.call(REVOKE, json!({"grantId": hex_encode(&confirmed.grant_id)}));
        assert_eq!(revoke.code, OK);
        listener.stop();
        let state = node.store.state().unwrap();
        assert_eq!(
            state.reference.grants[0].state,
            syrtis_agent::security::GrantState::Revoked
        );
        assert_eq!(node.call(STATUS, json!({})).data["activeGrantCount"], 0);
    }

    /// A rogue endpoint's answer to the command: `(key, clientNonce,
    /// serverNonce, requestId)` to response bytes.
    type Reply = fn(&[u8; 32], &[u8; 32], &[u8; 32], &[u8; 16]) -> Vec<u8>;

    /// A rogue endpoint for the client tests. It answers the hello with a
    /// proof made from `token` (or random bytes when `None`), then reports
    /// how many bytes the client sent after the proof, and, when `reply`
    /// is set, answers the command with it.
    fn rogue(
        path: PathBuf,
        token: Option<[u8; 32]>,
        reply: Option<Reply>,
    ) -> mpsc::Receiver<usize> {
        let listener = UnixListener::bind(&path).unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut hello = [0; 34];
            stream.read_exact(&mut hello).unwrap();
            let client_nonce: [u8; 32] = hello[2..].try_into().unwrap();
            let server_nonce = [7; 32];
            let key = control_key(&token.unwrap_or([0; 32]));
            let mac = match token {
                Some(_) => control_server_mac(&key, 1, &client_nonce, &server_nonce),
                None => [0x99; 32],
            };
            stream.write_all(&server_nonce).unwrap();
            stream.write_all(&mac).unwrap();
            let mut received = Vec::new();
            match reply {
                // One read: the command arrives at once, or the client
                // closes (EOF, or a reset: nothing received either way).
                None => {
                    let mut buf = [0; 4_096];
                    let read = stream.read(&mut buf).unwrap_or(0);
                    received.extend_from_slice(&buf[..read]);
                }
                Some(reply) => {
                    let mut header = [0; 22];
                    stream.read_exact(&mut header).unwrap();
                    let len = u32::from_be_bytes(header[18..].try_into().unwrap()) as usize;
                    let mut rest = vec![0; len + 32];
                    stream.read_exact(&mut rest).unwrap();
                    received.extend_from_slice(&header);
                    let request_id: [u8; 16] = header[..16].try_into().unwrap();
                    let _ =
                        stream.write_all(&reply(&key, &client_nonce, &server_nonce, &request_id));
                }
            }
            sender.send(received.len()).unwrap();
        });
        receiver
    }

    /// Acceptance (2): a wrong token fails at the server proof and the
    /// client sends no command byte: against the real server, and against
    /// a rogue endpoint that counts what arrives (0; a correct proof, the
    /// control, gets the command). A wrong command MAC gets no response and
    /// changes nothing.
    #[test]
    fn a_wrong_token_or_command_mac_sends_and_changes_nothing() {
        let node = Node::new(true);
        let before = node.state_bytes();
        let wrong = node.client_with([0xee; 32]);
        let command = Command {
            id: LISTEN_CONFIGURE,
            body: json!({"bindHost": LOOPBACK, "bindPort": 40_000}),
        };
        assert_eq!(wrong.call(&command), Err(ControlError::ServerProof));
        assert_eq!(node.state_bytes(), before);

        let token = node.token();
        for (proof_token, expected_zero) in [(None, true), (Some(token), false)] {
            let path = node.home.0.join("rogue.sock");
            let _ = fs::remove_file(&path);
            let received = rogue(path.clone(), proof_token, None);
            let result = Client::new(Secret32::new(token), path).call(&command);
            let count = received.recv_timeout(Duration::from_secs(5)).unwrap();
            if expected_zero {
                assert_eq!(result, Err(ControlError::ServerProof));
                assert_eq!(count, 0, "command bytes reached a rogue endpoint");
            } else {
                assert!(count > 0, "control: a correct proof gets the command");
            }
        }

        let mut raw = Raw::open(node.server.socket_path(), &token);
        let frame = raw.frame(
            LISTEN_CONFIGURE,
            json!({"bindHost": LOOPBACK, "bindPort": 40_000}),
            true,
        );
        raw.send(&frame);
        assert!(closed_within(&mut raw.stream, Duration::from_secs(1)));
        assert_eq!(node.state_bytes(), before);
        // Control: the same frame with its real MAC is answered.
        let mut raw = Raw::open(node.server.socket_path(), &token);
        let frame = raw.frame(STATUS, json!({}), false);
        raw.send(&frame);
        assert_eq!(raw.response_code(), OK);
    }

    /// Client response checks: a bad response MAC, or a MAC-valid response
    /// naming another request ID, is refused; the well-formed one (the
    /// control) is accepted.
    #[test]
    fn the_client_refuses_a_forged_or_misaddressed_response() {
        fn response(
            key: &[u8; 32],
            client: &[u8; 32],
            server: &[u8; 32],
            request_id: &[u8; 16],
            named: &[u8; 16],
            tamper: bool,
        ) -> Vec<u8> {
            let json = CanonicalJsonV1::encode(&json!({
                "code": 0, "controlVersion": 1, "data": null, "requestId": hex_encode(named),
            }))
            .unwrap();
            let mut mac =
                control_response_mac(key, 1, client, server, request_id, 0, &json).unwrap();
            if tamper {
                mac[31] ^= 1;
            }
            let mut out = 0u16.to_be_bytes().to_vec();
            out.extend_from_slice(&(json.len() as u32).to_be_bytes());
            out.extend_from_slice(&json);
            out.extend_from_slice(&mac);
            out
        }
        let home = TempHome::new();
        let token = [0x44; 32];
        let cases: [(Reply, bool); 3] = [
            (|k, c, s, r| response(k, c, s, r, r, true), false),
            (|k, c, s, r| response(k, c, s, r, &[0xee; 16], false), false),
            (|k, c, s, r| response(k, c, s, r, r, false), true),
        ];
        for (n, (reply, accepted)) in cases.into_iter().enumerate() {
            let path = home.0.join(format!("r{n}.sock"));
            let received = rogue(path.clone(), Some(token), Some(reply));
            let result = Client::new(Secret32::new(token), path).call(&Command {
                id: SHUTDOWN,
                body: json!({}),
            });
            received.recv_timeout(Duration::from_secs(5)).unwrap();
            if accepted {
                assert_eq!(result.unwrap().code, OK, "{n}");
            } else {
                assert_eq!(result, Err(ControlError::Response), "{n}");
            }
        }
    }

    /// Acceptance (3): the client bytes of a complete exchange, replayed on
    /// a new connection, fail the command MAC (fresh server nonce): no
    /// response, state unchanged.
    #[test]
    fn a_replayed_conversation_fails_and_changes_nothing() {
        let node = Node::new(true);
        let token = node.token();
        let first = free_port();
        let mut raw = Raw::open(node.server.socket_path(), &token);
        let frame = raw.frame(
            LISTEN_CONFIGURE,
            json!({"bindHost": LOOPBACK, "bindPort": first}),
            false,
        );
        raw.send(&frame);
        assert_eq!(raw.response_code(), OK);
        let recorded = raw.sent.clone();
        // Move away from the recorded port, so a replay would show.
        node.configure(free_port());
        let before = node.state_bytes();

        let mut replay = UnixStream::connect(node.server.socket_path()).unwrap();
        replay.write_all(&recorded[..34]).unwrap();
        let mut proof = [0; 64];
        replay.read_exact(&mut proof).unwrap();
        replay.write_all(&recorded[34..]).unwrap();
        assert!(closed_within(&mut replay, Duration::from_secs(1)));
        assert_eq!(node.state_bytes(), before);
    }

    /// Acceptance (4): each of the eleven commands succeeds once, and each
    /// gets `invalid` for a body the frozen validator refuses, with the
    /// state unchanged, no shutdown signalled and no hook called. Commands
    /// 10 and 11 reach their hooks with the body's value (their effects:
    /// `sharing_set_runs_the_runtime_gate_and_maps_its_errors` here and
    /// `tests/agent_v1.rs`).
    #[test]
    fn each_command_succeeds_and_each_validator_refusal_is_invalid() {
        let node = Node::with_effect_hooks();
        let refusals = [
            (STATUS, json!({"extra": 1})),
            (OFFER_CREATE, json!({"ttlSeconds": 901})),
            (OFFER_CANCEL, json!({"offerId": "zz"})),
            (PENDING_LIST, json!({"extra": 1})),
            (APPROVE, json!({"pendingId": hex_encode(&[1; 16])})),
            (REJECT, json!({"pendingId": "00", "sasGeneration": 1})),
            (REVOKE, json!({"grantId": 7})),
            (
                LISTEN_CONFIGURE,
                json!({"bindHost": LOOPBACK, "bindPort": 80}),
            ),
            (SHUTDOWN, json!({"now": true})),
            (SHARING_SET, json!({"enabled": 1})),
            (SCOPE_APPROVE, json!({"ownerInputsSha256": "AB".repeat(32)})),
        ];
        let before = node.state_bytes();
        for (id, body) in refusals {
            let response = node.call(id, body);
            assert_eq!(response.code, INVALID, "command {id}");
            assert_eq!(response.data, Value::Null);
        }
        assert_eq!(node.state_bytes(), before);
        assert_eq!(node.shutdowns.load(Ordering::SeqCst), 0);
        assert!(node.effects.lock().unwrap().is_empty());

        assert_eq!(node.call(STATUS, json!({})).code, OK);
        let digest = "0123456789abcdef".repeat(4);
        for (id, body) in [
            (SHARING_SET, json!({"enabled": false})),
            (SHARING_SET, json!({"enabled": true})),
            (SCOPE_APPROVE, json!({ "ownerInputsSha256": digest })),
        ] {
            let response = node.call(id, body);
            assert_eq!((response.code, response.data), (OK, Value::Null));
        }
        assert_eq!(
            *node.effects.lock().unwrap(),
            ["sharing false", "sharing true", &format!("scope {digest}")]
        );
        node.configure(free_port());
        let (cancelled, _) = node.offer();
        let cancel = node.call(OFFER_CANCEL, json!({"offerId": hex_encode(&cancelled)}));
        assert_eq!(cancel.code, OK);
        assert_eq!(
            node.store.state().unwrap().reference.offers[0].state,
            OfferState::Cancelled
        );
        let (_, approved) = node.offer();
        let (_, rejected) = node.offer();
        let approved = node.claim(&approved, 0x0a);
        let rejected = node.claim(&rejected, 0x0b);
        let list = node.call(PENDING_LIST, json!({}));
        assert_eq!(list.code, OK);
        assert_eq!(list.data.as_array().unwrap().len(), 2);
        let approve = node.call(
            APPROVE,
            json!({"pendingId": hex_encode(&approved), "sasGeneration": 1}),
        );
        assert_eq!(approve.code, OK);
        let reject = node.call(
            REJECT,
            json!({"pendingId": hex_encode(&rejected), "sasGeneration": 1}),
        );
        assert_eq!(reject.code, OK);
        assert_eq!(node.call(PENDING_LIST, json!({})).data, json!([]));
        let grant_id = node.store.state().unwrap().reference.grants[0].grant_id;
        assert_eq!(
            node.call(REVOKE, json!({"grantId": hex_encode(&grant_id)}))
                .code,
            OK
        );
        assert_eq!(node.call(SHUTDOWN, json!({})).code, OK);
        assert_eq!(node.shutdowns.load(Ordering::SeqCst), 1);
    }

    /// A server started without the `sharingSet` and `scopeApprove` hooks
    /// (`Server::start`, as SA-0G left it) answers `internal` with `null`
    /// data and writes nothing; a refused body is still `invalid`.
    #[test]
    fn without_hooks_sharing_set_and_scope_approve_are_internal_and_change_nothing() {
        for sharing in [false, true] {
            let node = Node::new(sharing);
            let before = node.state_bytes();
            for (id, body) in [
                (SHARING_SET, json!({"enabled": true})),
                (SHARING_SET, json!({"enabled": false})),
                (
                    SCOPE_APPROVE,
                    json!({"ownerInputsSha256": "0123456789abcdef".repeat(4)}),
                ),
            ] {
                let response = node.call(id, body.clone());
                assert_eq!(response.code, INTERNAL, "{id}: {body}");
                assert_eq!(response.data, Value::Null);
                assert_eq!(node.state_bytes(), before, "{id}: {body}");
            }
            for (id, body) in [
                (SHARING_SET, json!({"enabled": 1})),
                (SCOPE_APPROVE, json!({"ownerInputsSha256": "AB".repeat(32)})),
            ] {
                assert_eq!(node.call(id, body.clone()).code, INVALID, "{id}: {body}");
            }
            assert_eq!(node.state_bytes(), before);
            let status = node.call(STATUS, json!({}));
            assert_eq!(status.data["sharingEnabled"], sharing);
            assert_eq!(status.data["scopeApproved"], false);
        }
    }

    /// SA-2C2b acceptance (2): `sharingSet` on a runtime runs the
    /// runtime's own entry points. Off twice while off: `ok` both times,
    /// nothing written. On: `ok`; on again: `invalid` (the frozen
    /// `Conflict`), nothing written. Off with a full record table leaves
    /// an offer that can still be claimed; on is then the gate's `busy`,
    /// nothing written. A runtime without a scope approval hook answers
    /// `scopeApprove` with `internal`.
    #[test]
    fn sharing_set_runs_the_runtime_gate_and_maps_its_errors() {
        let home = TempHome::new();
        let clock = Arc::new(TestClock::default());
        let options = Options {
            clock: Arc::clone(&clock) as Arc<dyn Clock>,
            housekeeping_period: Duration::from_secs(60),
        };
        let runtime = retry_busy(|| {
            Runtime::start(
                SecureRoot::open_under(&home.0, SUFFIX)?,
                Arc::new(NoSource),
                options.clone(),
            )
            .map_err(|error| match error {
                RuntimeError::Store(error) => error,
                _ => StorageError::Unknown,
            })
        })
        .unwrap();
        let store = runtime.store();
        let token = *store.state().unwrap().control_token.expose();
        let call = |id: u16, body: Value| {
            Client::new(Secret32::new(token), runtime.socket_path().to_path_buf())
                .call(&Command { id, body })
                .unwrap()
        };
        let bytes = || encode_state(&store.state().unwrap()).unwrap();
        let sharing = |enabled: bool| call(SHARING_SET, json!({ "enabled": enabled }));

        let before = bytes();
        for _ in 0..2 {
            assert_eq!(sharing(false).code, OK);
            assert_eq!(bytes(), before, "a disable with nothing to end wrote");
        }
        assert_eq!(sharing(true).code, OK);
        assert!(store.state().unwrap().reference.sharing_enabled);
        let on = bytes();
        let again = sharing(true);
        assert_eq!((again.code, again.data), (INVALID, Value::Null));
        assert_eq!(bytes(), on);

        let port = free_port();
        let configured = call(
            LISTEN_CONFIGURE,
            json!({"bindHost": LOOPBACK, "bindPort": port}),
        );
        assert_eq!(configured.code, OK);
        let offer = call(OFFER_CREATE, json!({"ttlSeconds": 600}));
        assert_eq!(offer.code, OK);
        let offer_id: [u8; 16] = decode_fixed_hex(offer.data["offerId"].as_str().unwrap()).unwrap();
        // A full record table: the disable cannot cancel the offer.
        store
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
                        terminal_at_ms: NOW_MS,
                        cleanup_complete: true,
                    });
                }
                Ok(next)
            })
            .unwrap();
        assert_eq!(sharing(false).code, OK);
        let state = store.state().unwrap().reference;
        assert!(!state.sharing_enabled);
        assert!(
            state
                .offers
                .iter()
                .any(|offer| offer.offer_id == offer_id && offer.state == OfferState::Active)
        );
        let gated = bytes();
        let busy = sharing(true);
        assert_eq!((busy.code, busy.data), (BUSY, Value::Null));
        assert_eq!(bytes(), gated, "a gated enable wrote");
        assert!(!store.state().unwrap().reference.sharing_enabled);

        let scope = call(
            SCOPE_APPROVE,
            json!({"ownerInputsSha256": "0123456789abcdef".repeat(4)}),
        );
        assert_eq!(scope.code, INTERNAL);
        assert_eq!(call(STATUS, json!({})).data["scopeApproved"], false);
        drop(clock);
    }

    /// SA-0G acceptance (d): `status` carries `scopeApproved`, `false`
    /// without a provider and the provider's answer with one. Each reply
    /// passed the frozen `verify_control_response` inside `call`.
    #[test]
    fn status_reports_scope_approved_from_its_provider() {
        let node = Node::new(true);
        let status = node.call(STATUS, json!({}));
        assert_eq!(status.code, OK);
        assert_eq!(status.data["scopeApproved"], false);

        for approved in [true, false] {
            let home = TempHome::new();
            let store = open_store(&home);
            let mut server = Server::start_with_scope_hook(
                Arc::clone(&store),
                Arc::new(TestClock::default()),
                Arc::new(|| {}),
                Arc::new(|| {}),
                Arc::new(ScanStatus::default),
                Arc::new(move |_: &StateStore| approved),
            )
            .unwrap();
            let token = *store.state().unwrap().control_token.expose();
            let response = Client::new(Secret32::new(token), server.socket_path().to_path_buf())
                .call(&Command {
                    id: STATUS,
                    body: json!({}),
                })
                .unwrap();
            assert_eq!(response.code, OK);
            assert_eq!(response.data["scopeApproved"], approved);
            server.stop();
        }
    }

    /// Acceptance (6): with 4 connections stalled before their hello, a
    /// 5th is closed at once; after the 2 s hello deadline the slots are
    /// free again and a call succeeds.
    #[test]
    fn a_fifth_pre_auth_connection_is_closed_and_slots_free_after_the_deadline() {
        let node = Node::new(true);
        assert_eq!(PRE_AUTH_CONNECTIONS, 4);
        let started = Instant::now();
        let mut held: Vec<UnixStream> = (0..PRE_AUTH_CONNECTIONS)
            .map(|_| UnixStream::connect(node.server.socket_path()).unwrap())
            .collect();
        thread::sleep(Duration::from_millis(300));

        let mut fifth = UnixStream::connect(node.server.socket_path()).unwrap();
        let checked = Instant::now();
        assert!(closed_within(&mut fifth, Duration::from_secs(3)));
        assert!(
            checked.elapsed() < Duration::from_secs(1),
            "{:?}",
            checked.elapsed()
        );
        for (n, stream) in held.iter_mut().enumerate() {
            assert!(!closed_within(stream, Duration::from_millis(50)), "{n}");
        }

        for (n, stream) in held.iter_mut().enumerate() {
            assert!(closed_within(stream, Duration::from_secs(3)), "{n}");
        }
        assert!(started.elapsed() >= Duration::from_millis(1_900));
        assert_eq!(node.call(STATUS, json!({})).code, OK);
        assert_eq!(node.server.pre_auth_memory_used(), 0);
    }

    /// Acceptance (7): a hello sent one byte at a time is cut at the 2 s
    /// absolute deadline (it would take 34 × 200 ms to finish); a wrong
    /// version is closed at once without a proof.
    #[test]
    fn a_slow_hello_is_cut_at_the_absolute_deadline_and_a_wrong_version_closes() {
        let node = Node::new(true);
        let mut slow = UnixStream::connect(node.server.socket_path()).unwrap();
        let started = Instant::now();
        let mut cut = None;
        for _ in 0..34 {
            if slow.write_all(&[0]).is_err() {
                cut = Some(started.elapsed());
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }
        let cut = cut.expect("the slow hello was never cut");
        assert!(
            (Duration::from_millis(1_800)..Duration::from_secs(3)).contains(&cut),
            "{cut:?}"
        );

        let mut wrong = UnixStream::connect(node.server.socket_path()).unwrap();
        let mut hello = vec![0, 2];
        hello.extend_from_slice(&[0; 32]);
        wrong.write_all(&hello).unwrap();
        assert!(closed_within(&mut wrong, Duration::from_millis(500)));
    }

    /// The command deadline: after the server proof, a client that sends
    /// nothing is closed at the 2 s deadline, not before 1.5 s.
    #[test]
    fn a_stalled_command_is_closed_at_its_deadline() {
        let node = Node::new(true);
        let mut raw = Raw::open(node.server.socket_path(), &node.token());
        let started = Instant::now();
        assert!(closed_within(&mut raw.stream, Duration::from_secs(4)));
        let elapsed = started.elapsed();
        assert!(
            (Duration::from_millis(1_500)..Duration::from_secs(3)).contains(&elapsed),
            "{elapsed:?}"
        );
    }

    /// Acceptance (8): a command length of 4,097 is closed at once, before
    /// any reservation; a stalled body holds its reservation until the
    /// deadline, which returns it; the ledger is back at 0.
    #[test]
    fn an_oversize_command_closes_and_pre_auth_memory_returns_to_baseline() {
        let node = Node::new(true);
        let token = node.token();
        let mut raw = Raw::open(node.server.socket_path(), &token);
        let mut header = [0x5a; 16].to_vec();
        header.extend_from_slice(&STATUS.to_be_bytes());
        header.extend_from_slice(&4_097u32.to_be_bytes());
        raw.send(&header);
        assert!(closed_within(&mut raw.stream, Duration::from_millis(500)));
        assert_eq!(node.server.pre_auth_memory_used(), 0);

        let mut raw = Raw::open(node.server.socket_path(), &token);
        let mut header = [0x5a; 16].to_vec();
        header.extend_from_slice(&STATUS.to_be_bytes());
        header.extend_from_slice(&100u32.to_be_bytes());
        raw.send(&header);
        raw.send(&[b'{'; 10]);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(node.server.pre_auth_memory_used(), 100 + 32);
        assert!(closed_within(&mut raw.stream, Duration::from_secs(3)));
        thread::sleep(Duration::from_millis(100));
        assert_eq!(node.server.pre_auth_memory_used(), 0);
    }

    /// Acceptance (9): the socket is `0600`, a socket, inside the root; a
    /// stale socket of this UID is replaced; a path over `sun_path` fails.
    #[test]
    fn the_socket_is_0600_in_the_root_and_a_stale_one_is_replaced() {
        let mut node = Node::new(true);
        let path = node.server.socket_path().to_path_buf();
        assert_eq!(path, node.home.root().join(SOCKET_NAME));
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);

        node.server.stop();
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        let again = Server::start(
            Arc::clone(&node.store),
            Arc::clone(&node.clock) as Arc<dyn Clock>,
            Arc::new(|| {}),
        )
        .unwrap();
        let client = Client::new(Secret32::new(node.token()), path);
        assert_eq!(
            client
                .call(&Command {
                    id: STATUS,
                    body: json!({})
                })
                .unwrap()
                .code,
            OK
        );
        drop(again);

        let long = TempHome::named(&format!("-{}", "x".repeat(80)));
        assert!(long.root().join(SOCKET_NAME).as_os_str().len() > 108);
        let store = open_store(&long);
        assert_eq!(
            Server::start(store, Arc::new(TestClock::default()), Arc::new(|| {})).err(),
            Some(ControlError::PathTooLong)
        );
    }

    /// Acceptance (10): offerCreate is `invalid` without a bind host or
    /// with one the listener would refuse, `unauthorized` with sharing off;
    /// the Pair URL parses with the frozen parser and names this identity.
    #[test]
    fn offer_create_needs_a_bindable_host_and_sharing_and_names_this_identity() {
        let node = Node::new(true);
        let before = node.state_bytes();
        assert_eq!(
            node.call(OFFER_CREATE, json!({"ttlSeconds": 60})).code,
            INVALID
        );
        node.store
            .set_listen_config(Some("localhost".into()), 50_000, None)
            .unwrap();
        let hostname = node.state_bytes();
        assert_eq!(
            node.call(OFFER_CREATE, json!({"ttlSeconds": 60})).code,
            INVALID
        );
        assert_eq!(node.state_bytes(), hostname);
        assert_ne!(hostname, before);

        let port = free_port();
        node.configure(port);
        let response = node.call(OFFER_CREATE, json!({"ttlSeconds": 60}));
        assert_eq!(response.code, OK);
        let offer = parse_pair_url(response.data["pairUrl"].as_str().unwrap(), NOW_MS).unwrap();
        assert_eq!(offer.responder_static, hex_encode(&node.identity()));
        assert_eq!((offer.host.as_str(), offer.port), (LOOPBACK, port));
        assert_eq!(offer.offer_id, response.data["offerId"].as_str().unwrap());
        assert_eq!(offer.expires_at, NOW_MS + 60_000);
        assert_eq!(response.data["expiresAt"], NOW_MS + 60_000);

        let off = Node::new(false);
        off.configure(free_port());
        let before = off.state_bytes();
        assert_eq!(
            off.call(OFFER_CREATE, json!({"ttlSeconds": 60})).code,
            UNAUTHORIZED
        );
        assert_eq!(off.state_bytes(), before);
    }

    /// Acceptance (11): the token, the Pair URL and the offer secret appear
    /// in no `Debug` output of the client, server, response, command or
    /// any error.
    #[test]
    fn no_debug_output_shows_the_token_url_or_secret() {
        let node = Node::new(true);
        node.configure(free_port());
        let response = node.call(OFFER_CREATE, json!({"ttlSeconds": 60}));
        let url = response.data["pairUrl"].as_str().unwrap().to_owned();
        let secret = parse_pair_url(&url, NOW_MS).unwrap().secret;
        let token = node.token();
        let command = Command {
            id: OFFER_CREATE,
            body: json!({"ttlSeconds": 60}),
        };
        let errors = [
            ControlError::Unsupported,
            ControlError::PathTooLong,
            ControlError::UnsafeSocket,
            ControlError::Socket,
            ControlError::Unavailable,
            ControlError::Command,
            ControlError::ServerProof,
            ControlError::Response,
        ];
        let outputs = [
            format!("{:?}", node.client()),
            format!("{:#?}", node.client()),
            format!("{:?}", node.server),
            format!("{response:?}"),
            format!("{response:#?}"),
            format!("{command:?}"),
            format!("{errors:?}"),
            format!("{:?}", node.client().call(&command)),
        ];
        for output in outputs {
            for sentinel in [
                hex_encode(&token),
                format!("{token:?}"),
                url.clone(),
                secret.clone(),
            ] {
                assert!(!output.contains(&sentinel), "{output}");
            }
        }
        // Control: the URL sentinel is really in the data.
        assert!(response.data.to_string().contains(&url));
        assert_eq!(secret.len(), 64);
    }

    /// Acceptance (12): after a reset, a client with the old token fails at
    /// the server proof and one with the new token succeeds; the server
    /// was started before the reset.
    #[test]
    fn after_a_reset_the_old_token_fails_and_the_new_one_works() {
        let node = Node::new(true);
        let old = node.token();
        assert_eq!(node.call(STATUS, json!({})).code, OK);
        node.store.reset(NOW + 10, (NOW + 10) * 1_000).unwrap();
        let new = node.token();
        assert_ne!(new, old);
        let command = Command {
            id: STATUS,
            body: json!({}),
        };
        assert_eq!(
            node.client_with(old).call(&command),
            Err(ControlError::ServerProof)
        );
        assert_eq!(node.client_with(new).call(&command).unwrap().code, OK);
    }

    /// A reset between the server proof and the command: the command is
    /// authenticated under the token read at the hello, but it must not
    /// run against the state the reset produced.
    #[test]
    fn a_command_authenticated_before_a_reset_does_not_run_after_it() {
        let node = Node::new(true);
        let old = node.token();
        let mut raw = Raw::open(node.server.socket_path(), &old);
        node.store.reset(NOW + 10, (NOW + 10) * 1_000).unwrap();
        let before = node.state_bytes();
        let frame = raw.frame(
            LISTEN_CONFIGURE,
            json!({"bindHost": LOOPBACK, "bindPort": free_port()}),
            false,
        );
        raw.send(&frame);
        assert!(closed_within(&mut raw.stream, Duration::from_secs(1)));
        assert_eq!(node.state_bytes(), before);
    }

    /// Acceptance (13): `localhost` and `0x0` pass the frozen validator but
    /// not the listener's bind rule: `invalid`, state unchanged.
    #[test]
    fn listen_configure_refuses_what_the_listener_would_not_bind() {
        let node = Node::new(true);
        let before = node.state_bytes();
        for host in ["localhost", "0x0"] {
            let response = node.call(
                LISTEN_CONFIGURE,
                json!({"bindHost": host, "bindPort": 50_000}),
            );
            assert_eq!(response.code, INVALID, "{host}");
            assert_eq!(node.state_bytes(), before, "{host}");
        }
        // Control: an IP literal is written.
        node.configure(50_000);
        assert_ne!(node.state_bytes(), before);
    }

    /// Acceptance (14): a regular file, a symlink or a directory at
    /// `control.sock` stops the start and is left as it was; this UID's
    /// stale socket is replaced.
    #[test]
    fn a_residue_that_is_not_our_socket_fails_closed_and_stays() {
        let home = TempHome::new();
        let store = open_store(&home);
        let path = home.root().join(SOCKET_NAME);
        let target = home.0.join("target");
        fs::write(&target, b"target").unwrap();
        let start = || {
            Server::start(
                Arc::clone(&store),
                Arc::new(TestClock::default()),
                Arc::new(|| {}),
            )
        };

        fs::write(&path, b"keep").unwrap();
        assert_eq!(start().err(), Some(ControlError::UnsafeSocket));
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        fs::remove_file(&path).unwrap();

        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(start().err(), Some(ControlError::UnsafeSocket));
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), b"target");
        fs::remove_file(&path).unwrap();

        fs::create_dir(&path).unwrap();
        assert_eq!(start().err(), Some(ControlError::UnsafeSocket));
        assert!(fs::symlink_metadata(&path).unwrap().is_dir());
        fs::remove_dir(&path).unwrap();

        drop(UnixListener::bind(&path).unwrap());
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        let server = start().unwrap();
        let client = Client::new(
            Secret32::new(*store.state().unwrap().control_token.expose()),
            path,
        );
        assert_eq!(
            client
                .call(&Command {
                    id: STATUS,
                    body: json!({})
                })
                .unwrap()
                .code,
            OK
        );
        drop(server);
    }

    /// Acceptance (15): with 4 connections stalled before their hello, an
    /// owner `revoke` (retried while the slots are full) completes within
    /// 5 s. The measured time is printed.
    #[test]
    fn revoke_completes_within_five_seconds_while_four_hellos_stall() {
        let node = Node::new(true);
        let grant_id = node.grant();
        let _held: Vec<UnixStream> = (0..PRE_AUTH_CONNECTIONS)
            .map(|_| UnixStream::connect(node.server.socket_path()).unwrap())
            .collect();
        thread::sleep(Duration::from_millis(300));

        let started = Instant::now();
        let command = Command {
            id: REVOKE,
            body: json!({"grantId": hex_encode(&grant_id)}),
        };
        let client = node.client();
        let mut attempts = 0;
        let response = loop {
            attempts += 1;
            match client.call(&command) {
                Ok(response) => break response,
                Err(ControlError::Socket) if started.elapsed() < Duration::from_secs(5) => {
                    thread::sleep(Duration::from_millis(50))
                }
                Err(error) => panic!("{error:?} after {:?}", started.elapsed()),
            }
        };
        let elapsed = started.elapsed();
        println!("SA-2B2c1 (15): revoke completed in {elapsed:?} after {attempts} attempts");
        assert_eq!(response.code, OK);
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(
            node.store.state().unwrap().reference.grants[0].state,
            syrtis_agent::security::GrantState::Revoked
        );
    }
}
