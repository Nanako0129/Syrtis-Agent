//! W2 acceptance: the in-process control entry `Runtime::control`
//! (`spec/control-v1.md`, "In-process entry"), through the public API.
//!
//! Every test needs a secure root; they run on macOS, Linux and Windows
//! (`W3b`). On macOS and Linux the side-by-side test runs every command
//! over the control socket and in-process on the same runtime; Windows has
//! no control socket, so there `Node::socket` is the in-process entry too
//! and the test checks the fixed expectations it states. Homes come from
//! `support::new_home` (short `/tmp` names on Unix so the socket path fits
//! `sun_path`). TCP listeners bind 127.0.0.1.

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
mod support;

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
mod disk {
    #[cfg(not(windows))]
    use std::fs;
    use std::{
        net::TcpListener,
        path::PathBuf,
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };

    use serde_json::{Value, json};
    use syrtis_agent::{
        control::{
            APPROVE, COMMAND_JSON_MAX, Command, ControlError, INVALID, LISTEN_CONFIGURE,
            OFFER_CANCEL, OFFER_CREATE, OK, PENDING_LIST, REJECT, REVOKE, Response, SCOPE_APPROVE,
            SHARING_SET, SHUTDOWN, STATUS, UNAUTHORIZED,
        },
        pairing::Clock,
        report_peer::NoSource,
        runtime::{Options, Runtime, RuntimeError},
        secure_fs::{SecureRoot, StorageError},
        security::{OfferClaim, decode_fixed_hex, hex_encode, parse_pair_url},
        state_store::{StateStore, encode_state},
    };
    #[cfg(not(windows))]
    use syrtis_agent::{
        control::{Client, SOCKET_NAME},
        state_store::Secret32,
    };

    const NOW: i64 = 1_700_000_000;
    const NOW_MS: i64 = NOW * 1_000;
    const SUFFIX: &[&str] = &["r"];
    const LOOPBACK: &str = "127.0.0.1";

    /// A wall clock frozen at `NOW`: offers created over either path get
    /// the same `expiresAt`.
    struct Frozen(Mutex<Duration>);

    impl Clock for Frozen {
        fn monotonic(&self) -> Duration {
            *self.0.lock().unwrap()
        }

        fn os_now_seconds(&self) -> Result<i64, StorageError> {
            Ok(NOW)
        }

        fn sleep(&self, duration: Duration) {
            *self.0.lock().unwrap() += duration;
        }
    }

    /// A short temporary home (`support::new_home`); only what this helper
    /// created is removed.
    struct TempHome(PathBuf);

    impl TempHome {
        fn new() -> Self {
            Self(super::support::new_home("scl"))
        }

        #[cfg(not(windows))]
        fn root(&self) -> PathBuf {
            SUFFIX
                .iter()
                .fold(self.0.clone(), |path, part| path.join(part))
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn options() -> Options {
        Options {
            clock: Arc::new(Frozen(Mutex::new(Duration::ZERO))),
            housekeeping_period: Duration::from_secs(60),
        }
    }

    /// `Runtime::start`, retried while a reopen still sees the owner lock.
    fn start(home: &TempHome) -> Result<Runtime, RuntimeError> {
        for _ in 0..200 {
            let root = SecureRoot::open_under(&home.0, SUFFIX).map_err(RuntimeError::Store)?;
            match Runtime::start(root, Arc::new(NoSource), options()) {
                Err(RuntimeError::Store(StorageError::Busy)) => {
                    thread::sleep(Duration::from_millis(10))
                }
                other => return other,
            }
        }
        panic!("the runtime did not start");
    }

    fn free_port() -> u16 {
        TcpListener::bind((LOOPBACK, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[cfg(not(windows))]
    fn listening(port: u16) -> bool {
        std::net::TcpStream::connect((LOOPBACK, port)).is_ok()
    }

    struct Node {
        runtime: Runtime,
        _home: TempHome,
    }

    impl Node {
        fn new() -> Self {
            let home = TempHome::new();
            Self {
                runtime: start(&home).unwrap(),
                _home: home,
            }
        }

        fn store(&self) -> &Arc<StateStore> {
            self.runtime.store()
        }

        /// The control socket. Windows has none: the in-process entry, so
        /// the comparisons below compare two in-process calls and the test
        /// rests on its fixed expectations.
        #[cfg(windows)]
        fn socket(&self, id: u16, body: Value) -> Response {
            self.local(id, body)
        }

        #[cfg(not(windows))]
        fn socket(&self, id: u16, body: Value) -> Response {
            let token = *self.store().state().unwrap().control_token.expose();
            Client::new(
                Secret32::new(token),
                self.runtime.socket_path().to_path_buf(),
            )
            .call(&Command { id, body })
            .unwrap()
        }

        fn local(&self, id: u16, body: Value) -> Response {
            self.runtime.control(&Command { id, body }).unwrap()
        }

        /// The same command over both paths, on the same state: the two
        /// must give the same code and data.
        fn same(&self, id: u16, body: Value) -> Response {
            let socket = self.socket(id, body.clone());
            let local = self.local(id, body.clone());
            assert_eq!(
                (socket.code, &socket.data),
                (local.code, &local.data),
                "command {id}: {body}"
            );
            local
        }

        fn state_bytes(&self) -> Vec<u8> {
            encode_state(&self.store().state().unwrap()).unwrap()
        }

        fn configure(&self) -> u16 {
            let port = free_port();
            self.same(
                LISTEN_CONFIGURE,
                json!({"bindHost": LOOPBACK, "bindPort": port}),
            );
            port
        }

        /// Claims the offer of `url` straight through the store; returns
        /// the pending ID (`[n; 16]`, initiator `[n; 32]`).
        fn claim(&self, url: &str, n: u8) -> [u8; 16] {
            let offer = parse_pair_url(url, NOW_MS).unwrap();
            let pending_id = [n; 16];
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
                            NOW,
                        )
                        .map(|(next, _, _)| next)
                })
                .unwrap();
            pending_id
        }

        fn grant_of(&self, n: u8) -> [u8; 16] {
            let state = self.store().state().unwrap();
            state
                .reference
                .grants
                .iter()
                .find(|grant| grant.initiator_static == [n; 32])
                .unwrap()
                .grant_id
        }
    }

    /// `offerCreate` over the socket and in-process: both `ok`, with the
    /// same `expiresAt`, host, port and responder; the IDs and secrets are
    /// fresh per call. Returns `(socket, local)` Pair URLs.
    fn offer_pair(node: &Node) -> (String, String) {
        let body = json!({"ttlSeconds": 600});
        let socket = node.socket(OFFER_CREATE, body.clone());
        let local = node.local(OFFER_CREATE, body);
        assert_eq!((socket.code, local.code), (OK, OK));
        assert_eq!(socket.data["expiresAt"], local.data["expiresAt"]);
        assert_eq!(local.data["expiresAt"], NOW_MS + 600_000);
        let (s, l) = (
            parse_pair_url(socket.data["pairUrl"].as_str().unwrap(), NOW_MS).unwrap(),
            parse_pair_url(local.data["pairUrl"].as_str().unwrap(), NOW_MS).unwrap(),
        );
        assert_eq!(
            (&s.host, s.port, &s.responder_static),
            (&l.host, l.port, &l.responder_static)
        );
        assert_eq!(local.data["offerId"].as_str(), Some(l.offer_id.as_str()));
        assert_ne!(s.offer_id, l.offer_id);
        (
            socket.data["pairUrl"].as_str().unwrap().into(),
            local.data["pairUrl"].as_str().unwrap().into(),
        )
    }

    /// W2 acceptance: each of the eight commands gives the same code and
    /// data through `Runtime::control` as through the control socket, for
    /// success and for refusals (a refused body, sharing off, no host, a
    /// record that is not there or no longer active). Commands that create
    /// records run once per path on twin records, then the outcome is
    /// compared; reads run on the same state.
    #[test]
    fn each_of_the_eight_commands_answers_in_process_as_over_the_socket() {
        let node = Node::new();
        let status = node.same(STATUS, json!({}));
        assert_eq!(status.code, OK);
        assert_eq!(node.same(PENDING_LIST, json!({})).data, json!([]));
        // No host yet, then sharing off.
        let no_host = node.same(OFFER_CREATE, json!({"ttlSeconds": 600}));
        assert_eq!(no_host.code, INVALID);
        let port = node.configure();
        assert_eq!(node.runtime.listener_addr().unwrap().port(), port);
        let off = node.same(OFFER_CREATE, json!({"ttlSeconds": 600}));
        assert_eq!(off.code, UNAUTHORIZED);
        assert_eq!(
            node.same(
                LISTEN_CONFIGURE,
                json!({"bindHost": LOOPBACK, "bindPort": 80})
            )
            .code,
            INVALID
        );
        node.runtime.enable_sharing().unwrap();
        assert_eq!(node.same(STATUS, json!({})).data["sharingEnabled"], true);

        // offerCreate, then offerCancel of each path's own offer.
        let (s, l) = offer_pair(&node);
        let ids = [&s, &l].map(|url| parse_pair_url(url, NOW_MS).unwrap().offer_id);
        assert_eq!(node.same(STATUS, json!({})).data["activeOfferCount"], 2);
        let cancel_s = node.socket(OFFER_CANCEL, json!({"offerId": ids[0]}));
        let cancel_l = node.local(OFFER_CANCEL, json!({"offerId": ids[1]}));
        assert_eq!(
            (cancel_s.code, &cancel_s.data),
            (cancel_l.code, &cancel_l.data)
        );
        assert_eq!((cancel_l.code, cancel_l.data), (OK, Value::Null));
        for id in &ids {
            assert_eq!(
                node.same(OFFER_CANCEL, json!({ "offerId": id })).code,
                INVALID
            );
        }

        // Four pending records: approve and reject one each per path.
        let (a, b) = offer_pair(&node);
        let (c, d) = offer_pair(&node);
        let pending = [(a, 0x0a), (b, 0x0b), (c, 0x0c), (d, 0x0d)]
            .map(|(url, n)| hex_encode(&node.claim(&url, n)));
        let list = node.same(PENDING_LIST, json!({}));
        assert_eq!(list.data.as_array().unwrap().len(), 4);
        assert_eq!(node.same(STATUS, json!({})).data["pendingCount"], 4);
        for (command, first, second) in [(APPROVE, 0, 1), (REJECT, 2, 3)] {
            let body = |n: usize| json!({"pendingId": pending[n], "sasGeneration": 1});
            let socket = node.socket(command, body(first));
            let local = node.local(command, body(second));
            assert_eq!((socket.code, &socket.data), (local.code, &local.data));
            assert_eq!((local.code, local.data), (OK, Value::Null), "{command}");
            for n in [first, second] {
                let again = node.same(command, body(n));
                assert_ne!(again.code, OK, "{command} again");
            }
        }
        assert_eq!(node.same(PENDING_LIST, json!({})).data, json!([]));
        assert_eq!(node.same(STATUS, json!({})).data["activeGrantCount"], 2);

        // revoke one grant per path, then again.
        let grants = [0x0a, 0x0b].map(|n| hex_encode(&node.grant_of(n)));
        let socket = node.socket(REVOKE, json!({"grantId": grants[0]}));
        let local = node.local(REVOKE, json!({"grantId": grants[1]}));
        assert_eq!((socket.code, &socket.data), (local.code, &local.data));
        assert_eq!((local.code, local.data), (OK, Value::Null));
        for grant in &grants {
            assert_ne!(node.same(REVOKE, json!({ "grantId": grant })).code, OK);
        }
        let end = node.same(STATUS, json!({}));
        assert_eq!(end.data["activeGrantCount"], 0);
        assert_eq!(end.data["bindPort"], port);
    }

    /// W2 (b) negative controls: the frozen validator runs in-process.
    /// `ttlSeconds` 901 (the handler alone would accept it) and a body with
    /// an extra key are `invalid` with `null` data, and nothing is stored;
    /// control: 900 creates an offer. A command over `COMMAND_JSON_MAX` is
    /// refused before anything runs.
    #[test]
    fn the_frozen_validator_refuses_in_process_and_nothing_is_stored() {
        let node = Node::new();
        node.configure();
        node.runtime.enable_sharing().unwrap();
        let before = node.state_bytes();
        for body in [
            json!({"ttlSeconds": 901}),
            json!({"ttlSeconds": 600, "extra": 1}),
        ] {
            let response = node.local(OFFER_CREATE, body.clone());
            assert_eq!(
                (response.code, response.data),
                (INVALID, Value::Null),
                "{body}"
            );
            assert!(node.store().state().unwrap().reference.offers.is_empty());
            assert_eq!(node.state_bytes(), before, "{body}");
        }
        let oversize = node.runtime.control(&Command {
            id: STATUS,
            body: json!({"pad": "x".repeat(COMMAND_JSON_MAX)}),
        });
        assert_eq!(oversize, Err(ControlError::Command));
        assert_eq!(node.state_bytes(), before);

        let control = node.local(OFFER_CREATE, json!({"ttlSeconds": 900}));
        assert_eq!(control.code, OK);
        assert_eq!(node.store().state().unwrap().reference.offers.len(), 1);
    }

    /// W2 (d): `shutdown`, `sharingSet` and `scopeApprove` (and an unknown
    /// ID) are `invalid` in-process with valid bodies, and nothing runs:
    /// the state is unchanged, sharing stays off, and the runtime still
    /// answers.
    #[test]
    fn shutdown_sharing_set_and_scope_approve_are_invalid_in_process() {
        let node = Node::new();
        let before = node.state_bytes();
        for (id, body) in [
            (SHUTDOWN, json!({})),
            (SHARING_SET, json!({"enabled": true})),
            (
                SCOPE_APPROVE,
                json!({"ownerInputsSha256": "0123456789abcdef".repeat(4)}),
            ),
            (99, json!({})),
        ] {
            let response = node.local(id, body);
            assert_eq!(
                (response.code, response.data),
                (INVALID, Value::Null),
                "{id}"
            );
        }
        assert_eq!(node.state_bytes(), before);
        assert!(!node.store().state().unwrap().reference.sharing_enabled);
        // Control: over the socket, `sharingSet` runs the runtime's gate
        // (Windows, which has no socket: the direct method), so the state
        // above could have changed.
        #[cfg(not(windows))]
        assert_eq!(node.socket(SHARING_SET, json!({"enabled": true})).code, OK);
        #[cfg(windows)]
        node.runtime.enable_sharing().unwrap();
        assert!(node.store().state().unwrap().reference.sharing_enabled);
        assert_eq!(node.local(STATUS, json!({})).code, OK);
    }

    /// W2 (d): after `stop`, `Runtime::control` is the Rust-level
    /// `Stopped` for every ID; no wire code is involved.
    #[test]
    fn a_call_after_stop_is_stopped() {
        let node = Node::new();
        assert_eq!(node.local(STATUS, json!({})).code, OK);
        node.runtime.stop();
        for id in [STATUS, LISTEN_CONFIGURE, SHUTDOWN, 99] {
            assert_eq!(
                node.runtime.control(&Command {
                    id,
                    body: json!({}),
                }),
                Err(ControlError::Stopped),
                "{id}"
            );
        }
    }

    /// W2 (a): outside Windows the server is not optional. A regular file
    /// at the `control.sock` path fails `Runtime::start` with
    /// `Control(UnsafeSocket)`, leaves the file, and binds no port although
    /// a bindable listen address is stored.
    #[cfg(not(windows))]
    #[test]
    fn a_non_socket_at_the_control_path_fails_the_start_and_binds_no_port() {
        let home = TempHome::new();
        let port = free_port();
        {
            let store =
                StateStore::open(SecureRoot::open_under(&home.0, SUFFIX).unwrap(), NOW).unwrap();
            store
                .set_listen_config(Some(LOOPBACK.into()), port, None)
                .unwrap();
        }
        let path = home.root().join(SOCKET_NAME);
        fs::write(&path, b"keep").unwrap();
        assert_eq!(
            start(&home).err(),
            Some(RuntimeError::Control(ControlError::UnsafeSocket))
        );
        assert!(!listening(port), "a port was bound");
        assert_eq!(fs::read(&path).unwrap(), b"keep");

        // Control: with the file gone the same home starts and listens.
        fs::remove_file(&path).unwrap();
        let runtime = start(&home).unwrap();
        assert!(listening(port));
        drop(runtime);
    }
}
