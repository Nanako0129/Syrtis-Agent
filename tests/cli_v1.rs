//! SA-2C2b acceptance: the standalone binary and its menu (`src/cli.rs`,
//! `src/main.rs`, `spec/cli-v1.md`).
//!
//! The menu tests drive `cli::menu` with an injected reader and writer
//! against an `Agent` in this test process (the resident). The `run`
//! tests start the compiled debug binary with `SYRTIS_AGENT_DEBUG_HOME`
//! pointing at a temp home; no test runs it without that variable. Homes
//! are short directories below the real `/tmp`, so the control socket path
//! fits `sun_path`. Nothing reads the real home, loads a service or leaves
//! loopback. The release-build refusal (5b) is the CI step "Release build
//! refuses the debug home" (`.github/workflows/ci.yml`).

use std::io::Cursor;

use syrtis_agent::cli::{LINE_MAX, Line, read_line};

/// Acceptance (7), the reader: a line of exactly `LINE_MAX` bytes is
/// accepted, one byte more is `TooLong`, and the line after it is read
/// normally.
#[test]
fn a_line_over_the_limit_is_refused_and_the_next_one_is_read() {
    let exact = "a".repeat(LINE_MAX);
    let over = "b".repeat(LINE_MAX + 1);
    let mut input = Cursor::new(format!("{exact}\n{over}\nnext\r\n").into_bytes());
    assert_eq!(read_line(&mut input).unwrap(), Line::Text(exact));
    assert_eq!(read_line(&mut input).unwrap(), Line::TooLong);
    assert_eq!(read_line(&mut input).unwrap(), Line::Text("next".into()));
    assert_eq!(read_line(&mut input).unwrap(), Line::Eof);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod disk {
    use std::{
        fs,
        io::Cursor,
        net::TcpListener,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
        process::{Child, Command as Process, Output, Stdio},
        sync::atomic::{AtomicUsize, Ordering},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use serde_json::json;
    use syrtis_agent::{
        agent::{Agent, AgentConfig, AgentError, ScannerSettings},
        cli::{
            ALREADY_RUNNING, DEBUG_HOME_VAR, LINE_MAX, LINE_TOO_LONG, Menu, NOT_RUNNING,
            STOP_FIRST, USAGE, default_dirs, menu,
        },
        control::{Client, Command, OK, SHUTDOWN, SOCKET_NAME, STATUS},
        runtime::RuntimeError,
        secure_fs::{STATE_SUFFIX, SecureRoot, StorageError},
        security::{GrantState, OfferClaim, decode_fixed_hex, hex_encode, parse_pair_url},
        state_store::{STATE_FILE, STATE_FILE_MAX_BYTES, Secret32, StateStore, decode_state},
    };

    const SUFFIX: &[&str] = &["a"];
    const LOOPBACK: &str = "127.0.0.1";

    /// A short temp home below the real `/tmp` (canonical, so no component
    /// is a symlink). Only this directory is removed.
    struct TempHome(PathBuf);

    impl TempHome {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = fs::canonicalize("/tmp").unwrap().join(format!(
                "scli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn root(&self) -> PathBuf {
            self.0.join(SUFFIX[0])
        }

        fn menu(&self) -> Menu {
            Menu {
                home: self.0.clone(),
                suffix: SUFFIX,
                exe: None,
            }
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::set_permissions(self.root(), fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The resident, as `run` starts it: default roots of this home.
    fn start(home: &TempHome) -> Agent {
        for _ in 0..200 {
            let (config_dir, data_dir) = default_dirs(&home.0);
            let mut config = AgentConfig::new(
                home.0.clone(),
                config_dir,
                data_dir,
                ScannerSettings::default(),
            );
            config.state_suffix = SUFFIX;
            match Agent::start(config) {
                Err(AgentError::Storage(StorageError::Busy))
                | Err(AgentError::Runtime(RuntimeError::Store(StorageError::Busy))) => {
                    thread::sleep(Duration::from_millis(10))
                }
                other => return other.unwrap(),
            }
        }
        panic!("the agent did not start");
    }

    /// Runs the menu over `input`; returns everything it wrote. The output
    /// may hold a Pair URL: never put it in an assertion message.
    fn drive(menu_of: &Menu, input: &str) -> String {
        let mut out = Vec::new();
        menu(
            menu_of,
            &mut Cursor::new(input.as_bytes().to_vec()),
            &mut out,
        )
        .unwrap();
        String::from_utf8(out).unwrap()
    }

    fn free_port() -> u16 {
        TcpListener::bind((LOOPBACK, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn now_seconds() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Every path below `dir` with its kind, size and modification time.
    fn tree(dir: &Path) -> Vec<(PathBuf, bool, u64, i64, i64)> {
        let mut all = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(next) = stack.pop() {
            for entry in fs::read_dir(&next).unwrap() {
                let path = entry.unwrap().path();
                let meta = fs::symlink_metadata(&path).unwrap();
                if meta.is_dir() {
                    stack.push(path.clone());
                }
                all.push((
                    path,
                    meta.is_dir(),
                    meta.len(),
                    meta.mtime(),
                    meta.mtime_nsec(),
                ));
            }
        }
        all.sort();
        all
    }

    /// Claims the offer of `url` straight through the store, as the
    /// producer side of a claim would; returns the pending ID.
    fn claim(agent: &Agent, url: &str, n: u8) -> [u8; 16] {
        let offer = parse_pair_url(url, now_seconds() * 1_000).unwrap();
        let pending_id = [n; 16];
        agent
            .runtime()
            .store()
            .transition(|state| {
                state
                    .claim_offer(
                        OfferClaim {
                            offer_id: decode_fixed_hex(&offer.offer_id).unwrap(),
                            secret: decode_fixed_hex(&offer.secret).unwrap(),
                            responder_static: decode_fixed_hex(&offer.responder_static).unwrap(),
                            pending_id,
                            initiator_static: [n; 32],
                            sas_code: "ABCD-0123".into(),
                            sas_generation: 1,
                        },
                        now_seconds(),
                    )
                    .map(|(next, _, _)| next)
            })
            .unwrap();
        pending_id
    }

    /// The Pair URL the menu printed (the line after the heading).
    fn pair_url(out: &str) -> String {
        // The heading follows the prompt on the same line. Never print
        // `out`: it may hold the URL.
        let mut lines = out.lines();
        if lines.any(|line| line.contains("Pair URL (")) {
            if let Some(url) = lines.next() {
                return url.to_owned();
            }
        }
        panic!("no offer was created (output withheld)");
    }

    // ------------------------------------------------- open_read_only (0)

    /// Acceptance (0): with the agent of this process holding the owner
    /// lock, the menu's real path (`open_read_only`, `state.json`, the
    /// control token) reaches the agent and `status` answers.
    #[test]
    fn the_menu_reads_the_token_while_the_agent_holds_the_lock() {
        let home = TempHome::new();
        let agent = start(&home);
        assert_eq!(
            SecureRoot::open_under(&home.0, SUFFIX).err(),
            Some(StorageError::Busy),
            "the agent does not hold the lock"
        );
        let out = drive(&home.menu(), "1\n0\n");
        assert!(out.contains("Sharing: no"), "{out}");
        assert!(out.contains("Scan scope approved: no"), "{out}");
        drop(agent);
    }

    /// Acceptance (0): `open_read_only` refuses a root that is `0755` and a
    /// `state.json` that is a symlink (`UnsafeState`), and the menu then
    /// reports a safety check instead of calling.
    #[test]
    fn open_read_only_refuses_a_loose_root_or_a_symlinked_state() {
        let home = TempHome::new();
        drop(start(&home));
        fs::set_permissions(home.root(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            SecureRoot::open_read_only(&home.0, SUFFIX).err(),
            Some(StorageError::UnsafeState)
        );
        assert!(drive(&home.menu(), "1\n0\n").contains("failed a safety check (UnsafeState)"));
        fs::set_permissions(home.root(), fs::Permissions::from_mode(0o700)).unwrap();

        let state = home.root().join(STATE_FILE);
        let moved = home.0.join("state-elsewhere.json");
        fs::rename(&state, &moved).unwrap();
        symlink(&moved, &state).unwrap();
        let root = SecureRoot::open_read_only(&home.0, SUFFIX)
            .unwrap()
            .unwrap();
        assert_eq!(
            root.read_file(STATE_FILE, STATE_FILE_MAX_BYTES).err(),
            Some(StorageError::UnsafeState)
        );
        assert!(drive(&home.menu(), "1\n0\n").contains("failed a safety check (UnsafeState)"));
    }

    /// Acceptance (0): `open_read_only` creates nothing: on an empty home
    /// it is `None` and the home stays empty; on an existing root (agent
    /// running) every entry keeps its size and modification time.
    #[test]
    fn open_read_only_creates_nothing() {
        let home = TempHome::new();
        assert!(
            SecureRoot::open_read_only(&home.0, SUFFIX)
                .unwrap()
                .is_none()
        );
        assert!(
            SecureRoot::open_read_only(&home.0, STATE_SUFFIX)
                .unwrap()
                .is_none()
        );
        assert!(tree(&home.0).is_empty());

        drop(start(&home));
        let before = tree(&home.0);
        let root = SecureRoot::open_read_only(&home.0, SUFFIX)
            .unwrap()
            .unwrap();
        let bytes = root
            .read_file(STATE_FILE, STATE_FILE_MAX_BYTES)
            .unwrap()
            .unwrap();
        decode_state(&bytes).unwrap();
        assert_eq!(root.read_file("absent.json", 16).unwrap(), None);
        assert_eq!(tree(&home.0), before);
    }

    /// Acceptance (0): with the agent running, install and uninstall print
    /// the fixed message and create or remove nothing.
    #[test]
    fn install_and_uninstall_refuse_while_the_agent_runs() {
        let home = TempHome::new();
        let agent = start(&home);
        let exe = home.0.join("binary");
        fs::write(&exe, b"not a real binary").unwrap();
        let menu_of = Menu {
            exe: Some(exe),
            ..home.menu()
        };
        let installed = [
            home.0.join(".local/bin/syrtis-agent"),
            home.0
                .join("Library/LaunchAgents/com.nyanako.syrtis.agent.plist"),
            home.0.join(".config/systemd/user/syrtis-agent.service"),
        ];
        let out = drive(&menu_of, "10\n11\npurge\nuninstall\n0\n");
        assert_eq!(out.matches(STOP_FIRST).count(), 2, "{out}");
        for object in &installed {
            assert!(!object.exists(), "{}", object.display());
        }
        let state = agent.runtime().store().state().unwrap();
        assert!(state.reference.grants.is_empty());
        assert!(home.root().join(STATE_FILE).exists());
        drop(agent);
    }

    // ------------------------------------------------------- the menu (1)

    /// Acceptance (1): every menu item against the running agent: listen,
    /// sharing on, the scope disclosure and approval, an offer (its Pair
    /// URL), pending with approve and reject, grants with revoke, status,
    /// sharing off.
    #[test]
    fn every_menu_item_drives_the_running_agent() {
        let home = TempHome::new();
        let agent = start(&home);
        let menu_of = home.menu();
        let port = free_port();

        let out = drive(&menu_of, &format!("5\n{LOOPBACK}\n{port}\n2\n0\n"));
        assert!(out.contains("The listen address is set."), "{out}");
        assert!(out.contains("Sharing is on."), "{out}");
        let state = agent.runtime().store().state().unwrap();
        assert!(state.reference.sharing_enabled);
        assert_eq!(state.config.bind_port, port);
        assert!(drive(&menu_of, "2\n0\n").contains("sharing is already on"));

        let out = drive(&menu_of, "4\nno\n0\n");
        assert!(out.contains("Not approved."), "{out}");
        assert!(!agent.scope_approved());
        let out = drive(&menu_of, "4\napprove\n0\n");
        assert!(
            out.contains(&format!(
                "Inputs digest: {}",
                agent.source().owner_inputs_sha256()
            )),
            "{out}"
        );
        assert!(out.contains("Extra scan paths: none"), "{out}");
        assert!(out.contains("Scope approved."), "{out}");
        assert!(agent.scope_approved());

        let approved = claim(&agent, &pair_url(&drive(&menu_of, "6\n\n0\n")), 0x0a);
        let rejected = claim(&agent, &pair_url(&drive(&menu_of, "6\n300\n0\n")), 0x0b);
        assert!(drive(&menu_of, "6\n901\n0\n").contains("No offer was created"));
        let out = drive(&menu_of, "7\n1\napprove\n0\n");
        assert!(out.contains("code ABCD-0123"), "{out}");
        assert!(out.contains("Approved."), "{out}");
        let out = drive(&menu_of, "7\n1\nreject\n0\n");
        assert!(out.contains("Rejected."), "{out}");
        assert!(drive(&menu_of, "7\n0\n").contains("No pairing is waiting."));
        let reference = agent.runtime().store().state().unwrap().reference;
        let pending_state = |id: [u8; 16]| {
            reference
                .pending
                .iter()
                .find(|p| p.pending_id == id)
                .unwrap()
                .state
        };
        assert_ne!(pending_state(approved), pending_state(rejected));
        let grant = reference.grants[0].clone();
        assert_eq!(grant.state, GrantState::Active);

        let out = drive(&menu_of, "1\n0\n");
        assert!(out.contains("Active grants: 1"), "{out}");
        assert!(out.contains("Scan scope approved: yes"), "{out}");
        let out = drive(
            &menu_of,
            &format!("8\n{}\n0\n", hex_encode(&grant.grant_id)),
        );
        assert!(out.contains("Active grants: 1"), "{out}");
        assert!(out.contains("Revoked."), "{out}");
        let reference = agent.runtime().store().state().unwrap().reference;
        assert_eq!(reference.grants[0].state, GrantState::Revoked);

        let out = drive(&menu_of, "3\n1\n0\n");
        assert!(out.contains("Sharing is off."), "{out}");
        assert!(out.contains("Sharing: no"), "{out}");
        assert!(
            !agent
                .runtime()
                .store()
                .state()
                .unwrap()
                .reference
                .sharing_enabled
        );
    }

    /// Acceptance (1), grants while stopped: the menu takes the lock,
    /// lists the active grant and revokes it on the store (`revoke_commit`).
    #[test]
    fn grants_are_listed_and_revoked_on_the_store_when_the_agent_is_stopped() {
        let home = TempHome::new();
        let agent = start(&home);
        let menu_of = home.menu();
        let port = free_port();
        drive(&menu_of, &format!("5\n{LOOPBACK}\n{port}\n2\n0\n"));
        let pending = claim(&agent, &pair_url(&drive(&menu_of, "6\n\n0\n")), 0x0c);
        drive(&menu_of, "7\n1\napprove\n0\n");
        let reference = agent.runtime().store().state().unwrap().reference;
        assert!(reference.pending.iter().any(|p| p.pending_id == pending));
        let grant_id = reference.grants[0].grant_id;
        drop(agent);

        // A child process another test forks can hold the released lock
        // for a moment (`secure_fs` `retry_busy`): only that is retried.
        let input = format!("8\n{}\n0\n", hex_encode(&grant_id));
        let mut out = drive(&menu_of, &input);
        for _ in 0..100 {
            if !out.contains(STOP_FIRST) {
                break;
            }
            thread::sleep(Duration::from_millis(20));
            out = drive(&menu_of, &input);
        }
        assert!(
            out.contains("The agent is not running. Active grants: 1"),
            "{out}"
        );
        assert!(out.contains(&hex_encode(&grant_id)), "{out}");
        assert!(out.contains("Revoked."), "{out}");
        let store = StateStore::open(
            SecureRoot::open_under(&home.0, SUFFIX).unwrap(),
            now_seconds(),
        )
        .unwrap();
        assert_eq!(
            store.state().unwrap().reference.grants[0].state,
            GrantState::Revoked
        );
    }

    /// Acceptance (5c): with no resident, every control item prints the
    /// fixed hint, and `state.json` is unchanged byte for byte.
    #[test]
    fn with_the_agent_stopped_control_items_write_nothing() {
        let home = TempHome::new();
        drop(start(&home));
        let state = home.root().join(STATE_FILE);
        let before = fs::read(&state).unwrap();
        let tree_before = tree(&home.0);
        let out = drive(
            &home.menu(),
            &format!("2\n3\n4\napprove\n5\n{LOOPBACK}\n4000\n6\n\n7\n9\n1\n0\n"),
        );
        assert_eq!(out.matches(NOT_RUNNING).count(), 8, "{out}");
        assert_eq!(fs::read(&state).unwrap(), before);
        assert_eq!(tree(&home.0), tree_before);
    }

    /// Acceptance (7), the menu: a choice line over the limit is reported
    /// and ignored; the menu goes on.
    #[test]
    fn the_menu_ignores_a_line_over_the_limit() {
        let home = TempHome::new();
        let input = format!("{}\n0\n", "1".repeat(LINE_MAX + 1));
        let out = drive(&home.menu(), &input);
        assert!(out.contains(LINE_TOO_LONG), "{out}");
        assert!(tree(&home.0).is_empty());
    }

    // ------------------------------------------------ the binary (5), (6)

    /// The compiled debug binary on `home`, never without the variable.
    fn binary(home: &Path) -> Process {
        let mut process = Process::new(env!("CARGO_BIN_EXE_syrtis-agent"));
        process
            .env(DEBUG_HOME_VAR, home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        process
    }

    /// Kills the child if the test fails first.
    struct Running(Option<Child>);

    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn output_within(mut child: Child, within: Duration) -> Output {
        let deadline = Instant::now() + within;
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("the binary did not exit within {within:?}");
            }
            thread::sleep(Duration::from_millis(20));
        }
        child.wait_with_output().unwrap()
    }

    /// The control client the menu would build, for the binary's root.
    fn client_of(home: &Path) -> Option<Client> {
        let root = SecureRoot::open_read_only(home, STATE_SUFFIX).ok()??;
        let bytes = root.read_file(STATE_FILE, STATE_FILE_MAX_BYTES).ok()??;
        let token = *decode_state(&bytes).ok()?.control_token.expose();
        let socket = STATE_SUFFIX
            .iter()
            .fold(home.to_path_buf(), |path, part| path.join(part))
            .join(SOCKET_NAME);
        Some(Client::new(Secret32::new(token), socket))
    }

    /// Acceptance (5): `run` on a temp home serves `status`; a second `run`
    /// while it runs exits non-zero with the fixed message; `shutdown`
    /// ends the first with status 0.
    #[test]
    fn run_serves_status_and_exits_zero_on_shutdown() {
        let home = TempHome::new();
        let mut running = Running(Some(binary(&home.0).arg("run").spawn().unwrap()));
        let deadline = Instant::now() + Duration::from_secs(20);
        let client = loop {
            let ready = client_of(&home.0).filter(|client| {
                client
                    .call(&Command {
                        id: STATUS,
                        body: json!({}),
                    })
                    .is_ok_and(|reply| reply.code == OK)
            });
            if let Some(client) = ready {
                break client;
            }
            assert!(Instant::now() < deadline, "status never answered");
            thread::sleep(Duration::from_millis(50));
        };

        let second = output_within(
            binary(&home.0).arg("run").spawn().unwrap(),
            Duration::from_secs(20),
        );
        assert!(!second.status.success());
        assert_eq!(
            String::from_utf8_lossy(&second.stderr).trim_end(),
            ALREADY_RUNNING
        );

        let reply = client
            .call(&Command {
                id: SHUTDOWN,
                body: json!({}),
            })
            .unwrap();
        assert_eq!(reply.code, OK);
        let first = output_within(running.0.take().unwrap(), Duration::from_secs(20));
        assert_eq!(first.status.code(), Some(0));
    }

    /// Acceptance (6): neither `run` nor the menu takes any other
    /// argument (no secret can arrive by argv); each is refused with the
    /// usage line before anything is opened.
    #[test]
    fn unknown_arguments_are_refused_before_anything_is_opened() {
        let home = TempHome::new();
        for args in [
            &["--token", "00"][..],
            &["run", "--pair-url"][..],
            &["menu"][..],
            &["run", "run"][..],
        ] {
            let out = output_within(
                binary(&home.0).args(args).spawn().unwrap(),
                Duration::from_secs(20),
            );
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            assert_eq!(String::from_utf8_lossy(&out.stderr).trim_end(), USAGE);
        }
        assert!(tree(&home.0).is_empty());
    }
}
