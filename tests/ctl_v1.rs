//! `syrtis-agent ctl` acceptance (`spec/cli-v1.md`, "ctl").
//!
//! Every `ctl` call here is the compiled debug binary on a temp home
//! (`SYRTIS_AGENT_DEBUG_HOME`), so the real argument parser, the real
//! `open_read_only` token path and the real control socket are exercised.
//! The resident is either an `Agent` of this test process (so a test can
//! plant a pending pairing straight through the store, as a producer-side
//! claim would) or a `run` subprocess. Homes are short directories below
//! the real `/tmp` so the control socket path fits `sun_path`. Nothing
//! reads the real home or leaves loopback. The unit-level pending rules
//! (a recording fake control) are in `src/cli/ctl.rs`.
//!
//! These tests run on macOS and Linux alike; the only Linux-only check is
//! the golden unit text in `tests/install_v1.rs`.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::{
    ffi::{OsStr, OsString},
    fs,
    net::TcpListener,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command as Process, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use syrtis_agent::{
    agent::{Agent, AgentConfig, AgentError, ScannerSettings},
    cli::{DEBUG_HOME_VAR, default_dirs},
    runtime::RuntimeError,
    secure_fs::StorageError,
    security::{OfferClaim, PendingState, decode_fixed_hex, hex_encode, parse_pair_url},
};

const PREFIX: &str = "SYRTIS-CTL-V1 ";
const LOOPBACK: &str = "127.0.0.1";
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A short temp home below the real `/tmp`. Only this directory is
/// removed.
struct TempHome(PathBuf);

impl TempHome {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = fs::canonicalize("/tmp").unwrap().join(format!(
            "sctl-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The resident of this process, on the frozen suffix `ctl` uses.
fn start(home: &TempHome) -> Agent {
    for _ in 0..200 {
        let (config_dir, data_dir) = default_dirs(&home.0);
        let config = AgentConfig::new(
            home.0.clone(),
            config_dir,
            data_dir,
            ScannerSettings::default(),
        );
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

fn binary(home: &Path) -> Process {
    let mut process = Process::new(env!("CARGO_BIN_EXE_syrtis-agent"));
    process
        .env(DEBUG_HOME_VAR, home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    process
}

/// Kills the child if a test fails first.
struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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

/// What one `ctl` call produced, after the output contract was checked.
struct Ctl {
    code: i32,
    /// The JSON object after the prefix (success only).
    json: Value,
    stderr: String,
}

/// Runs `ctl <args>` and checks the contract that holds for every call:
/// success is exit 0, one `PREFIX` line of JSON on stdout and an empty
/// stderr; failure is a non-zero exit, an empty stdout and one stderr
/// line. A Pair URL never appears on stderr (this holds for both).
fn ctl(home: &Path, args: &[&str]) -> Ctl {
    let mut process = binary(home);
    process.arg("ctl").args(args);
    let out = output_within(process.spawn().unwrap(), Duration::from_secs(30));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    let code = out.status.code().unwrap();
    assert!(!stderr.contains("syrtis://"), "a Pair URL reached stderr");
    if code == 0 {
        assert_eq!(stderr, "", "{args:?}");
        assert_eq!(stdout.lines().count(), 1, "{args:?}");
        assert!(stdout.ends_with('\n'));
        let body = stdout.strip_prefix(PREFIX).expect("the fixed prefix");
        let json: Value = serde_json::from_str(body.trim_end()).unwrap();
        assert!(json.is_object());
        Ctl { code, json, stderr }
    } else {
        assert_eq!(stdout, "", "{args:?}");
        assert_eq!(stderr.lines().count(), 1, "{args:?}: {stderr}");
        assert!(stderr.starts_with("syrtis-agent ctl: "), "{stderr}");
        Ctl {
            code,
            json: Value::Null,
            stderr,
        }
    }
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

/// Every path below `dir` with its kind and size.
fn tree(dir: &Path) -> Vec<(PathBuf, bool, u64)> {
    let mut all = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                stack.push(path.clone());
            }
            all.push((path, meta.is_dir(), meta.len()));
        }
    }
    all.sort();
    all
}

/// Scope approved, a loopback listen address set and sharing on, all
/// through `ctl`; returns the digest that was approved.
fn make_ready(home: &Path) -> String {
    let disclosure = ctl(home, &["scope", "disclosure"]);
    assert_eq!(disclosure.code, 0);
    let digest = disclosure.json["ownerInputsSha256"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        ctl(home, &["scope", "approve", "--digest", &digest]).code,
        0
    );
    let port = free_port().to_string();
    assert_eq!(
        ctl(home, &["listen", "--host", LOOPBACK, "--port", &port]).code,
        0
    );
    assert_eq!(ctl(home, &["sharing", "on"]).code, 0);
    digest
}

/// A Pair URL from `ctl offer create`, kept out of any assertion text.
fn offer(home: &Path, ttl: &str) -> String {
    let created = ctl(home, &["offer", "create", "--ttl", ttl]);
    assert_eq!(created.code, 0);
    created.json["pairUrl"].as_str().unwrap().to_owned()
}

/// Claims the offer of `url` through the store as a producer-side claim
/// would; returns the pending ID.
fn claim(agent: &Agent, url: &str, n: u8, sas: &str) -> [u8; 16] {
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
                        sas_code: sas.into(),
                        sas_generation: 1,
                    },
                    now_seconds(),
                )
                .map(|(next, _, _)| next)
        })
        .unwrap();
    pending_id
}

fn pending_state(agent: &Agent, id: [u8; 16]) -> PendingState {
    agent
        .runtime()
        .store()
        .state()
        .unwrap()
        .reference
        .pending
        .iter()
        .find(|pending| pending.pending_id == id)
        .unwrap()
        .state
}

// ------------------------------------------------------------ arguments

/// Every illegal value is refused with the usage line and exit 2 before
/// anything is opened: no root, no socket, no file. Nothing arrives by a
/// secret-looking flag either.
#[test]
fn illegal_arguments_are_refused_before_anything_is_opened() {
    let home = TempHome::new();
    let upper = ZERO_DIGEST.replace('0', "A");
    let mut cases: Vec<Vec<OsString>> = [
        &["scope", "approve", "--digest", upper.as_str()][..],
        &["scope", "approve", "--digest", &ZERO_DIGEST[..63]][..],
        &["scope", "approve", "--digest", "xyz"][..],
        &["scope", "approve"][..],
        &["listen", "--host", "0.0.0.0", "--port", "50000"][..],
        &["listen", "--host", LOOPBACK, "--port", "80"][..],
        &["listen", "--host", LOOPBACK, "--port", "70000"][..],
        &["offer", "create", "--ttl", "121"][..],
        &["offer", "create", "--ttl", "0"][..],
        &["offer", "create", "--ttl", "-1"][..],
        &["pending", "approve", "--expect-sas", "abcd-0123"][..],
        &["pending", "approve", "--expect-sas", "ABCD0123"][..],
        &["grant", "revoke", "--grant-id", "00"][..],
        &["--token", "00"][..],
        &["status", "--token", ZERO_DIGEST][..],
        &["pair-url", "syrtis://pair?offer=00"][..],
        &[][..],
    ]
    .iter()
    .map(|args| args.iter().map(OsString::from).collect())
    .collect();
    cases.push(vec![
        OsString::from("status"),
        OsStr::from_bytes(b"\xff\xfe").to_owned(),
    ]);
    for args in cases {
        let mut process = binary(&home.0);
        process.arg("ctl").args(&args);
        let out = output_within(process.spawn().unwrap(), Duration::from_secs(30));
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert_eq!(stderr.lines().count(), 1, "{args:?}");
        assert!(stderr.starts_with("syrtis-agent ctl: usage: "), "{stderr}");
    }
    assert!(tree(&home.0).is_empty());
}

/// With no resident every control command exits 4 and changes nothing.
#[test]
fn without_a_resident_control_commands_exit_4_and_write_nothing() {
    let home = TempHome::new();
    for args in [
        &["status"][..],
        &["sharing", "on"][..],
        &["scope", "approve", "--digest", ZERO_DIGEST][..],
        &["listen", "--host", LOOPBACK, "--port", "47123"][..],
        &["offer", "create", "--ttl", "120"][..],
        &["pending", "approve", "--expect-sas", "ABCD-0123"][..],
        &["shutdown"][..],
    ] {
        assert_eq!(ctl(&home.0, args).code, 4, "{args:?}");
    }
    assert!(tree(&home.0).is_empty());
}

// ------------------------------------------------------ digest, consent

/// `status` gives the baseline fields; the disclosure digest is the
/// resident's own; a digest that is well formed but not the resident's is
/// refused (exit 5) and the scope stays unapproved; the right digest
/// approves it.
#[test]
fn a_wrong_digest_is_refused_and_the_right_one_approves() {
    let home = TempHome::new();
    let agent = start(&home);

    let baseline = ctl(&home.0, &["status"]).json;
    assert_eq!(baseline["sharingEnabled"], false);
    assert_eq!(baseline["bindHost"], Value::Null);
    assert!(baseline["bindPort"].is_u64());
    assert_eq!(baseline["activeGrantCount"], 0);
    assert_eq!(baseline["scopeApproved"], false);

    let disclosure = ctl(&home.0, &["scope", "disclosure"]).json;
    let digest = disclosure["ownerInputsSha256"].as_str().unwrap();
    assert_eq!(digest, agent.source().owner_inputs_sha256());
    assert!(disclosure["lines"].as_array().unwrap().len() >= 5);

    let refused = ctl(&home.0, &["scope", "approve", "--digest", ZERO_DIGEST]);
    assert_eq!(refused.code, 5);
    assert!(refused.stderr.contains("invalid"), "{}", refused.stderr);
    assert!(!agent.scope_approved());
    assert_eq!(ctl(&home.0, &["status"]).json["scopeApproved"], false);

    assert_eq!(
        ctl(&home.0, &["scope", "approve", "--digest", digest]).code,
        0
    );
    assert!(agent.scope_approved());
    assert_eq!(ctl(&home.0, &["status"]).json["scopeApproved"], true);
}

// ------------------------------------------------------ pending approve

/// A SAS that matches no pending pairing, then one carried by two of
/// them: both exit 8 and every pending stays as it was (not approved, not
/// rejected). The one pending with a unique SAS is then approved, and the
/// others are untouched.
#[test]
fn only_a_unique_sas_match_approves_and_no_other_pending_is_touched() {
    let home = TempHome::new();
    let agent = start(&home);
    make_ready(&home.0);
    let first = claim(&agent, &offer(&home.0, "120"), 0x01, "AAAA-1111");
    let second = claim(&agent, &offer(&home.0, "120"), 0x02, "BBBB-2222");
    let twin = claim(&agent, &offer(&home.0, "120"), 0x03, "AAAA-1111");
    let waiting = |ids: &[[u8; 16]]| {
        ids.iter()
            .all(|id| pending_state(&agent, *id) == PendingState::AwaitingApproval)
    };
    assert_eq!(ctl(&home.0, &["status"]).json["pendingCount"], 3);

    // Mismatch.
    let none = ctl(
        &home.0,
        &["pending", "approve", "--expect-sas", "CCCC-3333"],
    );
    assert_eq!(none.code, 8);
    assert!(waiting(&[first, second, twin]));

    // Two pending pairings with the same code: ambiguous.
    let several = ctl(
        &home.0,
        &["pending", "approve", "--expect-sas", "AAAA-1111"],
    );
    assert_eq!(several.code, 8);
    assert!(
        several.stderr.contains("more than one"),
        "{}",
        several.stderr
    );
    assert!(waiting(&[first, second, twin]));
    assert_eq!(ctl(&home.0, &["status"]).json["activeGrantCount"], 0);

    // Exactly one: approved; the others are neither approved nor rejected.
    let approved = ctl(
        &home.0,
        &["pending", "approve", "--expect-sas", "BBBB-2222"],
    );
    assert_eq!(approved.code, 0);
    assert_eq!(approved.json["approved"], true);
    assert_eq!(pending_state(&agent, second), PendingState::Approved);
    assert!(waiting(&[first, twin]));
    assert_eq!(ctl(&home.0, &["status"]).json["activeGrantCount"], 1);
}

/// A pending pairing past its expiry is not approved, and no other
/// pending pairing is rejected or approved.
#[test]
fn an_expired_pending_is_not_approved_and_nothing_else_is_touched() {
    let home = TempHome::new();
    let agent = start(&home);
    make_ready(&home.0);
    // Two seconds, not one: an offer is stamped on a whole second, so a
    // one-second offer can already be past its expiry when `claim` parses
    // its URL a few milliseconds later.
    let expired = claim(&agent, &offer(&home.0, "2"), 0x01, "AAAA-1111");
    let live = claim(&agent, &offer(&home.0, "120"), 0x02, "BBBB-2222");
    thread::sleep(Duration::from_millis(3_300));

    let result = ctl(
        &home.0,
        &["pending", "approve", "--expect-sas", "AAAA-1111"],
    );
    assert_eq!(result.code, 8);
    let state = pending_state(&agent, expired);
    assert_ne!(state, PendingState::Approved);
    assert_ne!(state, PendingState::Rejected);
    assert_eq!(pending_state(&agent, live), PendingState::AwaitingApproval);
    assert_eq!(ctl(&home.0, &["status"]).json["activeGrantCount"], 0);
}

// ------------------------------------------------------- secret output

/// The Pair URL is on stdout of `offer create` only; a refused
/// `offer create` and every other call keep it off stderr (`ctl` itself
/// asserts that on every call). Also `grant revoke` and `offer cancel`.
#[test]
fn the_pair_url_is_on_stdout_only_and_offers_and_grants_are_managed() {
    let home = TempHome::new();
    let agent = start(&home);

    // Sharing is off: refused, and the failure line carries no URL.
    let refused = ctl(&home.0, &["offer", "create", "--ttl", "120"]);
    assert_eq!(refused.code, 5);

    make_ready(&home.0);
    let created = ctl(&home.0, &["offer", "create", "--ttl", "120"]);
    let url = created.json["pairUrl"].as_str().unwrap();
    assert!(parse_pair_url(url, now_seconds() * 1_000).is_ok());
    let offer_id = created.json["offerId"].as_str().unwrap().to_owned();
    assert_eq!(ctl(&home.0, &["status"]).json["activeOfferCount"], 1);
    assert_eq!(
        ctl(&home.0, &["offer", "cancel", "--offer-id", &offer_id]).code,
        0
    );
    assert_eq!(ctl(&home.0, &["status"]).json["activeOfferCount"], 0);
    // Cancelling again is refused, not a success.
    assert_eq!(
        ctl(&home.0, &["offer", "cancel", "--offer-id", &offer_id]).code,
        5
    );

    claim(&agent, &offer(&home.0, "120"), 0x07, "ABCD-0123");
    assert_eq!(
        ctl(
            &home.0,
            &["pending", "approve", "--expect-sas", "ABCD-0123"]
        )
        .code,
        0
    );
    let grant = agent.runtime().store().state().unwrap().reference.grants[0].grant_id;
    let grant_id = hex_encode(&grant);
    assert_eq!(ctl(&home.0, &["status"]).json["activeGrantCount"], 1);
    assert_eq!(
        ctl(&home.0, &["grant", "revoke", "--grant-id", &grant_id]).code,
        0
    );
    assert_eq!(ctl(&home.0, &["status"]).json["activeGrantCount"], 0);
    assert_eq!(
        ctl(&home.0, &["grant", "revoke", "--grant-id", &"0".repeat(32)]).code,
        5
    );
}

// -------------------------------------------------------------- install

/// The destination (`.local/bin`) is writable by group or others:
/// `ctl install` refuses with exit 7 and `UnsafeState`, and writes no
/// binary and no autostart object.
#[test]
fn install_refuses_a_destination_others_can_write() {
    for mode in [0o777, 0o757, 0o775] {
        let home = TempHome::new();
        let bin = home.0.join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(mode)).unwrap();

        let result = ctl(&home.0, &["install"]);
        assert_eq!(result.code, 7, "{mode:o}");
        assert!(result.stderr.contains("UnsafeState"), "{}", result.stderr);
        assert_eq!(fs::read_dir(&bin).unwrap().count(), 0, "{mode:o}");
        assert!(!home.0.join(".config/systemd/user").exists());
        assert!(!home.0.join("Library/LaunchAgents").exists());
    }
}

/// A symlinked destination is refused too (the no-follow walk), and the
/// link target is left alone.
#[test]
fn install_refuses_a_symlinked_destination_directory() {
    let home = TempHome::new();
    let decoy = home.0.join("decoy");
    fs::create_dir(&decoy).unwrap();
    fs::create_dir_all(home.0.join(".local")).unwrap();
    std::os::unix::fs::symlink(&decoy, home.0.join(".local/bin")).unwrap();

    assert_eq!(ctl(&home.0, &["install"]).code, 7);
    assert_eq!(fs::read_dir(&decoy).unwrap().count(), 0);
}

/// `ctl install` through `install::install`: the binary and the autostart
/// object land at the frozen paths with their modes, nothing is started;
/// then `ctl uninstall --purge` removes them. The binary is run from a
/// copy at a path made of bytes install accepts.
#[test]
fn install_and_uninstall_use_the_frozen_install_path() {
    let home = TempHome::new();
    let source = home.0.join("src");
    fs::create_dir(&source).unwrap();
    let exe = source.join("syrtis-agent");
    fs::copy(env!("CARGO_BIN_EXE_syrtis-agent"), &exe).unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();

    let mut process = Process::new(&exe);
    process
        .env(DEBUG_HOME_VAR, &home.0)
        .args(["ctl", "install"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let deadline = Instant::now() + Duration::from_secs(2);
    let child = loop {
        match process.spawn() {
            Ok(child) => break child,
            Err(err) if err.raw_os_error() == Some(26) && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => panic!("spawn failed: {err}"),
        }
    };
    let out = output_within(child, Duration::from_secs(60));
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{PREFIX}{{\"installed\":true}}\n")
    );
    let installed = home.0.join(".local/bin/syrtis-agent");
    assert_eq!(fs::read(&installed).unwrap(), fs::read(&exe).unwrap());
    assert_eq!(installed.metadata().unwrap().mode() & 0o777, 0o755);
    let autostart = if cfg!(target_os = "macos") {
        home.0
            .join("Library/LaunchAgents/com.nyanako.syrtis.agent.plist")
    } else {
        home.0.join(".config/systemd/user/syrtis-agent.service")
    };
    assert_eq!(autostart.metadata().unwrap().mode() & 0o777, 0o644);
    let text = fs::read_to_string(&autostart).unwrap();
    assert!(text.contains(installed.to_str().unwrap()));

    let removed = ctl(&home.0, &["uninstall", "--purge"]);
    assert_eq!(removed.code, 0);
    assert_eq!(removed.json["purged"], true);
    assert_eq!(removed.json["binary"], "removed");
    assert_eq!(removed.json["autostart"], "removed");
    assert!(!installed.exists());
    assert!(!autostart.exists());
}

/// `install` and `uninstall` refuse while the resident runs (exit 9) and
/// touch nothing.
#[test]
fn install_and_uninstall_refuse_while_the_resident_runs() {
    let home = TempHome::new();
    let agent = start(&home);
    assert_eq!(ctl(&home.0, &["install"]).code, 9);
    assert_eq!(ctl(&home.0, &["uninstall", "--purge"]).code, 9);
    let autostart = if cfg!(target_os = "macos") {
        home.0
            .join("Library/LaunchAgents/com.nyanako.syrtis.agent.plist")
    } else {
        home.0.join(".config/systemd/user/syrtis-agent.service")
    };
    assert!(!home.0.join(".local/bin/syrtis-agent").exists());
    assert!(!autostart.exists());
    assert_eq!(ctl(&home.0, &["status"]).code, 0);
    drop(agent);
}

// ------------------------------------------------- clean agent to offer

/// A clean resident (`run` on a temp home) walked to a live offer with
/// `ctl` alone, in the order of the plan: status baseline, disclosure,
/// scope approve, sharing on, listen, offer create. Then the offer is
/// cancelled and `shutdown` ends the resident with status 0.
#[test]
fn a_clean_agent_is_walked_to_an_offer_with_ctl_alone() {
    let home = TempHome::new();
    let mut resident = Kill(binary(&home.0).arg("run").spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    let baseline = loop {
        let status = ctl(&home.0, &["status"]);
        if status.code == 0 {
            break status.json;
        }
        assert!(Instant::now() < deadline, "the resident never answered");
        thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(baseline["sharingEnabled"], false);
    assert_eq!(baseline["bindHost"], Value::Null);
    assert_eq!(baseline["activeGrantCount"], 0);
    assert_eq!(baseline["scopeApproved"], false);

    let digest = make_ready(&home.0);
    assert_eq!(digest.len(), 64);
    let port = ctl(&home.0, &["status"]).json["bindPort"].as_u64().unwrap();
    let after = ctl(&home.0, &["status"]).json;
    assert_eq!(after["sharingEnabled"], true);
    assert_eq!(after["scopeApproved"], true);
    assert_eq!(after["bindHost"], LOOPBACK);
    assert_eq!(after["bindPort"], port);

    let created = ctl(&home.0, &["offer", "create", "--ttl", "120"]);
    let offer = parse_pair_url(
        created.json["pairUrl"].as_str().unwrap(),
        now_seconds() * 1_000,
    )
    .unwrap();
    assert_eq!(offer.host, LOOPBACK);
    assert_eq!(u64::from(offer.port), port);
    assert_eq!(ctl(&home.0, &["status"]).json["activeOfferCount"], 1);
    let offer_id = created.json["offerId"].as_str().unwrap();
    assert_eq!(
        ctl(&home.0, &["offer", "cancel", "--offer-id", offer_id]).code,
        0
    );

    assert_eq!(ctl(&home.0, &["shutdown"]).code, 0);
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = resident.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the resident did not stop");
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(0));
}

/// `ctl uninstall` in a home that never had an agent changes nothing: no
/// root, no identity, no control token. Reports every object absent.
#[test]
fn uninstall_in_an_empty_home_creates_nothing() {
    let home = TempHome::new();
    for args in [&["uninstall"][..], &["uninstall", "--purge"][..]] {
        let out = ctl(&home.0, args);
        assert_eq!(out.code, 0, "{args:?}");
        assert_eq!(out.json["purged"], false);
        for object in [
            "autostart",
            "binary",
            "producerCache",
            "receiverCache",
            "sourceCache",
        ] {
            assert_eq!(out.json[object], "absent", "{object}");
        }
        assert_eq!(fs::read_dir(&home.0).unwrap().count(), 0, "{args:?}");
    }
}

/// After a purge (which keeps `owner.lock`, the emptied `source-cache` and
/// what no uninstall touches) a second uninstall has nothing to do and
/// creates nothing. A cache that is still in the state directory (as after
/// an uninstall that could not clear it) is not "nothing": the full
/// uninstall runs and removes it instead of reporting it `absent`, with or
/// without `--purge`, and the identity it has to create on the way never
/// stays behind.
#[test]
fn uninstall_does_not_report_a_leftover_cache_as_absent() {
    let home = TempHome::new();
    drop(start(&home));
    assert_eq!(ctl(&home.0, &["uninstall", "--purge"]).json["purged"], true);

    let lock = tree(&home.0)
        .into_iter()
        .map(|(path, _, _)| path)
        .find(|path| path.ends_with("owner.lock"))
        .expect("the purge keeps owner.lock");
    let root = lock.parent().unwrap();
    let before = tree(&home.0);
    assert!(!root.join("state.json").exists());
    let again = ctl(&home.0, &["uninstall", "--purge"]);
    assert_eq!(
        (again.code, &again.json["sourceCache"]),
        (0, &"absent".into())
    );
    assert_eq!(tree(&home.0), before, "nothing was created");

    // The purge emptied `source-cache` and kept the directory.
    let cache = root.join("source-cache");
    for (args, purged) in [
        (&["uninstall"][..], false),
        (&["uninstall", "--purge"][..], true),
    ] {
        fs::write(cache.join("left"), b"x").unwrap();
        let cleared = ctl(&home.0, args);
        assert_eq!(cleared.code, 0, "{args:?}: {}", cleared.stderr);
        assert_eq!(cleared.json["sourceCache"], "removed", "{args:?}");
        assert_eq!(cleared.json["purged"], purged, "{args:?}");
        assert_eq!(tree(&home.0), before, "{args:?}: no identity was left");
    }
}

/// macOS: an empty 0700 `source-cache` that carries an extended ACL is not
/// what a purge leaves. `clear_private_subdir` refuses it, so the uninstall
/// keeps answering exit 7 for it instead of `absent` on the retry.
#[cfg(target_os = "macos")]
#[test]
fn uninstall_does_not_report_a_cache_with_an_acl_as_absent() {
    let home = TempHome::new();
    drop(start(&home));
    assert_eq!(ctl(&home.0, &["uninstall", "--purge"]).json["purged"], true);
    let cache = tree(&home.0)
        .into_iter()
        .map(|(path, _, _)| path)
        .find(|path| path.ends_with("source-cache"))
        .expect("the purge keeps the emptied source-cache");
    let status = Process::new("/bin/chmod")
        .args(["+a", "everyone allow read"])
        .arg(&cache)
        .status()
        .unwrap();
    assert!(status.success());

    for _ in 0..2 {
        let refused = ctl(&home.0, &["uninstall", "--purge"]);
        assert_eq!(refused.code, 7, "{}", refused.stderr);
        assert!(refused.stderr.contains("sourceCache"), "{}", refused.stderr);
    }
}

/// line, which does not claim that nothing happened.
#[test]
fn an_unwritable_stdout_is_a_local_failure_with_its_stderr_line() {
    let home = TempHome::new();
    // The write end of a pipe nobody reads: every write is EPIPE. (A
    // closed or read-only descriptor would not do: std reports success
    // for EBADF on stdout.)
    let mut reader = Process::new("true").stdin(Stdio::piped()).spawn().unwrap();
    let broken = reader.stdin.take().unwrap();
    reader.wait().unwrap();
    let mut process = binary(&home.0);
    process.args(["ctl", "uninstall"]).stdout(broken);
    let out = output_within(process.spawn().unwrap(), Duration::from_secs(30));
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        "syrtis-agent ctl: the result could not be written; the command may have taken effect\n"
    );
}

/// A unit written from upstream's previous template (36ce382) is still the
/// agent's: `ctl uninstall --purge` removes it and purges.
#[cfg(target_os = "linux")]
#[test]
fn uninstall_purge_accepts_a_unit_from_the_previous_template() {
    let home = TempHome::new();
    let binary = home.0.join(".local/bin/syrtis-agent");
    let unit = home.0.join(".config/systemd/user/syrtis-agent.service");
    // Created 0755 whatever the umask: install refuses a group-writable parent.
    for dir in [binary.parent().unwrap(), unit.parent().unwrap()] {
        fs::create_dir_all(dir).unwrap();
        for ancestor in dir.ancestors().take_while(|path| *path != home.0) {
            fs::set_permissions(ancestor, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    fs::write(&binary, b"agent").unwrap();
    fs::write(
        &unit,
        format!(
            "[Unit]\nDescription=Syrtis Agent\n\n[Service]\nExecStart={} run\n\n\
[Install]\nWantedBy=default.target\n",
            binary.display()
        ),
    )
    .unwrap();

    let removed = ctl(&home.0, &["uninstall", "--purge"]);

    assert_eq!(removed.code, 0, "{}", removed.stderr);
    assert_eq!(removed.json["purged"], true);
    assert_eq!(removed.json["autostart"], "removed");
    assert_eq!(removed.json["binary"], "removed");
    assert!(!unit.exists());
}
