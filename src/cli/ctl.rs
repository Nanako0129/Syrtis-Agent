//! `syrtis-agent ctl <command>`: the non-interactive face of the menu
//! (`spec/cli-v1.md`, "ctl").
//!
//! Every command that reaches the resident goes through the same
//! `control::Client` the menu uses; the token is read from `state.json`
//! through `open_read_only` and stays in memory. Nothing here adds a
//! control command, a state field or a wire byte.
//!
//! Output contract: on success stdout is exactly one line, [`PREFIX`]
//! followed by one JSON object; stderr stays empty. On failure stdout is
//! empty and stderr is exactly one line with a stable class (never a
//! path, a token or a Pair URL), and the exit status says why. The Pair
//! URL exists only in the stdout line of `offer create`.

use std::{ffi::OsString, io::Write, net::IpAddr, os::unix::fs::MetadataExt, path::PathBuf};

use serde_json::{Value, json};

use super::imp::{Menu, Reach, code_name};
use crate::{
    agent::{Agent, AgentError, AgentUninstallReport},
    control::{
        APPROVE, LISTEN_CONFIGURE, OFFER_CANCEL, OFFER_CREATE, OK, PENDING_LIST, REVOKE, Response,
        SCOPE_APPROVE, SHARING_SET, SHUTDOWN, SOCKET_NAME, STATUS,
    },
    install::{self, Outcome},
    listener::bind_address,
    secure_fs::{SecureRoot, StorageError},
    source::{PRICING_DIR, SOURCE_CACHE_DIR},
    state_store::{STATE_FILE, STATE_FILE_MAX_BYTES},
};

/// The first bytes of the one stdout line of a successful command.
pub const PREFIX: &str = "SYRTIS-CTL-V1 ";
/// The longest offer lifetime `ctl` creates, in seconds.
pub const TTL_MAX: u64 = 120;
pub const USAGE: &str = "usage: syrtis-agent ctl status | install | uninstall [--purge] | scope disclosure | scope approve --digest <64 hex> | sharing on|off | listen --host <ip> --port <1024-65535> | offer create --ttl <1-120> | offer cancel --offer-id <32 hex> | pending approve --expect-sas <XXXX-XXXX> | grant revoke --grant-id <32 hex> | shutdown";

/// Exit statuses. 0 is success; 3 belongs to the release gate.
pub const EXIT_USAGE: u8 = 2;
/// The resident is not running, or did not answer; nothing was sent.
pub const EXIT_NOT_RUNNING: u8 = 4;
/// The resident answered with an error code; nothing changed.
pub const EXIT_REFUSED: u8 = 5;
/// The command went out in full and no valid reply came back.
pub const EXIT_UNKNOWN: u8 = 6;
/// A local failure: the state directory, install, or the output.
pub const EXIT_LOCAL: u8 = 7;
/// `pending approve`: not exactly one pending pairing has that code.
pub const EXIT_NO_MATCH: u8 = 8;
/// `install` or `uninstall` while the resident runs.
pub const EXIT_RUNNING: u8 = 9;

/// The control commands `ctl` needs, so the pending-approval rule can be
/// checked against a recording fake.
pub(super) trait Control {
    fn call(&self, id: u16, body: Value) -> Result<Response, Reach>;
}

impl Control for Menu {
    fn call(&self, id: u16, body: Value) -> Result<Response, Reach> {
        Menu::call(self, id, body)
    }
}

/// A failed command: the exit status and the one stderr line.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct Fail {
    pub code: u8,
    pub line: String,
}

fn fail(code: u8, line: impl Into<String>) -> Fail {
    Fail {
        code,
        line: line.into(),
    }
}

impl From<Reach> for Fail {
    fn from(reach: Reach) -> Self {
        match reach {
            Reach::NotRunning => fail(
                EXIT_NOT_RUNNING,
                "the agent is not running or not answering; nothing was changed",
            ),
            Reach::Unsafe(error) => fail(
                EXIT_LOCAL,
                format!(
                    "the state directory failed a safety check ({error:?}); nothing was changed"
                ),
            ),
            Reach::Unknown => fail(
                EXIT_UNKNOWN,
                "the command was sent but no valid reply came back; it may or may not have taken effect; check status before trying again",
            ),
            Reach::Failed(error) => fail(
                EXIT_LOCAL,
                format!("the control call failed ({error:?}); nothing was sent"),
            ),
        }
    }
}

/// The success reply of a control call, or why there is none.
fn reply(result: Result<Response, Reach>) -> Result<Response, Fail> {
    let response = result?;
    if response.code == OK {
        Ok(response)
    } else {
        Err(fail(
            EXIT_REFUSED,
            format!(
                "the agent refused: {}; nothing was changed",
                code_name(response.code)
            ),
        ))
    }
}

/// What a parsed command line asks for. Every value is already validated.
#[derive(Debug, Eq, PartialEq)]
enum Cmd {
    Status,
    Install,
    Uninstall { purge: bool },
    ScopeDisclosure,
    ScopeApprove { digest: String },
    Sharing { enabled: bool },
    Listen { host: String, port: u16 },
    OfferCreate { ttl: u64 },
    OfferCancel { offer_id: String },
    PendingApprove { sas: String },
    GrantRevoke { grant_id: String },
    Shutdown,
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `XXXX-XXXX` over `0-9A-F`: the agent's SAS format.
fn valid_sas(value: &str) -> bool {
    value.len() == 9
        && value.bytes().enumerate().all(|(i, b)| {
            if i == 4 {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'A'..=b'F').contains(&b)
            }
        })
}

/// A decimal integer in `lo..=hi`, written canonically (digits only, no
/// sign, no leading zero).
fn integer(value: &str, lo: u64, hi: u64) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) || value.len() > 5 {
        return None;
    }
    let n: u64 = value.parse().ok()?;
    (n.to_string() == value && (lo..=hi).contains(&n)).then_some(n)
}

/// `--name value` pairs for exactly the names in `names`, each once, in
/// any order. Anything else is `None`.
fn flags<'a>(args: &[&'a str], names: &[&str]) -> Option<Vec<&'a str>> {
    if args.len() != names.len() * 2 {
        return None;
    }
    let mut found: Vec<Option<&str>> = vec![None; names.len()];
    for pair in args.chunks(2) {
        let at = names.iter().position(|name| pair[0] == *name)?;
        if found[at].replace(pair[1]).is_some() {
            return None;
        }
    }
    found.into_iter().collect()
}

fn parse(args: &[String]) -> Option<Cmd> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["status"] => Some(Cmd::Status),
        ["install"] => Some(Cmd::Install),
        ["uninstall"] => Some(Cmd::Uninstall { purge: false }),
        ["uninstall", "--purge"] => Some(Cmd::Uninstall { purge: true }),
        ["scope", "disclosure"] => Some(Cmd::ScopeDisclosure),
        ["scope", "approve", rest @ ..] => {
            let [digest] = flags(rest, &["--digest"])?[..] else {
                return None;
            };
            lower_hex(digest, 64).then(|| Cmd::ScopeApprove {
                digest: digest.to_owned(),
            })
        }
        ["sharing", "on"] => Some(Cmd::Sharing { enabled: true }),
        ["sharing", "off"] => Some(Cmd::Sharing { enabled: false }),
        ["listen", rest @ ..] => {
            let [host, port] = flags(rest, &["--host", "--port"])?[..] else {
                return None;
            };
            let port = u16::try_from(integer(port, 1024, 65_535)?).ok()?;
            // Canonical text, and an address the listener would bind.
            let ip: IpAddr = host.parse().ok()?;
            (ip.to_string() == host && bind_address(host, port).is_ok()).then(|| Cmd::Listen {
                host: host.to_owned(),
                port,
            })
        }
        ["offer", "create", rest @ ..] => {
            let [ttl] = flags(rest, &["--ttl"])?[..] else {
                return None;
            };
            Some(Cmd::OfferCreate {
                ttl: integer(ttl, 1, TTL_MAX)?,
            })
        }
        ["offer", "cancel", rest @ ..] => {
            let [offer_id] = flags(rest, &["--offer-id"])?[..] else {
                return None;
            };
            lower_hex(offer_id, 32).then(|| Cmd::OfferCancel {
                offer_id: offer_id.to_owned(),
            })
        }
        ["pending", "approve", rest @ ..] => {
            let [sas] = flags(rest, &["--expect-sas"])?[..] else {
                return None;
            };
            valid_sas(sas).then(|| Cmd::PendingApprove {
                sas: sas.to_owned(),
            })
        }
        ["grant", "revoke", rest @ ..] => {
            let [grant_id] = flags(rest, &["--grant-id"])?[..] else {
                return None;
            };
            lower_hex(grant_id, 32).then(|| Cmd::GrantRevoke {
                grant_id: grant_id.to_owned(),
            })
        }
        ["shutdown"] => Some(Cmd::Shutdown),
        _ => None,
    }
}

/// Runs one `ctl` command line (`args` after `ctl`) and returns the exit
/// status. Success writes one [`PREFIX`] line to `out`; failure writes one
/// line to `err` and nothing to `out`.
pub(super) fn run(menu: &Menu, args: &[OsString], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let outcome = match args
        .iter()
        .map(|arg| arg.to_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()
        .and_then(|args| parse(&args))
    {
        Some(cmd) => execute(menu, cmd),
        None => Err(fail(EXIT_USAGE, USAGE)),
    };
    match outcome {
        Ok(value) => match writeln!(out, "{PREFIX}{value}").and_then(|()| out.flush()) {
            Ok(()) => 0,
            Err(_) => {
                // The command ran; only its result line was lost.
                let _ = writeln!(
                    err,
                    "syrtis-agent ctl: the result could not be written; the command may have taken effect"
                );
                EXIT_LOCAL
            }
        },
        Err(Fail { code, line }) => {
            let _ = writeln!(err, "syrtis-agent ctl: {}", one_line(&line));
            code
        }
    }
}

/// The stderr line: one line, and never a Pair URL.
fn one_line(line: &str) -> String {
    if line.contains("syrtis://") {
        return "an error text was withheld".into();
    }
    line.replace(['\n', '\r'], " ")
}

fn execute(menu: &Menu, cmd: Cmd) -> Result<Value, Fail> {
    match cmd {
        Cmd::Status => status(menu),
        Cmd::Install => install_cmd(menu),
        Cmd::Uninstall { purge } => uninstall_cmd(menu, purge),
        Cmd::ScopeDisclosure => disclosure(menu),
        Cmd::ScopeApprove { digest } => {
            reply(menu.call(SCOPE_APPROVE, json!({ "ownerInputsSha256": digest })))?;
            Ok(json!({ "scopeApproved": true }))
        }
        Cmd::Sharing { enabled } => {
            reply(menu.call(SHARING_SET, json!({ "enabled": enabled })))?;
            Ok(json!({ "sharingEnabled": enabled }))
        }
        Cmd::Listen { host, port } => {
            reply(menu.call(
                LISTEN_CONFIGURE,
                json!({ "bindHost": host, "bindPort": port }),
            ))?;
            Ok(json!({ "bindHost": host, "bindPort": port }))
        }
        Cmd::OfferCreate { ttl } => {
            let data = reply(menu.call(OFFER_CREATE, json!({ "ttlSeconds": ttl })))?.data;
            Ok(json!({
                "expiresAt": data["expiresAt"],
                "offerId": data["offerId"],
                "pairUrl": data["pairUrl"],
            }))
        }
        Cmd::OfferCancel { offer_id } => {
            reply(menu.call(OFFER_CANCEL, json!({ "offerId": offer_id })))?;
            Ok(json!({ "cancelled": true }))
        }
        Cmd::PendingApprove { sas } => approve_matching(menu, &sas),
        Cmd::GrantRevoke { grant_id } => {
            reply(menu.call(REVOKE, json!({ "grantId": grant_id })))?;
            Ok(json!({ "revoked": true }))
        }
        Cmd::Shutdown => {
            reply(menu.call(SHUTDOWN, json!({})))?;
            Ok(json!({ "stopping": true }))
        }
    }
}

/// The values a caller records as its baseline. The grant count is all the
/// resident can say about grants: control has no grant list.
fn status(menu: &Menu) -> Result<Value, Fail> {
    let data = reply(menu.call(STATUS, json!({})))?.data;
    Ok(json!({
        "sharingEnabled": data["sharingEnabled"],
        "bindHost": data["bindHost"],
        "bindPort": data["bindPort"],
        "nodeLabel": data["nodeLabel"],
        "activeGrantCount": data["activeGrantCount"],
        "activeOfferCount": data["activeOfferCount"],
        "pendingCount": data["pendingCount"],
        "scopeApproved": data["scopeApproved"],
    }))
}

/// What the menu shows before it asks to approve, and the digest it would
/// send. Needs a resident that answers, as the menu does; changes nothing.
fn disclosure(menu: &Menu) -> Result<Value, Fail> {
    reply(menu.call(STATUS, json!({})))?;
    let Some((lines, digest)) = menu.disclosure() else {
        return Err(fail(
            EXIT_LOCAL,
            "the scan inputs could not be described (a path is not UTF-8)",
        ));
    };
    let lines: Vec<Value> = lines
        .into_iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect();
    Ok(json!({ "lines": lines, "ownerInputsSha256": digest }))
}

/// Approves the one pending pairing whose SAS is `sas`, and nothing else.
///
/// The list is read once. Exactly one entry must carry `sas`; its
/// `pendingId` goes to `approve` with generation 1 (a v1 agent never
/// re-issues a SAS). No match, several matches or an unreadable list send
/// nothing, and no other pending pairing is ever rejected or approved.
/// An expired pending pairing is absent from the list, so it is no match;
/// one that expires between the list and `approve` is answered `expired`
/// by the agent and nothing else is sent.
fn approve_matching(control: &dyn Control, sas: &str) -> Result<Value, Fail> {
    let listed = reply(control.call(PENDING_LIST, json!({})))?.data;
    let Some(items) = listed.as_array() else {
        return Err(fail(EXIT_LOCAL, "the pending list had an unexpected shape"));
    };
    let mut matching = Vec::new();
    for item in items {
        let (Some(id), Some(code)) = (item["pendingId"].as_str(), item["sasCode"].as_str()) else {
            return Err(fail(EXIT_LOCAL, "the pending list had an unexpected shape"));
        };
        if code == sas {
            matching.push(id);
        }
    }
    let pending_id = match matching.as_slice() {
        [id] if lower_hex(id, 32) => (*id).to_owned(),
        [_] => return Err(fail(EXIT_LOCAL, "the pending list had an unexpected shape")),
        [] => {
            return Err(fail(
                EXIT_NO_MATCH,
                "no pending pairing has that code; nothing was approved",
            ));
        }
        _ => {
            return Err(fail(
                EXIT_NO_MATCH,
                "more than one pending pairing has that code; nothing was approved",
            ));
        }
    };
    reply(control.call(
        APPROVE,
        json!({ "pendingId": pending_id, "sasGeneration": 1 }),
    ))?;
    Ok(json!({ "approved": true, "pendingId": pending_id }))
}

/// `install::install` under the owner lock, with the resident stopped, as
/// menu item 10 does: the no-follow, owner and mode checks are the ones of
/// `spec/install-v1.md`. It starts nothing.
fn install_cmd(menu: &Menu) -> Result<Value, Fail> {
    stopped(menu)?;
    let Some(exe) = &menu.exe else {
        return Err(fail(
            EXIT_LOCAL,
            "this program's own path is unknown; nothing was installed",
        ));
    };
    // Held while installing: a resident that starts meanwhile cannot take
    // the lock and exits "already running".
    let _lock = match SecureRoot::open_under(&menu.home, menu.suffix) {
        Ok(root) => root,
        Err(StorageError::Busy) => return Err(running()),
        Err(error) => return Err(Reach::Unsafe(error).into()),
    };
    match install::install(&menu.home, exe) {
        Ok(()) => Ok(json!({ "installed": true })),
        Err(error) => Err(fail(
            EXIT_LOCAL,
            format!("not installed ({error:?}); nothing was started"),
        )),
    }
}

/// `Agent::uninstall_stopped` as menu item 11 runs it, with the resident
/// stopped. Fails (exit 7) when anything was left for a manual repair.
fn uninstall_cmd(menu: &Menu, purge: bool) -> Result<Value, Fail> {
    stopped(menu)?;
    if nothing_installed(menu) {
        let mut value = json!({ "purged": false });
        for object in [
            "autostart",
            "binary",
            "producerCache",
            "receiverCache",
            "sourceCache",
        ] {
            value[object] = json!("absent");
        }
        return Ok(value);
    }
    // Without a `state.json` the store writes a fresh one (an identity and
    // a control token) just to be opened. That one is always purged again,
    // asked or not: it is not the owner's state, and nothing may be left
    // behind by an uninstall. An unreadable state counts as present.
    let fresh_state = matches!(
        SecureRoot::open_read_only(&menu.home, menu.suffix),
        Ok(Some(root)) if matches!(root.read_file(STATE_FILE, STATE_FILE_MAX_BYTES), Ok(None))
    );
    let report = match Agent::uninstall_stopped(&menu.home, menu.suffix, purge || fresh_state) {
        Ok(report) => report,
        Err(AgentError::Storage(StorageError::Busy)) => return Err(running()),
        Err(error) => {
            return Err(fail(EXIT_LOCAL, format!("not uninstalled ({error:?})")));
        }
    };
    let mut value = uninstall_result(&report, purge || fresh_state)?;
    // `purged` answers what was asked: the fresh state does not count.
    value["purged"] = json!(purge && report.install.purged);
    Ok(value)
}

/// The result of a finished uninstall. Exit 7 names everything that is
/// still there: an object left for a manual repair, the identity and
/// pairing state when `--purge` did not remove it (`state`), and
/// `source-scope.json` when the state went and it did not (`sourceScope`).
fn uninstall_result(report: &AgentUninstallReport, purge: bool) -> Result<Value, Fail> {
    let name = |outcome: Outcome| match outcome {
        Outcome::Removed => "removed",
        Outcome::Absent => "absent",
        Outcome::ManualRepair => "manualRepair",
    };
    let objects = [
        ("autostart", report.install.autostart),
        ("binary", report.install.binary),
        ("producerCache", report.install.producer_cache),
        ("receiverCache", report.install.receiver_cache),
        ("sourceCache", report.source_cache),
    ];
    let mut left: Vec<&str> = objects
        .iter()
        .filter(|(_, outcome)| *outcome == Outcome::ManualRepair)
        .map(|(object, _)| *object)
        .collect();
    if purge && !report.install.purged {
        left.push("state");
    }
    if report.install.purged && !report.scope_removed {
        left.push("sourceScope");
    }
    if !left.is_empty() {
        return Err(fail(
            EXIT_LOCAL,
            format!(
                "uninstall left objects for a manual repair: {}",
                left.join(",")
            ),
        ));
    }
    let mut value = json!({ "purged": report.install.purged });
    for (object, outcome) in objects {
        value[object] = json!(name(outcome));
    }
    Ok(value)
}

/// Read-only: neither install object, and a state directory that is
/// missing or holds only what a finished purge leaves (`owner.lock`, which
/// is never removed, a stale `control.sock`, `pricing`, which no uninstall
/// touches, and an emptied `source-cache`), means there is nothing to
/// uninstall, and opening the store would create an identity and a control
/// token. Any doubt (an unsafe root, a directory that cannot be listed,
/// any other entry such as a state file or a cache a failed uninstall
/// left, an object present) returns `false` and the full uninstall runs.
fn nothing_installed(menu: &Menu) -> bool {
    let listed = |dir: PathBuf| -> Option<Vec<OsString>> {
        std::fs::read_dir(dir)
            .ok()?
            .map(|entry| entry.map(|entry| entry.file_name()).ok())
            .collect()
    };
    let root = menu.root_path();
    let left_by_a_purge = |name: &OsString| {
        name == "owner.lock"
            || name == SOCKET_NAME
            || name == PRICING_DIR
            || (name == SOURCE_CACHE_DIR && {
                // The directory `clear_private_subdir` would accept, and
                // empty: a link or another mode is for the full uninstall.
                let cache = root.join(SOURCE_CACHE_DIR);
                std::fs::symlink_metadata(&cache)
                    .is_ok_and(|meta| meta.is_dir() && meta.mode() & 0o7777 == 0o700)
                    && no_acl(&cache)
                    && listed(cache).is_some_and(|inside| inside.is_empty())
            })
    };
    let empty_root = match SecureRoot::open_read_only(&menu.home, menu.suffix) {
        Ok(None) => true,
        Ok(Some(_)) => listed(root.clone()).is_some_and(|names| names.iter().all(left_by_a_purge)),
        Err(_) => false,
    };
    empty_root && !install::objects_present(&menu.home)
}

/// macOS: the directory verifiably carries no extended ACL, the other
/// thing `clear_private_subdir` refuses. Elsewhere there is none to carry.
#[cfg(target_os = "macos")]
fn no_acl(dir: &std::path::Path) -> bool {
    std::fs::File::open(dir).is_ok_and(|dir| crate::secure_fs::acl::none(&dir))
}
#[cfg(not(target_os = "macos"))]
fn no_acl(_dir: &std::path::Path) -> bool {
    true
}

fn running() -> Fail {
    fail(
        EXIT_RUNNING,
        "the agent is running; stop it first (shutdown); nothing was changed",
    )
}

/// Refuses while a resident answers `status`.
fn stopped(menu: &Menu) -> Result<(), Fail> {
    if menu.running() {
        Err(running())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn parse_accepts_each_command_in_its_one_form() {
        let id = "00112233445566778899aabbccddeeff";
        assert_eq!(parse(&words("status")), Some(Cmd::Status));
        assert_eq!(parse(&words("install")), Some(Cmd::Install));
        assert_eq!(
            parse(&words("uninstall")),
            Some(Cmd::Uninstall { purge: false })
        );
        assert_eq!(
            parse(&words("uninstall --purge")),
            Some(Cmd::Uninstall { purge: true })
        );
        assert_eq!(
            parse(&words("scope disclosure")),
            Some(Cmd::ScopeDisclosure)
        );
        assert_eq!(
            parse(&words(&format!("scope approve --digest {DIGEST}"))),
            Some(Cmd::ScopeApprove {
                digest: DIGEST.into()
            })
        );
        assert_eq!(
            parse(&words("sharing on")),
            Some(Cmd::Sharing { enabled: true })
        );
        assert_eq!(
            parse(&words("listen --port 47123 --host 127.0.0.1")),
            Some(Cmd::Listen {
                host: "127.0.0.1".into(),
                port: 47_123
            })
        );
        assert_eq!(
            parse(&words("offer create --ttl 120")),
            Some(Cmd::OfferCreate { ttl: 120 })
        );
        assert_eq!(
            parse(&words(&format!("offer cancel --offer-id {id}"))),
            Some(Cmd::OfferCancel {
                offer_id: id.into()
            })
        );
        assert_eq!(
            parse(&words("pending approve --expect-sas 0A1B-2C3D")),
            Some(Cmd::PendingApprove {
                sas: "0A1B-2C3D".into()
            })
        );
        assert_eq!(
            parse(&words(&format!("grant revoke --grant-id {id}"))),
            Some(Cmd::GrantRevoke {
                grant_id: id.into()
            })
        );
        assert_eq!(parse(&words("shutdown")), Some(Cmd::Shutdown));
    }

    #[test]
    fn parse_refuses_every_illegal_value() {
        let upper = DIGEST.to_uppercase();
        let short = &DIGEST[..63];
        let long = format!("{DIGEST}0");
        let non_hex = format!("{}g", &DIGEST[..63]);
        for line in [
            "",
            "status extra",
            "uninstall --purge --purge",
            "uninstall purge",
            "sharing",
            "sharing maybe",
            "scope approve",
            "scope approve --digest",
            "scope approve --digest 00",
            &format!("scope approve --digest {upper}"),
            &format!("scope approve --digest {short}"),
            &format!("scope approve --digest {long}"),
            &format!("scope approve --digest {non_hex}"),
            &format!("scope approve --digest={DIGEST}"),
            &format!("scope approve --digest {DIGEST} --digest {DIGEST}"),
            &format!("scope approve --digest {DIGEST} extra"),
            "listen --host 127.0.0.1",
            "listen --port 47123",
            "listen --host 0.0.0.0 --port 47123",
            "listen --host :: --port 47123",
            "listen --host localhost --port 47123",
            "listen --host 127.1 --port 47123",
            "listen --host 127.0.0.01 --port 47123",
            "listen --host 127.0.0.1 --port 1023",
            "listen --host 127.0.0.1 --port 65536",
            "listen --host 127.0.0.1 --port 047123",
            "listen --host 127.0.0.1 --port +47123",
            "listen --host 127.0.0.1 --port -1",
            "listen --host 127.0.0.1 --port 1e4",
            "listen --host 127.0.0.1 --port 47123 --label x",
            "offer create",
            "offer create --ttl 0",
            "offer create --ttl 121",
            "offer create --ttl 600",
            "offer create --ttl 060",
            "offer create --ttl -5",
            "offer create --ttl 1.5",
            "offer create --ttl 99999999999999999999",
            "offer cancel --offer-id 00",
            "offer cancel --offer-id 00112233445566778899AABBCCDDEEFF",
            "pending approve --expect-sas 0a1b-2c3d",
            "pending approve --expect-sas 0A1B2C3D",
            "pending approve --expect-sas 0A1B-2C3G",
            "pending approve --expect-sas 0A1B-2C3D-",
            "pending approve --expect-sas",
            "pending approve",
            "pending reject --expect-sas 0A1B-2C3D",
            "grant revoke 00112233445566778899aabbccddeeff",
            "grant revoke --grant-id 0011",
            "grant list",
            "shutdown now",
            "run",
        ] {
            assert_eq!(parse(&words(line)), None, "{line:?}");
        }
        // A value that is not UTF-8 never reaches `parse`; `run` refuses it.
    }

    /// Records what `approve_matching` sends and answers from a script.
    struct Fake {
        pending: Value,
        approve_code: u16,
        sent: RefCell<Vec<(u16, Value)>>,
    }

    impl Control for Fake {
        fn call(&self, id: u16, body: Value) -> Result<Response, Reach> {
            self.sent.borrow_mut().push((id, body));
            match id {
                PENDING_LIST => Ok(Response {
                    code: OK,
                    data: self.pending.clone(),
                }),
                APPROVE => Ok(Response {
                    code: self.approve_code,
                    data: Value::Null,
                }),
                _ => panic!("command {id} must never be sent"),
            }
        }
    }

    fn pending(entries: &[(&str, &str)]) -> Value {
        Value::Array(
            entries
                .iter()
                .map(|(id, sas)| json!({"expiresAt": 1, "pendingId": id, "sasCode": sas}))
                .collect(),
        )
    }

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn attempt(
        entries: &[(&str, &str)],
        approve_code: u16,
    ) -> (Result<Value, Fail>, Vec<(u16, Value)>) {
        let fake = Fake {
            pending: pending(entries),
            approve_code,
            sent: RefCell::new(Vec::new()),
        };
        let result = approve_matching(&fake, "0A1B-2C3D");
        (result, fake.sent.into_inner())
    }

    #[test]
    fn one_matching_pending_is_approved_with_its_own_id_and_generation() {
        let (result, sent) = attempt(&[(A, "FFFF-0000"), (B, "0A1B-2C3D")], OK);
        assert_eq!(result.unwrap(), json!({"approved": true, "pendingId": B}));
        assert_eq!(
            sent,
            vec![
                (PENDING_LIST, json!({})),
                (APPROVE, json!({"pendingId": B, "sasGeneration": 1})),
            ]
        );
    }

    #[test]
    fn a_code_mismatch_sends_no_approve_and_no_reject() {
        let (result, sent) = attempt(&[(A, "FFFF-0000"), (B, "1111-2222")], OK);
        assert_eq!(result.unwrap_err().code, EXIT_NO_MATCH);
        assert_eq!(sent, vec![(PENDING_LIST, json!({}))]);
    }

    #[test]
    fn several_pending_with_the_code_send_no_approve_and_no_reject() {
        let (result, sent) = attempt(&[(A, "0A1B-2C3D"), (B, "0A1B-2C3D")], OK);
        assert_eq!(result.unwrap_err().code, EXIT_NO_MATCH);
        assert_eq!(sent, vec![(PENDING_LIST, json!({}))]);
    }

    #[test]
    fn an_expired_pending_is_absent_from_the_list_and_nothing_is_sent() {
        let (result, sent) = attempt(&[], OK);
        assert_eq!(result.unwrap_err().code, EXIT_NO_MATCH);
        assert_eq!(sent, vec![(PENDING_LIST, json!({}))]);
    }

    #[test]
    fn a_pending_that_expires_before_approve_is_refused_and_nothing_else_is_sent() {
        let (result, sent) = attempt(
            &[(A, "FFFF-0000"), (B, "0A1B-2C3D")],
            crate::control::EXPIRED,
        );
        let failure = result.unwrap_err();
        assert_eq!(failure.code, EXIT_REFUSED);
        assert!(failure.line.contains("expired"), "{}", failure.line);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].0, APPROVE);
    }

    #[test]
    fn a_malformed_list_or_id_sends_nothing() {
        let fake = Fake {
            pending: json!({"not": "a list"}),
            approve_code: OK,
            sent: RefCell::new(Vec::new()),
        };
        assert_eq!(
            approve_matching(&fake, "0A1B-2C3D").unwrap_err().code,
            EXIT_LOCAL
        );
        let (result, sent) = attempt(&[("../etc", "0A1B-2C3D")], OK);
        assert_eq!(result.unwrap_err().code, EXIT_LOCAL);
        assert_eq!(sent.len(), 1);
    }

    fn report(purged: bool, scope_removed: bool, source_cache: Outcome) -> AgentUninstallReport {
        AgentUninstallReport {
            install: install::UninstallReport {
                autostart: Outcome::Removed,
                binary: Outcome::Removed,
                producer_cache: Outcome::Removed,
                receiver_cache: Outcome::Removed,
                purged,
            },
            source_cache,
            scope_removed,
        }
    }

    /// Exit 0 only when nothing asked for is left: a purge that kept the
    /// state, a purge that kept `source-scope.json` and a cache left for a
    /// manual repair are each exit 7 naming what stayed.
    #[test]
    fn an_uninstall_that_left_something_is_a_failure_naming_it() {
        let left = |report: AgentUninstallReport, purge| {
            let fail = uninstall_result(&report, purge).unwrap_err();
            assert_eq!(fail.code, EXIT_LOCAL);
            fail.line
        };
        assert!(left(report(false, false, Outcome::Removed), true).ends_with(": state"));
        assert!(left(report(true, false, Outcome::Removed), true).ends_with(": sourceScope"));
        assert!(
            left(report(false, false, Outcome::ManualRepair), true)
                .ends_with(": sourceCache,state")
        );
        assert!(
            left(report(false, false, Outcome::ManualRepair), false).ends_with(": sourceCache")
        );

        let kept = uninstall_result(&report(false, false, Outcome::Removed), false).unwrap();
        assert_eq!(kept["purged"], false);
        let purged = uninstall_result(&report(true, true, Outcome::Removed), true).unwrap();
        assert_eq!(purged["purged"], true);
        assert_eq!(purged["sourceCache"], "removed");
    }

    #[test]
    fn the_stderr_line_is_one_line_and_never_a_pair_url() {
        assert_eq!(one_line("a\nb\r\nc"), "a b  c");
        assert!(!one_line("bad syrtis://pair?offer=00").contains("syrtis"));
    }
}
