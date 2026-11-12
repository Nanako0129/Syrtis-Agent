//! The standalone binary (`spec/cli-v1.md`): `syrtis-agent run`, the
//! resident entry point, and with no argument a plain numbered menu that
//! manages the running agent over its control socket.
//!
//! The menu never opens a file of the secure root by path: it reads
//! `state.json` through `SecureRoot::open_read_only` (for the control
//! token, kept in memory) and writes only through a `SecureRoot` whose lock
//! it holds. Sharing, scope approval, offers, approvals and the listen
//! address go through control only. No argument or environment variable
//! carries a secret. macOS and Linux; elsewhere both entry points print
//! [`UNSUPPORTED`].

use std::{
    ffi::OsString,
    io::{self, BufRead},
    path::{Path, PathBuf},
    process::ExitCode,
};

/// Debug builds only: the home `run` and the menu use instead of the
/// directory-service home, so a test can run the binary on a temp home.
/// A release build refuses to start while it is set (`release_gate`).
pub const DEBUG_HOME_VAR: &str = "SYRTIS_AGENT_DEBUG_HOME";
/// The longest input line the menu accepts, in bytes (newline excluded).
pub const LINE_MAX: usize = 16_384;

pub const USAGE: &str = "usage: syrtis-agent [run]";
pub const UNSUPPORTED: &str = "syrtis-agent: this platform is not supported yet.";
pub const RELEASE_REFUSES_DEBUG_HOME: &str = "syrtis-agent: SYRTIS_AGENT_DEBUG_HOME is set, but this build does not accept it. Nothing was opened.";
pub const ALREADY_RUNNING: &str =
    "syrtis-agent: another syrtis-agent is already running for this user.";
pub const NOT_RUNNING: &str = "The agent is not running (or not answering). Start it with `syrtis-agent run` or its autostart entry, then try again. Nothing was changed.";
pub const STOP_FIRST: &str =
    "The agent is running. Stop it first (menu item 9), then try again. Nothing was changed.";
pub const LINE_TOO_LONG: &str = "That line is longer than 16384 bytes and was ignored.";
pub const OUTCOME_UNKNOWN: &str = "The command was sent, but no valid reply came back: it may or may not have taken effect. Check Status (menu item 1) before trying again.";
pub const NO_STATE: &str = "There is no agent state on this machine. Nothing was changed.";

/// Exit status of a refused debug home in a release build.
const EXIT_REFUSED: u8 = 3;
const EXIT_USAGE: u8 = 2;

/// The binary's entry point: `args` without the program name.
pub fn main(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    // Before arguments, the home or any root: a release build never runs
    // with a home other than the directory service's.
    if release_gate() {
        eprintln!("{RELEASE_REFUSES_DEBUG_HOME}");
        return ExitCode::from(EXIT_REFUSED);
    }
    let args: Vec<OsString> = args.into_iter().collect();
    let resident = match args.as_slice() {
        [] => false,
        [run] if run == "run" => true,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    imp::start(resident)
}

/// The config and data directories the engine resolves clients against,
/// from the home by platform convention (no environment variable is read):
/// macOS `Library/Application Support` for both; elsewhere `.config` and
/// `.local/share`.
pub fn default_dirs(home: &Path) -> (PathBuf, PathBuf) {
    if cfg!(target_os = "macos") {
        let support = home.join("Library").join("Application Support");
        (support.clone(), support)
    } else {
        (home.join(".config"), home.join(".local").join("share"))
    }
}

#[cfg(debug_assertions)]
fn release_gate() -> bool {
    false
}

/// A release build has no way to change the home: the variable only stops
/// it.
#[cfg(not(debug_assertions))]
fn release_gate() -> bool {
    std::env::var_os(DEBUG_HOME_VAR).is_some()
}

/// One input line, at most [`LINE_MAX`] bytes. A longer line is read to
/// its end (never held whole) and reported as [`Line::TooLong`].
#[derive(Debug, Eq, PartialEq)]
pub enum Line {
    Text(String),
    TooLong,
    Eof,
}

pub fn read_line(input: &mut dyn BufRead) -> io::Result<Line> {
    let mut line = Vec::new();
    let (mut any, mut too_long) = (false, false);
    loop {
        let buf = input.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        any = true;
        let newline = buf.iter().position(|&byte| byte == b'\n');
        let chunk = &buf[..newline.unwrap_or(buf.len())];
        if !too_long {
            if line.len() + chunk.len() > LINE_MAX {
                too_long = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        let used = newline.map_or(buf.len(), |at| at + 1);
        input.consume(used);
        if newline.is_some() {
            break;
        }
    }
    if !any {
        return Ok(Line::Eof);
    }
    if too_long {
        return Ok(Line::TooLong);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Line::Text(String::from_utf8_lossy(&line).trim().to_owned()))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use super::*;

    pub(super) fn start(_resident: bool) -> ExitCode {
        eprintln!("{UNSUPPORTED}");
        ExitCode::FAILURE
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use imp::{Menu, menu};

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod imp {
    use std::io::Write;

    use serde_json::{Value, json};

    use super::*;
    use crate::{
        agent::{Agent, AgentConfig, AgentError, ScannerSettings},
        control::{
            self, APPROVE, BUSY, Client, Command, ControlError, EXPIRED, INTERNAL, INVALID,
            LISTEN_CONFIGURE, OFFER_CREATE, OK, PENDING_LIST, REJECT, REVOKE, Response,
            SCOPE_APPROVE, SHARING_SET, SHUTDOWN, STATUS, UNAUTHORIZED, UNSAFE_STATE,
        },
        install::{self, Outcome},
        runtime::RuntimeError,
        secure_fs::{STATE_SUFFIX, SecureRoot, StorageError, trusted_home},
        security::{GrantState, clock_status, decode_fixed_hex, hex_encode},
        source::{SOURCE_CACHE_DIR, owner_inputs_sha256},
        state_store::{STATE_FILE, STATE_FILE_MAX_BYTES, Secret32, StateStore, decode_state},
    };

    pub(super) fn start(resident: bool) -> ExitCode {
        let home = match home() {
            Ok(home) => home,
            Err(error) => {
                eprintln!("syrtis-agent: the home directory could not be resolved ({error:?}).");
                return ExitCode::FAILURE;
            }
        };
        if resident {
            return run(home);
        }
        let menu = Menu {
            home,
            suffix: STATE_SUFFIX,
            exe: std::env::current_exe().ok(),
        };
        let (stdin, stdout) = (io::stdin(), io::stdout());
        match super::imp::menu(&menu, &mut stdin.lock(), &mut stdout.lock()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        }
    }

    #[cfg(debug_assertions)]
    fn home() -> Result<PathBuf, StorageError> {
        match std::env::var_os(DEBUG_HOME_VAR) {
            Some(home) => Ok(PathBuf::from(home)),
            None => trusted_home(),
        }
    }

    #[cfg(not(debug_assertions))]
    fn home() -> Result<PathBuf, StorageError> {
        trusted_home()
    }

    /// The resident: starts `Agent` on the frozen suffix with default
    /// roots only, blocks until control `shutdown`, then stops it.
    fn run(home: PathBuf) -> ExitCode {
        let (config_dir, data_dir) = default_dirs(&home);
        let config = AgentConfig::new(home, config_dir, data_dir, ScannerSettings::default());
        match Agent::start(config) {
            Ok(agent) => {
                agent.runtime().wait();
                agent.runtime().stop();
                ExitCode::SUCCESS
            }
            Err(
                AgentError::Storage(StorageError::Busy)
                | AgentError::Runtime(RuntimeError::Store(StorageError::Busy)),
            ) => {
                eprintln!("{ALREADY_RUNNING}");
                ExitCode::FAILURE
            }
            Err(error) => {
                eprintln!("syrtis-agent: the agent did not start ({error:?}).");
                ExitCode::FAILURE
            }
        }
    }

    /// What the menu works on.
    pub struct Menu {
        /// The owner's home: the directory-service home in the binary.
        pub home: PathBuf,
        /// The secure root below it: the frozen suffix in the binary.
        pub suffix: &'static [&'static str],
        /// The binary `install` copies (`current_exe`); `None` refuses it.
        pub exe: Option<PathBuf>,
    }

    /// Why a control call did not get a reply.
    enum Reach {
        /// No root, no state, or no answer on the socket.
        NotRunning,
        /// The root or `state.json` failed a check.
        Unsafe(StorageError),
        /// The command was sent in full and no valid reply came back
        /// (`NoReply`, `Response`): it may have run.
        Unknown,
        /// Nothing was sent (the server proof failed, or the command could
        /// not be encoded).
        Failed(ControlError),
    }

    impl Menu {
        fn root_path(&self) -> PathBuf {
            self.suffix
                .iter()
                .fold(self.home.clone(), |path, part| path.join(part))
        }

        /// The control token, read through `open_read_only` (never
        /// `open_under`: the resident holds the lock), and the socket.
        fn client(&self) -> Result<Client, Reach> {
            let root = SecureRoot::open_read_only(&self.home, self.suffix)
                .map_err(Reach::Unsafe)?
                .ok_or(Reach::NotRunning)?;
            let bytes = root
                .read_file(STATE_FILE, STATE_FILE_MAX_BYTES)
                .map_err(Reach::Unsafe)?
                .ok_or(Reach::NotRunning)?;
            let token = *decode_state(&bytes)
                .map_err(Reach::Unsafe)?
                .control_token
                .expose();
            Ok(Client::new(
                Secret32::new(token),
                self.root_path().join(control::SOCKET_NAME),
            ))
        }

        fn call(&self, id: u16, body: Value) -> Result<Response, Reach> {
            match self.client()?.call(&Command { id, body }) {
                Ok(response) => Ok(response),
                // Not connected, or cut before the whole command was out:
                // the command did not run.
                Err(ControlError::Socket) => Err(Reach::NotRunning),
                Err(ControlError::NoReply | ControlError::Response) => Err(Reach::Unknown),
                Err(error) => Err(Reach::Failed(error)),
            }
        }

        fn running(&self) -> bool {
            matches!(self.call(STATUS, json!({})), Ok(response) if response.code == OK)
        }

        /// The owner inputs the resident computes from the same home.
        fn disclosure(&self) -> Option<(Vec<(&'static str, String)>, String)> {
            let (config_dir, data_dir) = default_dirs(&self.home);
            let cache = self.root_path().join(SOURCE_CACHE_DIR);
            let settings = ScannerSettings::default();
            let digest =
                owner_inputs_sha256(&self.home, &config_dir, &data_dir, &cache, &settings)?;
            let clients: Vec<&str> = tokscale_core::ClientId::ALL
                .iter()
                .map(|client| client.as_str())
                .collect();
            let lines = vec![
                ("Home", self.home.display().to_string()),
                ("Config directory", config_dir.display().to_string()),
                ("Data directory", data_dir.display().to_string()),
                ("Engine source cache", cache.display().to_string()),
                (
                    "Extra scan paths",
                    "none (the standalone agent scans default roots only)".into(),
                ),
                ("Clients the engine reads", clients.join(", ")),
            ];
            Some((lines, digest))
        }
    }

    /// Runs the menu until `0` or end of input. Every item that needs the
    /// resident says so when it is not running and changes nothing.
    pub fn menu(menu: &Menu, input: &mut dyn BufRead, out: &mut dyn Write) -> io::Result<()> {
        loop {
            writeln!(
                out,
                "\nSyrtis Agent\n \
                 1. Status\n \
                 2. Turn sharing on\n \
                 3. Turn sharing off\n \
                 4. Show the scan scope and approve it\n \
                 5. Set the listen address and port\n \
                 6. Create a pairing offer\n \
                 7. Pending pairings: approve or reject\n \
                 8. Grants: list and revoke\n \
                 9. Stop the running agent\n\
                 10. Install (start at login)\n\
                 11. Uninstall\n \
                 0. Quit"
            )?;
            let Some(choice) = ask(input, out, "Choose: ")? else {
                return Ok(());
            };
            match choice.as_str() {
                "1" => status(menu, out)?,
                "2" => sharing(menu, out, true)?,
                "3" => sharing(menu, out, false)?,
                "4" => scope(menu, input, out)?,
                "5" => listen(menu, input, out)?,
                "6" => offer(menu, input, out)?,
                "7" => pending(menu, input, out)?,
                "8" => grants(menu, input, out)?,
                "9" => simple(menu, out, SHUTDOWN, json!({}), "The agent is stopping.")?,
                "10" => install_item(menu, out)?,
                "11" => uninstall_item(menu, input, out)?,
                "0" => return Ok(()),
                "" => {}
                _ => writeln!(out, "Choose a number from the list.")?,
            }
        }
    }

    /// Prompts and reads one line. `None` at end of input; a line over
    /// [`LINE_MAX`] is reported and read as empty.
    fn ask(
        input: &mut dyn BufRead,
        out: &mut dyn Write,
        prompt: &str,
    ) -> io::Result<Option<String>> {
        write!(out, "{prompt}")?;
        out.flush()?;
        match read_line(input)? {
            Line::Text(text) => Ok(Some(text)),
            Line::TooLong => {
                writeln!(out, "\n{LINE_TOO_LONG}")?;
                Ok(Some(String::new()))
            }
            Line::Eof => Ok(None),
        }
    }

    fn code_name(code: u16) -> &'static str {
        match code {
            OK => "ok",
            INVALID => "invalid",
            UNAUTHORIZED => "unauthorized",
            EXPIRED => "expired",
            BUSY => "busy",
            UNSAFE_STATE => "unsafeState",
            INTERNAL => "internal",
            _ => "unknown",
        }
    }

    /// Prints why a call did not succeed. Stable classes only.
    fn report(out: &mut dyn Write, result: &Result<Response, Reach>) -> io::Result<()> {
        match result {
            Ok(response) => writeln!(
                out,
                "The agent refused: {}. Nothing was changed.",
                code_name(response.code)
            ),
            Err(Reach::NotRunning) => writeln!(out, "{NOT_RUNNING}"),
            Err(Reach::Unsafe(error)) => writeln!(
                out,
                "The agent's state directory failed a safety check ({error:?}). Nothing was changed."
            ),
            Err(Reach::Unknown) => writeln!(out, "{OUTCOME_UNKNOWN}"),
            Err(Reach::Failed(error)) => {
                writeln!(
                    out,
                    "The control call failed ({error:?}). Nothing was sent."
                )
            }
        }
    }

    /// One command whose success has nothing to show but `done`.
    fn simple(
        menu: &Menu,
        out: &mut dyn Write,
        id: u16,
        body: Value,
        done: &str,
    ) -> io::Result<()> {
        let result = menu.call(id, body);
        match &result {
            Ok(response) if response.code == OK => writeln!(out, "{done}"),
            _ => report(out, &result),
        }
    }

    fn status(menu: &Menu, out: &mut dyn Write) -> io::Result<()> {
        let result = menu.call(STATUS, json!({}));
        let data = match &result {
            Ok(response) if response.code == OK => &response.data,
            _ => return report(out, &result),
        };
        let on = |key: &str| if data[key] == true { "yes" } else { "no" };
        let listen = match (&data["bindHost"], &data["bindPort"]) {
            (Value::String(host), port) if host.contains(':') => format!("[{host}]:{port}"),
            (Value::String(host), port) => format!("{host}:{port}"),
            _ => "not set".into(),
        };
        let label = data["nodeLabel"].as_str().unwrap_or("not set");
        let families: Vec<&str> = data["sourceFamilies"]
            .as_array()
            .map(|all| all.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        writeln!(out, "Sharing: {}", on("sharingEnabled"))?;
        writeln!(out, "Listen address: {listen}")?;
        writeln!(out, "Node label: {label}")?;
        writeln!(
            out,
            "Active grants: {}, active offers: {}, pending pairings: {}",
            data["activeGrantCount"], data["activeOfferCount"], data["pendingCount"]
        )?;
        writeln!(
            out,
            "Last scan: {} (at {}), clients: {}",
            data["scanStatus"].as_str().unwrap_or("?"),
            data["lastScanAt"],
            if families.is_empty() {
                "none".into()
            } else {
                families.join(", ")
            }
        )?;
        writeln!(out, "Scan scope approved: {}", on("scopeApproved"))
    }

    fn sharing(menu: &Menu, out: &mut dyn Write, enabled: bool) -> io::Result<()> {
        let result = menu.call(SHARING_SET, json!({ "enabled": enabled }));
        match &result {
            Ok(response) if response.code == OK => writeln!(
                out,
                "{}",
                if enabled {
                    "Sharing is on."
                } else {
                    "Sharing is off. Every grant was revoked and every offer and pending pairing ended."
                }
            ),
            Ok(response) if enabled && response.code == BUSY => writeln!(
                out,
                "An offer from before sharing was turned off can still be claimed. Try again after it expires (at most 15 minutes). Nothing was changed."
            ),
            Ok(response) if enabled && response.code == INVALID => writeln!(
                out,
                "Not turned on (invalid): sharing is already on, or the state refused the change. Nothing was changed."
            ),
            _ => report(out, &result),
        }
    }

    /// Shows what the resident scans, then sends the digest of exactly
    /// that disclosure (`SA-0G`).
    fn scope(menu: &Menu, input: &mut dyn BufRead, out: &mut dyn Write) -> io::Result<()> {
        // Only a reachable resident can approve: no disclosure or prompt
        // otherwise.
        let reached = menu.call(STATUS, json!({}));
        if !matches!(&reached, Ok(response) if response.code == OK) {
            return report(out, &reached);
        }
        let Some((lines, digest)) = menu.disclosure() else {
            return writeln!(
                out,
                "The scan inputs could not be described (a path is not UTF-8). Nothing was changed."
            );
        };
        writeln!(
            out,
            "With sharing on, paired devices receive aggregate usage (tokens, cost, model and client by day, hour and agent) computed from these inputs:"
        )?;
        for (name, value) in &lines {
            writeln!(out, "  {name}: {value}")?;
        }
        writeln!(out, "  Inputs digest: {digest}")?;
        writeln!(
            out,
            "A first approval, or one after the inputs changed, ends every grant made before it."
        )?;
        let answer = ask(input, out, "Type \"approve\" to approve this scope: ")?;
        if answer.as_deref() != Some("approve") {
            return writeln!(out, "Not approved. Nothing was changed.");
        }
        let result = menu.call(SCOPE_APPROVE, json!({ "ownerInputsSha256": digest }));
        match &result {
            Ok(response) if response.code == OK => writeln!(out, "Scope approved."),
            Ok(response) if response.code == INVALID => writeln!(
                out,
                "The agent refused the approval (invalid); the scope was not approved. If the running agent was started with other inputs than the ones shown (a change since it started), restart it and try again. Status (menu item 1) shows the current state."
            ),
            _ => report(out, &result),
        }
    }

    fn listen(menu: &Menu, input: &mut dyn BufRead, out: &mut dyn Write) -> io::Result<()> {
        let Some(host) = ask(
            input,
            out,
            "IP address to listen on (an address of this machine, or 0.0.0.0): ",
        )?
        else {
            return Ok(());
        };
        let Some(port) = ask(input, out, "Port (1024-65535): ")? else {
            return Ok(());
        };
        let Ok(port) = port.parse::<u16>() else {
            return writeln!(out, "That is not a port number. Nothing was changed.");
        };
        simple(
            menu,
            out,
            LISTEN_CONFIGURE,
            json!({"bindHost": host, "bindPort": port}),
            "The listen address is set.",
        )
    }

    fn offer(menu: &Menu, input: &mut dyn BufRead, out: &mut dyn Write) -> io::Result<()> {
        let Some(ttl) = ask(input, out, "Offer lifetime in seconds, 1-900 [600]: ")? else {
            return Ok(());
        };
        let ttl = if ttl.is_empty() {
            600
        } else if let Ok(ttl) = ttl.parse::<u64>() {
            ttl
        } else {
            return writeln!(out, "That is not a number. Nothing was changed.");
        };
        let result = menu.call(OFFER_CREATE, json!({ "ttlSeconds": ttl }));
        match &result {
            Ok(response) if response.code == OK => {
                let url = response.data["pairUrl"].as_str().unwrap_or_default();
                writeln!(
                    out,
                    "Pair URL (paste it on the other device; it is shown only now, valid for {ttl} seconds):\n{url}"
                )
            }
            Ok(response) if response.code == UNAUTHORIZED => writeln!(
                out,
                "No offer was created: sharing is off, five offers are active, or the clock is off."
            ),
            Ok(response) if response.code == INVALID => writeln!(
                out,
                "No offer was created: set a listen address first, and use a lifetime of 1-900 seconds."
            ),
            _ => report(out, &result),
        }
    }

    fn pending(menu: &Menu, input: &mut dyn BufRead, out: &mut dyn Write) -> io::Result<()> {
        let result = menu.call(PENDING_LIST, json!({}));
        let listed: Vec<(String, String)> = match &result {
            Ok(response) if response.code == OK => response
                .data
                .as_array()
                .map(|all| {
                    all.iter()
                        .map(|pending| {
                            (
                                pending["pendingId"].as_str().unwrap_or_default().to_owned(),
                                pending["sasCode"].as_str().unwrap_or_default().to_owned(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
            _ => return report(out, &result),
        };
        if listed.is_empty() {
            return writeln!(out, "No pairing is waiting.");
        }
        for (n, (_, sas)) in listed.iter().enumerate() {
            writeln!(out, "  {}. code {sas}", n + 1)?;
        }
        let Some(pick) = ask(input, out, "Number to answer, or Enter to go back: ")? else {
            return Ok(());
        };
        let Some((pending_id, sas)) = pick
            .parse::<usize>()
            .ok()
            .and_then(|n| listed.get(n.checked_sub(1)?))
        else {
            return Ok(());
        };
        writeln!(
            out,
            "Approve only if the other device shows the same code: {sas}\nApproving lets that device read aggregate usage (tokens, cost, model and client by day, hour and agent) of the approved scan scope until you revoke it or it expires."
        )?;
        let answer = ask(
            input,
            out,
            "Type \"approve\" or \"reject\", or Enter to go back: ",
        )?;
        let body = json!({"pendingId": pending_id, "sasGeneration": 1});
        match answer.as_deref() {
            Some("approve") => simple(menu, out, APPROVE, body, "Approved."),
            Some("reject") => simple(menu, out, REJECT, body, "Rejected."),
            _ => writeln!(out, "Nothing was changed."),
        }
    }

    /// Running: the count, and a revoke by `grantId` over control. Not
    /// running: the menu takes the lock and lists and revokes on the store
    /// itself (`revoke_commit`), the one store write it makes besides
    /// `Agent::uninstall`.
    fn grants(menu: &Menu, input: &mut dyn BufRead, out: &mut dyn Write) -> io::Result<()> {
        let result = menu.call(STATUS, json!({}));
        match &result {
            Ok(response) if response.code == OK => {
                writeln!(out, "Active grants: {}", response.data["activeGrantCount"])?;
                writeln!(
                    out,
                    "While the agent runs, grants can only be counted, not listed (control has no grant list): revoke one by its grant ID, or stop the agent to see the list."
                )?;
                let Some(grant_id) = revoke_prompt(input, out)? else {
                    return Ok(());
                };
                simple(
                    menu,
                    out,
                    REVOKE,
                    json!({ "grantId": hex_encode(&grant_id) }),
                    "Revoked.",
                )
            }
            Err(Reach::NotRunning) => grants_offline(menu, input, out),
            _ => report(out, &result),
        }
    }

    fn revoke_prompt(input: &mut dyn BufRead, out: &mut dyn Write) -> io::Result<Option<[u8; 16]>> {
        let Some(text) = ask(
            input,
            out,
            "Grant ID to revoke (32 hex digits), or Enter to go back: ",
        )?
        else {
            return Ok(None);
        };
        if text.is_empty() {
            return Ok(None);
        }
        match decode_fixed_hex::<16>(&text) {
            Ok(grant_id) => Ok(Some(grant_id)),
            Err(_) => {
                writeln!(out, "That is not a grant ID. Nothing was changed.")?;
                Ok(None)
            }
        }
    }

    /// Lists under the lock, lets the lock go for the prompt (a resident
    /// may start meanwhile), then takes it again only to revoke. Writes
    /// nothing when the root or `state.json` is missing: `StateStore::open`
    /// would create a new identity there.
    fn grants_offline(menu: &Menu, input: &mut dyn BufRead, out: &mut dyn Write) -> io::Result<()> {
        let active: Vec<_> = {
            let store = match open_existing_store(menu) {
                Ok(Some(store)) => store,
                Ok(None) => return writeln!(out, "{NO_STATE}"),
                Err(StorageError::Busy) => return writeln!(out, "{STOP_FIRST}"),
                Err(error) => return report(out, &Err(Reach::Unsafe(error))),
            };
            let state = match store.state() {
                Ok(state) => state,
                Err(error) => return report(out, &Err(Reach::Unsafe(error))),
            };
            state
                .reference
                .grants
                .into_iter()
                .filter(|grant| grant.state == GrantState::Active)
                .collect()
        };
        writeln!(
            out,
            "The agent is not running. Active grants: {}",
            active.len()
        )?;
        for grant in &active {
            writeln!(
                out,
                "  {}  device {}…  expires at {} (Unix ms)",
                hex_encode(&grant.grant_id),
                &hex_encode(&grant.initiator_static)[..16],
                grant.expires_at_ms
            )?;
        }
        let Some(grant_id) = revoke_prompt(input, out)? else {
            return Ok(());
        };
        let store = match open_existing_store(menu) {
            Ok(Some(store)) => store,
            Ok(None) => return writeln!(out, "{NO_STATE}"),
            Err(StorageError::Busy) => {
                return writeln!(
                    out,
                    "The agent started meanwhile. Nothing was revoked; choose item 8 again."
                );
            }
            Err(error) => return report(out, &Err(Reach::Unsafe(error))),
        };
        let os_now = crate::state_store::os_now_seconds().ok();
        let result = store.transition(|state| {
            let wall = state.last_accepted_wall_unix_seconds();
            let now = os_now
                .map(|os_now| clock_status(os_now, wall))
                .filter(|status| !status.anomaly)
                .map_or(wall, |status| status.effective_now);
            let at = now
                .checked_mul(1_000)
                .ok_or(crate::security::SecurityError::Bounds)?;
            state.revoke_commit(grant_id, at)
        });
        match result {
            Ok(()) => writeln!(out, "Revoked."),
            Err(error) => writeln!(out, "Not revoked ({error:?}). Nothing was changed."),
        }
    }

    /// The state store under the owner lock, only when `state.json`
    /// already exists (checked read-only first, so a missing root or file
    /// is never created). `Ok(None)` when either is missing.
    fn open_existing_store(menu: &Menu) -> Result<Option<StateStore>, StorageError> {
        let Some(root) = SecureRoot::open_read_only(&menu.home, menu.suffix)? else {
            return Ok(None);
        };
        if root.read_file(STATE_FILE, STATE_FILE_MAX_BYTES)?.is_none() {
            return Ok(None);
        }
        let now = crate::state_store::os_now_seconds()?;
        StateStore::open(SecureRoot::open_under(&menu.home, menu.suffix)?, now).map(Some)
    }

    fn install_item(menu: &Menu, out: &mut dyn Write) -> io::Result<()> {
        if menu.running() {
            return writeln!(out, "{STOP_FIRST}");
        }
        let Some(exe) = &menu.exe else {
            return writeln!(
                out,
                "This program's own path is unknown. Nothing was installed."
            );
        };
        // Held while installing: a resident that starts meanwhile cannot
        // take the lock (it is non-blocking) and exits "already running".
        let _lock = match SecureRoot::open_under(&menu.home, menu.suffix) {
            Ok(root) => root,
            Err(StorageError::Busy) => return writeln!(out, "{STOP_FIRST}"),
            Err(error) => return report(out, &Err(Reach::Unsafe(error))),
        };
        match install::install(&menu.home, exe) {
            Ok(()) => writeln!(
                out,
                "Installed. It starts at the next login; to start it now, load the autostart entry yourself (macOS: launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.nyanako.syrtis.agent.plist; Linux: systemctl --user daemon-reload && systemctl --user enable --now syrtis-agent.service)."
            ),
            Err(error) => writeln!(out, "Not installed ({error:?})."),
        }
    }

    fn uninstall_item(menu: &Menu, input: &mut dyn BufRead, out: &mut dyn Write) -> io::Result<()> {
        if menu.running() {
            return writeln!(out, "{STOP_FIRST}");
        }
        writeln!(
            out,
            "Uninstall turns sharing off, revokes every grant, removes the autostart entry, the installed binary and the caches."
        )?;
        let purge = ask(
            input,
            out,
            "Also delete this machine's agent identity and pairing state? Type \"purge\" for yes, Enter for no: ",
        )?;
        let Some(purge) = purge else {
            return Ok(());
        };
        let confirm = ask(input, out, "Type \"uninstall\" to continue: ")?;
        if confirm.as_deref() != Some("uninstall") {
            return writeln!(out, "Nothing was changed.");
        }
        let outcome = |outcome: Outcome| match outcome {
            Outcome::Removed => "removed",
            Outcome::Absent => "not there",
            Outcome::ManualRepair => "LEFT IN PLACE, remove it by hand",
        };
        // No runtime: nothing listens or serves during an uninstall.
        match Agent::uninstall_stopped(&menu.home, menu.suffix, purge == "purge") {
            Ok(report) => {
                writeln!(
                    out,
                    "Autostart entry: {}",
                    outcome(report.install.autostart)
                )?;
                writeln!(out, "Installed binary: {}", outcome(report.install.binary))?;
                writeln!(
                    out,
                    "Caches: {}, {}, {}",
                    outcome(report.install.producer_cache),
                    outcome(report.install.receiver_cache),
                    outcome(report.source_cache)
                )?;
                writeln!(
                    out,
                    "Identity and pairing state: {}",
                    if report.install.purged {
                        "deleted"
                    } else {
                        "kept (sharing off)"
                    }
                )?;
                writeln!(
                    out,
                    "An autostart entry that is loaded stays loaded until you unload it or log out."
                )
            }
            Err(AgentError::Storage(StorageError::Busy)) => writeln!(out, "{STOP_FIRST}"),
            Err(error) => writeln!(out, "Not uninstalled ({error:?})."),
        }
    }
}
