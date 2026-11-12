# Syrtis Agent Standalone CLI v1

## Purpose and boundary

This document fixes the standalone binary `syrtis-agent` (`SA-2C2b`): `syrtis-agent run`, the resident entry point, and `syrtis-agent` with no argument, a plain numbered menu that manages the running resident over its control socket. Implementation: `src/main.rs` (three lines) and `src/cli.rs`; acceptance: `tests/cli_v1.rs`, plus the control and agent cases named below. The standalone agent is a producer only: no dashboard, no receiver, nothing to paste.

The binary adds no state, no wire format and no transition. Sharing, scope approval, offers, approvals and the listen address change only through the frozen control commands (`spec/control-v1.md`); their effects are the runtime's and the agent's (`spec/runtime-v1.md`, `spec/agent-v1.md`).

macOS and Linux. On every other platform (Windows included until `SA-4`) the binary compiles; `run` and the menu print `syrtis-agent: this platform is not supported yet.` and exit 1.

## Arguments and the home

`main` takes, in this order:

1. **Release gate.** In a build without `debug_assertions`, if the environment variable `SYRTIS_AGENT_DEBUG_HOME` is set (any value), the binary prints `syrtis-agent: SYRTIS_AGENT_DEBUG_HOME is set, but this build does not accept it. Nothing was opened.` to stderr and exits 3, before reading its arguments or resolving any home.
2. **Arguments.** None: the menu. Exactly `run`: the resident. Anything else: `usage: syrtis-agent [run]` on stderr, exit 2, nothing opened. No argument carries a value, so no secret, token or Pair URL can arrive by argv; no environment variable is read except the one above.
3. **Home.** `secure_fs::trusted_home()` (the directory-service home of the effective UID; `HOME` and `XDG_*` are ignored). In a debug build only, `SYRTIS_AGENT_DEBUG_HOME` replaces it. Both functions that read the variable for that purpose are compiled under an item-level `#[cfg(debug_assertions)]`; the release counterparts never read it. This is how `tests/cli_v1.rs` runs the binary on a temp home.

The secure root is the frozen `secure_fs::STATE_SUFFIX` below that home. The engine's config and data directories come from the home by platform convention, never from the environment: macOS `Library/Application Support` for both, Linux `.config` and `.local/share` (`cli::default_dirs`).

## `run`

`Agent::start` with that home, those directories, the frozen suffix and empty `ScannerSettings`: **the standalone agent scans default roots only.** It has no setting for extra scan paths, exclusions or database paths; adding one needs a new persisted file and a frozen-contract amendment. It then blocks in `Runtime::wait` until control `shutdown`, calls `Runtime::stop` and exits 0. Another process holding the owner lock (`Busy`): `syrtis-agent: another syrtis-agent is already running for this user.` on stderr, exit 1. Any other start failure prints the stable error class (for example `Storage(UnsafeState)`), no path, exit 1. It does not daemonize and writes no pid file: launchd or systemd manages it (`spec/install-v1.md`).

The standalone agent never fetches pricing and puts nothing in `Agent::pricing_dir()`; its costs are what the engine computes without a pricing dataset (`spec/source-v1.md`, `spec/agent-v1.md`).

## The menu

Input is read one line at a time, at most 16,384 bytes (newline excluded); a longer line is read to its end without being held, reported (`That line is longer than 16384 bytes and was ignored.`) and treated as empty. End of input quits. Nothing in the menu asks for a secret, so there is no no-echo input.

**Reaching the resident.** For every control item the menu opens the root with `SecureRoot::open_read_only` (below), reads `state.json` through it, decodes it with the frozen `decode_state`, keeps only `controlToken` (in memory, as `Secret32`) and calls `control::Client` on `<root>/control.sock`. A missing root or `state.json`, or a socket that does not answer (`ControlError::Socket`), prints the fixed hint `The agent is not running (or not answering). …Nothing was changed.` and writes nothing. A root or `state.json` that fails a check prints `…failed a safety check (<class>). Nothing was changed.` Never `open_under`: the resident holds the owner lock, so it would be `Busy`.

| # | Item | What it sends or does |
|---|---|---|
| 1 | Status | `status`; shows sharing, listen address, node label, active grant, offer and pending counts, scan status, last scan time and clients, and whether the scope is approved. |
| 2 | Turn sharing on | `sharingSet{enabled: true}`. `busy` (the enable gate) and `invalid` (already on) get their own messages. |
| 3 | Turn sharing off | `sharingSet{enabled: false}`. |
| 4 | Show the scan scope and approve it | Shows the disclosure first: home, config and data directories, the engine source cache (`<root>/source-cache`), "no extra scan paths", the engine's client list (`tokscale_core::ClientId::ALL`), and the `ownerInputsSha256` of exactly those inputs (`source::owner_inputs_sha256` with empty settings). Only after the owner types `approve` does it send `scopeApprove{ownerInputsSha256}` with that digest. `invalid` means the running agent was started with other inputs: nothing was approved. |
| 5 | Set the listen address and port | Asks for an IP and a port; `listenConfigure{bindHost, bindPort}`. |
| 6 | Create a pairing offer | Asks for a lifetime (1–900 s, default 600); `offerCreate{ttlSeconds}`; prints the Pair URL once, in that reply only. |
| 7 | Pending pairings | `pendingList`; lists each SAS code; for the chosen one shows the code to compare and what approving grants, then sends `approve` or `reject` `{pendingId, sasGeneration: 1}` only on the typed word. |
| 8 | Grants | Resident running: `status` (the active grant count), then `revoke{grantId}` for a typed 32-hex grant ID. Not running: see "Direct store access". |
| 9 | Stop the running agent | `shutdown`. |
| 10 | Install | See below. |
| 11 | Uninstall | See below. |
| 0 | Quit | |

**Direct store access** (security review F2) happens only while the resident is not running, and only in three ways: listing active grants (ID, first 16 hex digits of the device key, expiry) and revoking one with the frozen `revoke_commit` (item 8: `SecureRoot::open_under` takes the owner lock, `StateStore::open`, one `StateStore::transition`; the terminal timestamp is the effective now, or the durable wall while the clock is unreadable or anomalous); and `Agent::uninstall` (item 11). Sharing, scope approval, offers, approvals and the listen address are never written without the resident: they print the fixed hint. Item 8 first checks with `open_read_only` that a root exists, so it creates none.

**Install and uninstall** need the resident stopped. Each first asks control for `status`; a reply means it runs, and the menu prints `The agent is running. Stop it first (menu item 9), then try again. Nothing was changed.` without touching any file. Then each takes the owner lock itself (a `Busy` there prints the same message):

- Install: holds `SecureRoot::open_under` while `install::install(home, current_exe)` copies the binary and writes the autostart object (`spec/install-v1.md`). It loads nothing; it prints the `launchctl` / `systemctl` command for the owner to run.
- Uninstall: asks whether to purge (`purge` typed), then for the word `uninstall`; starts `Agent` on the root (which takes the lock) and calls `Agent::uninstall(purge)`; prints each outcome. An autostart entry that is loaded stays loaded until the owner unloads it or logs out.

**What is never done.** No file of the secure root is opened by path with `std::fs`; reads go through `open_read_only`, writes only through a `SecureRoot` the menu holds the lock of. The control token, the identity key and the Pair URL never appear in an argument, an environment variable, a log or an error; output shows paths (the disclosure) and stable classes only.

## `SecureRoot::open_read_only`

`SecureRoot::open_read_only(home, suffix) -> Result<Option<ReadOnlyRoot>, StorageError>` (`src/secure_fs/unix.rs`): the checks of `open_under` on the same descriptors (home owned by the effective UID, not group- or other-writable, deny-only ACL on macOS; each component opened relative to its parent with `O_NOFOLLOW`; intermediates owned and not group- or other-writable; the root owned, exactly `0700`, no ACL on macOS, on a local filesystem). It creates, chmods, syncs, tags (backup exclusion) and locks nothing. A missing component is `Ok(None)`. `ReadOnlyRoot::read_file` is `SecureRoot::read_file`'s check set: no-follow, regular, owned, `0600`, one link, no ACL on macOS, bounded. It is the only operation of `ReadOnlyRoot`.

This is a read path without the owner lock (readiness security review). The resident replaces `state.json` by `rename`, so a read sees the old or the new file whole. The windows stub fails closed (`UnsafeState`).

## Acceptance map (`tests/cli_v1.rs` unless noted)

| # | Test |
|---|---|
| (0) token read while the agent holds the lock | `disk::the_menu_reads_the_token_while_the_agent_holds_the_lock` |
| (0) `0755` root, symlinked `state.json` → `UnsafeState` | `disk::open_read_only_refuses_a_loose_root_or_a_symlinked_state` |
| (0) creates nothing | `disk::open_read_only_creates_nothing` |
| (0) install / uninstall while running | `disk::install_and_uninstall_refuse_while_the_agent_runs` |
| (1) every menu item against the resident | `disk::every_menu_item_drives_the_running_agent`; grants while stopped: `disk::grants_are_listed_and_revoked_on_the_store_when_the_agent_is_stopped` |
| (2) `sharingSet` through the enable gate | `tests/runtime_control_v1.rs` `sharing_set_runs_the_runtime_gate_and_maps_its_errors` |
| (3) `scopeApprove` | `tests/agent_v1.rs` `live::scope_approve_over_control_needs_the_running_digest_and_ends_earlier_grants` |
| (4) `scopeApproved` agrees with `report` | `tests/agent_v1.rs` `live::status_scope_approved_matches_what_report_serves` |
| (5) `run` subprocess: status, second `run`, shutdown exit 0 | `disk::run_serves_status_and_exits_zero_on_shutdown` |
| (5b) release build refuses the debug home | CI step "Release build refuses the debug home" (`.github/workflows/ci.yml`) |
| (5c) stopped: control items write nothing | `disk::with_the_agent_stopped_control_items_write_nothing` |
| (6) unknown arguments refused | `disk::unknown_arguments_are_refused_before_anything_is_opened` |
| (7) line limit | `a_line_over_the_limit_is_refused_and_the_next_one_is_read`, `disk::the_menu_ignores_a_line_over_the_limit` |

## Non-claims

- **Loading the autostart entry** (`launchctl`, `systemctl`) is not run by the binary or by any test; that is the owner's step and the cross-machine acceptance.
- **Signals.** `run` installs no signal handler. A `SIGTERM` from launchd or systemd ends the process without `Runtime::stop`, so without the final housekeeping checkpoint; the owner lock is released by the kernel at exit. Not exercised.
- **The release gate's position** is observed only by the CI step's exit status and message; with the gate removed, the step's extra argument stops the binary at the usage check (status 2), which is how the step turns red without opening a real home.
- **Install from the menu** is not exercised by a test (it would copy the test binary); `install::install` itself is tested in `tests/install_v1.rs`.
- **Windows**: compiling and the unsupported message are claimed for CI; not run on this machine.
- **Same UID.** A process of the same UID can read the token from `state.json` as the menu does (`spec/state-store-v1.md`, `spec/control-v1.md`).
