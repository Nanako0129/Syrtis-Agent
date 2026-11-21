# Syrtis Agent Library Entry Point v1

## Purpose and boundary

This document fixes `Agent` (`src/agent.rs`), the one entry point that assembles a secure root, the engine-backed report source (`spec/source-v1.md`) and the runtime (`spec/runtime-v1.md`), and `merge::combine` (`src/merge.rs`), which sums the local report with the reports pulled from producers. It is what `SA-3` embeds and what the `SA-2C2b` CLI drives. Acceptance: `tests/agent_v1.rs`, plus the `clear_private_subdir` unit tests in `src/secure_fs/unix.rs`.

This module computes no usage number. The engine computes every record (`EngineSource`); `combine` only orders, filters and hands records to the frozen `merge_*` functions of `src/report.rs`. Pairing, grants, authorization and `source_change_commit` are the frozen transitions of `src/security.rs`, reached through `StateStore::transition`. Nothing here reads the environment, the network beyond what `Runtime::pull` does, or any path not derived from the caller's inputs.

macOS, Linux and Windows (`W3b`). On Windows the agent is embedded in the app: the runtime starts no control server (`spec/runtime-v1.md`), the app drives control through `Runtime::control`, and there is no install or CLI (section "Windows" below). On other unix targets the secure root fails closed (`spec/state-store-v1.md`); a target that is neither Unix nor Windows has no `Agent` and `Agent::start` is `Unsupported`.

## Start

`Agent::start(AgentConfig { trusted_home, scan_home, config_dir, data_dir, xdg_data_home, settings, state_suffix, options })`:

1. `SecureRoot::open_under(trusted_home, state_suffix)`. `AgentConfig::new` (signature unchanged) sets `scan_home` and `xdg_data_home` to `None`, `state_suffix` to the frozen platform suffix (`secure_fs::STATE_SUFFIX`) and `options` to `Options::default()`; a product passes `secure_fs::trusted_home()` as `trusted_home`. A test passes a temp home and a suffix without spaces.
2. The agent keeps `trusted_home`; `uninstall` uses it (below), so the install objects and the secure root are always below the same home.
3. `Runtime::start_with_scope`, whose `make_source` builds the one `EngineSource` of this root from the state store's own root, with `home = scan_home` (or `trusted_home` when `scan_home` is `None`, every macOS and Linux caller), `config_dir`, `data_dir`, `xdg_data_home` and `settings` (`EngineSource::new_with_xdg_data_home`). `xdg_data_home` is an optional separate XDG data root (`spec/source-v1.md`, "Separate XDG data root"): an owner input in the scope digest, so a caller that sets it must show it in its scope disclosure (it reads it back as `Agent::source().xdg_data_home()`, or computes the digest with `source::owner_inputs_sha256_with_xdg_data_home`). `None` scans and hashes as before it existed, so an approved scope stays approved. Control `status` reads that source's scan record (`spec/source-v1.md`, "Scan record") and `scopeApproved` (below); control `scopeApprove` runs the scope approval (below). The control server starts before the source exists: until it does, `scopeApproved` is false and `scopeApprove` is `internal`. In the same step the agent builds its scope disclosure (below) from the same values and checks that its digest equals the source's `owner_inputs_sha256`; a difference fails the start (`Runtime(Store(Refused(Invalid)))`), so a disclosure can never show other inputs than the ones hashed.

The inputs are fixed for the agent's life. To change a scan setting the caller stops the agent and starts a new one with the new settings; the approved scope then no longer matches (below).

`Agent::runtime()` gives the runtime operations (sharing, `pull`, `last_good`, `store`, `peers`); `Agent::source()` the source (scope record, scan status); `Agent::pricing_dir()` the engine's pricing root in the secure root.

## Approved scope

`scope_approved()` is true only when `source-scope.json` exists, its digest equals this agent's inputs, and its generation equals the state's `sourceScopeGeneration`. Anything unreadable is false. Those are the record conditions `report` checks (with the request's generation, which admission checked against the same counter).

`approve_scope()` is an owner action, serialized per agent:

| Record | Action |
|---|---|
| None, or a digest other than these inputs | `StateStore::transition(source_change_commit)` (generation forward, deny floor raised: every grant so far stops authorizing), then `EngineSource::approve`. A first approval takes this row too, so a grant paired before the first approval does not inherit the scope approved after it. |
| Same digest, generation other than the state's (after `reset`, or a crash between the commit and `approve` after which the owner set the inputs back) | `EngineSource::approve` only; no commit. |
| Same digest and generation | Nothing is written. |

**Through control (`SA-2C2b`).** Both bodies are functions in `agent.rs` over the state store, the agent's `EngineSource` and one `approving` mutex; `Agent::scope_approved` and `approve_scope` call them, and so do the two hooks `Agent::start` passes to the runtime. Control `status` reports `scopeApproved` with the same function, so it is true exactly when the record conditions `report` checks hold. Control `scopeApprove{ownerInputsSha256}` first compares the digest with the running source's (`EngineSource::owner_inputs_sha256`, computed once at start): another value is `Refused(Invalid)`, `invalid`, nothing written, because the owner consented to the inputs they were shown and the running agent may have been started with others (`SA-0G`). An equal digest runs the table above under the same mutex as `approve_scope`.

**Bound to what the owner was shown (`W3b`, SR P1-1).** `Agent::scope_disclosure() -> &ScopeDisclosure` returns the exact strings hashed into `ownerInputsSha256` (`home`, `configDir`, `dataDir`, `xdgDataHome` when set, `sourceCacheDir`, `extraScanPaths`, `excludedScanPaths`, `opencodeDbPaths`: UTF-8 path strings as given, lists sorted and deduplicated, maps by client) and that digest (`owner_inputs_sha256`). `Agent::approve_scope_for(digest)` is `approve_scope` behind the check control `scopeApprove` makes: a digest other than the running source's is `Refused(Invalid)` and nothing is written; an equal one runs the table above under the same mutex. A caller shows the disclosure's strings as they are (no canonicalization, case folding or path round trip) and approves with its digest; it never computes a digest itself.

**Entry points per platform (`W4`).** On macOS and Linux `approve_scope()` and `EngineSource::approve` stay public: the macOS app does not approve through control `scopeApprove`; its FFI compares the digest it showed with a digest it computes itself from the inputs it started the agent with (the same `owner_inputs_sha256` function over the same inputs) and then calls `approve_scope()`. On Windows neither exists outside the crate: `Agent::approve_scope_for(digest)` and `EngineSource::approve_for(&StateStore, digest)` (every platform; a digest other than the source's own is `Refused(Invalid)` and writes nothing) are the only public approval entries, and in-crate callers (the control hook, `approve_scope_for` itself) use the unchecked body. The embedding app is trusted: it can still pass the digest back without showing anything, or build its own runtime with `Runtime::start_with_scope`. Hiding the unchecked entries on Windows only prevents mistakes; it is not a security boundary.

The record is removed only by `uninstall` with `purge` (below). `reset` keeps it: removing it without moving the generation would let a later `approve` put new inputs under grants that are still valid.

## Pull and merge

`Agent::pull_all(query, local)`: calls are serialized by one mutex on the agent, so concurrent calls (an app asking for the four endpoints at once) wait in line instead of losing pulls to the runtime's fetch limiter, which refuses (`TooMany`) rather than waits. Then, for every peer record that is `usable` now, `Runtime::pull`, in batches of at most `report_peer::MAX_FETCHES` (2) concurrent pulls, no retry. A failed pull is classified (below); only `NoAnswer` falls back to `Runtime::last_good`, whose cached body is decoded with the frozen `decode_response` (no expected request). Then `combine(query.endpoint, local, parts)`. A caller's own `Runtime::pull` running at the same time still competes for the two fetch slots.

### Last-good fallback

A cached body is used only when the producer gave no answer about authorization. When it answered and refused, or its reply was invalid, the cached body would otherwise be merged for up to 30 days although the producer no longer authorizes it (only `revoked`/`expired` clear the cache). `merge::classify(PullError) -> FailureClass`:

| `PullError` | Class | Part (`PeerData` / `PartStatus`) |
|---|---|---|
| `Fetch(TooMany)`: this side's two slots in use, nothing sent | `NoAnswer` | `LastGood` / `LastGood`, or `None` / `Unavailable` without a cached body |
| `Fetch(Busy)`: producer code 5 (rate limit, compute slot, ledger) | `NoAnswer` | same |
| `Fetch(Timeout)` | `NoAnswer` | same |
| `Fetch(Transport(_))`: connect, handshake, transport | `NoAnswer` | same |
| `Fetch(TooLarge)`: body cost above the whole ledger | `NoAnswer` | same |
| `Fetch(Memory)`: this side's ledger refused a reservation | `NoAnswer` | same |
| `Fetch(InvalidQuery)`: refused before sending | `NoAnswer` | same |
| `Fetch(Revoked)`, `Fetch(Expired)`: codes 4, 3 (the runtime also clears the cache) | `Refused` | `Refused` / `Refused` |
| `Fetch(CheckGrantStatus)`: code 2 | `Refused` | same |
| `Fetch(Rejected)`: code 1 | `Refused` | same |
| `Fetch(Incompatible)`: code 6, the producer speaks another report schema (`DR-2b`) | `Refused` | same |
| `Fetch(Internal)`: code 8 | `Refused` | same |
| `Fetch(Unusable)`, `NoPeer`: this side's record is not usable or gone | `Refused` | same |
| `Fetch(Protocol)`, `Fetch(Invalid)`: a broken frame, or a body the decoder refused | `InvalidReply` | `InvalidReply` / `InvalidReply` |

Not classified with certainty:

- `Internal` (code 8) is what the producer sends both when its source denies the scope (a refusal) and when its engine fails or runs late (no statement about authorization). It is put in `Refused`, the side that stops showing data the producer may no longer authorize.
- `Transport(Crypto)` (handshake authentication failed) also happens when the producer was reset and has a new identity, which revoked every grant; the receiver cannot tell that from a wrong host, and it stays `NoAnswer` with the rest of the transport class.
- `Busy` can also come from the producer's state store failing to read (`storage_error_code`), not only from rate or slot limits; it stays `NoAnswer`.
- `Memory` and `TooLarge` happen after the producer authorized and started sending; `NoAnswer` there means "not refused", not "silent".
- `InvalidQuery` and `NoPeer` cannot have a cached body under the same key (no pull of that query on that record succeeded); their class changes nothing observable. `local` is the caller's own report (SA-3: the App's engine result); `None` here means no local part.

`combine(endpoint, local, peers)`:

1. Sorts `peers` by producer static, then `Fresh` before `LastGood` before the kinds without data (`None`, `Refused`, `InvalidReply`), then grant ID. The result therefore does not depend on the input order.
2. Of the parts of one producer only the first is considered; the others are `Duplicate`.
3. A part (local or peer) whose records are not `endpoint`'s variant, or fail the frozen `validate_*_records`, is `Invalid` and left out alone.
4. Every kept part's records go, concatenated, to the frozen `merge_graph` / `merge_models` / `merge_hourly` / `merge_agents` (direct sum, saturating).
5. `saturated` is true when a kept part was saturated or the merge saturated a sum. A left-out part's flag is not carried.

`Combined.records` is `None` only if the frozen merge refused its input; every part passed `validate_*_records` first, and no input that passes it and fails the merge is known. `Combined.peers` lists every part in the order of step 1 with its `PartStatus` (`Fresh`, `LastGood`, `Unavailable`, `Refused`, `InvalidReply`, `Invalid`, `Duplicate`) and the pull error when there was one.

## Pricing

`Agent::pricing_dir()` is `<root>/pricing`. The caller (SA-3) puts the pricing files there; this crate never fetches pricing. While the directory is empty every cost is 0 (`spec/source-v1.md`).

## Uninstall

`Agent::uninstall(self, purge)`, in this order (the install objects are looked for below the `trusted_home` the agent was started with). On Windows `install::uninstall` is `Unsupported` (no install exists in this version): step 1 stops the runtime, step 3 returns `Install(Unsupported)`, and nothing is removed: uninstalling the Windows app leaves the agent's state (`LocalAppData\Nyanako\Syrtis Agent`, including `source-cache` and `source-scope.json`) in place (owner decision; whether the installer removes it is decided with the installer).

1. `Runtime::into_store`: stops the runtime and takes the only handle to the state store. Another live handle: `Storage(Busy)`, and nothing is removed (the runtime is stopped).
2. The terminal timestamp: the effective now (`max(osNow, wall)`), or the durable wall while the clock is unreadable or anomalous.
3. `install::uninstall(store, <the agent's trusted_home>, purge, terminal_at_ms)`: its first step is the durable `StateStore::uninstall` (sharing off, every grant revoked, deny floor raised), and if that fails nothing is removed and the error is returned; then the installed objects, both report caches and, with `purge` and nothing marked, `state.json` and `peers.json` (`spec/install-v1.md`).
4. `SecureRoot::clear_private_subdir("source-cache")` empties the engine's source cache (session IDs and paths). A failure here marks `source_cache` as `ManualRepair`; it neither stops the uninstall nor returns an error.
5. If step 3 purged the state, `source-scope.json` is removed; `scope_removed` says whether that succeeded.

`Agent::uninstall_stopped(trusted_home, state_suffix, purge)` (`SA-2C2b` review) is the same uninstall without a running agent, for the standalone menu: `SecureRoot::open_under` (another holder: `Storage(Busy)`, nothing removed), `StateStore::open` at the OS clock (a root without `state.json` gets a fresh one first, as at any start, which the durable uninstall then disables and a purge removes), then steps 2–5 above, with the system clock for step 2. It starts no runtime, control server, listener, housekeeping or engine source. `Agent::uninstall` runs the same steps 2–5 through one shared function after step 1.

`AgentUninstallReport::manual_repair()` is true when step 3 marked anything, step 4 failed, or the state was purged and the scope record was not removed. The secure root's owner lock is held until the function returns.

## Windows (`W3b`)

The app builds its config with `AgentConfig::with_scan_roots(secure_fs::trusted_home()?, agent::default_scan_roots()?, settings)`:

- `secure_fs::trusted_home()`: the secure root's base, the LocalAppData known folder of the process token (flags 0; a local drive path only, `spec/state-store-v1.md`). The root is `<base>\Nyanako\Syrtis Agent`.
- `agent::default_scan_roots() -> Result<ScanRoots, StorageError>` (`cfg(windows)`): `home` = the Profile known folder, `config_dir` = RoamingAppData, `data_dir` = LocalAppData, `xdg_data_home` = `home\.local\share` (derived from the same `home` value). Each folder comes from `SHGetKnownFolderPath` with the process token and `KF_FLAG_DONT_VERIFY` (never NULL or the default-user token, never `KF_FLAG_CREATE`; one helper, `secure_fs::known_folder`, which `trusted_home` also uses). Each must be absolute, not verbatim (no `\\?\`), with a drive or UNC prefix and no `.` or `..`; normally `X:\…`, UNC when a folder is redirected. Anything else is `UnsafeState`. Nothing is created or opened.
- On Windows the state base and the scan home are therefore two values; `AgentConfig.scan_home` carries the second. Unix callers leave it `None`.
- The scope digest covers all four roots (W3a's `xdgDataHome` is always set here); the app shows `Agent::scope_disclosure()` and approves with `approve_scope_for` (above), the only public approval entry on Windows (`W4`).
- Control commands go through `Runtime::control` (`spec/control-v1.md`, "In-process entry"); `control::Server`, `control::call`, `install`, `Agent::uninstall` (above) and the CLI are `Unsupported`.

Known limits on Windows:

- No environment variable is followed: `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `HOME`, `HOMEDRIVE`, `HOMEPATH`, `TMP`, `TEMP`, `XDG_*` and `TOKSCALE_CONFIG_DIR` change neither the defaults (`windows_roots::environment_variables_do_not_move_the_default_scan_roots`) nor the scan (`spec/source-v1.md`). An owner who points a tool at another directory with an environment variable is not scanned there (the same limit as on macOS).
- Uninstalling the app leaves the agent's state (above).
- The state base (LocalAppData) may be writable by other accounts, for example the principals of OpenAI's Codex sandbox (`W4`). The agent then starts, and the residual risks the app must disclose are listed in `spec/state-store-v1.md`, "Windows non-claims" (another writer of the base) and "Residual risks".
- Junctions and symbolic links inside the scan roots are handled by the engine as it handles symlinks on Unix (`spec/source-v1.md`, "Engine facts on Windows"); a same-user process that plants one is outside the threat model.

## Acceptance map (`tests/agent_v1.rs` unless noted)

| Item | Test |
|---|---|
| (1) E2E: four endpoints merged equal the producer's records and the fixture; nothing after the producer's uninstall | `live::e2e_four_endpoints_merge_to_the_producer_fixture_and_nothing_after_uninstall` |
| (2) unapproved producer serves nothing; first approval ends earlier grants; approve then pair works | `live::scope_must_be_approved_and_a_first_approval_ends_earlier_grants` |
| (3) changed settings: unapproved, refused; `approve_scope` moves the generation and ends the old grant; unchanged inputs write nothing | `live::changed_settings_need_approval_and_end_the_old_grant` |
| (4) `reset` keeps the record; `approve_scope` re-approves without a commit | `live::after_reset_approve_scope_reapproves_without_another_commit` |
| (5) `combine`: bad peer alone, duplicate, order, saturation | `combine_leaves_out_only_the_invalid_peers`, `combine_keeps_one_part_per_producer_whatever_the_order`, `combine_carries_saturation` |
| Review: `pull_all` calls queue | `live::concurrent_pull_all_calls_queue_and_all_get_fresh_parts` |
| Review: no last-good after a refusal | `classify_matches_the_spec_table`, `live::a_refused_pull_does_not_fall_back_to_the_cached_body`, `live::changed_settings_need_approval_and_end_the_old_grant` (`Internal` with a cached body present); `LastGood` on a connect failure: `live::pull_all_falls_back_to_last_good_when_the_producer_is_stopped` |
| Review: a scope denial is not a scan | `live::status_reports_never_then_ok_then_error` |
| (6) producer stopped: last good, marked | `live::pull_all_falls_back_to_last_good_when_the_producer_is_stopped` |
| (7) `status`: `never` (also after scope denials), `ok`, `error` (engine failure) | `live::status_reports_never_then_ok_then_error` |
| (8) uninstall, purge, another store handle | `live::uninstall_ends_grants_and_clears_the_source_cache`, `live::purge_removes_the_scope_record_and_the_next_start_is_new`, `live::uninstall_with_another_store_handle_fails_and_removes_nothing` |
| (8b) `clear_private_subdir` (`src/secure_fs/unix.rs`) | `clear_private_subdir_empties_nested_dirs_and_unlinks_symlinks_only`, `clear_private_subdir_follows_a_symlink_only_without_nofollow`, `clear_private_subdir_refuses_a_symlinked_or_loose_directory` |
| (8c) source cache not clearable | `live::a_source_cache_that_cannot_be_cleared_only_marks_manual_repair` |
| `SA-2C2b` (3) `scopeApprove`: digest check, full approval | `live::scope_approve_over_control_needs_the_running_digest_and_ends_earlier_grants` |
| `SA-2C2b` (4) `scopeApproved` agrees with `report` | `live::status_scope_approved_matches_what_report_serves` |
| W3a: a scope approved without a separate XDG data root is not approved with one; `approve_scope` commits once | `live::a_separate_xdg_data_home_needs_its_own_approval` |
| W3b (SR P1-1): a scan home other than the state base is scanned; the disclosure re-hashes to the running digest; `approve_scope_for` with any other digest writes nothing | `live::approve_scope_for_binds_the_approval_to_the_disclosed_roots` |
| W3b: Windows defaults are four plain absolute known folders, X below home | `windows_roots::the_default_scan_roots_are_four_plain_absolute_known_folders` (Windows) |
| W3b: environment variables do not move the defaults | `windows_roots::environment_variables_do_not_move_the_default_scan_roots` (Windows) |
| W3b: on Windows `uninstall` is `Install(Unsupported)` and removes nothing | `live::e2e_four_endpoints_merge_to_the_producer_fixture_and_nothing_after_uninstall` (its Windows branch) |

Every `live::` test runs on macOS, Linux and Windows except these, which stay macOS/Linux: `scope_approve_over_control_needs_the_running_digest_and_ends_earlier_grants` and `status_scope_approved_matches_what_report_serves` (control `scopeApprove` is not an in-process command; Windows approves through `approve_scope_for`), the three uninstall tests of item (8) (no install on Windows), and `a_source_cache_that_cannot_be_cleared_only_marks_manual_repair` (a Unix symlink; the Windows junction case is a `secure_fs::windows` unit test).

## Non-claims

- A last-good body is decoded outside the runtime's memory ledger (the ledger is private to the runtime); a cached body is at most `LOGICAL_BODY_MAX`.
- `pull_all` with every pull timing out takes up to `ceil(peers / 2) × FETCH_DEADLINE`, and a queued call waits for the calls before it on top of that; it is not cancellable.
- `lastScanAt` is the OS wall clock, not the injected runtime clock.
- The uninstall order (durable uninstall before any cleanup) is fixed by the code above and by `install::uninstall`'s own unit test; no test in this slice injects a durable-uninstall failure through `Agent::uninstall`.
- Same-UID processes are outside the threat model (`spec/state-store-v1.md`), including swapping `source-cache/` between the check and the removal.
