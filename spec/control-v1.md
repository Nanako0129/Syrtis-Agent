# Syrtis Agent Local Control v1

## Purpose and boundary

This document fixes the local control wire: how a program of the same user (the CLI or the App) reaches the agent over a Unix domain socket, how both sides prove they hold the control token, and what each of the eleven control commands does. Implementation: `src/control.rs`. The command and response envelopes, the result codes and the success data shapes are frozen in `spec/v1.md` ("Control bodies and results"); the MAC constructions and their domain tags are frozen in `spec/security-v1.md` and `src/security.rs` (`control_key`, `control_server_mac`, `control_command_mac`, `control_response_mac`, `verify_control_command`, `verify_control_response`, `verify_mac`). This wire adds no cryptography: its byte framing only carries the inputs of those functions.

The socket server and client are macOS and Linux only. Every other platform, Windows included, fails closed: the server does not start and the client does not connect (`Unsupported`). A Windows named pipe is not in this version. On Windows the embedding App runs commands through the in-process entry `Runtime::control` instead (`W2`, "In-process entry" below); the command dispatcher behind both is platform-independent.

The `Runtime` that assembles store, listener and control (`SA-2B2c2`, `spec/runtime-v1.md`) owns what this wire leaves to its hooks: the real effect of `shutdown`, restarting the peer listener after `listenConfigure`, the sharing enable and disable entry points with the F-7 disable composition (command 10 `sharingSet` reaches them through a hook, `SA-2C2b`), scope approval (command 11 `scopeApprove`, through the agent's hook), and the SEC-SPLIT-02 checkpoint and `expire_one` schedule.

> v1 makes no claim against the same UID (`spec/state-store-v1.md`). The socket mode, the peer-UID check and the mutual proof stop other local UIDs and rogue endpoints; a process of the same UID can read the token from `state.json` and can exhaust the four pre-auth slots.

## Socket

The socket is `control.sock` in the agent's secure root, which is already exactly `0700`, owner-checked and on a local filesystem.

**Pathname exception.** `spec/state-store-v1.md` says nothing is reopened by pathname after a check. The control socket is the one stated exception: there is no `bindat` on macOS, so the server binds `<root path>/control.sock` by pathname. `secure_fs` records the path the root was opened with (`home/suffix…`) and exposes it read-only inside the crate; it reopens nothing by it. Every step below that uses the path can be raced only by a process that can write into the `0700` root, that is, the same UID, which is the existing same-UID non-claim.

At start, before any bind:

1. A path that does not fit `sun_path` fails the start (`PathTooLong`); nothing is touched.
2. `lstat` of `control.sock` (never follows a link): absent → bind. A socket owned by the effective UID (a stale one from an earlier run) → `unlink` (never follows), then bind. Anything else (regular file, symlink, directory, FIFO, a socket of another owner) → the start fails closed (`UnsafeSocket`) and the object is left in place.
3. After the bind: `chmod 0600` (a failure is `UnsafeSocket`), then `lstat` again; the start succeeds only if it is still a socket owned by the effective UID. Otherwise `UnsafeSocket` (the socket file is left; the next start replaces it under rule 2). `chmod` follows a link, so a same-UID swap between the bind and the `chmod` changes the swapped-in target's mode; the `lstat` then fails closed.

Stopping the server leaves the socket file; the next start replaces it.

## Admission

| Rule | Value |
|---|---|
| Owner check | After `accept` and before a slot, a worker thread or any read: the kernel's peer UID (`getpeereid` on macOS, `SO_PEERCRED` on Linux) must equal the effective UID. A mismatch, or no answer, closes the connection at once. |
| Slots | At most 4 connections are served at once, independent of the peer listener's 8. A connection holds its slot from admission until it closes (through the command and the response, not only until the command MAC verifies). A 5th connection, after the owner check, is closed at once, unread. |
| Pre-auth memory | A 64 KiB ledger, independent of the 384 MiB peer ledger. The command body buffer (`len + 32` bytes) is reserved before it is allocated and returned when the connection ends, on every path (EOF, timeout, MAC failure, success). The fixed 34-, 22- and 64-byte arrays are on the stack and not counted. With 4 slots and a 4,128-byte maximum the ledger cannot fill; it bounds the design, not a reachable state. |
| State snapshot | The one `store.state()` copy per connection, taken to derive the key, is not counted in the ledger: only a same-UID peer that passed the owner check can trigger it. |

## Handshake and framing

One command per connection. All integers are big-endian.

| Step | Direction | Bytes |
|---|---|---|
| 1 | client → server | `u16(controlVersion) ‖ clientNonce[32]`. A version other than 1 closes the connection without a proof. |
| 2 | server → client | `serverNonce[32] ‖ serverMac[32]`, `serverMac = control_server_mac(key, 1, clientNonce, serverNonce)`; `serverNonce` is fresh from the CSPRNG per connection. |
| 3 | client | `verify_mac` of `serverMac`. On a mismatch the client closes and sends no command byte. |
| 4 | client → server | `requestId[16] ‖ u16(commandId) ‖ u32(len) ‖ commandJson[len] ‖ commandMac[32]`, `len ≤ 4,096`, `commandMac = control_command_mac(key, 1, clientNonce, serverNonce, requestId, commandId, commandJson)`. `commandJson` is the CanonicalJsonV1 command envelope `{body, commandId, controlVersion, requestId}`. |
| 5 | server | `len > 4,096` closes before any allocation. Then `verify_mac` of `commandMac`; a mismatch closes without a response and without touching the state. Then the frozen `verify_control_command(commandJson, requestId, commandId)`; a refusal is answered `invalid`. |
| 6 | server → client | `u16(code) ‖ u32(len) ‖ responseJson[len] ‖ responseMac[32]`, `responseMac = control_response_mac(key, 1, clientNonce, serverNonce, requestId, code, responseJson)`; `responseJson` is the CanonicalJsonV1 envelope `{code, controlVersion, data, requestId}`. |
| 7 | client | `len ≤ 65,536`, `verify_mac` of `responseMac`, then the frozen `verify_control_response(responseJson, requestId, commandId, code)`, which checks the request ID and the code against the transcript and the success data shape for the command sent. |

**Key.** The server derives `control_key(controlToken)` per connection from the `controlToken` of one `store.state()` snapshot, taken after the owner check and the slot and before the server proof, and never caches it. After the command MAC verifies, the server reads the token again; if it differs from the one read at the hello, the connection is closed without a reply and nothing runs, so a command authenticated before a reset does not act on the state after it. A sticky-unknown store closes the connection without a proof. After a reset the old token fails at the very next server proof.

**Deadlines.** Absolute, on the monotonic clock; partial bytes never extend them. Accept → complete hello: 2 s. Server proof written → complete command: 2 s. Response write: 2 s. A timeout, EOF or MAC failure returns the slot and the memory. The client has one 10 s deadline for the whole call. Both sides wait with non-blocking sockets and `poll(2)`, not socket timeouts (macOS refuses `setsockopt` with `EINVAL` once the peer has closed, even while its last bytes are unread).

**Replay.** A recorded hello, command or response cannot be replayed: each MAC binds the fresh `serverNonce` (and the client's `clientNonce`).

## In-process entry (`W2`)

`Runtime::control(&self, command: &Command) -> Result<Response, ControlError>` (`spec/runtime-v1.md`) is the one public in-process entry; there is no `control::Local` and no other public way to reach the dispatcher. It exists so the Windows App, which has no control endpoint in this version, can run the commands the macOS App sends over its own socket. It is available on every platform the runtime starts on.

**Same dispatcher.** The dispatcher (`Shared`: the store, the clock, the hooks and a stopped flag) and `execute` with its handlers are platform-independent and crate-private (`pub(crate)`, never `pub`). The runtime builds one `Shared`, the control server serves it, and `Runtime::control` runs on the same one: the same handlers, the same `listenConfigure`, scan and scope hooks, the same store error mapping, the same result codes and success data. **Invariant:** no `Shared`, and nothing that reaches one, is ever given to a `Listener` or a `ReportSource`; the runtime keeps it in a field of `Runtime` itself, not in the state its hooks and listener share, so no peer path can run a control command.

**Command set.** Exactly the eight commands `status`, `offerCreate`, `offerCancel`, `pendingList`, `approve`, `reject`, `revoke`, `listenConfigure`. Any other ID, including `shutdown` (9), `sharingSet` (10) and `scopeApprove` (11), is answered 1 `invalid` with `null` data and nothing runs: the owning process has the direct methods (`Runtime::stop`, `Runtime::enable_sharing` / `disable_sharing`, the agent's scope approval).

**What it keeps.** The command envelope is built as the client builds it (CanonicalJsonV1 `{body, commandId, controlVersion, requestId}`, a fresh CSPRNG `requestId`, at most 4,096 bytes; over that, or a body that does not encode, is `ControlError::Command` and nothing runs) and goes through the same code as step 5 of the socket: the frozen `verify_control_command(commandJson, requestId, commandId)` (a refusal is `invalid`, so every validator bound applies, such as `ttlSeconds` 1..=900 and the `bindPort` range), then `execute` on its body. The response envelope is built as the server builds it and checked as the client checks it (step 7): at most 65,536 bytes and the frozen `verify_control_response`; a failure is `ControlError::Response` (the command may have run).

**What it skips, and why.** No MAC, no framing, no peer-UID check, no slot or pre-auth ledger, no deadline: the caller is the process that owns the `Runtime`, which already holds the store and the token. The control token is still generated and stored on every platform (it is part of the state schema), but on Windows nothing reads it.

**Stop.** The dispatcher's stopped flag sits under a read-write lock. `execute` runs under a read guard on both paths: the socket path takes it around step 5, the in-process entry for its whole call. `Runtime::stop`, after asking for shutdown, takes the write guard, so it waits for every command in flight on either path, then sets the flag. From then on `Runtime::control` returns `ControlError::Stopped`, a Rust-level error and never a wire code, and runs nothing. The socket path does not read the flag; its server is stopped and joined in the next step, as before.

**Caller duties.** The in-process call has no deadline: a store commit, the `listenConfigure` listener restart and the scan and scope hooks can block, so it must not be called on a UI thread (the socket path's client gives up after 10 s). Before `approve`, showing the owner the SAS and getting their confirmation that it matches is the caller's obligation, as on the socket. A hook runs under the read guard, so a hook must never call `Runtime::control` or `Runtime::stop`.

## Commands

Bodies arrive already checked by the frozen validator. Every state change goes through `StateStore::transition` with frozen `ReferenceState` transitions, `StateStore::set_listen_config`, `pairing::approve`, or one of the two effect hooks (`sharingSet`, `scopeApprove`), whose own changes are the runtime's and the agent's. A terminal record's timestamp is the effective now (`max(osNow, lastAcceptedWall)`), or the durable wall when the OS clock is unavailable or anomalous, so `revoke`, `reject` and `offerCancel` never fail on the clock. `status` and `pendingList` read "now" the same way (in milliseconds): an offer or pending record whose `expiresAt` that now has reached is left out, whether or not housekeeping has stored it as expired yet.

| Command | Effect |
|---|---|
| `status` | From one snapshot: counts of `active` grants, of `active` offers and of `awaitingApproval` pending records (offers and pending records past `expiresAt` by now are not counted; grants are counted as stored); `bindHost`, `bindPort`, `nodeLabel` from the listen config (`null` while unset, SA-0F); `sharingEnabled`; `lastScanAt`, `scanStatus`, `sourceFamilies` from the scan provider the server was started with (`Server::start_with_hooks`; the runtime passes the one it is given, `spec/runtime-v1.md`); `sourceFamilies` is sorted, deduplicated and cut to 128 here whatever the provider returns. Without a provider: `null`, `"never"`, `[]`. `scopeApproved` (`SA-0G`) from the scope provider the server was started with (`Server::start_with_scope_hook`, `Server::start_with_all_hooks`), which is given the server's store; every other constructor passes none, and without one it is `false`. The provider may read the store and the scope record (the agent's does), so `scopeApproved` and the other fields are not guaranteed to come from one snapshot. |
| `offerCreate{ttlSeconds}` | Needs a `bindHost` (else `invalid`) that passes `listener::bind_address` with the stored port (else `invalid`; a hostname or `0x0` that the store accepted is refused here, as the listener would). The `responderStatic` is the identity of the same snapshot. `offerId` and `secret` come from the CSPRNG; `secretHash = offer_secret_hash(offerId, secret, responderStatic)`; the frozen `create_offer` runs with `createdAt` = effective now and `expiresAt = createdAt + ttlSeconds × 1000`. Its refusals (sharing off, five active offers, clock anomaly, record cap) are `unauthorized`. A reset between the snapshot and the commit turns sharing off, so `create_offer` refuses an offer bound to the old identity. Success data: `{expiresAt, offerId, pairUrl}`, `pairUrl = pair_url(…)` with the stored host and port. |
| `offerCancel{offerId}` | Frozen `cancel_offer`. Not an active offer → `invalid`. |
| `pendingList` | `awaitingApproval` records not past `expiresAt` by now, as `{expiresAt, pendingId, sasCode}`, sorted by `pendingId`. v1 never re-issues a SAS, so the `sasGeneration` to approve or reject with is 1. |
| `approve{pendingId, sasGeneration}` | `pairing::approve` with `disclosureExact = true`: in one commit it revokes the pending initiator's active grants and approves (`spec/pairing-v1.md`, "Approval"), so approving ends that device's earlier grant. The server cannot see what the owner was shown: showing the disclosure and getting the owner's confirmation before sending `approve` is the caller's (App or CLI) obligation. |
| `reject{pendingId, sasGeneration}` | Frozen `reject_pending`. |
| `revoke{grantId}` | Frozen `revoke_commit`; the terminal record's ID is the `grantId`. |
| `listenConfigure{bindHost, bindPort}` | `listener::bind_address(bindHost, bindPort)` first; a refusal is `invalid` and nothing is written. Then `set_listen_config`, keeping the stored `nodeLabel`. After that commit and before the reply, on the serving thread, the listen hook the server was started with is called (`Server::start_with_listen_hook`; `Server::start` passes none): the runtime restarts the peer listener there, so a client that sees `ok` finds it already moved or stopped (`spec/runtime-v1.md`, "Listener slot"). |
| `sharingSet{enabled}` | Wire and validation frozen by `SA-0G` (`spec/v1.md`). The server calls the sharing hook it was started with (`Server::start_with_all_hooks`, `Hooks::sharing`) with `enabled`, on the serving thread, and maps its error with the table below; it makes no transition itself. The runtime's hook is `enable_sharing` / `disable_sharing` (`spec/runtime-v1.md`): the enable gate's `Busy` is 5 `busy`, `enabled: true` while sharing is on is the frozen `Refused(Conflict)`, 1 `invalid`, and a disable with nothing to end is `ok` with nothing written. Without a hook (`Server::start` and the other constructors): 8 `internal`, nothing written. |
| `scopeApprove{ownerInputsSha256}` | Wire and validation frozen by `SA-0G`. The server calls the scope-approve hook it was started with (`Hooks::scope_approve`) with its store and the digest, on the serving thread, and maps its error with the table below. The agent's hook (`spec/agent-v1.md`, "Approved scope") compares the digest with its running source's `ownerInputsSha256` first: another value is `Refused(Invalid)`, 1 `invalid`, and nothing is written; an equal one runs the agent's full scope approval. Without a hook (a runtime without an `EngineSource`, or a bare server): 8 `internal`, nothing written. |
| `shutdown` | Answered `ok`; then, on the serving thread, the hook the server was started with is called, whether or not the reply could be written: the command was authenticated, so a client that disconnects still shuts the agent down. The hook must not stop the server synchronously (stopping joins that thread); the runtime's hook only sets a flag and wakes `Runtime::wait`. It is not called for a refused body. |

| Store error | Code |
|---|---|
| `Refused(Unauthorized)` | 2 `unauthorized` |
| `Refused(Expired)` | 3 `expired` |
| every other `Refused` | 1 `invalid` |
| `Busy` | 5 `busy` |
| `UnsafeState` | 7 `unsafeState` (local control may say so; the peer wire folds it into `internal`) |
| `Unknown`, `Incompatible`, `Corrupt`, `Unavailable` | 8 `internal` |

Error `data` is always `null`. `revoked` (4) and `incompatible` (6) are not sent by this server.

## Client

`control::Client::new(token, socketPath)` holds the token as `Secret32`. `call(command)` opens one connection and runs steps 1–7; it sends no command byte before the server proof verifies, and returns a response only after the MAC and the frozen validator pass. A failure before the whole command is written (connect, the hello, the proof read, a partial command write; all slots busy, a wrong version) is a `Socket` error: the command did not run, and the caller may retry. Once the whole command is written, a reply that does not arrive (deadline, early close, read error) is `NoReply` and a reply that fails its MAC, bound or validator is `Response`: in both the command may have run, and the caller has to read the state (`status`) before acting again (`SA-2C2b` review). `revoke` while four same-UID connections stall in their hello completes once their 2 s hello deadline frees a slot (measured below 5 s).

## Secret confinement

The token, the offer secret and the Pair URL never appear in a `Debug` output or an error: `Client`, `Server` and `Response` have hand-written `Debug` (the response's omits `data`), `ControlError` carries no bytes, and the token is held as `Secret32`. The Pair URL exists only in the `offerCreate` success data (`spec/v1.md` (ii)). The frozen `PairOffer` derives a `Debug` that prints its secret, so it exists only as the temporary argument of `pair_url`. Nothing is logged. Buffers are not zeroized.

## Non-claims

- **Cross-UID refusal is not observed by a test.** No test may switch users. The UID comparison is tested with a test-build-only override of the kernel's answer (`src/control.rs` unit test); a release build has no API to inject a UID. That the kernel reports another user's UID as different is inferred from `getpeereid(3)` and `unix(7)`.
- **A stale socket owned by another UID** is refused by rule 2 (inferred; such a socket cannot be created in a test without a second user).
- **The post-bind `lstat`** (rule 3) is not exercised: it fires only on a same-UID swap between the bind and the check, which is not reproduced, and removing it leaves every test green. The `0600` mode itself is asserted.
- **The response write deadline** is not exercised: a response is at most a few kilobytes and fits the socket buffer, so a test cannot make the write block.
- **Same-UID availability.** A same-UID process can hold all four slots, each for up to about 4 s without the token (the hello and command deadlines; with the token it is the owner), or start a server that owns `control.sock` first; clients then fail or get `ServerProof`. Same-UID non-claim.
- **Linux `connect`.** A blocking `connect` to a socket whose listen backlog is full can wait on Linux; the accept loop drains it every 50 ms at most. Not measured.

## Acceptance map (`tests/runtime_control_v1.rs` unless noted)

| # | Test |
|---|---|
| 1 | `a_receiver_pairs_and_is_revoked_through_control_end_to_end` |
| 2 | `a_wrong_token_or_command_mac_sends_and_changes_nothing`, `the_client_refuses_a_forged_or_misaddressed_response` |
| 3 | `a_replayed_conversation_fails_and_changes_nothing` |
| 4 | `each_command_succeeds_and_each_validator_refusal_is_invalid` (all eleven commands) |
| 5 | `src/control.rs` `a_peer_with_another_uid_is_closed_before_any_slot_or_read`; same-UID admission by every integration test |
| 6 | `a_fifth_pre_auth_connection_is_closed_and_slots_free_after_the_deadline` |
| 7 | `a_slow_hello_is_cut_at_the_absolute_deadline_and_a_wrong_version_closes`, `a_stalled_command_is_closed_at_its_deadline` |
| 8 | `an_oversize_command_closes_and_pre_auth_memory_returns_to_baseline` |
| 9 | `the_socket_is_0600_in_the_root_and_a_stale_one_is_replaced` |
| 10 | `offer_create_needs_a_bindable_host_and_sharing_and_names_this_identity` |
| 11 | `no_debug_output_shows_the_token_url_or_secret` |
| 12 | `after_a_reset_the_old_token_fails_and_the_new_one_works` |
| 13 | `listen_configure_refuses_what_the_listener_would_not_bind` |
| 14 | `a_residue_that_is_not_our_socket_fails_closed_and_stays` |
| 15 | `revoke_completes_within_five_seconds_while_four_hellos_stall` |
| `SA-0G` | `without_hooks_sharing_set_and_scope_approve_are_internal_and_change_nothing`, `status_reports_scope_approved_from_its_provider` |
| `SA-2C2b` | `sharing_set_runs_the_runtime_gate_and_maps_its_errors`; dispatch of 10 and 11 to their hooks: `each_command_succeeds_and_each_validator_refusal_is_invalid`; `scopeApprove` and `scopeApproved`: `tests/agent_v1.rs` `live::scope_approve_over_control_needs_the_running_digest_and_ends_earlier_grants`, `live::status_scope_approved_matches_what_report_serves` |
| `SA-2B2c2` | The expiry filter of `status` and `pendingList`: `tests/runtime_lifecycle_v1.rs` `status_and_pending_list_leave_out_what_has_expired`; the hooks: that file and `spec/runtime-v1.md` |

`W2` (in-process entry; `tests/runtime_control_local_v1.rs` unless noted; since `W3b` they run on macOS, Linux and Windows, except the last row, which is macOS/Linux by what it tests. Windows has no control socket, so there the side-by-side test compares two in-process calls and rests on the fixed codes and data it asserts, and the `sharingSet` control of the refusal test uses `Runtime::enable_sharing`):

| Item | Test |
|---|---|
| The eight commands answer as over the socket | `each_of_the_eight_commands_answers_in_process_as_over_the_socket` |
| The frozen validator runs (`ttlSeconds` 901, an extra key, the size bound) | `the_frozen_validator_refuses_in_process_and_nothing_is_stored` (with the validator call removed from the in-process path, it fails: executor report) |
| `shutdown`, `sharingSet`, `scopeApprove` refused | `shutdown_sharing_set_and_scope_approve_are_invalid_in_process` |
| `Stopped` after `stop` | `a_call_after_stop_is_stopped` |
| `stop` waits for an in-process hook | `src/runtime.rs` `stop_during_a_held_in_process_listen_configure_leaves_no_port_open` |
| No server is only a Windows build: elsewhere a bad socket path fails the start | `a_non_socket_at_the_control_path_fails_the_start_and_binds_no_port` |
