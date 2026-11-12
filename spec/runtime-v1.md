# Syrtis Agent Runtime v1

## Purpose and boundary

This document fixes the agent runtime: what `Runtime::start` assembles, the order `stop()` takes it down in, how the peer listener follows `listenConfigure`, what the control `shutdown` command does, the two sharing entry points (the F-7 disable composition and the enable gate), the receiver pull entry point and its cache (`SA-2B3b`), and the SEC-SPLIT-02 housekeeping schedule (clock checkpoint and expiry sweep). Implementation: `src/runtime.rs`; acceptance: `tests/runtime_lifecycle_v1.rs`, `tests/runtime_pull_v1.rs` and the unit tests in `src/runtime.rs`.

Every state change is one `StateStore::transition` closure over frozen `ReferenceState` transitions (`src/security.rs`), `StateStore::checkpoint`, or a control command (`spec/control-v1.md`). The runtime adds no transition, no cryptography and no wire format. Not in this slice: real report sources (`SA-2B3cd`), the producer cache (not wired; `spec/cache-store-v1.md` keeps the role), install and the CLI (`SA-2C`), Windows.

macOS and Linux only. Elsewhere the control server fails closed (`Unsupported`), so `Runtime::start` fails with `Control(Unsupported)` before any thread runs.

## Assembly

`Runtime::start(root, source, options)`:

1. Reads the OS clock (`options.clock`), opens `StateStore` in `root` (a new state's install wall is that reading), and opens `PeerStore` in the same root, under the same owner lock.
2. Creates one memory ledger, one pairing rate limiter and one `Reports` (with `source`) for the process; every listener the runtime starts shares them. Opens the receiver `CacheStore` (`spec/cache-store-v1.md`) in the same root on that ledger. If it does not open (`UnsafeState`, `Busy`, anything else), the runtime runs without a cache until the next start: `pull` still works, nothing is cached, `last_good` is `None`. It is not retried.
3. Starts exactly one control server on that store, with two hooks: `shutdown` and `listenConfigure` (below). A second server on the same store would unlink the first one's socket, so the runtime never starts another.
4. Starts the peer listener when the stored `bindHost` is set, passes `listener::bind_address` and binds. Unset, refused or unbindable: no listener, and the runtime runs on; `status` answers.
5. Starts the housekeeping thread, whose first round runs at once.

A failure in steps 1–3 returns an error before any thread runs; a failure to spawn the housekeeping thread stops what started and returns `Thread`. `RuntimeError` carries no path or OS error.

## Listener slot

The listener (at most one) and a `stopping` flag sit under one runtime mutex. The `listenConfigure` hook, called by the control server on the connection thread after `set_listen_config` committed and before the reply is written, takes the mutex and:

- returns at once when `stopping` is set;
- returns, keeping the listener and its connections, when a listener runs and its bound address equals `listener::bind_address` of the stored `bindHost` and `bindPort`;
- otherwise stops the old listener (which joins its threads), then starts a new one. `Listener::start` reads `bindHost` and `bindPort` from the store while the mutex is held, so whichever of two concurrent `listenConfigure` hooks runs last binds what the store holds after both commits.

A new address that does not bind leaves no listener: no fallback to the old address, no other address tried. `status` still answers. A client that sees `ok` therefore finds the listener already moved (or stopped). Housekeeping retries it (below).

## Shutdown and stop

The control `shutdown` hook sets a flag and wakes `wait()`. It never stops anything: the hook runs on a connection thread that stopping the server would join.

`wait()` blocks until shutdown is asked for, by control `shutdown` or by `stop()`.

`stop()`, serialized and idempotent, in this order:

1. Asks for shutdown (wakes `wait()`).
2. Stops the control server, which joins every connection thread, so no hook runs after this step.
3. Takes the listener mutex, sets `stopping`, stops and joins the listener.
4. Halts the housekeeping thread and joins it; its last act is one final checkpoint.

It returns only after every thread has ended. Dropping the runtime calls `stop()`. The control socket file stays; the next start replaces it (`spec/control-v1.md`, "Socket"). Step 2 alone already prevents a hook from starting a listener after step 3; the `stopping` flag is a second, independent guard.

## Sharing entry points (F-7)

No control command enables or disables sharing; the runtime's library entry points do. A terminal record's timestamp (`at` below) is the effective now in milliseconds, or the durable wall while the OS clock is unavailable or anomalous, as in `spec/control-v1.md` ("Commands"). Neither entry point fails on the clock.

**`disable_sharing()`**: one transition closure, in order:

1. The frozen `disable_commit(recordId, at)`, `recordId` fresh from the CSPRNG: sharing off, every active grant revoked, the deny floor raised. It never fails on record count.
2. The frozen `reject_pending` for every `awaitingApproval` pending. It never fails on record count.
3. The frozen `cancel_offer` for every `active` offer. A cancel refused with `Bounds` (the record table holds `MAX_RECORDS`) is skipped and the state before it kept; any other refusal fails the whole closure.

So a disable never fails on record count; it never calls the bare `StateStore::disable()`. When sharing is already off and no pending is awaiting, no offer is active and no grant is active, the call writes nothing: every disable adds a terminal record, so a caller that disables on each launch would otherwise fill the record table.

**`enable_sharing()`**: one transition closure:

0. If sharing is already on: the frozen `enable_sharing` refusal (`Conflict`), before anything else, and nothing is written.
1. The frozen `reject_pending` for every `awaitingApproval` pending. A claim is refused while sharing is off, so such a pending predates the last disable or uninstall; an uninstall rejects none itself. Then `cancel_offer` again on every `active` offer, skipping `Bounds`.
2. If any offer is still `active` with `expiresAt > lastAcceptedWall × 1000` (the wall of the state inside the closure): refuse with `StorageError::Busy`. Nothing is written, not even the rejects and cancels of step 1.
3. Otherwise the frozen `enable_sharing`.

**Why this closes F-7 without comparing clocks.** While sharing is off no offer can be created (`create_offer` refuses). A claim's effective now is never below the wall, and the frozen `claim_offer` refuses at effective now ≥ `expiresAt`. The wall decreases only in a reset, which removes every offer. So once enable succeeds, no offer created before a disable (or an uninstall, which disables) can ever be claimed, and no pending from before it can be approved: `disable_sharing` rejects them, and enable rejects any that an uninstall or the bare `StateStore::disable()` left awaiting. Cost: with a full record table, enable can be refused for up to an offer's lifetime (15 minutes), plus up to one housekeeping period (60 s) until a checkpoint moves the wall.

The listener keeps running while sharing is off: Grant status must still answer `revoked`.

## Housekeeping (SEC-SPLIT-02)

One thread. A round:

0. If no listener runs, `stopping` is not set, and the stored `bindHost` is set (an earlier bind failed): one run of the `listenConfigure` hook's body. This step does not depend on the clock.
1. Reads the OS clock and the state. An unreadable clock, a sticky-unknown store, or a clock anomaly by the frozen `clock_status` (more than 300 s behind or 86,400 s ahead of the wall) skips the round: nothing is written.
2. `StateStore::checkpoint(osNow)`: the frozen `compact_terminals`, which advances the durable wall. Then the receiver cache's `purge_expired(effectiveNowMs)`.
3. For each `active` offer or grant and each `awaitingApproval` pending whose `expiresAt` ≤ effective now (ms), one transition with the frozen `expire_one(recordId, effectiveNowMs)`.

Failures are ignored; the next round tries again (`expire_one` refuses `Bounds` while the record table is full, for example). The thread then waits on a condition variable until `stop()` or the pause ends. The pause is the period (60 s; `Options::housekeeping_period`), or, when a record not yet expired expires sooner, the time until then but at least 1 s (the wall clock has whole seconds) and never more than the period. A skipped or failed round waits the full period: the thread never spins. Clock and period are injectable (`Options`); production uses the OS clock and 60 s.

Nothing depends on the sweep for authority: claim, approval, Pair and Grant status and authorization compare `expiresAt` with the effective now themselves. The sweep only makes the stored state say so, and frees the slots (five active offers, five awaiting pending, sixteen active grants) that expired records would otherwise hold.

## Receiver pull and cache (`SA-2B3b`)

`Runtime::pull(responderStatic, query) -> Result<Fetched, PullError>`:

1. Takes the producer's record from `PeerStore` (no readable record: `NoPeer`, nothing sent).
2. Calls `report_peer::fetch` with that record, this runtime's state store, its memory ledger and one `FetchLimiter` per runtime. `fetch` refuses an unusable record (`peer_store::usable`) before anything is sent; `pull` adds no second check.
3. Success: `CacheStore::put` under the frozen `CacheKey` with `role` receiver, `peerStatic` and `grantId` of the record (lowercase hex), its `authEpoch` and `sourceScopeGeneration`, the query's endpoint, dates, timezone and clients, and the `AGGREGATION_REVISION`, `REPORT_SCHEMA_VERSION` and `TZDB_REVISION` constants: the fields of the request `fetch` sent, minus `requestId` and `protocol`. `createdAt` is the effective now (`max(osNow, lastAcceptedWall)`, ms); `expiresAt` is the earlier of `createdAt` + 30 days and the record's `expiresAt` (the grant's, producer clock). A failed or skipped write (no cache, unreadable clock, a refused key) does not change the result.
4. `Revoked` or `Expired`: first `PeerStore::set_state(responderStatic, grantId, revoked | expired)`, durable; a `Refused(Conflict)` (the producer was paired again) or a failure does not stop the next step. Then `CacheStore::remove_peer(peerStatic)`, every entry of that producer. Then the error. Read access ends once `set_state` is durable; a removal that fails after it only leaves files no usable record names, which expiry or eviction deletes.
5. Any other error (`Busy`, `Timeout`, `Transport`, `TooLarge`, …) leaves the cache alone.

`Runtime::last_good(responderStatic, query) -> Result<Option<CachedBody>, StorageError>`: `None` without a cache, without a readable record, when that record is not `usable`, when the OS clock or the state cannot be read, or while the clock is anomalous (a read at a wrong time would delete entries that are still valid; `pull` does not write the cache then either); otherwise `CacheStore::get` under the key built from that same record, at the effective now in ms. A revoked or expired record, or one bound to an identity from before a reset, therefore reads nothing, whatever is still on disk. A record removed or replaced by a new pairing (another `grantId`) builds another key; the old entries are left to expiry and eviction.

## Acceptance map (`tests/runtime_lifecycle_v1.rs` unless noted)

| # | Test |
|---|---|
| 1 | `the_runtime_pairs_serves_a_report_and_shuts_down_by_command` |
| 2 | `shutdown_returns_wait_and_stop_closes_the_socket_and_the_port` |
| 3 | `listen_configure_moves_the_listener_and_an_unbindable_address_stops_it` |
| 4 | `disable_rejects_cancels_and_revokes_and_nothing_old_works_after_enable` |
| 5 | `with_a_full_record_table_enable_waits_until_the_wall_passes_the_stranded_offer`; the enable cancel retry: `enable_cancels_a_stranded_offer_once_the_table_has_room` |
| 6 | `after_disable_and_enable_and_after_a_reset_new_offers_pair` |
| 6b | `src/runtime.rs` `stop_during_a_held_listen_configure_hook_leaves_no_port_open`; `concurrent_listen_configures_end_bound_to_the_stored_address` |
| 7 | `housekeeping_expires_offers_pending_and_grants_and_advances_the_wall` |
| 8 | `an_anomalous_round_is_skipped_and_the_next_sane_one_sweeps`, `a_sticky_store_neither_stops_nor_spins_housekeeping` |
| 9 | `stop_takes_a_final_checkpoint` |
| 10 | `without_a_bindable_host_the_runtime_runs_control_without_a_listener` |
| control filter | `status_and_pending_list_leave_out_what_has_expired` |

`SA-2B3b` (`tests/runtime_pull_v1.rs` unless noted):

| # | Test |
|---|---|
| 1 | `a_pulled_report_is_the_last_good_after_the_producer_stops` |
| 2 | `a_revoked_pull_marks_the_peer_and_removes_its_cache` |
| 2b | `an_unusable_record_does_not_read_its_cache_entry` |
| 3 | `an_expired_pull_marks_the_peer_and_removes_its_cache` |
| 3b | `an_entry_does_not_outlive_the_grant` |
| 3c | `src/runtime.rs` `a_crash_at_the_cache_unlink_after_revoked_leaves_nothing_readable` |
| 4 | `busy_and_disconnect_leave_the_cache_alone` |
| 5 | `a_symlinked_cache_file_leaves_the_runtime_without_a_cache` |
| 6 | `housekeeping_purges_expired_entries` |
| 7 | `listen_configure_to_the_bound_address_keeps_the_listener` |
| 8 | `housekeeping_retries_a_listener_that_did_not_bind` |

**Record table fixture (5).** One `StateStore::transition` whose closure pushes filler terminal records onto `terminal` until offers + pending + grants + terminal = 256 (`MAX_RECORDS`). Each filler has a unique ID, `cleanupComplete: true` and `terminalAt` = a chosen instant minus 90 days, so the frozen `compact_terminals` (the checkpoint) removes them all exactly when the effective now reaches that instant, and none before. That lets one test hold the table full through the disable and the gated enable, then free it to show that the later claim refusal is the offer's expiry, not the table.

## Non-claims

- **The `stopping` flag and the stop order are redundant guards.** Each alone keeps every listener from outliving `stop()`; the acceptance test fails only when both are removed (measured in the executor report).
- **A `shutdown` hook that stopped the server on its own thread** cannot be written against this structure (the hook holds no handle to the server), so the self-join deadlock it would cause is not exercised; the test asserts the reply arrives and `stop()` finishes within 3 s.
- **A sticky store is induced by making the root read-only** so the next checkpoint cannot stage its temp file. Where the test user can write a `0500` directory anyway (a privileged user), that test skips and says so.
- **Cancelling a report source.** The source has no cancel hook, so `Listener::stop` (and therefore `stop()`) can wait until a running `ReportSource::report` returns.
- **A fetched body's memory.** The `Fetched` that `pull` returns is not charged to the ledger once `fetch` returns (as before this slice); only the cache's own reads and writes are.
- **The crash in (3c) is simulated**: every secure-root step on the pulling thread fails from the cache `unlink` on, then the runtime is restarted. A real power loss between the two writes is not exercised.
- **Pre-reset offers.** The enable gate argument relies on `reset` removing every offer (`spec/state-store-v1.md`); it is not re-tested here beyond acceptance 6.
