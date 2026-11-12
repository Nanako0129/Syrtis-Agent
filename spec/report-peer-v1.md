# Syrtis Agent Peer Report Transport v1 (producer)

## Purpose and boundary

This document fixes how the producer answers a Peer request on the peer wire: dispatch, the static binding, authorization, the error codes, limits, the report source seam, memory accounting, and how a response is sent in chunks while revocation stays effective. The Peer request and response field sets, value rules and obligations (i)–(iii) are frozen by `spec/v1.md`, and the request and response codecs by `spec/report-cache-v1.md` and `src/report.rs`; this document adds none. Transport (Noise IK, frames, deadlines) and the product listener are in `spec/pairing-v1.md`. Implementation: `src/report_peer.rs`, the dispatch in `src/pairing.rs`, and `StateStore::authorize_then` in `src/state_store.rs`. Acceptance: `tests/runtime_report_v1.rs` and the unit tests in `src/report_peer.rs`.

Not in this slice: the receiver's `fetch` and its count-before-decode scan (`SA-2B2b2`); the real report source and cache (`SA-2B3`); checkpoint and sweep scheduling (`SA-2B2c`).

## Connection

A Peer request arrives on a connection accepted by the product listener and served by `Producer::serve`, like the pairing surfaces: one handshake, one request frame, then either one error frame or the response chunks, then close. The report path does not use the pairing rate limiter.

## Processing order

| Step | Check | Failure |
|---|---|---|
| 1 | Handshake, frame kind Request, payload ≤ `FRAME_PAYLOAD_MAX` (61,402, enforced by the frozen `Frame::decode`), CanonicalJsonV1, exact key set equal to the Peer request set, `protocol` an integer equal to `1`, typed decode into the frozen `ReportRequest`, payload `requestId` equal to the frame header's `requestId` | Frame and handshake failures close without a frame (`spec/pairing-v1.md`); otherwise `invalid`, and an integer `protocol` other than `1` is `incompatible`. Reads no state |
| 2 | Static binding: from one `StateStore::state()` snapshot, the grant whose `grantId` is the request's, and the Noise remote static equal to its `initiatorStatic` (constant-time) | `unauthorized`. A `grantId` that is not 16-byte lowercase hex, an unknown grant and a foreign static send the same payload. An unreadable state answers by the store error map of `spec/pairing-v1.md` |
| 3 | Authorization: `StateStore::authorize` with the request's `grantId`, `authEpoch`, `sourceScopeGeneration`, `endpoint` and the OS wall clock now | See "Refusal codes" |
| 4 | `ReportRequest::validate` | `invalid` |
| 5 | Per-grant limit ("Limits") | `busy` |
| 6 | Compute slot ("Report source") | `busy` |
| 7 | Call the source; check the body length is 1..=`LOGICAL_BODY_MAX`; reserve the length on the memory ledger | A source error, a result returned at or after the compute deadline, an empty body or one over 16,777,216 bytes is `internal`, and no chunk is sent; a refused reservation is `busy` |
| 8 | Send the body in chunks ("Chunks and revocation") | Stop and close, no error frame |

Each error is one error frame, CanonicalJsonV1 `{code, protocol: 1}`, then close. Codes are drawn from 1 `invalid`, 2 `unauthorized`, 3 `expired`, 4 `revoked`, 5 `busy`, 6 `incompatible` and 8 `internal`; 3 and 4 are sent only after step 2 passed. Nothing is logged.

The step 1 decode happens before any binding. Its cost is bounded by the 61,402-byte payload and is not charged on the ledger ("Memory").

### Dispatch with the pairing surfaces

Step 1 is shared with the pairing surfaces (`spec/pairing-v1.md`, "Producer processing order"): the exact key set chooses Pair claim, Pair status, Grant status or the Peer request, and only then does the 4,096-byte cap apply, to the three pairing surfaces only. A Peer request between 4,097 and 61,402 bytes therefore reaches this path. The four key sets are pairwise distinct (`spec/v1.md`).

## Refusal codes

When step 3 refuses, the code comes from the same function Grant status uses (`pairing::grant_status_of`), which reads only the grant's own fields and the state's counters, never the request:

| `grant_status_of` | Code |
|---|---|
| `expired` | 3 `expired` |
| `revoked` | 4 `revoked` |
| `active` (so the request's `authEpoch`, `sourceScopeGeneration` or `endpoint` is what failed), `busy` (clock anomaly), or an unreadable OS clock | 2 `unauthorized` |

So a revocation of another grant, which renumbers this grant's `authEpoch`, makes a request with the old epoch `unauthorized`, not `revoked`. The receiver learns the new epoch from Grant status. The snapshot used is the one from step 2; a commit between that snapshot and step 3 can only turn a 3 or 4 into a 2.

When the code is 3 and the stored grant is still `active`, the producer also commits the frozen `expire_one(grantId, effectiveNow × 1000)` through `StateStore::transition`. A failure of that commit does not change the answer. With the expiry stored, a later OS clock moved back (even past the anomaly limit) still answers 3 from the stored state.

## Limits

Per grant, after steps 2–4, so only an authorized, valid request is counted. The table is keyed by grant ID, on the producer's injectable monotonic clock:

- At most one request in flight per grant. It is in flight from step 5 until its response ends: the source call and every chunk.
- A token bucket: 2 tokens, plus 1 for every 60 s, up to 2. A request refused at this step takes none. One admitted here takes one, and keeps it spent if a later step refuses it (`busy` for the compute slot or the ledger, `internal` for the source).
- A bucket that is full and not in flight is removed at the next admission, so the table holds only grants used recently.

## Report source

```rust
trait ReportSource: Send + Sync {
    fn report(&self, request: &ReportRequest, deadline: Instant) -> Result<Vec<u8>, SourceError>;
}
```

The source returns the canonical `ReportResponse` body for the request's endpoint. The producer does not decode or validate it; the receiver validates the echo. `NoSource`, used until `SA-2B3`, always fails, so every authorized request is `internal`.

- **Compute slot.** One per `Reports` value, with no queue: a second request while the source runs is `busy`. The listener holds one `Reports`, and the agent runs one listener per process, so in the product that is one computation per process. The slot is released only when the source call returns, however late.
- **Deadline.** 120 s on the producer's injectable monotonic clock, measured from just before the call. The source gets the same deadline as an `Instant` and must keep to it itself: nothing interrupts it. A result returned at or after the deadline is discarded and answered `internal`.

## Memory

| What | Ledger |
|---|---|
| The request frame | Charged: `Session::receive` reserves 3 × the declared ciphertext length before reading it. The reservation is returned once the request has been parsed |
| The JSON values and the typed `ReportRequest` built in step 1 (and, for a pairing surface, the values built before the 4,096-byte cap is applied) | Not charged. Bounded by the 61,402-byte payload and the listener's 8-connection cap |
| The body while the source builds it | Not charged. The source is local code (`SA-2B3`) and must bound itself; a body over 16 MiB is refused after it exists |
| The body from step 7 until the response ends | Charged: its length, reserved before the first chunk and returned when the response ends or stops, on every path |
| Per-chunk buffers: the chunk payload copy, its encoded plaintext and its ciphertext (each at most about 61.5 KB, one chunk at a time per connection) | Not charged |
| Error frames | Not charged |

## Chunks and revocation

The body is split into chunks of at most `FRAME_PAYLOAD_MAX` bytes, 1 to 274 chunks, all with the request's `requestId`, `chunkCount` the number of chunks, `chunkIndex` in order and `final` set on the last. The client reassembles them with the frozen `assemble_response`.

Every chunk is authorized again. `StateStore::authorize_then(query, f)` evaluates the frozen predicate against the current durable state under the store's shared lock and, only if it holds, calls `f` while still holding that lock; `f` writes the chunk (`Session::send`). The query is the admission query with the OS wall clock read again for this chunk, so an expiry reached during the response also stops it. If the predicate fails, or the write fails or times out, the producer stops and closes the connection without an error frame.

**Turnstile.** The store has a second mutex, the turnstile. A commit takes it before it asks for the state exclusively and holds it until the in-memory swap. `authorize_then` takes it before taking the shared lock and releases it once the shared lock is held, before calling `f`. So once a commit is waiting, no new authorization starts, and the commit waits only for the `f` calls already running. This gives writer preference on every platform; it does not rely on `std::sync::RwLock`, which does not guarantee it (on macOS its queue-based lock lets readers slip past a waiting writer, measured in `SA-2B2b1`). Lock order: the commit mutex, then the turnstile, then the state lock. `f` must take no lock of the store, `state()` included: a waiting commit holds the turnstile and waits for `f`.

**Claim.** After a commit that ends authorization (revoke, disable, source change, reset, uninstall, or an expiry commit) holds the turnstile and the state lock, no chunk `send` call starts on any connection: the next chunk's authorization reads the new state. Such a commit waits only for the `send` calls already running, each bounded by its 2 s chunk deadline, so a revoke waits at most about one chunk's deadline for report traffic. (`state()` reads do not pass through the turnstile; each holds the shared lock only to copy the state.)

**Non-claim.** The claim is about `send` calls. Bytes the kernel accepted from a `send` that returned before the commit may still reach the receiver after the commit returns.

| Deadline | Value |
|---|---|
| Each chunk's write | 2 s, or less if the response deadline is nearer |
| The whole response, from the first chunk | 15 s |
| An error frame | 15 s (`spec/pairing-v1.md`, "Write the reply") |

A client that stops reading makes a chunk's write time out after at most 2 s; the producer then closes and returns the body's reservation.

## Acceptance map

| Acceptance | Test |
|---|---|
| (1) four endpoints, a multi-chunk body, client decode with the frozen functions | `four_endpoints_are_served_and_decode_to_the_stub_records` |
| (2) five `unauthorized` causes, identical payloads | `five_unauthorized_causes_send_byte_identical_payloads` |
| (3) a foreign static on a revoked grant | `a_foreign_static_on_a_revoked_grant_is_unauthorized` |
| (4) revoke, disable, source change, expiry | `revoke_disable_and_source_change_are_revoked_and_expiry_is_expired` |
| (5) a revocation of another grant | `revoking_another_grant_leaves_a_stale_epoch_unauthorized_not_revoked` |
| (6) a revoke during a response | unit `a_revoke_during_a_response_stops_it_after_the_chunk_in_flight` (a test-only seam around `send`) |
| (7) a client that stops reading | `a_client_that_stops_reading_is_dropped_after_one_chunk_deadline` |
| (8) per-grant limit | `the_grant_limit_is_two_then_one_a_minute_and_one_in_flight`, unit `the_grant_limit_allows_a_burst_of_two_then_one_a_minute` |
| (9) compute slot and deadline | `the_compute_slot_is_held_until_the_source_returns`, unit `the_compute_slot_admits_one_at_a_time` |
| (10) source failures, a full ledger, the ledger baseline | `source_failures_are_internal_and_a_full_ledger_is_busy` |
| (11) `requestId`, `validate`, the 4,096-byte cap per surface | `malformed_report_requests_are_invalid_and_only_pairing_is_capped_at_4096` |
| (12) `authorize_then` and the turnstile | `authorize_then_skips_a_refused_query_and_a_revoke_is_not_starved` (timing: a revoke against two readers taking turns); unit `state_store::tests::disk::a_commit_holds_the_turnstile_and_authorize_then_waits_for_it` (deterministic: each half of the turnstile) |
| (13) expiry then a clock moved back | `after_expiry_a_clock_moved_back_is_still_expired` |

The tests that need a secure root run on macOS and Linux; the unit tests of the limit, the slot and the code numbering run on all three platforms.
