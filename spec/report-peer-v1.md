# Syrtis Agent Peer Report Transport v1

## Purpose and boundary

This document fixes how the producer answers a Peer request on the peer wire (dispatch, the static binding, authorization, the error codes, limits, the report source seam, memory accounting, and how a response is sent in chunks while revocation stays effective) and how the receiver asks for one and checks the reply (section "Receiver"). The Peer request and response field sets, value rules and obligations (i)–(iii) are frozen by `spec/v1.md`, and the request and response codecs by `spec/report-cache-v1.md` and `src/report.rs`; this document adds none. Transport (Noise IK, frames, deadlines) and the product listener are in `spec/pairing-v1.md`; the receiver's peer records in `spec/peer-store-v1.md`. Implementation: `src/report_peer.rs`, the dispatch in `src/pairing.rs`, and `StateStore::authorize_then` in `src/state_store.rs`. Acceptance: `tests/runtime_report_v1.rs`, `tests/runtime_report_memory_v1.rs` and the unit tests in `src/report_peer.rs`.

Not in this slice: the real report source and cache, and charging a fetched report while it is kept (`SA-2B3`); checkpoint and sweep scheduling (`SA-2B2c`); background polling, automatic retry and UI.

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

## Receiver

`report_peer::fetch(peer, query, stateStore, ledger, limiter)` asks the producer named by one peer record for one report and returns `Fetched { body, records, saturated }`, the records typed by the endpoint asked for. The producer is untrusted for framing, size and content. `fetch` never retries, never polls in the background and writes no cache and no log.

`query` is the endpoint, `startDate`, `endDateExclusive`, `timezone` and `clients`. Everything else in the Peer request comes from the record (`grantId`, `authEpoch`, `sourceScopeGeneration`) or is a protocol constant; `requestId` is 16 random bytes, the same in the payload and in the frame header.

| Step | Check | Failure |
|---|---|---|
| 1 | `ReportRequest::validate` on the request built from the record and the query | `InvalidQuery`; nothing is sent |
| 2 | `peer_store::usable(record, stateStore)`, and the identity read again for the handshake equals the record's `initiatorStatic` (a reset between the two reads must not send under an identity the record is not bound to) | `Unusable`; nothing is sent |
| 3 | A slot of the `FetchLimiter`: at most 2 fetches at once per limiter, no queue. The agent shares one per process | `TooMany`; nothing is sent |
| 4 | Connect and handshake, `responderStatic` pinned (`noise::connect`) | `Transport` |
| 5 | Send the request, then read the reply. One absolute deadline covers both: 135 s (the producer's 120 s compute deadline plus its 15 s response deadline) from the end of the handshake, never extended by progress | `Timeout` |
| 6 | First frame: its `requestId` is the one sent; kind Error is mapped below; kind Request is a violation; kind Response must have `chunkIndex` 0. The frozen `Frame::decode` already holds every Response frame to `chunkCount` 1..=274 and `final` to the last index | `Protocol` |
| 7 | Reserve `chunkCount × 61,402` on the ledger before keeping any chunk; the body is then allocated once at that capacity and never grows | `Memory`, and no later chunk is read |
| 8 | Each later chunk: kind Response, the same `requestId`, the same `chunkCount`, the next `chunkIndex`, and the total at most 16,777,216 bytes. Chunks are checked one by one with the rules of the frozen `assemble_response`, which is not called (it would copy the body again) | `Protocol` |
| 9 | The shape gate and counts ("Before decoding") | `Invalid` |
| 10 | Reserve the decode cost ("Before decoding") | `Memory` |
| 11 | The frozen `decode_response(body, Some(request))`: CanonicalJsonV1, the typed decode, and `validate` against the request this receiver sent (echo fields, endpoint, records) | `Invalid` |

Any failure discards everything received and returns every reservation. Errors carry no bytes from the producer.

| Error frame `{code, protocol}` | `FetchError` |
|---|---|
| 3 | `Expired` |
| 4 | `Revoked` |
| 2 | `CheckGrantStatus`: the grant may be fine and the record stale (a revocation of another grant renumbers `authEpoch`). The caller asks Grant status (`PairingClient::grant_status`) and stores its answer with `PeerStore::update_grant` |
| 5 | `Busy`. The producer answers `busy` after its rate step too, with a token already spent (section "Limits"), so the caller must not retry at once: not before 60 s |
| 8 | `Internal` |
| 1, 6 | `Rejected` |
| Another code, `protocol` other than 1, or a payload that is not a CanonicalJsonV1 `{code, protocol}` | `Protocol` |

**Which record.** Nothing in the reply chooses the type, the endpoint or the record: the reply is checked against the request this receiver built. A caller that updates `peers.json` after a fetch (`set_state`, `update_grant`) names the record by the `responderStatic` and `grantId` of the record it fetched with, never by bytes of the reply. `PeerStore` refuses a write naming another `grantId` (`spec/peer-store-v1.md`).

### Before decoding

The frozen decoder builds a `serde_json` value tree (objects are `BTreeMap<String, Value>`: `serde_json` is built without `preserve_order`), converts it to the typed response, then builds a second tree when it re-encodes the typed value to check canonical form. Those allocations are reserved before it runs (`spec/security-v1.md`, the remote-memory ledger), from one pass over the body that allocates nothing (`report_peer::scan`). The pass does two things.

**Shape gate.** It refuses, before any tree is built, the structures the typed decode or `validate` refuses anyway, and it replaces none of the decoder's checks, which all still run in step 11. Two limits come on top and are the receiver's own: the decoder would accept a body over them (only the 8 MiB one can be reached within 16 MiB).

- No whitespace and nothing after the top-level value (CanonicalJsonV1 has neither).
- The top level is an object whose keys are exactly the 15 response keys, in canonical order, written without escapes.
- `clients` is an array of at most 128 strings. `records` is an array of objects, each with exactly the endpoint's record keys in canonical order, and each value a string, an integer or `null`.
- Every other top-level value is a string, an integer, `true`, `false` or `null`. No other array or object appears anywhere (depth at most 3).
- An integer has at most 20 digits; a fraction or exponent (a float) is refused.
- Every string, key or value, is at most 255 bytes once decoded (no valid response holds a longer one), has no raw control character, no unknown escape and no unpaired surrogate escape. This also bounds the decoder's escape scratch buffer and the NFC checks' buffers.
- Receiver limits: at most 262,144 `records` (unreachable: the smallest record takes over 200 bytes, so 16 MiB holds fewer than 84,000), and the value strings together at most 8 MiB decoded (keys are not counted here; they are in the cost).

**Counts.** Objects, entries (keys) and the keys' decoded bytes, value strings and their decoded bytes, every value, array elements and records, with decoded lengths computed as `serde_json` decodes (`\uXXXX` by its UTF-8 length, a surrogate pair as 4 bytes). A unit test checks these counts equal the counts of the tree `serde_json` builds from the same bytes, escapes included.

**Cost.** Checked arithmetic, one term per allocation class, each allocation rounded up to 16 bytes:

| Term | Bytes |
|---|---|
| Object nodes, per object | `std`'s B-tree holds 11 entries per node. A leaf is `16 + 11 × (size_of String + size_of Value)` and an internal node a leaf plus 12 edge pointers, each rounded up to 16 (640 and 736 on 64-bit). 1–11 entries: one leaf. 12–17 entries: two leaves and one internal node, whether the map is built by insertion (the second tree) or in bulk (the first): after the split at 12 each leaf holds at least 5, so neither can split again before 18. The gate admits only 13–15 |
| Strings | Each key and each value string: its decoded length rounded up to 16, bounded as `bytes + 15 × count` |
| Value slots | `size_of Value` for the top-level value and twice for each array element (`Vec` growth); map values live inside the nodes |
| One tree | nodes + strings + value slots |
| Trees | two (the first tree and the re-encoded second) |
| Typed records | `2 × records × size_of R` (`Vec` growth) |
| Re-encoding buffer | `3 × body length` (doubling growth, and the old and new buffer while it grows) |
| Slack | 64 KiB: the scratch and NFC buffers of strings at most 255 bytes, the `clients` vectors, the request copy `validate` makes, error text |

The bound is checked by measurement, not only argued: `tests/runtime_report_memory_v1.rs` installs a counting global allocator (std only; it charges each allocation rounded up to 16 and counts a growing `Vec`'s old and new buffers at once) and asserts, for each body shape, that the decoder's real peak is at most the reservation. Measured (macOS, `SA-2B2b2`):

| Body | Records | Decoder peak | Reservation |
|---|---|---|---|
| graph, smallest records, 16 MiB | 74,233 | 204.2 MiB | 419.6 MiB |
| models, smallest records, 16 MiB | 65,279 | 184.4 MiB | 379.4 MiB |
| hourly, smallest records, 16 MiB | 65,534 | 185.0 MiB | 376.8 MiB |
| agents, smallest records, 16 MiB | 76,958 | 210.3 MiB | 432.1 MiB |
| agents, every string 255 bytes, just over 8 MiB | 6,837 | 54.1 MiB | 71.8 MiB |
| agents, every string 255 bytes, at the 8 MiB string limit (9.6 MiB) | 8,224 | 59.8 MiB | 86.3 MiB |

### Receiver memory

| What | Ledger |
|---|---|
| Each received frame | Charged: `Session::receive` reserves 3 × the declared ciphertext length; returned once the frame is copied |
| The body | Charged: `chunkCount × 61,402`, reserved at the first chunk before any is kept, held until `fetch` returns |
| The decoder | Charged: the decode cost above, reserved before the decoder runs, held until `fetch` returns |
| The request this receiver encodes and sends | Not charged: at most 61,402 bytes, built from local input |
| An error frame's payload decode | Not charged: the payload is at most 4,096 bytes (`ERROR_PAYLOAD_MAX`) |
| The returned `Fetched` | Not charged once returned; keeping it is `SA-2B3`'s (cache accounting) |

### Receiver non-claims

- The ledger is an accounting model: an allocation is charged at its size rounded up to 16 bytes. Allocator headers and fragmentation are not modelled.
- A body whose reservations do not fit the free ledger is refused with `Memory`, so a large legitimate body can fail while the ledger is busy. With the cost above, a body near 16 MiB of the smallest records needs 377–432 MiB besides its 16.8 MiB body reservation, more than the 384 MiB ledger, and is refused even when nothing else holds the ledger; the measured decoder peak for those bodies is 184–210 MiB.
- The node sizes follow `std`'s B-tree layout (11 entries per node). The measurement test is the guard on each toolchain CI runs; it is not re-derived at run time.
- `Fetched` is returned outside the ledger.

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

Receiver (`SA-2B2b2`):

| Acceptance | Test |
|---|---|
| (1) pair, then fetch the four endpoints, one in several chunks | `fetch_returns_the_stub_records_for_all_four_endpoints`; unit `a_multi_chunk_reply_decodes_to_the_producers_records` |
| (2) `Revoked`, `Expired`, `CheckGrantStatus` then Grant status and `update_grant` | `fetch_reports_revoked_expired_and_a_stale_epoch` |
| (3) hostile framing | unit `hostile_framing_is_refused_and_the_ledger_returns_to_baseline`, `error_codes_map_to_their_variants` |
| (4) echo mismatch | unit `a_body_echoing_another_request_is_invalid` |
| (5) memory: gate, limits, reservations, differential, measured bound | unit `the_shape_gate_refuses_before_reserving_or_decoding`, `the_scanner_limits_records_strings_and_clients`, `scanner_counts_equal_what_serde_json_decodes`, `the_gate_key_lists_are_the_typed_keys`, `a_full_ledger_stops_the_fetch_at_the_first_chunk`, `the_decode_cost_is_reserved_before_the_decoder_runs`, `two_large_pulls_at_once_the_second_is_refused_by_the_ledger`; `tests/runtime_report_memory_v1.rs` `the_reservation_bounds_the_decoders_measured_peak` |
| (6) at most two fetches at once | `a_third_fetch_at_once_is_refused_without_connecting`; unit `the_fetch_limiter_admits_two_at_once` |
| (7) nothing sent for an unusable record or a bad query | `unusable_records_and_bad_queries_never_connect` |
| (8) the absolute deadline | unit `the_fetch_deadline_is_absolute` (a shortened deadline: a silent producer, and chunks 300 ms apart that together outlast it) |
| (9) `peer_store` guards | `spec/peer-store-v1.md` |

The tests that need a secure root run on macOS and Linux; the unit tests of the limit, the slot and the code numbering, the receiver unit tests (a scripted producer that completes a real handshake, then writes any frame) and the memory measurement run on all three platforms.
