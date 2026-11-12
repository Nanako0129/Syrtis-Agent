# Syrtis Agent Pairing Wire v1

## Purpose and boundary

This document fixes how two agents pair over the peer wire: the Noise transport, the derivation of pairing IDs, how the producer answers Pair claim, Pair status and Grant status, how the owner approves, and how the receiver claims, polls and confirms a grant. Field sets, value rules and obligations (i)–(iii) are frozen by `spec/v1.md` ("Surface field registry" and "Peer wire obligations"); this document adds none. Implementation: `src/noise.rs` and `src/pairing.rs`; acceptance: `tests/runtime_pairing_v1.rs` and the unit tests in both files.

Not in this slice: the product listener and its bind rules and the handshake concurrency cap (`SA-2B2a3`); the peer report path (`SA-2B2b`); the control command that calls approval, and the disable half of F-7 (`SA-2B2c`). The receiver client returns what it confirmed and stores nothing; its caller stores a confirmed grant in the receiver peer store (`spec/peer-store-v1.md`).

> Grant status is advisory. It releases no byte, and no admission decision may be taken from it: the report path authorizes through `StateStore::authorize` only.

## Connection and handshake

One TCP connection carries one handshake, one request frame and one reply frame (a response or an error), then closes.

| Item | Value |
|---|---|
| Suite | `Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `syrtis-peer-v1\0` (`spec/security-v1.md`) |
| Implementation | `snow` `0.10.0` only |
| Initiator | The receiver; pins the Pair URL's `responderStatic` as the remote static |
| Initiator connect | The host is resolved first (`getaddrinfo`); resolution is not bounded by the handshake deadline, because std offers no way to bound it. Each resolved address is then tried in order, all under the one 10 s connect-plus-handshake deadline; each address's connect gets the time left divided by the number of addresses not yet tried, so an unresponsive first address cannot take the whole deadline. Once a TCP connection is up, a handshake failure (the pinned static among its causes) ends the attempt: no other address is tried |
| Blocking mode | The responder puts an accepted stream in blocking mode before the handshake, whatever it inherited from the listener (this differs by OS), so a deadline loop waits instead of spinning. The initiator's stream comes from `TcpStream::connect_timeout` and is used as returned; a unit test in `src/noise.rs` checks that its handshake read waits rather than spins |
| Responder identity | The agent identity in `state.json`, read once by the caller before serving; a handshake reads and writes no state |
| Message 1 on the wire | `u32be(96) ‖ 96 bytes` (`e` 32, encrypted `s` 48, tag 16; empty payload) |
| Message 2 on the wire | `u32be(48) ‖ 48 bytes` (`e` 32, tag 16; empty payload) |
| Wrong length prefix | Connection closed at once: no body byte is read and nothing is written |
| Non-empty handshake payload | Refused. Under exact framing it cannot arrive (the length leaves room only for the tag), so this check is defense in depth; a unit test feeds a longer message to the read helper directly |
| After the handshake | `hFinal` is the handshake hash; the initiator identity is the Noise remote static, and nothing else |

Every read and write runs against an absolute monotonic deadline. Each system call gets only the time left, so a peer that sends partial bytes cannot extend it.

| Deadline | Initiator (receiver) | Responder (producer) |
|---|---:|---:|
| Connect plus handshake | 10 s | 10 s (handshake) |
| Write the request | 10 s | — |
| Read the request | — | 10 s |
| Write the reply | — | 15 s |
| Read the reply | 15 s | — |

## Transport frames and memory

Each transport message is the frozen `u32be(ciphertextLen) ‖ NoiseCiphertext` (`security::encode_outer` / `decode_outer`), decrypted and decoded with the frozen `Frame::decode`. The receiving side reads the 4-byte length, refuses a length above `FRAME_CIPHERTEXT_MAX` (61,456), then reserves 3 × the declared length on the process memory ledger (ciphertext, plaintext and the decoded payload copy) before allocating or reading anything. The reservation is held while the frame is processed and returned when it is dropped, on every path.

A length, ledger, decryption or `Frame::decode` failure closes the connection without sending a frame: no request ID has been authenticated to answer. The producer does nothing with state, and counts nothing, until the first transport frame has decrypted and decoded (F-6), so a replayed message 1 reaches no state.

## Derivations

| Value | Definition |
|---|---|
| `secretHash` | `offer_secret_hash(offerId, presentedSecret, ownStatic)` (`spec/security-v1.md`), computed from the secret presented in the request, never looked up |
| `pendingId` | `SHA-256("syrtis-pair-pending-v1\0" ‖ secretHash ‖ hFinal)[..16]` |
| `grantId` | `SHA-256("syrtis-pair-grant-v1\0" ‖ pendingId)[..16]` |
| `sasGeneration` | Always `1`: v1 never re-issues a SAS |
| SAS | The frozen `pair_sas(1, offerId, responderStatic, initiatorStatic, hFinal)`, computed by each side from its own connection |
| Grant lifetime | 30 days from the effective now of the approval |

The pending ID passed to the frozen claim is the one derived on the connection that carries the claim. A retry by the same initiator gets, from the frozen claim, the ID of the first attempt whose claim was committed, so the receiver keeps the derived ID and SAS of each attempt that may still be answered (the record rule under "Receiver client") and shows the SAS whose ID came back.

## Threat model and non-claims

The handshake hash is public to anyone who knows `responderStatic` and saw the handshake (Noise §15.2), so `hFinal` alone must not determine an ID. `secretHash` is the value mixed in for that: only the producer and holders of this offer's Pair URL can compute it, because only they know the bearer secret. The secret itself appears only in the transport-phase Pair claim request.

Non-claims:

- A holder of the same Pair URL who also observes the handshake can compute that connection's pending and grant IDs. With them it gains only response-time differences, since every refusal is the same `unauthorized` payload.
- A change of a grant's `authEpoch` or `sourceScopeGeneration` in Grant status tells its receiver that another grant was revoked or the source scope changed (F-6).
- The rate-limit table can be filled by a LAN attacker who generates a new static key per handshake, which refuses new pairing requests with `busy` while it lasts. This is availability only: a Pair claim answered `busy` was refused before any state was read (a store `Busy` on Pair claim is sent as `internal`), so the receiver drops that attempt's record and a filled table does not use up an offer's records.
- The frozen claim refuses a full record table as `unauthorized`, indistinguishable from the other causes; the receiver never infers why an offer was refused.
- An offer keeps at most 5 attempt records on the receiver. Only `internal` and a transport failure after the handshake keep a record, one per claim call, so an on-path attacker who resets each connection after the handshake, or a producer that keeps answering `internal`, can fill all five. A full table does not stop the receiver from connecting: a reply that names a kept record or the connection's own pending ID still succeeds. But a connection made with all five in use has no record, so if its successful reply is lost after the producer committed it, every later claim of that offer is answered with that connection's pending ID, matches nothing and ends as a lost attempt; the owner must reject that pending request and create a new offer. This affects availability only.
- The Pair URL carries the bearer secret. The receiver client takes it only as a string argument, parses it with the frozen `parse_pair_url`, and never formats, logs or returns it, nor the parsed `PairOffer` (whose derived `Debug` prints the secret); it is not stored, and `peers.json` holds no secret.
- A low-order (small-subgroup) remote static key is not rejected. Binding a pairing to it still needs the Pair URL's bearer secret and the owner's SAS check.
- The producer's identity is read once by its caller, not per handshake, so a handshake touches no state. Obligation on `SA-2B2a3` and `SA-2B2c`, not enforced or tested here: after a reset, creating offers, serving handshakes and approving must all use the same, current identity. On the receiver side, a stored peer record is usable only while its `initiatorStatic` equals the identity read from `state.json` at the time of use (`spec/peer-store-v1.md`).

## Producer processing order

| Step | Check | Failure |
|---|---|---|
| 1 | Handshake and frame (above) | Close, no frame |
| 2 | Frame kind is Request; payload ≤ 4,096 bytes; CanonicalJsonV1; exact key set dispatches to Pair claim, Pair status or Grant status; `protocol` is an integer equal to `1`; typed decode | `invalid`; an integer `protocol` other than `1` is `incompatible`. The Peer request key set is `invalid` here (F-10) |
| 3 | Rate limit keyed by the Noise remote static | `busy` |
| 4 | The remote static is not this agent's own | `unauthorized` |
| 5 | The surface (below), including sharing and the static binding | Per surface |

Steps 1–4 read no state and depend on no ID. This order deliberately differs from the peer report path, where authorization precedes rate limiting: a pairing request is itself the authorization attempt, so there is nothing to authorize first. Keying the limit on the authenticated static, before any state lookup, makes `busy` independent of whether an ID exists and of `sharingEnabled`.

## Rate limit

One table for all three pairing surfaces: per remote static, the monotonic time its last request was admitted. Before each check, every entry at least 1 s old is removed. A static admitted less than 1 s ago is `busy`; a new static while the table holds 256 entries is `busy`. Only an admission stores a time: a `busy` answer does not move it. The monotonic clock is injectable.

## Surfaces

### Pair claim

One `StateStore::transition` whose closure first refuses (`unauthorized`, nothing written) when `sharingEnabled` is false, then calls the frozen `claim_offer`. The sharing check is inside the closure, so a disable committed after any earlier read still refuses the claim. `OfferClaim` is built only inside that closure. Every frozen refusal (wrong secret, unknown, expired or consumed offer, full table, clock anomaly) is the same `unauthorized` and commits nothing. A commit failure (`Refused(Invalid)`, sticky `unknown`) answers by the error map (with the Pair claim exception under "Error codes") and never sends the claim response. The response `{expiresAt, pendingId, protocol}` is sent only after `transition` returns success, with `expiresAt` the pending's expiry and `pendingId` the one the frozen claim returned.

### Pair status

Answered from one `StateStore::state()` snapshot, in this order:

1. `sharingEnabled` false: `unauthorized`.
2. No pending with that ID, or the remote static is not `pending.initiatorStatic`: `unauthorized`, the same payload.
3. By stored state. Only `awaitingApproval` needs the clock, and it is read only after the binding, so only the bound static can see `busy`; the other states are answered even when the clock is anomalous or cannot be read:

| Stored | Condition | Wire |
|---|---|---|
| `awaitingApproval` | clock anomaly (frozen `clock_status`) | `busy` (error) |
| `awaitingApproval` | OS wall clock unreadable | the OS clock error, by the error map (`internal`) |
| `awaitingApproval` | effective now ≥ `expiresAt` | `expired` (no sweep needed) |
| `awaitingApproval` | otherwise | `awaiting` |
| `rejected` | — | `rejected` |
| `expired` | — | `expired` |
| `approved` | grant `derive(pendingId)` exists | approved shape, fields from that grant as it is now, whether or not the pending has since expired (F-8) |
| `approved` | grant absent | `expired` (unreachable under the frozen transitions; kept fail-closed) |

`awaiting` is the wire name of the stored `awaitingApproval`; a named test pins it.

### Grant status

Answered from one snapshot. Sharing being off does not refuse it: the bound static must learn `revoked` explicitly (F-5). No grant with that ID, or a remote static other than `grant.initiatorStatic`: `unauthorized`, the same payload. Then:

| Clock | Condition | `state` |
|---|---|---|
| Anomaly or unreadable | `grant.state` revoked, sharing off, `authEpoch ≤ denyFloor`, or `sourceScopeGeneration` ≠ the counter | `revoked` (none of these needs a clock) |
| Anomaly or unreadable | `grant.state` expired | `expired` |
| Anomaly | otherwise | `busy` (error) |
| Unreadable | otherwise | the OS clock error, by the error map (`internal`) |
| Sane | effective now ≥ `expiresAt`, or `grant.state` expired | `expired` |
| Sane | any revocation condition above | `revoked` |
| Sane | otherwise | `active` |

"Unreadable" is an OS wall clock that cannot be read at all. Expiry is checked before revocation on purpose: the grant is unusable either way, and expiry needs no further explanation. The fields are the grant's current values.

## Approval

`pairing::approve(store, pendingId, sasGeneration, disclosureExact, osNowSeconds)` reads this agent's static from one snapshot, derives `grantId`, sets the expiry to 30 days after the effective now, and commits the frozen `approve_pending` through `transition`. The control command that calls it is `SA-2B2c`.

## Error codes

Error payload: CanonicalJsonV1 `{code, protocol: 1}`. Each error path sends exactly one error frame and closes. The store-error map is total:

| Store error | Code |
|---|---|
| `Refused(Unauthorized)` | 2 `unauthorized` |
| `Refused(Bounds)`, `Refused(Canonical)`, `Refused(Conflict)`, `Refused(Expired)`, `Refused(Invalid)` | 8 `internal` |
| `Busy` | 5 `busy` |
| `UnsafeState`, `Unknown`, `Incompatible`, `Corrupt`, `Unavailable` | 8 `internal` |

Every one of these arises after the secret check or independently of any ID, so none is an oracle. The pairing surfaces send only 1, 2, 5, 6 and 8.

Pair claim alone sends a store `Busy` as 8 `internal`, not 5. So `busy` on Pair claim can only come from the rate limit (step 3), before any state is read, and a receiver may take it as proof that nothing was committed (see "Receiver client"). Pair status and Grant status use the map above unchanged.

## Receiver client

**Claim.** Takes the Pair URL as a string and the receiver's effective now in milliseconds, and parses it with the frozen `parse_pair_url`, which owns the whole offer validation (version 1, port ≥ 1024, the canonical host, the hex fields, the lifetime). Anything it refuses ends the call as an invalid offer before any connection; the client adds no second check of its own. The URL and the parsed offer are never formatted, logged, returned or placed in an error (the frozen `PairOffer` derives a `Debug` that prints the secret). Refuses an offer whose `responderStatic` is its own, pins `responderStatic`, and sends `{offerId, protocol, secret}`.

An attempt record maps a derived `pendingId` to its SAS, and a `pendingId` exists only once the handshake has completed (`hFinal`). An offer keeps at most 5 records. A retry against the frozen claim returns the ID of the first attempt whose claim was committed, so a record is kept while it may still be answered. The record rule:

| Event | Record |
|---|---|
| Connect or handshake failure | None is created |
| Handshake completed, fewer than 5 records | This connection's record is created, before the request is written |
| Handshake completed, 5 records | None is created; the connection goes ahead |
| Authenticated `busy`, `unauthorized`, `invalid` or `incompatible` | This connection's record, if it created one, is removed: on Pair claim each of these is sent before any commit (a store `Busy` is sent as `internal`) |
| Success whose `pendingId` matches an earlier record | This connection's record, if it created one, is removed: the offer was consumed by that earlier attempt, so the ID this connection derived is never answered |
| Success whose `pendingId` is this connection's own | Kept (if one was created) |
| `internal` | Kept: the request may have been committed |
| Transport failure after the handshake | Kept: the request may have reached the producer and been committed |
| Reply that breaks the protocol, or a success matching nothing | Kept |

A removal only ever applies to the record the same connection created; a connection that created none (all five were in use) removes nothing. No other event removes a record, and nothing is evicted to make room. A success whose `pendingId` matches a kept record returns that record's SAS; one that matches no record but equals the connection's own derived ID (possible only with all five in use) returns that connection's SAS; one that matches neither ends with "This device lost track of an earlier attempt. Ask the owner to reject the request and create a new offer." `unauthorized` ends with "This offer cannot be used. If the owner's device shows a pending request for this offer, ask the owner to reject it." (the cause is not inferred). `invalid` and `incompatible` stop.

Retries within one claim call are at least 1 s apart; a call's first try does not wait. `internal` ends the call with that code, keeping its record, so each further try is the caller's choice. A transport failure after the handshake also ends the call at once, keeping its record. An authenticated `busy` is retried within the call; after 5 `busy` answers in one claim call, the call ends with the `busy` code. A connect or handshake failure is retried without a record; after 5 of them in one claim call, the call ends with a transport error. A later call may always try again: a full record table never stops the client from connecting. A new attempt or a different offer clears only what is displayed, never the records.

**Reply checks.** The reply frame must have `chunkCount` 1, index 0, final set, and the `requestId` that was sent. Its type follows from the request that was sent and the frame kind, never from the key set; a Pair status response's shape is chosen by its `state` value. `state` is checked per surface (Pair status refuses `active`, Grant status refuses `approved`); `protocol` must be `1`; an approved `grantId` must equal `derive(pendingId)`; a Grant status `grantId` must equal the one requested; an error code outside {1, 2, 5, 6, 8} or an error frame with the wrong `requestId` or `protocol` stops the client.

**Polling.** One scheduler, one request at a time, any two requests (Pair status, then Grant status) at least 3 s apart; at most 960 s of receiver monotonic time after the successful claim (the longest offer, 900 s, plus 60 s) and at most 320 requests. The producer's `expiresAt` is shown only, never compared with the receiver's clock, so a receiver clock that disagrees with the producer's does not end polling. Stop on `approved` (then Grant status), `rejected`, `expired`, `unauthorized`, `invalid`, `incompatible` and any protocol violation; count and continue on `busy`, `internal`, transport errors and timeouts. Only Grant status `active` returns the confirmed grant `{grantId, authEpoch, sourceScopeGeneration, expiresAt, responderStatic, initiatorStatic, pendingId}`. Clocks and the sleeper are injectable.

With 3 s spacing the 960 s window allows 319 requests, so the 320 cap binds only if the clock misbehaves; a test with a clock that never advances proves it.

## Secret confinement

On the peer wire, `secret` exists only in the transport-phase Pair claim request; off the wire, the receiver gets it only inside the Pair URL its claim takes as input. Neither `secret` nor a Pair URL appears in any log (`spec/v1.md` (ii)). The pairing and Noise types hold it only as `Secret32`, whose `Debug` is redacted. The frozen `PairOffer` and `OfferClaim` derive `Debug` and would print it, as would a request `Frame` or a decrypted plaintext buffer: the pairing code never formats, logs or places any of them in an error, `OfferClaim` is built only inside the transition closure, and every pairing or Noise type that holds a frame has a hand-written redacted `Debug`. A malformed secret is refused without echoing the input. Buffers are not zeroized.

## Assigned elsewhere

- **F-7, disable half (`SA-2B2c`).** The control disable must, in one `transition` closure, combine `disable_commit` with `cancel_offer` for every active offer and `reject_pending` for every awaiting pending, designed so that disable never fails on record count (`cancel_offer` returns `Bounds` at `MAX_RECORDS`). Ordering gate: no integration or release that can enable sharing (`SA-3` onwards) may ship before that acceptance is merged, and control disable must not call the bare `StateStore::disable()`. Until then, by reading the frozen transitions (not exercised by a test here), an offer created before a disable stays claimable after a re-enable, within its lifetime of at most 15 minutes.
- **Grant status `expired` (`SA-2B3`).** A receiver must clear its cache on `expired` as it does on `revoked`, because expiry-first ordering hides a simultaneous revocation. The receiver peer store records either state for the producer (`spec/peer-store-v1.md`); clearing the cache is `SA-2B3`.
