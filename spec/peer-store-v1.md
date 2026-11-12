# Syrtis Agent Receiver Peer Store v1

## Purpose and boundary

This document fixes how a receiver stores the producers it has paired with: the file `peers.json`, its bytes, how it is validated on load and on write, how it is replaced, and when a record may be written or used. It does not define keys. The two key sets are frozen by `spec/v1.md` (rows "Receiver peer store top level" and "Receiver peer record") and this store adds none. Implementation: `src/peer_store.rs`; acceptance: `tests/runtime_peer_store_v1.rs` (the grant guards: `grant_guards_refuse_stale_writes_and_leave_the_file_alone`) and the unit tests in `src/peer_store.rs`.

> A peer record grants the receiver nothing. Every request the receiver makes is still authorized by the producer, against the producer's own grant and the Noise static binding (`spec/pairing-v1.md`, `spec/v1.md` (i)). A record only tells the receiver where to connect and which grant to name.

Not in this slice: polling Grant status in the background, and clearing the receiver cache on `revoked` or `expired` (`SA-2B3`).

## Root and lock

`peers.json` lives in the same secure root as `state.json` (`spec/state-store-v1.md`), under the same `owner.lock`. The state store opens the root and hands it out with `StateStore::root()`; the peer store is opened on that same root (`PeerStore::open(store.root())`), so no second lock exists and a second process opening the root gets `busy` while either store is open. A peer store keeps the root, and so the lock, open after the state store that gave it out is dropped. One peer store per root.

| Name | Purpose |
|---|---|
| `peers.json` | The receiver's peer list |
| `.peers.json.tmp` | Commit temp file. Present only during a commit or after a crash; removed on open |

Reads and writes use the root's agent-file rules unchanged (`read_file`, `stage` then `publish`, `remove_stale_temp`). The read bound is 1 MiB; sixteen records stay far below it.

## Encoding

`peers.json` is one CanonicalJsonV1 object (`src/canonical.rs`), no trailing newline: `{peers, schema}` with `schema` the integer `1` and `peers` an array of records with exactly the keys of the "Receiver peer record" row.

| Value | Encoding |
|---|---|
| `schema` | Integer `1` |
| `grantId`, `pendingId` | Lowercase hex, 16 bytes |
| `initiatorStatic`, `responderStatic` | Lowercase hex, 32 bytes |
| `authEpoch`, `sourceScopeGeneration` | Unsigned integer |
| `createdAt` | Unix milliseconds on the receiver's wall clock, signed integer |
| `expiresAt` | Unix milliseconds on the producer's wall clock (from Grant status), signed integer |
| `host` | String: the host of the claimed Pair URL |
| `port` | Integer: the port of the claimed Pair URL |
| `nodeLabel` | The receiver's own label for the producer: a string of at most 128 bytes, NFC, or `null` |
| `state` | `active`, `revoked` or `expired` |

Every field other than `nodeLabel` is required and never `null`. `peers` is sorted by `responderStatic`, holds at most one record per `responderStatic`, and at most 16 records.

## Load

Load fails closed. An absent `peers.json` is an empty list, and opening does not create the file.

| Condition | Error |
|---|---|
| `schema` an integer other than 1 | `incompatible` |
| Over 1 MiB; not CanonicalJsonV1 (including a non-NFC string); `schema` missing or not an integer; a missing, unknown or `null` required key; a value of the wrong type or range (for example `port` above 65535 or a `state` outside the three) | `corrupt` |
| More than 16 records; `responderStatic` not strictly increasing (unsorted or repeated) | `corrupt` |
| An ID or static whose hex is not lowercase or not the exact length | `corrupt` |
| `host` and `port` refused by the frozen Pair URL rule (canonical host, port at least 1024), checked through the public `pair_url` rather than a second copy of the rule | `corrupt` |
| `nodeLabel` over 128 bytes | `corrupt` |

`expiresAt` is not compared with `createdAt`: the first is the producer's clock and the second the receiver's, and they cannot be compared.

## Writes

Every write builds the next list, encodes it, and runs those bytes through the load decoder before staging them: the store never writes a file that load would refuse. A write load would refuse is `refused(invalid)` and writes nothing; it is a caller error, so the store does not become unknown. So is a guard refusal (`refused(conflict)` below). A write that leaves the list unchanged writes nothing.

A caller recording what a producer answered names the record by the `responderStatic` and `grantId` of the record it asked with, never by bytes of the answer (`spec/report-peer-v1.md`, "Receiver").

| Operation | Rule |
|---|---|
| `upsert(record)` | Only an `active` record. A record for a `responderStatic` already present replaces it (re-pairing) when its `authEpoch` is equal or higher; a lower one is `refused(conflict)`, so a stale answer cannot overwrite a newer pairing. A new one is inserted in order. A 17th distinct producer is `refused(bounds)`. Anything else load would refuse (an over-long or non-NFC `nodeLabel`, a non-canonical `host`, a `port` below 1024) is `refused(invalid)` |
| `set_state(responderStatic, grantId, state)` | `revoked` or `expired` only; `active` comes only from `upsert`. An unknown producer is `refused(invalid)`; a record holding another `grantId` (the producer was paired again since) is `refused(conflict)` |
| `update_grant(responderStatic, grantId, authEpoch, sourceScopeGeneration, expiresAt)` | Stores what Grant status answered `active`. Only the record holding `grantId` and still `active`, and never to a lower `authEpoch` (equal is allowed); otherwise `refused(conflict)`. An unknown producer is `refused(invalid)` |
| `remove(responderStatic)` | Removes that producer's record; an absent one is not an error |
| `peers()` | A snapshot, sorted by `responderStatic` |

A commit follows the state store: one commit mutex serializes writers; the in-memory list changes only after `publish` returns, while the writer holds the list exclusively; any failure while staging or publishing makes the store sticky `unknown` (every later read and write is `unknown`) until it is reopened. A reopen after such a failure reads the old list or the new one: a failure before the rename leaves the old file, a failure after it the new one.

## When a record is written

Only from a `ConfirmedGrant`, which the receiver client returns only when Grant status answered `active` (`spec/pairing-v1.md`): `PeerRecord::from_confirmed(grant, nodeLabel, createdAt)` takes the grant ID, `authEpoch`, `sourceScopeGeneration`, `expiresAt`, `pendingId`, `responderStatic`, `initiatorStatic`, `host` and `port` from the grant; `poll` carries `host` and `port` into the grant from the claim (the Pair URL's). Grant status `revoked` or `expired` is recorded with `set_state`, a later `active` answer with `update_grant`.

## When a record is usable

`usable(record, stateStore)` is true only when the record is `active` and its `initiatorStatic` equals the identity in `state.json` as read at that call. The identity is read from the state store on every call, never cached, so after a reset (which replaces the identity) every earlier record is unusable, whether or not it is rewritten. An unreadable state is unusable. A reset does not change `peers.json`.

## Non-claims

- `peers.json` holds no secret: no bearer secret, Pair URL, SAS or private key. It is protected like `state.json` (owner-only, no-follow, exclusive lock, atomic replace) against other local UIDs and partial writes, not against the owner.
- A record does not authorize anything, and `active` here is the last Grant status the receiver saw, not the producer's current answer.
- A power loss during a commit leaves the old list or the new one, by the root's commit sequence (`spec/state-store-v1.md`); this is not observable in a test beyond the injected step failures above.
