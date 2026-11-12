# Syrtis Agent Cache Store v1

## Purpose and boundary

This document fixes how the producer and receiver report caches are stored on disk: where, in what bytes, how many, how they are evicted, expired and cleared, how much memory a read reserves, and what happens on failure. It does not define the entry format. The cache key, the metadata, the file-name hash, the 30-day retention rule and entry validation are frozen by `spec/report-cache-v1.md` and computed by `src/cache.rs` (`cache_filename`, `CacheMetadata::for_body`, `encode_metadata`, `decode_metadata`, `validate_entry`); this store calls them and re-derives none of them. Implementation: `src/cache_store.rs` and the cache primitives of `src/secure_fs/` (`spec/state-store-v1.md`, "Cache primitives"); acceptance: `tests/cache_store_v1.rs`, the unit tests in `src/cache_store.rs` (fault injection) and in `src/secure_fs/unix.rs` (the primitives).

> A cache entry grants nothing. This module reads no state and decides no grant; whether a request may be served from the producer cache, and whether a receiver entry may be shown, is the caller's decision (`SA-2B3b`). Every cache error, including `unsafeState` and `unknown`, is at most a miss, never an authorization.

Not in this slice: calling the store from `serve`, `fetch`, housekeeping or revoke (`SA-2B3b`), the engine (`SA-2B3c`, `SA-2B3d`), clearing on uninstall (`SA-2B3e`), Windows (no secure root can be opened there, so no store either).

## Root and namespaces

Both caches live in the same secure root as `state.json`, under the same `owner.lock`, flat:

| Name | Purpose |
|---|---|
| `pcache-<64 hex>` | A producer entry |
| `rcache-<64 hex>` | A receiver entry |
| `.pcache-<64 hex>.tmp`, `.rcache-<64 hex>.tmp` | Commit temp files. Present only during a write or after a crash; removed when the role's store opens |

`<64 hex>` is the frozen `cache_filename(key)`. The two roles are two name prefixes in one directory, not two directories. "Producer and receiver cache namespaces are separate" (`spec/report-cache-v1.md`) is kept by three rules together:

- the writer binds the role: the prefix a store writes comes from the store's own role, never from the key, and `put` with a key of the other role is `refused(invalid)` with nothing written;
- `get` with a key of the other role is a miss (`None`);
- an entry is accepted only when its metadata's `role` is the store's (on open, and through the frozen `validate_entry` on every read), so a file renamed into the other prefix is deleted when that role's store opens.

One `CacheStore` per `(root, role)`. Both stores share the root's `Arc<SecureRoot>`.

## File content

```text
u32 big-endian metadata length ‖ metadata ‖ body
```

`metadata` is the CanonicalJsonV1 bytes `encode_metadata` returns, at most 64 KiB; `body` is the exact peer response body, at most `LOGICAL_BODY_MAX` (16 MiB). A file is therefore at most 4 + 64 KiB + 16 MiB (`ENTRY_FILE_MAX`). Writes use the root's agent-file commit unchanged (`stage` then `publish`: temp file, file sync, rename, directory sync).

## Operations

| Operation | Rule |
|---|---|
| `open(root, role, ledger)` | Removes the role's temp files, lists the role's entries (`list`; `unsafeState` there is `unsafeState` here, the caller decides whether to run without a cache) and reads each file to index it from its metadata alone: name, size, `createdAtUnixMs`, `expiresAtUnixMs`, `grantId`, `peerStatic`. No body is decoded. A file over `ENTRY_FILE_MAX`, whose length field is over 64 KiB or past the end, whose metadata does not decode canonically, holds the other role, or does not hash to its own file name is deleted. Expired entries are kept until `get` or `purge_expired` meets them |
| `put(key, body, createdAt, expiresAt)` | A key of the other role, a key the frozen validator refuses, or a retention the frozen rule refuses (expiry not after creation, or more than 30 days) is `refused(invalid)`; metadata over 64 KiB or a body over 16 MiB is `refused(bounds)`. A refusal writes nothing. Otherwise the caps are made room for (below), then the file is written. A `put` of a key already present replaces it. The body is stored as given; `put` does not decode it |
| `get(key, now)` | `None` when the key is of the other role, invalid, or not indexed. Otherwise reads the file, then the frozen `validate_entry` (metadata, role, file name, body hash, body decode, echoes, and `now >= expiresAtUnixMs` is expired). Any failure deletes the file and is `None` |
| `remove_grant(grantId)`, `remove_peer(peerStatic)`, `clear()`, `purge_expired(now)` | Delete the matching entries (`purge_expired`: `now >= expiresAtUnixMs`) and return how many |
| `len()`, `bytes()` | Indexed entries and the sum of their file sizes |

## Caps and eviction

Per role: 256 entries and 64 MiB, summed over file sizes. The roles count separately: a full producer cache does not touch the receiver's. Before a `put` writes, while the role would exceed either cap with the new entry, the oldest other entry is deleted, oldest by `createdAtUnixMs`, ties by file name. The entry being replaced by the same key is neither counted nor evicted. One entry is at most `ENTRY_FILE_MAX`, below 64 MiB, so a `put` always fits once the others are gone.

## Memory

Every byte read into memory is reserved on the shared `MemoryLedger` first (`spec/report-peer-v1.md`, "Receiver memory"). `MemoryReservation` cannot shrink or split, so a read takes separate reservations:

| Step | Reservation | Held |
|---|---|---|
| `open`, per file | File size + 1, before the read (`read_file_sized` allocates exactly that) | Until that file is indexed |
| `put` | The assembled file (4 + metadata + body) | Until `put` returns |
| `get` (a) | File size + 1, before the read | Until `get` returns |
| `get` (b) | `report_peer::decode_reservation(body, endpoint)`, after the read | Until `get` returns |
| `get` (c) | The body length, before `validate_entry` (which copies the body) | By the returned `CachedBody`, until it is dropped |

A reservation that does not fit is `busy`, and the file is kept. A body the shape gate refuses, or whose decode cost exceeds `REMOTE_MEMORY_MAX` (it could never fit), is a failed validation: the file is deleted and `get` is `None`, not `busy`. So a `get` needs `(size + 1) + decode cost + body length` free at once; after a success the store holds only the body length.

## Failures

| Failure | Result |
|---|---|
| `stage`, `publish` or `remove_file` fails (any write or delete, including eviction and the delete after a failed validation) | `unknown`, and the store is **sticky unknown**: `get` is `None`; `put`, the removals, `len` and `bytes` are `unknown`; only a reopen recovers (as `StateStore` and `PeerStore`) |
| `read_file_sized` is `unsafeState` (the file became a link, gained a link, changed mode or owner after indexing) | Nothing is deleted or followed. `open` is `unsafeState`; `get` is `unsafeState` and the store becomes sticky unknown |
| `read_file_sized` is `corrupt` (larger than its indexed size) | The file is deleted; `None` |
| The file is gone | The index entry is dropped; `None` |
| A ledger reservation does not fit | `busy`; nothing changes |

## Non-claims

- `open` reads every listed file in full, one at a time, so it can read up to 64 MiB per role (with at most `ENTRY_FILE_MAX` + 1 reserved at once).
- Eviction is by creation time, not by last use.
- A process of the same UID can delete or rewrite cache files. That causes a miss (the entry fails validation and is deleted) or, for a link or mode change, `unsafeState`; it never causes an authorization, because the cache authorizes nothing.
- Durability across power loss is not observable in a test. Tests prove the old-or-new outcome after an injected failure at each commit step, not what a disk does with its cache.
- One mutex serializes every operation of a store, file reads included; concurrent `get`s on one role queue. Not measured.
