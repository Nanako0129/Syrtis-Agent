# Syrtis Agent State Store v1

## Purpose and boundary

This document fixes how the agent's durable state is stored: where, in what bytes, how it is validated on load, and how it is replaced. It does not define keys. The state key set is frozen by `spec/v1.md` (rows "State top level" through "Terminal state record") and this store adds none. Implementation: `src/state_store.rs` and `src/secure_fs/`.

> v1 makes no confidentiality claim against the same UID, root, or Administrator. Owner-only modes, no-follow opens, an exclusive lock and atomic replace protect against other local UIDs and against partial writes, not against the owner.

## Root

| Platform | Trusted home | Root below the home |
|---|---|---|
| macOS | `getpwuid_r(geteuid())` `pw_dir` (directory service) | `Library/Application Support/com.nyanako.syrtis.agent` |
| Linux | `getpwuid_r(geteuid())` `pw_dir` | `.local/state/syrtis-agent` |
| Windows and every other platform | none | none: fails closed with `unsafeState` until `SA-2B1b` |

`HOME`, `XDG_*`, `LOCALAPPDATA` and every other environment variable are ignored. A home that is not absolute (`/`, not `//`) fails closed.

The home is opened by path and its owner is checked on the descriptor. Every component below it is opened with `openat(parent, name, O_DIRECTORY | O_NOFOLLOW)`; a missing component is created with `mkdirat(…, 0700)` and reopened the same way. Nothing is ever reopened by pathname after a check.

| Object | Required on the open descriptor |
|---|---|
| Home | Owner is the effective UID |
| Intermediate directory | Directory, owner is the effective UID, not group- or other-writable (`0755` is accepted) |
| Agent root | Directory, owner is the effective UID, mode exactly `0700`, local filesystem |
| Agent file | Regular file, owner is the effective UID, mode exactly `0600`, link count 1, opened `O_NOFOLLOW` |

Local filesystem: macOS requires `MNT_LOCAL` in `fstatfs` `f_flags`. Linux requires `fstatfs` `f_type` to be one of ext2/3/4 (`0xEF53`), XFS (`0x58465342`), Btrfs (`0x9123683E`) or tmpfs (`0x01021994`).

**Not observable in CI:** a foreign owner and a network filesystem cannot be created on a CI runner. Both classifications pass through a test-only seam that forces the result; the tests prove the guard refuses the forced result, not that the OS classifies a real foreign or network object the same way.

On macOS every open sets the extended attribute `com.apple.metadata:com_apple_backup_excludeItem` on the root to the binary plist string `com.apple.backupd` (the 61 bytes `tmutil addexclusion` writes); failure to set it fails closed. Tests prove the attribute is present; whether Time Machine honours it is not observable in CI.

Any failure of a rule above leaves listener, control endpoint and report serving off. Only bounded repair diagnostics are allowed.

## Files in the root

| Name | Purpose |
|---|---|
| `owner.lock` | Owner lock. Stable; never replaced; `flock(LOCK_EX \| LOCK_NB)`. |
| `state.json` | The durable state. |
| `.state.json.tmp` | Commit temp file. Present only during a commit or after a crash. |

The lock is taken on `owner.lock`, never on `state.json`: a lock on a file that is replaced is lost at the first replace. It is held for the life of the open root and released when the descriptor closes, including on process exit. A second opener gets `busy`. All commit APIs are reachable only through an open root, so a commit without the lock cannot be expressed.

## Encoding

`state.json` is one CanonicalJsonV1 object (`src/canonical.rs`) with exactly the keys of `spec/v1.md`. No trailing newline.

### Value encodings

| Value | Encoding |
|---|---|
| `schema` | Integer `1` (`STATE_SCHEMA_VERSION`) |
| Byte arrays (`controlToken`, `identityPrivate`, `offerId`, `pendingId`, `grantId`, `recordId`, `secretHash`, `initiatorStatic`, `responderStatic`) | Lowercase hex, exact length |
| Offer `state` | `active`, `consumed`, `cancelled`, `expired` |
| Pending `state` | `awaitingApproval`, `approved`, `rejected`, `expired` |
| Grant `state` | `active`, `revoked`, `expired` |
| Terminal `kind` | `offer`, `pending`, `grant`, `reset`, `uninstall` |
| `createdAt`, `expiresAt`, `terminalAt` | Unix milliseconds, signed integer |
| `lastAcceptedWallUnixSeconds` | Unix seconds, signed integer, strictly positive |
| Grant `scope` | `usage.aggregate.read.v1` only |
| Grant `endpoints` | `[1,2,3,4]` only |
| `bindHost`, `nodeLabel` | String or `null` |
| `bindPort` | Integer 0–65535 |

Enum values are camelCase variant names, matching the existing `GrantState` serializer; byte arrays match the existing `Grant` serializer. Golden: `tests/fixtures/v1/runtime/storage/state-golden.json` (synthetic keys only).

### Initial state

| Field | Initial value |
|---|---|
| `config.sharingEnabled` | `false` |
| `config.bindHost` | `null`: no listener can start before the owner chooses one |
| `config.bindPort` | CSPRNG, uniform in 49152–65535, persisted |
| `config.nodeLabel` | `null` |
| `counters` | `nextAuthEpoch` 1, `denyFloor` 0, `sourceScopeGeneration` 1, `lastAcceptedWallUnixSeconds` = OS time at install, strictly positive |
| `identityPrivate`, `controlToken` | 32 CSPRNG bytes each (snow's OS RNG, `getrandom`) |
| Records | Empty |

`config.sharingEnabled` is `ReferenceState.sharing_enabled`, one to one. `identityPrivate` and `controlToken` are held by the store, never by `ReferenceState`, and every type that holds them redacts them in `Debug`.

## Load validation

1. Read at most 4 MiB + 1 byte from the verified descriptor; more than 4 MiB is `corrupt`. This bounds a damaged same-UID file; it is not a security boundary.
2. `schema` other than 1 (older, newer or zero) is `incompatible`.
3. Strict CanonicalJsonV1 typed decode; a missing, extra or non-canonical key or value is `corrupt`.
4. The invariants below; any violation is `corrupt`.

| Invariant | Rule |
|---|---|
| Grant epochs | Every `grant.authEpoch < nextAuthEpoch` |
| Deny floor | `denyFloor < nextAuthEpoch` |
| Wall | `lastAcceptedWallUnixSeconds > 0` |
| Scope and endpoints | Frozen values above |
| Sharing | Sharing off implies no active grant |
| Active grants | At most 16 |
| Record IDs | Offer, pending and grant IDs unique across all three |
| Terminal IDs | `recordId` unique within `terminal`; a terminal may share the ID of the record it ended |
| Listen host | When `bindHost` is not `null`: `{bindHost,bindPort}` passes the frozen `listenConfigure` validator (`verify_control_command`, command 8: canonical host, port 1024–65535) and is not `0.0.0.0` or `::` |
| Node label | When not `null`: at most 128 bytes of UTF-8 |

There is no record-count check: revoke, disable, reset, uninstall and reject never fail on record count (`spec/security-v1.md`), so a valid state may hold more than 256 records. The store also refuses to commit any state that would fail these checks, so it never writes a state it could not load.

Errors are a stable enum with no path, OS error text or file content.

## Commit

Every change is a full replace of one agent-owned file in the root:

```text
openat(root, ".<name>.tmp", O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600); fchmod 0600
write (all bytes)
file sync          macOS fcntl(F_FULLFSYNC); Linux fsync
                   -- store takes its exclusive guard --
renameat(root, ".<name>.tmp", root, "<name>")
directory sync     macOS fcntl(F_FULLFSYNC) on the root; Linux fsync on the root
                   -- in-memory state replaced, guard released --
```

- Before anything is staged, `nextAuthEpoch`, `denyFloor` and `sourceScopeGeneration` must each be at least the currently persisted value, and so must `lastAcceptedWallUnixSeconds` except in the reset commit (below), the only commit allowed to lower the wall. A violation is a caller bug, not an I/O failure: the commit is refused with `refused(conflict)`, nothing is written, the in-memory state is unchanged, and the store does not become sticky unknown, because the durable state is known.
- In-memory state advances only after the directory sync succeeds.
- The store's exclusive guard is held from before the rename until the in-memory state is replaced. Authorization takes the shared guard and reads only that in-memory state, which is always the last durable commit. After the rename no authorization can read the pre-commit state; before it, none can read the new one.
- Any failure during the commit (create, write, sync, rename, directory sync, including `ENOSPC`) makes the store **sticky unknown** until the process restarts: no state reads, no authorization (always false), no further commits, and a sync is never retried and then trusted. The durable result is then the old or the new state.
- On open, a leftover `.state.json.tmp` from a crash is removed with `unlinkat`, which never follows a link; only that exact name is touched.
- **Not observable in CI:** durability across power loss. Tests prove the order of the calls and the old-or-new outcome after an injected error or a process abort at every step, not what a disk does with its cache.

## Reset and clock

Install wall: OS time in whole seconds, strictly positive. The wall advances only through the checked transitions of `spec/security-v1.md`; the store's checkpoint is `compact_terminals(osNow)`.

Owner-confirmed reset is the only recovery from a clock anomaly. It is two commits: first `disable_commit` (sharing off, active grants revoked, deny floor raised), then a new state with

| Field | After reset |
|---|---|
| `lastAcceptedWallUnixSeconds` | The current OS time; the only counter that may go down |
| `nextAuthEpoch` | Unchanged |
| `denyFloor` | `max(old, nextAuthEpoch - 1)` |
| `sourceScopeGeneration` | Old value + 1 |
| `offers`, `pending`, `grants` | Empty |
| `terminal` | Kept, including the record the disable just wrote |
| `identityPrivate`, `controlToken` | New CSPRNG values |
| `config` | Kept; `sharingEnabled` is `false` |

A crash between the two commits leaves the disabled state, which grants nothing. Transitions that take a caller-supplied new `record_id` (disable, uninstall) get 16 fresh CSPRNG bytes from the store; an ID is never reused.

Accepted trade-off (F-07): a checkpoint taken while the OS clock is temporarily fast writes that fast time into the durable wall. After the clock is corrected every clock-bound transition refuses until a reset. This fails closed and affects availability only.

## Residual risks

Restoring an older `state.json` from a backup can revive a revoked grant and lower `denyFloor` (SEC-2B1-12). The macOS backup exclusion above mitigates Time Machine only; no other backup tool is covered. This is disclosed here and must be disclosed in Settings.
