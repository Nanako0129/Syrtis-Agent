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

The home is opened by path and checked on the descriptor. Every component below it is opened with `openat(parent, name, O_DIRECTORY | O_NOFOLLOW)`; a missing component is created with `mkdirat(…, 0700)`, reopened the same way, set to exactly `0700` with `fchmod` on the new descriptor (the `mkdirat` mode is filtered by the process umask), has its extended ACL cleared on macOS, and then its parent directory is synced (`F_FULLFSYNC` on macOS, `fsync` on Linux) so the new entry is durable. Nothing is ever reopened by pathname after a check.

**Root parent sync.** Every open syncs the agent root's parent directory, whether the root was created in this call or found, after the root has passed every check in the table below (a refused root, for example one on a non-local filesystem, never triggers the sync), so a root that an earlier run created but crashed before syncing is durable before any commit lands in it. Creating the root syncs its parent once, not twice. A failure of this sync is `unsafeState` (nothing was committed, so the store does not become sticky unknown). Only the root's parent is synced on every open: an intermediate directory the agent created is synced once, right after its `mkdirat`, so a crash between that `mkdirat` and its sync, followed by a later open that finds the directory and a power loss, can lose it on ext4. That affects availability only (the root is then missing and is created again), not confidentiality.

**Created versus found.** Whether an object is `fchmod`-ed and has its ACL cleared is decided by name: a directory whose `mkdirat` succeeded in this call, `owner.lock` whose `O_CREAT|O_EXCL` open succeeded, and the commit temp file. Only a directory is reopened by name afterwards (`mkdirat` returns no descriptor), so another process of the same UID can substitute a directory in between; a substitute owned by another UID is stopped because `fchmod` on it fails with `EPERM`, which fails closed (inferred from `fchmod(2)`; a second UID cannot be created in a test). `owner.lock` and the temp file keep the descriptor their `O_EXCL` open returned, so nothing can be substituted for them. An object that already existed is checked exactly as found, and if it fails a rule it fails closed and is left in place for manual repair. A restrictive umask (for example `0277`) therefore cannot make the root unopenable.

**Interrupted creation.** Objects are created with mode `0700` (directories) or `0600` (files), filtered by the umask. A crash between creating an object and its `fchmod` or ACL clearing, or a lost first-start race against a process that has not done them yet, leaves an object that the next open checks as found:

- With a umask that clears no owner bit (for example `022` or `077`) and no inherited ACL, the object already has its exact mode and no ACL, so the next open accepts it (inferred from the create modes; not reproduced by a test).
- It may fail closed only under a restrictive umask that clears owner bits (measured: under umask `0277`, a root that is not `fchmod`-ed is refused) or when the root or `owner.lock` inherited an ACL from its parent (measured for the root: a root whose inherited ACL is not cleared is refused). After a crash it then needs manual repair, because the agent never fixes an object it did not just create. In a first-start race the loser's `unsafeState` is transient: once the winner has finished, a retry succeeds (inferred).

| Object | Required on the open descriptor |
|---|---|
| Home | Owner is the effective UID, not group- or other-writable (`0755` is accepted; the same rule as sshd `StrictModes`), and on macOS any extended ACL is deny-only (below) |
| Intermediate directory | Directory, owner is the effective UID, not group- or other-writable (`0755` is accepted), and on macOS any extended ACL is deny-only (below) |
| Agent root | Directory, owner is the effective UID, mode exactly `0700`, local filesystem, no extended ACL entry (macOS) |
| Agent file (`state.json`, `owner.lock`) | Regular file, owner is the effective UID, mode exactly `0600`, link count 1, opened `O_NOFOLLOW`, no extended ACL entry (macOS) |

**macOS ACLs.** An extended ACL grants or denies access whatever the mode says, and an inheritable entry on a parent is copied onto every new directory or file below it. The agent therefore replaces the extended ACL with an empty one (`acl_init(0)` + `acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED)`) on every directory it creates (each intermediate and the root), on `owner.lock` and on the commit temp file, right after creating each and before any secret byte is written.

- The root, `state.json` and `owner.lock` must carry no extended ACL entry at all (`acl_get_fd_np` + `acl_get_entry(ACL_FIRST_ENTRY)`).
- The home and every intermediate directory pass only if they carry no extended ACL, or if every entry's tag is `ACL_EXTENDED_DENY`. A stock account's `~`, `~/Library` and `~/Library/Application Support` carry only `everyone deny delete`, which passes. Every entry is read, `acl_get_entry(ACL_FIRST_ENTRY)` and then `ACL_NEXT_ENTRY`, up to `ACL_MAX_ENTRIES` (128); an `ACL_EXTENDED_ALLOW` entry (for example `everyone allow add_subdirectory,delete_child`, which would let another UID replace the next component), an `ACL_UNDEFINED_TAG` or unknown tag, a tag `acl_get_tag_type` cannot read, or more than 128 entries fails closed. A deny entry followed by an allow entry fails closed: the walk does not stop at the first entry.
- When `acl_get_entry` returns −1, errno is read immediately, before `acl_free`. Only `EINVAL` means "no more entries"; any other errno counts as an entry that may grant access, and fails closed. An ACL that `acl_get_fd_np` cannot read (any errno except `ENOENT`) also counts as present.
- An ACL on an object the agent did not just create fails closed and is not stripped.

**Linux** needs no ACL handling: with the mode exactly `0700`/`0600`, the POSIX ACL mask is zero, so no named entry can grant group or other access.

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
2. The top level must be an object with an integer `schema`; a missing or non-integer `schema`, or a top level that is not an object, is `corrupt`. An integer `schema` other than 1 (older, newer, zero or negative) is `incompatible`.
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
| Listen host | When `bindHost` is not `null`: `{bindHost,bindPort}` passes the frozen `listenConfigure` validator (`verify_control_command`, command 8: canonical host, port 1024–65535), and, if it parses as an IP address, `to_canonical()` of it is not unspecified (refuses `0.0.0.0`, `::`, `::ffff:0.0.0.0`). Hostnames are not resolved; a hostname that resolves to the wildcard is refused at bind time (SA-2B2) |
| Node label | When not `null`: at most 128 bytes of UTF-8 |

There is no record-count check: revoke, disable, reset, uninstall and reject never fail on record count (`spec/security-v1.md`), so a valid state may hold more than 256 records.

The store never writes a state it could not load. Before staging, a commit whose new state fails any invariant above, cannot be encoded canonically, or encodes to more than 4 MiB is refused with `refused(invalid)`. The file on disk is fine, so nothing is written, the in-memory state is unchanged, and the store does not become sticky unknown.

Errors are a stable enum with no path, OS error text or file content.

The listen-host rule recognises unspecified addresses only in the IP-literal spellings Rust's `IpAddr` parser accepts. Other spellings a resolver may accept for the wildcard, such as `0x0`, are treated as hostnames here and are not refused at load; refusing them belongs to the bind-time check of SA-2B2, which must bind only a resolved address that is not unspecified.

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
- A panic inside the staging step (between creating the temp file and the rename) unwinds without making the store sticky, but leaves `.state.json.tmp` behind; the next commit's `O_EXCL` create then fails and the store becomes sticky unknown until the process restarts, whose open removes the temp file.
- **Not observable in CI:** durability across power loss. Tests prove the order of the calls and the old-or-new outcome after an injected error or a process abort at every step, not what a disk does with its cache.

## Listen config

`set_listen_config(bindHost, bindPort, nodeLabel)` replaces `config` except `sharingEnabled` through the same commit path, so the load rules above apply: a non-null host must pass the frozen validator (port 1024–65535) and must not be an unspecified address; with a null host any `u16` port is stored; a label is at most 128 bytes and NFC. Counters, records and secrets are unchanged. A refused value returns `refused(invalid)` with nothing written.

A panic inside a caller's transition closure does not poison the store: the commit mutex guards no data, so its poison is ignored and the next commit (for example a revoke) proceeds. The state lock is only written after a successful durable commit, and a poisoned state lock still reads as sticky unknown (authorization false).

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
