# Syrtis Agent Security Reference v1

## Purpose and boundary

This document records deterministic SA-0 security reference behavior. All randomness and time are fixed fixtures. Production networking, native IPC admission, filesystem mutation, allocation instrumentation, resident startup, and user data remain SA-2 work.

> Sharing defaults off. An active grant satisfying the complete predicate is the only positive authority. A tombstone, cache entry, pending claim, Pair URL, or local-control token never grants peer report access.

## Cryptographic registry and provenance

| Item | Exact value |
|---|---|
| Noise suite | `Noise_IK_25519_ChaChaPoly_BLAKE2s` |
| Prologue | ASCII `syrtis-peer-v1\0` |
| `snow` | `0.10.0`; checksum `599b506ccc4aff8cf7844bc42cf783009a434c1e26c964432560fb6d6ad02d82`; MSRV 1.85 |
| `snow` features | `use-blake2,use-chacha20poly1305,use-curve25519,use-getrandom`; default features off |
| Unicode normalization | `0.1.25`; checksum `5fd4f6878c9cb28d874b009da9e8d183b5abc80117c40bbd187a1fde336be6e8`; MIT OR Apache-2.0; MSRV 1.36 |
| Independent oracle | `x25519-dalek 2.0.1`, `chacha20poly1305 0.10.1`, and `blake2 0.10.6`; default features off; test-only |
| Official vector | Snow crate `tests/vectors/snow.txt`, protocol `Noise_IK_25519_ChaChaPoly_BLAKE2s` |
| Formatted test module SHA-256 | `22057ba75c1a051d34413842aa9f91332497a44e18d26100ddb4c728a0f1b362` |
| Oracle golden | `tests/fixtures/v1/security/noise_ik_oracle.hex` |

The independent `tests/security_contract_v1.rs::independent_noise_ik_oracle` implements IK symmetric-state hashing, BLAKE2s HMAC/HKDF, X25519, and ChaCha20Poly1305 directly. It does not call `snow`. The test first reproduces the official Snow vector, then compares both implementations under the Syrtis prologue through exact message 1, message 2, and `hFinal` bytes.

### Domain tags and formulas

| Purpose | Exact NUL-terminated ASCII tag |
|---|---|
| Offer secret | `syrtis-offer-secret-v1\0` |
| Control key | `syrtis-control-key-v1\0` |
| Control server | `syrtis-control-server-v1\0` |
| Control command | `syrtis-control-command-v1\0` |
| Control response | `syrtis-control-response-v1\0` |
| Pair SAS | `syrtis-pair-sas-v1\0` |

`controlKey`, server proof, command MAC, and response MAC use HMAC-SHA256 exactly as frozen in the Plan. Integer inputs are big-endian; variable bytes carry a `u32be` length. JSON IDs, command IDs, and result code must equal their raw transcript values. MAC comparison is constant-time.

SAS hashes the exact 133-byte preimage `tag || u16be(protocol) || offerId[16] || responderStatic[32] || initiatorStatic[32] || hFinal[32]`. The first four digest bytes render as uppercase `HHHH-HHHH`. Approval accepts only the current `{pendingId,sasGeneration}`.

The offer secret is never stored. `secretHash` is `SHA-256("syrtis-offer-secret-v1\0" || offerId[16] || secret[32] || responderStatic[32])`, and a claim presents the raw secret so the reference state can recompute that hash and compare it in constant time.

## Authorization and durable-state reference

Authorization is exactly:

```text
sharingEnabled
&& grant.state == active
&& request.authEpoch == grant.authEpoch
&& grant.authEpoch > denyFloor
&& request.sourceScopeGeneration == grant.sourceScopeGeneration
&& grant.sourceScopeGeneration == counters.sourceScopeGeneration
&& max(osNow,lastAcceptedWall) < grant.expiresAt
&& endpoint in grant.endpoints
&& scope == "usage.aggregate.read.v1"
```

Every one of the nine conjuncts is independently falsifiable. The contract tests build the authorization request from literals chosen so that no two conjuncts read the same value, never from the grant under test; deleting or negating any single conjunct turns exactly one named test red. A request assembled from the object it is meant to constrain proves nothing, which is how eight of these nine once passed a frozen-contract acceptance.

The request carries no peer identity. Binding a grant to the paired static keys at authorization time is `SA-2B` work; the grant record does carry them (see below) so that `SA-2B` has something to bind to.

| Transition | Reference rule |
|---|---|
| Enable | Only disabled to enabled |
| Create offer | Enabled, no clock anomaly, ≤5 active, 1–900 second lifetime, unused ID, and strictly live at effective now |
| Claim | No clock anomaly; the presented secret must reproduce the stored `secretHash` under constant-time comparison, and a wrong secret leaves the offer active so a guess cannot consume it; active-offer CAS to consumed; one awaiting pending; same initiator retry returns the same pending and generation only while that pending is still awaiting approval; a terminal pending and a different initiator both get no metadata |
| Approve | No clock anomaly; current pending ID and generation, unexpired, exact disclosure; allocate `nextAuthEpoch`, then increment; the new grant records `createdAt`, the pending claim's `initiatorStatic`, and the responder static key supplied by the caller |
| Reject or expiry | Terminal record; never authority |
| Revoke | One immutable commit raises deny floor, re-epochs survivors, terminates target |
| Disable/reset/uninstall | One commit raises deny floor, disables sharing, leaves no active grant |
| Source change | Raises deny floor and source generation; existing grant cannot read the new scope before re-consent |
| Cleanup complete | No clock anomaly; the runtime reports that physical cleanup finished for one existing terminal record that is not already complete; changes no counter. A terminal record is compactable only after this transition |
| Compaction | No clock anomaly; only cleanup-complete terminal records aged at least 90 days; deterministic order; counters never decrease |

The reference methods return a new state. The pre-commit state remains the only crash-before result; the returned state is the crash-after result. No partial mutation is observable.

`tests/fixtures/v1/security/state_transitions.json` freezes the twelve **specification-level transition names**, and stays at twelve. It is not, and never was, a list of the crate's methods: it names `reset`, for which there is no method, while `cancel_offer` and `mark_cleanup_complete` are methods that it does not name. Local maintenance that grants nothing does not enter that set.

### Grant record identity

A grant record carries exactly the ten fields frozen in `spec/v1.md`: `authEpoch`, `createdAt`, `endpoints`, `expiresAt`, `grantId`, `initiatorStatic`, `responderStatic`, `scope`, `sourceScopeGeneration`, and `state`. `initiatorStatic` is the static key of the claim that produced the pending record. `responderStatic` is supplied as an explicit argument to approval: the reference state has no identity of its own, and `spec/v1.md` freezes the state top level, so it is not carried as a new state field.

`state` is `active`, `revoked`, or `expired`. There is no intermediate revocation state: revocation is one immutable commit, and a state that exists between "still authorized" and "revoked" contradicts that.

### Durable wall clock

`lastAcceptedWallUnixSeconds` is a State counter, so it never decreases, and the authorization clock is `max(osNow,lastAcceptedWall)`. Rollback therefore cannot extend or revive a grant.

| Rule | Value |
|---|---|
| Maximum tolerated rollback | 300 seconds |
| Maximum tolerated forward jump | 86,400 seconds |
| Anomalous clock | `osNow < lastAcceptedWall - 300` or `osNow > lastAcceptedWall + 86,400` |
| Effect of an anomaly | The transition is refused; the state is unchanged |
| Accepted wall after a checked reading | `max(osNow,lastAcceptedWall)` |

**The wall is advanced only by a checked clock reading, never by a record timestamp.** A record's `terminalAt` or `expiresAt` is data supplied with the transition; letting it advance the wall would let one absurd timestamp lock the durable clock into the future, after which every honest reading looks like a rollback. The twelve transitions therefore split into two sets, and the split is a decision, not an omission:

| Transition | Clock input | Wall |
|---|---|---|
| Create offer | `osNowSeconds`, checked | Advances |
| Claim | `osNowSeconds`, checked | Advances |
| Approve | `osNowSeconds`, checked | Advances |
| Cleanup complete | `osNowSeconds`, checked | Advances |
| Compaction | `osNowSeconds`, checked | Advances |
| Enable | none | Does not advance |
| Source change | none | Does not advance |
| Reject | `terminalAt` record timestamp | Does not advance |
| Cancel offer | `terminalAt` record timestamp | Does not advance |
| Expiry | `terminalAt` record timestamp | Does not advance |
| Revoke | `terminalAt` record timestamp | Does not advance |
| Disable/reset | `terminalAt` record timestamp | Does not advance |
| Uninstall | `terminalAt` record timestamp | Does not advance |

Every clock-regulated entry point takes whole seconds (`osNowSeconds`), matching the counter's unit. Milliseconds appear only inside records, as absolute timestamps.

State is constructed with the install-time wall clock in seconds, whose domain is strictly positive; zero or negative is refused rather than silently accepted. A fresh state whose wall is zero would make every real Unix timestamp look like a forward jump of decades, so offer creation, claims and approvals would all fail — the frozen "counters never decrease" rule leaves no in-crate transition that could lower it again. Supplying a *future* wall clock is fail-closed in the same direction and is deliberate: the state refuses new offers, claims, approvals, cleanup reports and compaction until real time catches up. **Recovery is outside this crate** — the runtime discards the state and rebuilds it from a correct clock. This is a named `SA-2B` prerequisite.

The authorization request's `osNow` and `lastAcceptedWall` are assembled by the caller from the *current* durable state. If a runtime authorizes against a stale snapshot, an already-revoked grant passes. That failure mode is structurally unobservable in a pure reference contract, and closing it is a named `SA-2B` prerequisite.

**Structural ceiling, not a defect:** a pure state machine cannot advance its own clock between two transitions, so the widest undetected forward jump is bounded by the timestamp of the last accepted transition rather than by wall time. Narrowing that window needs periodic checkpointing, which is runtime work. This contract does not pretend to provide it.

### Record capacity and terminal reserve

| Bound | Value | Applies to |
|---|---|---|
| `MAX_CREATION_RECORDS` | 255 | Offer creation, claim, approval |
| `MAX_RECORDS` | 256 | Offer cancellation, expiry |

The asymmetry is the terminal reserve and is deliberate. Creation stops one record short of the cap so that a full state still has room to record a termination. **Revoke, disable, reset, uninstall and reject never fail on record count.** Making them fail there would make a full state unrevocable: a terminal record leaves only by compaction, which needs a cleanup-complete report, ninety days, and a non-anomalous clock, so "cannot revoke" would persist for months and contradict the unconditional one-commit revoke rule above.

### Pending re-issue and `sasGeneration`

`sasGeneration` is owned by the runtime. It increments monotonically each time the runtime re-issues a pending claim's SAS; this contract only compares the supplied generation for equality and never increments it, because a pure function cannot know when a re-issue happened. Replay protection across re-issues rests on `PendingState`: a pending that is no longer awaiting approval yields neither approval nor its generation.

## Local trust, lifecycle, and resource reference

| Platform | Trusted root source | Exact state suffix |
|---|---|---|
| macOS | Effective-UID directory-service home | `Library/Application Support/com.nyanako.syrtis.agent/` |
| Linux | `getpwuid_r(geteuid())` home | `.local/state/syrtis-agent/` |
| Windows | Current-token LocalAppData known folder | `Nyanako\Syrtis Agent\` |

Environment `HOME`, `XDG_STATE_HOME`, and `LOCALAPPDATA` are ignored. Relative, foreign-owned, symlink/reparse, network-backed, broadly writable, or unverifiable roots fail closed. Install objects are exact absolute paths, invoke `[binary,"run"]`, and never use a shell or `PATH` lookup.

`RemoteSourcePolicy` starts with `use_env_roots=false`. Adding an owner-approved absolute custom root increments `sourceScopeGeneration` and requires owner re-consent. Paths remain local-only.

Uninstall first disables sharing, revokes grants, and raises deny floor. It then stops endpoints and removes only exact safe agent-owned objects. Unsafe metadata retains deny state and reports manual repair. Default uninstall preserves disabled identity/state; purge removes identity only when every candidate object is safe. Reinstall from retained state starts with zero listener and zero active grant.

The atomic remote-memory ledger is 384 MiB. Checked capacity arithmetic includes element layout, control bytes, and allocator rounding. A CAS-backed RAII reservation happens before allocation and is returned on success, EOF, parse error, timeout, cancellation, revoke, and replacement. Producer and receiver cache budgets remain separate within the same process-wide hard ledger.
