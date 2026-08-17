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
| Formatted test module SHA-256 | `85da1c5c330fba8e180a61ea6946f93916400142786be268636c197f39c8b788` |
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

| Transition | Reference rule |
|---|---|
| Enable | Only disabled to enabled |
| Create offer | Enabled, no clock anomaly, ≤5 active, 1–900 second lifetime, unused ID, and strictly live at effective now |
| Claim | Active-offer CAS to consumed; one awaiting pending; same initiator retry returns the same pending and generation; different initiator gets no metadata |
| Approve | Current pending ID and generation, unexpired, exact disclosure; allocate `nextAuthEpoch`, then increment |
| Reject or expiry | Terminal record; never authority |
| Revoke | One immutable commit raises deny floor, re-epochs survivors, terminates target |
| Disable/reset/uninstall | One commit raises deny floor, disables sharing, leaves no active grant |
| Source change | Raises deny floor and source generation; existing grant cannot read the new scope before re-consent |
| Compaction | Only cleanup-complete terminal records aged at least 90 days; deterministic order; counters never decrease |

The reference methods return a new state. The pre-commit state remains the only crash-before result; the returned state is the crash-after result. No partial mutation is observable.

Clock uses `max(osNow,lastAcceptedWall)`, so rollback cannot extend or revive a grant. Rollback over 300 seconds or a forward jump over 24 hours blocks offer, pending, grant creation, and age compaction.

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
