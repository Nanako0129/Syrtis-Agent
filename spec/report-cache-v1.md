---
status: active
id: syrtis-report-cache-v1
kind: contract
scope: repository
read_when: changing report records, peer responses, or cache reference validation
last_verified: 2026-08-16
sources: ["../src/report.rs", "../src/cache.rs", "v1.md"]
---

# Report and cache reference contract

This document freezes the SA-0 pure reference model. It does not describe
networking, filesystem I/O, parser ownership, allocation accounting, or
application integration.

> Responses carry aggregate numerators only. v1 directly sums selected nodes;
> synchronized history may therefore be counted more than once. No session ID,
> fingerprint, manifest, exclusion key, or deduplication oracle exists.

## Peer request and response

`ReportRequest` and `ReportResponse<R>` use `CanonicalJsonV1`. The response
repeats every request field byte-for-byte and adds `records`, `saturated`,
`nodeLabel` and `costIncomplete` (`DR-2b`), all four required.
Unknown or missing fields, non-canonical bytes, wrong revisions, invalid IDs,
invalid dates, unsorted clients, and endpoint/type mismatches are rejected.

| Field | Type and rule |
|---|---|
| `aggregationRevision` | `u16`, exactly `1` |
| `authEpoch` | `u64` |
| `clients` | NFC strings, bytewise sorted and unique; empty means all |
| `endDateExclusive`, `startDate` | ASCII `YYYY-MM-DD`; range is 1–370 days |
| `endpoint` | `1=graph`, `2=models`, `3=hourly`, `4=agents` |
| `grantId`, `requestId` | lowercase 16-byte hex |
| `protocol` | `u16`, exactly `1` |
| `reportSchema` | `u16`, exactly `2` |
| `sourceScopeGeneration` | `u64` |
| `timezone` | non-empty NFC string, at most 255 UTF-8 bytes |
| `tzdbRevision` | exactly `2026c` |
| `saturated` | `bool`; true if any `u64` merge add saturated |
| `nodeLabel` | The producer's `config.nodeLabel` or `null`. A string passes `security::valid_node_label`: 1–128 bytes, NFC, not only whitespace, no Cc, Zl or Zp character and none of U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069. The producer sends `null` for a stored label that fails it; `decode_response` reads such a label as `null` and keeps the rest of the body |
| `costIncomplete` | `bool`; true when the pricing table the producer priced the body with is missing or corrupt (the engine's `RemotePricingDiagnostic::Missing` or `Corrupt`), so a cost may be zero; false when it is fresh or stale. Only the boolean is sent, never the diagnostic |

All numerator fields are `u64` and merge with saturating addition. Optional
`model` and `provider` values are NFC strings or `null`; `client` and `agent`
are non-empty NFC strings. All strings are limited to 255 UTF-8 bytes.

| Endpoint | Identity and sort key | Additional fields |
|---|---|---|
| Graph | `date + client + model + provider` | `date` plus common numerators |
| Models | `client + model + provider` | `durationMillis`, `timedTokens`, `sampleCount` |
| Hourly | `bucketStartUnixMs + utcOffsetSeconds + client + model + provider` | signed bucket and offset plus common numerators |
| Agents | `agent + client + model + provider` | `agent` plus common numerators |

`merge_graph`, `merge_models`, `merge_hourly`, and `merge_agents` sort input,
merge equal identities, and return the saturation flag. Response encoding and
decoding require strict identity ordering with no duplicate identities. Sorting
compares UTF-8 bytes and treats `null` before a string.

## Direct-sum policy

The reference constants are `DIRECT_SUM_AGGREGATION = "directSum"`,
`DUPLICATE_WARNING = true`, and
`DUPLICATE_WARNING_TEXT = "同步過的歷史資料可能重複計算"`. These are UI/policy
signals, not extra peer response fields. The wire response contains no summary,
percentage, average, formatted cost, session manifest, or fingerprint.

## Cache key and metadata

Producer and receiver cache namespaces are separate. A cache entry is one
canonical metadata object plus one exact canonical peer response body; the
production filesystem is outside SA-0.

| Cache key field | Type and rule |
|---|---|
| `aggregationRevision` | `u16`, exactly `1` |
| `reportSchema` | `u16`, exactly `2` |
| `authEpoch`, `sourceScopeGeneration` | `u64` |
| `clients` | Same sorted, unique list as the request |
| `endDateExclusive`, `startDate`, `timezone`, `tzdbRevision` | Same request values |
| `endpoint` | `1..=4`, matching the body type |
| `grantId` | Lowercase 16-byte hex |
| `peerStatic` | Lowercase 32-byte hex |
| `role` | Exactly `producer` or `receiver` |

Metadata has exactly `bodySha256`, `cacheKey`, `createdAtUnixMs`, and
`expiresAtUnixMs`. Expiry must be after creation and no more than 30 days;
`now >= expiresAtUnixMs` rejects the entry. `bodySha256` is lowercase
SHA-256 of the exact body bytes.

The filename is lowercase hexadecimal `SHA-256(cacheKeyJson)`, where
`cacheKeyJson` is the canonical encoding of the exact cache-key object. The
validator checks expected role/root, filename, metadata shape, body hash, body
canonicality, endpoint type, and every cache-key/request echo before returning
the body.

## Validation and fixture boundary

`validate_entry` is pure and accepts metadata bytes, body bytes, filename,
expected role, and a fixed current time. It performs body-hash verification
before typed response decode. Missing/unknown fields, cross-role or cross-root
use, key/filename mismatch, body-hash mismatch, expired entries, malformed
responses, and cache/body echo mismatches all reject the complete entry.

Golden bytes live under `tests/fixtures/v1/report/` and
`tests/fixtures/v1/cache/`; `tests/report_cache_v1.rs` exercises ordering,
hourly DST identity separation, saturation, strict echoes, direct-sum policy,
exact schema, and each rejection class.
