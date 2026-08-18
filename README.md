# syrtis-agent

Reference contracts for Syrtis remote usage sharing.

This crate is the frozen, verifiable half of the protocol: canonical JSON
encoding, the report and cache schemas, and the security contract vectors —
Noise IK handshake transcripts, pairing SAS derivation, control-channel MACs,
pair URL grammar, consent enumeration, state transitions, uninstall ordering,
and memory-budget arithmetic.

It is deliberately inert. There is no listener, no session parser, no
filesystem cache, no installer, and no application bridge; those belong to the
runtime that builds on these contracts. Everything here is a pure function of
its inputs, which is what makes the fixtures under `tests/fixtures/v1/` worth
publishing: they can be re-derived and checked against an independent
implementation.

The security vectors include an independent Noise IK oracle implemented
directly from the specification in `spec/security-v1.md`, so the handshake is
pinned by two implementations rather than by the library under test.

## Verifying

```
cargo test --locked --all-targets
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

CI additionally re-derives the SHA-256 of every contract file against
`.github/candidate-digests.txt` on Linux, macOS, and Windows. The fixtures are
compared byte-for-byte by `include_str!`, so any end-of-line conversion would
silently break them; `.gitattributes` disables it and that check proves it
stayed disabled.

## Licence

MIT.
