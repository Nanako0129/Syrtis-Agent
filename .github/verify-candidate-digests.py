#!/usr/bin/env python3
"""Verify the imported SA-0 candidate is byte-identical to what was reviewed.

Runs on every CI platform. Windows is the one that matters: a stray
end-of-line conversion would rewrite the LF-only fixtures that
`tests/security_contract_v1.rs` compares byte-for-byte via `include_str!`,
and this reports which file changed instead of leaving a test failure to
be diagnosed from a mismatched hex blob.
"""
import hashlib
import pathlib
import sys

MANIFEST = pathlib.Path(".github/candidate-digests.txt")

expected = {}
for line in MANIFEST.read_text(encoding="utf-8").splitlines():
    # The manifest carries a header stating what it pins; without this the
    # header would crash the parser rather than degrade.
    if not line.strip() or line.lstrip().startswith("#"):
        continue
    digest, path = line.split("  ", 1)
    expected[path] = digest

problems = []
for path, digest in sorted(expected.items()):
    candidate = pathlib.Path(path)
    if not candidate.is_file():
        problems.append(f"missing: {path}")
        continue
    actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
    if actual != digest:
        problems.append(f"changed: {path}\n  expected {digest}\n  actual   {actual}")

if problems:
    print(f"candidate digest check FAILED ({len(problems)} of {len(expected)})")
    for problem in problems:
        print(f"  {problem}")
    sys.exit(1)

print(f"candidate digest check ok ({len(expected)} files)")
