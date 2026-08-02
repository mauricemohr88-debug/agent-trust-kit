# v0.1.0 — First public source release

Agent Trust Kit makes AI-agent handoffs narrower and easier to inspect:
explicitly select the input, record claims and evidence on return, and let the
controller recheck the result before accepting or merging it.

## Included

- `agent-packet` 0.1.0 for allowlist-based handoff archives with conservative
  path, archive, link, and secret-like-text checks;
- `agent-receipt` 0.1.0 for bounded claim-to-evidence receipts and
  controller-selected rechecks;
- a native Hermes plugin exposing `handoff_prepare`, `handoff_status`, and
  `handoff_verify_return`;
- operator-controlled project registration and packet approval;
- a fixed private return quarantine with manifest, digest, commit, and receipt
  checks;
- a controller-owned read-only verified snapshot;
- end-to-end documentation for Hermes/OpenClaw handoffs.

Return verification does not execute worker commands and never merges changes
automatically.

## Validation

Before source publication, the repository passed locally:

- 81 tests on each of Python 3.10, 3.11, 3.12, 3.13, and 3.14;
- Ruff lint and formatting checks;
- source and wheel builds plus `twine check`;
- fresh-environment wheel-install and CLI smoke tests;
- a synthetic native Hermes handoff ending in a fully rechecked, read-only
  snapshot.

See the [local validation record](LOCAL_VALIDATION.md) for the exact scope.

## Security boundary

This is a handoff control, not a global egress gate, OS sandbox, DLP system,
security certification, or proof that a worker is honest. Other tools, manual
transfers, unrestricted terminal access, and a compromised host remain outside
its boundary. Read the [threat model](../THREAT_MODEL.md) before using it with
private work.

## Availability

This is the first public source release. `agent-packet` and `agent-receipt` are
not yet published on PyPI. A real non-sensitive dogfood workflow and feedback
from outside testers remain planned before public package publication.
