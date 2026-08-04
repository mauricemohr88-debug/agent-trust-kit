# Draft v0.1.0 release notes

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
- operator-controlled project registration, preapproval packet review, and
  packet approval;
- a fixed private return quarantine with manifest, digest, commit, and receipt
  checks;
- a controller-owned read-only verified snapshot;
- end-to-end documentation for Hermes/OpenClaw handoffs.

Return verification does not execute worker commands and never merges changes
automatically.

## Validation

At source publication, the repository passed locally:

- 81 tests on each of Python 3.10, 3.11, 3.12, 3.13, and 3.14;
- Ruff lint and formatting checks;
- source and wheel builds plus `twine check`;
- fresh-environment wheel-install and CLI smoke tests;
- a synthetic native Hermes handoff ending in a fully rechecked, read-only
  snapshot.

On 2026-08-03, the installed native plugin also completed a real non-sensitive,
maintainer-run handoff through a separate bounded reviewer workspace. The run
included an expected secret-policy rejection, exact packet review, a
receipt-backed return, a fully rechecked snapshot, and a post-verification
mutation check. See the [dogfood record](DOGFOOD_2026-08-03.md).

The resulting preapproval review change passed 94 tests, Ruff lint and format,
the end-to-end smoke, source and wheel builds, `twine check`, and isolated wheel
installation in the release-preparation environment.

The first public `main` push also passed GitHub Actions CI and CodeQL. The first
Dependabot update was validated across Python 3.10–3.14, distribution builds,
and CodeQL after synchronizing the generated lockfile.

See the [local validation record](LOCAL_VALIDATION.md) for the exact scope.

## Security boundary

This is a handoff control, not a global egress gate, OS sandbox, DLP system,
security certification, or proof that a worker is honest. Other tools, manual
transfers, unrestricted terminal access, and a compromised host remain outside
its boundary. Read the [threat model](../THREAT_MODEL.md) before using it with
private work.

## Availability

The source repository is public, but `v0.1.0` has not yet been tagged as a
GitHub release and `agent-packet` and `agent-receipt` are not yet published on
PyPI. A real non-sensitive dogfood workflow and feedback from outside testers
were release gates. Dogfooding is now complete; feedback from two outside
testers still remains before a formal release decision.
