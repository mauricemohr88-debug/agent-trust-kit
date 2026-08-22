# Agent Trust Kit v0.1.0

This is the first public beta release. External operator feedback is still being
collected and is not represented as completed validation.

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

The release candidate passed locally:

- 94 tests, with the same suite also green in GitHub's Python 3.10, 3.11,
  3.12, 3.13, and 3.14 matrix;
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

## Availability and open validation

- The native Hermes plugin installs from the tagged GitHub repository.
- `agent-packet` and `agent-receipt` install independently from PyPI.
- Release distributions are built from the tag, checked, published with
  short-lived GitHub OIDC credentials, and attached to the GitHub release.

One real non-sensitive workflow has been dogfooded. Feedback from two outside
testers remains open in
[issue #3](https://github.com/mauricemohr88-debug/agent-trust-kit/issues/3).
Maurice approved publishing `v0.1.0` as an early beta on 2026-08-22 with that
limitation kept visible; the missing feedback is not treated as evidence.
