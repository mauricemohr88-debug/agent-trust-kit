# Local validation record

Snapshot: 2026-08-01, before the first public release.

## Passed locally

- Ruff lint and format checks across the workspace;
- 50 tests on each of Python 3.10, 3.11, 3.12, 3.13, and 3.14;
- end-to-end packet build, independently hashed materialization, receipt creation,
  and controller-side verification;
- source distributions and wheels for both packages;
- `twine check` for all four distributions;
- fresh-environment installation and CLI version smoke from the built wheels;
- the full check from a fresh local Git clone, which remained worktree-clean;
- focused read-only security rechecks after the packet and receipt hardening, with
  no open P0 or P1 findings in the reviewed scope.

The reproducible local entry point is:

```bash
scripts/check.sh
```

## Deliberately not claimed yet

- The GitHub Actions and CodeQL workflows have not run remotely because this
  working copy has not been pushed.
- The tools have not yet been followed by two outside testers without help.
- A real but non-sensitive Hermes-to-worker workflow still needs to be dogfooded.
- This is not a penetration test, certification, sandbox, DLP system, or guarantee
  that heuristic secret detection finds every sensitive value.

Public package release therefore remains subject to the
[release checklist](RELEASE_CHECKLIST.md) and Maurice's explicit approval.
