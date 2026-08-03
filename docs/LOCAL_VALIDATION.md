# Local validation record

Snapshot: 2026-08-03, after the first native Hermes dogfood workflow.

## Passed locally

- Ruff lint and format checks across the workspace;
- 81 tests on each of Python 3.10, 3.11, 3.12, 3.13, and 3.14;
- end-to-end packet build, independently hashed materialization, receipt creation,
  and controller-side verification;
- source distributions and wheels for both packages;
- `twine check` for all four distributions;
- fresh-environment installation and CLI version smoke from the built wheels;
- local user-plugin installation from the source tree recorded as commit
  `74c9dc4` on Hermes Agent 0.15.1 (release 2026.5.29), with the three intended
  model tools, the narrow `pre_tool_call` hook, and the operator CLI loaded from
  the installed clone;
- a synthetic native handoff through the installed plugin, ending in a private
  read-only snapshot with `fully_rechecked` assurance, zero worker commands
  executed by the verifier, and no automatic merge;
- a real non-sensitive, maintainer-run native Hermes handoff through a separate
  bounded reviewer workspace, including an expected packet-policy rejection,
  operator approval, a receipt-backed return, a fully rechecked snapshot, and a
  post-verification mutation of the original quarantine copy; see the
  [dogfood record](DOGFOOD_2026-08-03.md);
- the full release-preparation check after adding preapproval packet review: 94
  tests, Ruff lint and formatting, the end-to-end smoke, both package builds,
  `twine check`, and isolated wheel installation;
- a focused read-only security review of the preapproval change found no P0,
  P1, or P2 issue; additional P3 adversarial coverage was then added for local
  manifest, sidecar, link, special-file, and extra-file tampering;
- the full check from a fresh local Git clone, which remained worktree-clean;
- two focused read-only security reviews after the packet, receipt, snapshot,
  bounded-process, and state-lock hardening, with no open P0, P1, or P2 findings
  in the reviewed scope.

The reproducible local entry point is:

```bash
scripts/check.sh
```

## Passed remotely

- GitHub Actions CI and CodeQL passed on the first public `main` push. The first
  Dependabot update also passed the Python 3.10–3.14 matrix, distribution build,
  and CodeQL after its generated lockfile was synchronized.

## Deliberately not claimed yet

- The tools have not yet been followed by two outside testers without help.
- This is not a penetration test, certification, sandbox, DLP system, or guarantee
  that heuristic secret detection finds every sensitive value.

Formal release and public package publication therefore remain subject to the
[release checklist](RELEASE_CHECKLIST.md) and Maurice's explicit approval.
