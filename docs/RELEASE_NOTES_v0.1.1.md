# Agent Trust Kit v0.1.1

This patch release hardens verification and Windows cleanup behavior in response to the detailed
external review in [issue #6](https://github.com/mauricemohr88-debug/agent-trust-kit/issues/6).
Thanks to [@bobaba76](https://github.com/bobaba76) for reviewing the boundary and reporting each
finding with reproducible detail.

## Fixed

- `agent-receipt` now starts Windows evidence commands in a new process group and terminates normal
  descendant trees with the absolute System32 `taskkill.exe` path, `/T /F`, and a bounded cleanup
  timeout. If only the direct process can be stopped, the failed evidence explicitly reports that
  descendant cleanup is unconfirmed.
- Successful standalone rechecks now warn when neither a trusted signature nor
  verifier-supplied handoff context binds the receipt. The warning is additive and does not change
  `ok`, the exit code, assurance, or context matching.
- Native Hermes review no longer reconstructs `manifest.json` with the current serializer. The
  local inspection copy remains byte-for-byte bound to the exact manifest member from the
  verified packet archive.

## Compatibility and CI

- The existing `inspect_packet()` result remains a two-item tuple. A new
  `inspect_packet_details()` API exposes the verified archive and manifest-member hashes without
  breaking existing callers.
- Linux CI now runs the end-to-end smoke flow.
- Windows CI runs both standalone package suites, including real timeout, exited-launcher, and
  output-limit descendant-process regressions.
- PyPI publication for both packages now waits for the Windows job, and tag-specific release notes
  are checked before publishing.

## Boundary

The native Hermes plugin remains supported on macOS and Linux only. This release improves the
standalone `agent-receipt` Windows command-cleanup path; it does not claim a Windows sandbox or a
native Windows Hermes port. `taskkill /T /F` handles normal descendant process trees, not every
possible hostile process-escape technique.

## Validation before publication

The release candidate passed the complete local test suite on macOS, Ruff lint and format checks,
the end-to-end smoke, both wheel and source builds, `twine check`, and isolated installation of
both wheels. The three real Windows descendant-process tests are intentionally skipped on macOS and
must pass in the `windows-latest` GitHub job before either package can be published.

External quick-start feedback from two independent testers remains open in
[issue #3](https://github.com/mauricemohr88-debug/agent-trust-kit/issues/3); this patch does not
represent that validation as complete.
