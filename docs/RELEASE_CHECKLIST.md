# Public release checklist

## Trust boundaries

- [x] Threat model and package READMEs match actual behaviour.
- [x] No “secret-free”, “proof”, “safe”, “tamper-proof”, or truth/authenticity
      claims exceed tested properties.
- [x] Packet task and metadata are covered by the outbound-content policy.
- [x] Receipt rechecks cannot address paths or working directories outside a
      verifier-selected root.
- [x] Commands require a controller-owned exact allowlist, an absolute executable
      path, controller-owned success criteria, and explicit opt-in.
- [x] Hermes integration documents the operator-review workflow and does not claim
      human authentication, global egress, or OS-sandbox enforcement.
- [x] Native Hermes preparation requires registered Git projects, explicit
      includes, and a clean commit by default.
- [x] Native Hermes return verification requires `OUTPUT_MANIFEST.json` and
      `receipt.json`, rechecks all evidence without executing commands, and does
      not merge changes automatically.

## Adversarial verification

- [x] Traversal, absolute path, duplicate member, source/destination symlink,
      hardlink, device, FIFO, extra-file, compressed/decompressed size, PAX
      metadata, member-count, digest-snapshot, and manifest-privacy tests pass.
- [x] Path rebinding, symlink escape, unknown evidence, duplicate claim, digest
      forgery, untrusted key, command policy, and wrong-context receipt tests pass.
- [x] A clean end-to-end packet -> work -> receipt -> controller recheck passes.
- [x] Changing one input, output, command policy, packet digest, or receipt byte
      produces the expected failure.

## Supply chain and packaging

- [x] Ruff, test matrix, package builds, and `twine check` pass from a clean clone.
- [x] Wheels contain only intended package files.
- [x] GitHub Actions are least-privilege and pinned to reviewed commit SHAs.
- [x] Dependabot/Renovate and CodeQL configuration reviewed.
- [ ] Repository name, PyPI names, and CLI names checked immediately before publish.
- [ ] PyPI trusted publishing is used; no long-lived upload token is stored.

## Release decision

- [ ] One real but non-sensitive workflow has been dogfooded.
- [ ] At least two outside testers can follow the quick start without help.
- [ ] Native Hermes plugin installation and a synthetic return have been tested
      from a clean user-plugin directory on a supported Hermes release.
- [x] Open security blockers are zero.
- [ ] Maurice explicitly approves public GitHub/PyPI publishing.
