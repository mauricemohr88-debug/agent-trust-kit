# agent-receipt

Offline claim-to-evidence receipts for agent handoffs. A receipt records what was
observed; it is not proof that an agent's claim is true.

Install the unpublished working copy with:

```bash
uv tool install ./packages/agent-receipt
```

## Safety model

- Evidence paths are POSIX paths relative to a caller-supplied, trusted workspace
  root. Absolute paths, `.` / `..`, NULs, and symlink escapes are rejected.
- Rechecks require a verifier-supplied `--recheck-root`; the receipt never chooses
  a filesystem root or command working directory.
- Text evidence is literal substring matching only; v1 has no regex mode.
- File reads, receipt strings, claim/evidence counts, command arguments, captured
  command output, and command timeouts are bounded. A command that exceeds the
  output limit is terminated and recorded as failed.
- The optional `context` is either null or exactly binds `packet_digest`,
  `input_commit`, and `output_manifest_digest`. There is no arbitrary metadata.

`content_digest` detects inconsistent or non-rehashed changes to the unsigned
receipt body. Because it is unkeyed, an active attacker can replace both the body
and digest. An Ed25519 signature authenticates signer attribution against a
verifier-provided public key; it still does not establish claim truth.

## Build and verify

```bash
agent-receipt build \
  --workspace-root . \
  --agent worker --task "write report" --claim report="report exists" \
  --file-exists report=./report.md \
  --text-contains 'report=./report.md::PASS' \
  --out receipt.json

agent-receipt verify receipt.json --recheck --recheck-root .
```

Rechecks compare a current file hash to the hash observed while building the
receipt. They therefore catch later file changes.

## Command evidence

Commands run without a shell, with a constrained environment and bounded output.
They always run from the trusted build root; no cwd is stored in the receipt.
They can still execute repository code, so they are an explicit execution decision.

Command rechecks require both a verifier-selected root and an exact tuple allowlist:

```bash
agent-receipt verify receipt.json --recheck-commands --recheck-root . \
  --allow-command '/absolute/path/to/python -m pytest -q'
```

Inspect the executable, every argument, and the repository state before adding an
allowlist entry. The executable path must be absolute, so `PATH` cannot silently
select a different program. An unlisted receipt command fails closed. The
verifier, not the worker receipt, defines success as exit code 0, uses a fixed
20-second timeout, and ignores worker-selected output expectations. At most five
distinct commands may occur in one receipt.

Verification reports `assurance` and `coverage`. `reported` means no evidence was
rerun, `partially_rechecked` means only some evidence was independently rerun, and
`fully_rechecked` means every stored evidence item was rerun. Blocked command
evidence is counted separately and never presented as rechecked. By default,
verification exits successfully only for `fully_rechecked`. A lower threshold
requires an explicit decision such as `--minimum-assurance reported`; that mode
validates structure and internal consistency, not claim truth.

## Canonical output manifests

The controller can inventory a completed output directory without executing any
of its contents:

```bash
agent-receipt manifest create --workspace-root ./worker-output --json
agent-receipt manifest verify --workspace-root ./worker-output \
  --expected-digest '<independently trusted digest>' --json
```

Creation writes `OUTPUT_MANIFEST.json` under the selected root by default. The
manifest uses the strict `agent-output-manifest/v1` schema: relative POSIX paths
are unique and sorted, and every regular file has a SHA-256 and byte count. Its
digest is SHA-256 over canonical UTF-8 JSON with sorted object keys and compact
separators, excluding the storage newline. Verification rebuilds the inventory
and requires the exact file set, sizes, and hashes—not just the files named in the
manifest. JSON with duplicate object keys is rejected.

Traversal is descriptor-relative and bounded by file count, entry count, depth,
per-file size, total bytes, path length, and manifest size. Symbolic links, hard
links, special files, path traversal, duplicate paths, and detectable path/content
changes during scanning fail closed. `receipt.json` and `OUTPUT_MANIFEST.json` at
the root are control files and are excluded by default; a custom CLI manifest path
inside the root is also excluded exactly. No broad ignore patterns are applied.
Creation and verification each require two complete, identical scans. This catches
late changes missed by an earlier per-entry check, but it is not a transactional
filesystem snapshot and cannot prevent a write after the final system call. Stop
the worker before scanning and keep the output root quiescent until acceptance.

To bind a receipt to a handoff, supply all three strict context values at build and
verify time: `--packet-digest`, `--input-commit`, and `--output-manifest-digest`.
Verification compares the receipt context exactly to the verifier-provided values.
Use the digest printed by `manifest create`, transfer it through a trusted channel,
and independently run `manifest verify` before accepting the receipt. The digest
is unkeyed; use the receipt's Ed25519 signature when signer attribution is needed.

## Signatures

```bash
agent-receipt build ... --sign-private-key worker.pem --key-id worker-2026
agent-receipt verify receipt.json --trusted-key worker-2026=worker.pub \
  --minimum-assurance reported
```

Keep private keys out of receipts, repositories, command lines, and logs. Key IDs
are labels; the verifier's supplied public key is the trust anchor. The explicit
`reported` threshold above checks attribution and internal consistency only. Add
the appropriate independent rechecks before accepting any claim.
