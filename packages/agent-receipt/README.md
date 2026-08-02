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

To bind a receipt to a handoff, supply all three strict context values at build and
verify time: `--packet-digest`, `--input-commit`, and `--output-manifest-digest`.
Verification compares the receipt context exactly to the verifier-provided values.
The CLI does not generate the output manifest: it is an external, deterministic
artifact owned by the controller. Only use this context field when both sides have
agreed on the same canonical manifest format and the verifier computes its digest
independently.

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
