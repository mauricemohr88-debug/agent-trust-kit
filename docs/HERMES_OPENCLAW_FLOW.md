# Hermes to remote-worker handoff

The repository now includes a native Hermes plugin that keeps the controller
steps local and explicit. The standalone CLIs below remain useful for a worker
environment or for other orchestrators; the plugin is the recommended Hermes
entry point.

This walkthrough separates three things that are often confused:

1. selecting what may leave the controller;
2. checking archive integrity and structure at the worker;
3. independently rechecking returned evidence at the controller.

It does not create an OS sandbox. Run the worker and every controller-approved
command with the least privileges appropriate for the repository. The Hermes
plugin is not a global egress gate: terminal, browser, MCP, or manual paths can
still move data outside this flow.

## Native Hermes path

Install and configure the plugin on the trusted controller:

```bash
hermes plugins install file:///Users/maurice/Projects/agent-trust-kit --enable
hermes agent-trust project add my-project /path/to/git/project
```

Then use `handoff_prepare` with an explicit `project_id`, `task`, and `include`
list. Review the result and record operator approval:

```bash
hermes agent-trust approve <handoff-id>
hermes agent-trust return-path <handoff-id>
```

Only after approval should a separate worker workflow materialize the packet.
The worker must return the exact result files plus `OUTPUT_MANIFEST.json` and
`receipt.json` to the fixed quarantine path. Call `handoff_verify_return` to
create a private controller snapshot and perform the full recheck there. It
never executes receipt commands, creates a receipt, sends a packet, or merges
code. After successful verification, obtain the stable review location with:

```bash
hermes agent-trust verified-path <handoff-id>
```

Use that read-only snapshot for inspection. Copy it to a separate isolated
working directory before running any test or build that requires write access.

After work has stopped, the worker creates the manifest first and copies its
printed digest into all three receipt-context flags:

```bash
agent-receipt manifest create --workspace-root /tmp/worker-return

agent-receipt build \
  --workspace-root /tmp/worker-return \
  --agent remote-worker \
  --task "review the selected files" \
  --claim result="RESULT.md was returned" \
  --file-hash result=RESULT.md \
  --packet-digest '<approved-packet-sha256>' \
  --input-commit '<controller-input-commit>' \
  --output-manifest-digest '<printed-manifest-sha256>' \
  --out /tmp/worker-return/receipt.json
```

The native verifier requires every receipt evidence item to be independently
recheckable without commands. Command evidence therefore fails the native
`fully_rechecked` policy and is never executed by the plugin.

## 1. Controller: build and inspect

```bash
agent-packet build \
  --task "Review src/parser.py and write RESULT.md. Stay inside the payload." \
  --root /path/to/project \
  --include src/parser.py \
  --include tests/test_parser.py \
  --out /tmp/parser-packet

agent-packet inspect /tmp/parser-packet/packet.tar.gz --json
```

Review the task, included paths, file hashes, and omission/redaction counts before
sending anything. Secret detection is heuristic; it is not a guarantee that the
packet contains no sensitive value. Binary content is not scanned.

Send `packet.tar.gz`. Send its SHA-256 value over an authenticated channel that is
independent from an untrusted archive transport. A sidecar sent beside the archive
through the same channel only detects accidental corruption; an attacker can
replace both.

```bash
awk '{print $1}' /tmp/parser-packet/PACKET_SHA256.txt
```

## 2. Worker: materialize into a fresh directory

```bash
agent-packet materialize packet.tar.gz \
  --dest /tmp/parser-work \
  --expect-sha256 "$EXPECTED_PACKET_SHA256"

cd /tmp/parser-work/payload
# Work in an OS/container sandbox here.
printf 'PASS\n' > RESULT.md
```

Materialization rejects an existing destination, traversal, links, special files,
duplicates, undeclared members, oversized compressed/decompressed content,
unsupported PAX metadata, and payload hashes that do not match the manifest. The
digest and parser operate on one private snapshot; the destination parent is
canonicalized before extraction.

## 3. Worker: record claims without absolute paths

```bash
agent-receipt build \
  --workspace-root /tmp/parser-work/payload \
  --agent remote-worker \
  --task "review parser" \
  --claim result="RESULT.md exists and contains PASS" \
  --file-exists result=RESULT.md \
  --text-contains 'result=RESULT.md::PASS' \
  --file-hash result=RESULT.md \
  --out /tmp/parser-work/receipt.json
```

The receipt contains only workspace-relative evidence paths. Its unkeyed content
digest detects inconsistent or unrehashed edits, but an active attacker can
replace the body and digest together. Without a separately trusted signature it
does not identify the sender, and neither a digest nor a signature establishes
truth.

Return the changed workspace and `receipt.json` to the controller.

## 4. Controller: independently recheck

Choose the received checkout yourself; do not let the receipt select a root.

```bash
agent-receipt verify receipt.json \
  --recheck \
  --recheck-root /path/to/controller-selected/received-workspace
```

Look at both `ok` and `assurance`. `fully_rechecked` means every evidence item in
that receipt was rerun. `reported` means none was rerun. If the receipt includes a
worker-reported command, `--recheck` alone intentionally does not execute it.

Prefer running the controller's normal tests or CI policy directly. If you
explicitly choose receipt command rechecks, each exact command must be allowlisted:

```bash
agent-receipt verify receipt.json \
  --recheck \
  --recheck-commands \
  --recheck-root /path/to/controller-selected/received-workspace \
  --allow-command '/absolute/path/to/python -m pytest -q'
```

An allowlisted test or build command can execute repository code. The allowlist is
an execution decision, not a sandbox. The controller requires exit code 0, applies
a fixed 20-second timeout, requires an absolute executable path, and does not
trust worker-selected success criteria.

## Optional handoff context and signatures

A receipt can bind three controller-checked identifiers when all are available:

- packet archive SHA-256;
- input Git commit ID;
- SHA-256 of an externally generated deterministic output manifest.

Pass all three flags during `build`, then pass the independently known values
again during `verify`. A mismatch fails verification. Do not simply copy the
expected values out of the untrusted receipt.

The native Hermes flow requires this context and computes the output-manifest
digest independently at verification time. The worker must use the repository's
deterministic output-manifest format and return `OUTPUT_MANIFEST.json`; a
missing file, extra file, changed file, or context mismatch fails closed. The
standalone CLI remains flexible and may leave the optional context unset when
used outside the plugin.

Ed25519 signing can attribute a receipt to a trusted public key distributed by a
separate channel. It does not prove that commands ran or that outputs are safe.

## Reproduce this repository's flow

```bash
scripts/smoke_e2e.sh
```

The smoke test also changes the returned artifact after receipt creation and
requires the controller recheck to fail.
