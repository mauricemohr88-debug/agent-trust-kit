# agent-packet

**Conservatively filtered task packets for Hermes, OpenClaw, and other AI agents.**

Agents should not get raw home directories, `.env` files, or API keys when you hand work to an untrusted/sandboxed worker. `agent-packet` builds a portable, inspectable packet:

- allowlisted files only
- private paths denied (`private/`, `.env`, keys, credentials)
- files with secret-like strings blocked by default (optional explicit redaction)
- secret-like path components, `.env*` files, key files, and URL userinfo blocked
- external SHA-256 sidecar + tar.gz archive (no self-referential manifest hash)
- receiver validates the archive structure and listed file hashes before materializing

No network required. MIT. Python 3.10+.

## Install

```bash
uv tool install ./packages/agent-packet
# for contributors working inside the package:
pip install -e "./packages/agent-packet[dev]"
```

## Quick start (Hermes → OpenClaw)

```bash
# On the trusted Mac / Hermes side
agent-packet build \
  --task "Review this module and propose 3 safe local improvements. Do not request secrets." \
  --root ~/my-project \
  --include src \
  --include README.md \
  --out /tmp/oc-packet

# Inspect what would leave the machine
agent-packet inspect /tmp/oc-packet/packet.tar.gz --json | head

# On the worker / OpenClaw side
agent-packet materialize /tmp/oc-packet/packet.tar.gz --dest /tmp/oc-work \
  --expect-sha256 "$EXPECTED_PACKET_SHA256"
cat /tmp/oc-work/payload/TASK.md
```

When a file must be shared with a credential-shaped value removed, opt in explicitly:

```bash
agent-packet build --task "Review config" --root ./project --include config.py \
  --redact-secrets --out /tmp/oc-packet
agent-packet materialize /tmp/oc-packet/packet.tar.gz --dest /tmp/oc-work \
  --expect-sha256 "$EXPECTED_PACKET_SHA256"
```

Redaction is a leakage-reduction aid, not a semantics-preserving code transform.
Review redacted files before asking a worker to build or execute them.

`materialize` refuses an existing destination, archive links, traversal, duplicate
members, links/special files, unexpected files, oversized compressed or
decompressed archives, and unsupported/oversized PAX metadata. It hashes one
private snapshot and parses those same bytes, so replacing the source path between
the two steps cannot change the materialized payload. Destination parents are
canonicalized before staging and again before the final rename. The manifest never
records the producer's absolute source path or names of omitted include paths.

`build` requires at least one explicit `--include`; root aliases such as
`--include .` are refused. Selecting the entire root requires the visibly
intentional `--include-all` flag. `materialize` requires an
expected digest by default; obtain it independently from the archive transport.
`--accept-untrusted-archive` retains structural and file-hash checks but cannot
authenticate a replacement archive.

`--allow-binary` only allows binary files past the type filter; binary content is
not secret-scanned. Use it only for reviewed, non-sensitive inputs.

## Why this exists

Multi-agent setups (Hermes orchestrator + OpenClaw VPS worker, or any untrusted sub-agent) constantly leak context by accident:

- whole repo zips including `.env`
- chat paste with tokens
- “just send the folder”

`agent-packet` makes the selected boundary explicit and inspectable. Secret-like
text files are omitted by default; review the manifest counts and archive contents
before transport because heuristic detection can miss secrets.

## CLI

| Command | Purpose |
|---|---|
| `agent-packet build` | Create packet + manifest + archive |
| `agent-packet materialize` | Extract + verify hashes |
| `agent-packet inspect` | Summarize manifest |

## Agent usage contract

1. **Producer agent** builds a packet for a specific task.
2. **Consumer agent** only sees materialised `payload/`.
3. Consumer returns results (and ideally an `agent-receipt`).
4. Producer verifies receipt before trusting “done”.

## Open core and paid work

The complete local CLI stays open source and offline-first. Teams can pay for a
bounded workflow review, organisation-specific include/deny policies, CI or
orchestrator integration, and support. The first offer is a manually delivered
founding pilot, not a hosted dashboard.

## License

MIT
