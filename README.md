# Agent handoff tools

Two small, offline-first Python CLIs for passing bounded work to another AI agent
and checking the result without treating its prose as truth.

| Tool | Boundary it adds |
|---|---|
| [`agent-packet`](packages/agent-packet/) | Builds an allowlist-based handoff archive and rejects known private paths, links, unsafe archive structures, and secret-like text. |
| [`agent-receipt`](packages/agent-receipt/) | Records claims and evidence, then lets a controller repeat explicitly selected checks inside a controller-chosen workspace. |

The intended flow is:

```text
trusted controller -> inspectable packet -> remote worker
trusted controller <- changes + receipt <- remote worker
trusted controller -> independent checks -> accept or reject
```

This repository is a **local release candidate**. The tools reduce common handoff
mistakes; they do not sandbox an agent, certify code, guarantee that no secret is
present, or prove that a worker told the truth. Read the
[threat model](THREAT_MODEL.md) before using them with private work.

## Development

Requirements: Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --all-packages --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
```

Package-specific instructions and examples live in each package README. The
[Hermes/OpenClaw walkthrough](docs/HERMES_OPENCLAW_FLOW.md) shows the complete
handoff and independent verification boundary.

## Why open source, and what can be paid?

The local formats, scanners, verification logic, signatures, and CI examples stay
open. Teams can pay for judgement and implementation: a workflow review, a custom
policy, CI integration, and support. The first concrete offer is the
[149 € founding pilot](docs/FOUNDING_PILOT_DE.md), not a premature hosted dashboard.
The [German intake](docs/PILOT_INTAKE_DE.md) fixes the paid scope before work starts.

## Relationship to Hermes Plugin Guard

[Hermes Plugin Guard](https://github.com/mauricemohr88-debug/hermes-plugin-guard)
remains a separate project: it examines a plugin before activation. These tools
cover the later handoff boundary. They may be used together but have independent
release and support cycles.

## Status

- No repository or package has been published from this working copy.
- The original ZIP remains unchanged.
- Local lint, the Python 3.10–3.14 test matrix, package builds, wheel-install
  smoke, and the end-to-end handoff are green; see the
  [local validation record](docs/LOCAL_VALIDATION.md).
- Remote GitHub CI/CodeQL, one real non-sensitive dogfood workflow, two outside
  testers, and Maurice's explicit approval remain before public package release.

MIT licensed. See [SECURITY.md](SECURITY.md) for responsible reporting.
