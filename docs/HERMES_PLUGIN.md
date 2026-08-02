# Native Hermes plugin

`agent-trust-kit` can be loaded as a local Hermes plugin. It adds a small,
controller-owned handoff boundary around the existing `agent-packet` and
`agent-receipt` packages. The plugin keeps project registration, packet
creation, approval, quarantine, and return verification on the Hermes host.

## What it provides

The plugin registers three model-facing tools:

| Tool | Purpose |
| --- | --- |
| `handoff_prepare` | Build a bounded packet from a registered Git project and an explicit include list. |
| `handoff_status` | Read the bounded state of a handoff. |
| `handoff_verify_return` | Verify a returned result from the fixed private quarantine using the expected packet, commit, and output-manifest context. |

The plugin also registers the operator-facing `hermes agent-trust` command. Its
subcommands are `project add`, `project list`, `status`, `approve`, `reject`,
`return-path`, `verified-path`, and `doctor`.

There is deliberately no model-facing `send`, `materialize`, `create receipt`,
or `merge` operation. The intended workflow has an operator review and approve
a packet before it leaves the controller. A returned workspace is verified
without running commands; normal tests or CI remain a separate controller
decision.

## Installation

Install the public repository into the user Hermes plugin directory:

```bash
hermes plugins install mauricemohr88-debug/agent-trust-kit --enable
hermes agent-trust project add my-project /path/to/git/project
hermes agent-trust project list
hermes agent-trust doctor
```

Start a new Hermes session after enabling the plugin. The installer clones the
repository into Hermes' user plugin area. This plugin loads the two bundled
package sources from that exact clone and verifies their origins instead of
trusting another installed copy.

For local development, a committed working copy can be installed with
`hermes plugins install file:///absolute/path/to/agent-trust-kit --enable`.
The local Git installer clones committed files only.

## Typical controller flow

1. Register the project once with `project add`. The path must be a Git working
   tree and is kept in Hermes' local policy, not in a model prompt.
2. Ask Hermes to call `handoff_prepare` with a concrete task and explicit
   relative `include` paths. The policy requires a clean commit, and every
   packetized file must be a regular tracked blob whose bytes exactly match that
   commit. Ignored, untracked, filtered, and submodule content is refused.
3. Inspect the bounded result and use the operator-facing command
   `hermes agent-trust approve <handoff-id>` when the packet is acceptable.
4. Transfer and materialize the approved packet through the separately chosen
   worker workflow. The worker must return `OUTPUT_MANIFEST.json` and
   `receipt.json` alongside its result files.
5. Put the return in the path shown by
   `hermes agent-trust return-path <handoff-id>`, then ask Hermes to call
   `handoff_verify_return`. The plugin copies the declared files into a private,
   read-only controller snapshot, then checks the exact file set, packet digest,
   input commit, output-manifest digest, and receipt evidence against that
   snapshot.
6. Review the verification result, then obtain the controller-owned snapshot
   with `hermes agent-trust verified-path <handoff-id>`. Run read-only review
   tools against that snapshot. If a test or build needs write access, first
   copy it into a separate isolated working directory. The plugin never merges
   returned changes automatically.

The worker-side commands remain available for a deliberately separate worker
environment. See [the end-to-end flow](HERMES_OPENCLAW_FLOW.md) for the packet
and receipt format and for the independent transport assumptions.

## State and privacy

Runtime state is stored below Hermes' home in an `agent-trust` directory. Policy,
handoff metadata, packets, and the fixed return quarantine are private local
state. The plugin uses explicit includes and conservative deny rules; it does
not inspect an arbitrary home directory or silently include the whole project.
Operator CLI output may show local paths when needed to approve or materialize a
packet. Model-facing tool responses are bounded and avoid exposing those local
paths unnecessarily. A successful verification retains a private read-only
snapshot and rechecks its manifest and receipt before reporting it as verified
again; later changes in the original return directory are not trusted.

## Security boundary

This is a handoff control, not a global egress control or OS sandbox. Other
Hermes tools (for example terminal, browser, or MCP tools), manual copy/paste,
and an already-compromised host can bypass this workflow. The optional hook is
only narrow defense-in-depth for selected delegation/message calls; it is not a
complete transport gate, and Hermes plugin hooks must not be treated as a
kernel-enforced boundary. In particular, the CLI records operator intent but
does not authenticate a human against another process running as the same macOS
user; an unrestricted terminal tool can invoke or bypass it. Use least-privilege
credentials, an isolated worker, restricted controller tools, and an
OS/container sandbox for untrusted code.

The plugin cannot prove that a worker was honest or that a reviewed change is
safe. It makes the selected boundary explicit, gives the controller a stable
digest context, and refuses ambiguous or incomplete returns.
