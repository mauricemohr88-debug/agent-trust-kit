# Hermes v0.20.0 compatibility record

Date: 2026-08-05

## Scope and result

This was an isolated compatibility test against the official Hermes tag
`v2026.8.3` (Hermes v0.20.0). It was not a live upgrade of this repository's
Hermes installation, deployment, or dogfood environment.

Observed in the isolated test environment:

- the installer accepted `plugin.yaml`;
- the loader registered `handoff_prepare`, `handoff_status`, and
  `handoff_verify_return`;
- the operator CLI was available as `hermes agent-trust`;
- the narrow `pre_tool_call` hook loaded;
- focused smoke tests blocked a `send_message` input shaped like a private key
  and returned the bounded `project_not_registered` result for an unregistered
  project; and
- the integration suite passed: 29 passed.

Hermes v0.20.0 officially requires Node 26; that runtime requirement applies
when reproducing this v0.20.0 compatibility check.

## Interpretation and limits

The observed results support compatibility for the tested plugin installation,
tool registration, CLI, hook, and smoke paths at the stated tag. They do not
establish production deployment compatibility, a live upgrade, a security
guarantee, or coverage of every Hermes workflow.

The earlier Hermes Agent 0.15.1 installation and real non-sensitive dogfood
workflow remain separate historical evidence in
[the local validation record](LOCAL_VALIDATION.md) and
[the dogfood record](DOGFOOD_2026-08-03.md).
