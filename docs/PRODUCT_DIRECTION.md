# Product direction

## Product boundary

Keep `agent-packet` and `agent-receipt` together in one repository because they
form one handoff workflow. Keep Hermes Plugin Guard separate because it already
has its own users, package, release cadence, and narrowly defined plugin-scanning
job.

Do not force a public brand rename before release. Several obvious names in this
category already belong to active, similar projects. Recheck GitHub, PyPI, npm,
domains, and relevant trademarks immediately before selecting the public repo and
distribution names. The current repository name is a working name, not a legal
clearance claim.

## Honest positioning

Use:

> Reduce accidental data disclosure and make agent handoffs structured and
> independently recheckable.

Avoid:

- safe or secret-free packets;
- proof that a worker ran a command;
- verified, authentic, tamper-proof, zero-trust, or compliant workflows;
- signatures described as proof that a claim is true.

## Open source and paid boundary

Open source:

- complete offline CLIs and file formats;
- path, archive, schema, and integrity checks;
- verifier-controlled rechecks and signature verification;
- default policy examples, CI examples, and threat models.

Paid:

- workflow and repository review;
- organisation-specific include/deny and command policies;
- implementation in CI or an agent orchestration stack;
- managed identities, history, approvals, SSO/RBAC, support, and SLAs if customers
  later demonstrate demand.

Core verification must not become artificially weak to create a paywall.

## First revenue test

Sell three **149 € Agent Handoff Review** founding pilots before building a hosted
dashboard. Each pilot covers one immutable revision of one Python/JavaScript/
TypeScript repository, one handoff, no more than three relevant directories or
about 20,000 relevant LOC, a short prioritised report, a tailored policy, one
controller-defined local gate, and a 30-minute handoff. The 48-hour clock starts
only after payment, sanitised intake, and written scope confirmation. Fix
implementation and CI integration are separate work.

Success after 14 days:

- one paid pilot or three qualified conversations;
- one adversarially tested real handoff;
- two outside testers able to follow the quick start;
- zero open release-blocking security findings.

Only build a hosted product after at least three paid pilots reveal a repeated
problem that software can remove.

## 14-day execution

1. Finish threat models, archive and receipt recheck hardening.
2. Make test, lint, build, package-content, and end-to-end gates reproducible.
3. Dogfood one non-sensitive Hermes-to-worker handoff.
4. Give the release candidate to two operators and fix onboarding friction.
5. Publish only after the release checklist is green and Maurice approves it.
6. Contact ten to fifteen relevant agent operators personally with the founding
   pilot, focusing on their workflow rather than broadcasting generic promotion.
7. Deliver the first pilot manually and record repeated work before automating it.
