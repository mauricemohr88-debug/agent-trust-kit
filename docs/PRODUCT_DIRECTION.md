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

## Open source and optional later work

Open source:

- complete offline CLIs and file formats;
- path, archive, schema, and integrity checks;
- verifier-controlled rechecks and signature verification;
- default policy examples, CI examples, and threat models.

Possible later paid work, not an active offer:

- workflow and repository review;
- organisation-specific include/deny and command policies;
- implementation in CI or an agent orchestration stack;
- managed identities, history, approvals, SSO/RBAC, support, and SLAs if customers
  later demonstrate demand.

Core verification must not become artificially weak to create a paywall.

## Current focus: free, asynchronous workflow validation

As of 2026-09-12, the manually delivered 149 € review pilot is paused. Its calls,
48-hour turnaround, and follow-up support require operator time; they are not
the current onboarding route. The [offer](FOUNDING_PILOT_DE.md),
[intake](PILOT_INTAKE_DE.md), and [sales drafts](SALES_LAUNCH_DE.md) are historical
records, not booking or outreach instructions.

The immediate task is to help two independent testers complete one
non-sensitive packet → receipt → controller-recheck flow and report the first
point of friction in
[issue #3](https://github.com/mauricemohr88-debug/agent-trust-kit/issues/3).
Participation is free and asynchronous; no call or paid review is required.
Record installation, a local example, a real handoff, help needed, and repeat use
separately. Missing tester feedback is unknown, not adoption or revenue.

Keep the complete local core free. Do not add billing, a hosted control plane,
or another service offer on the strength of a release or maintainer smoke test.
Any later convenience layer needs repeated use and a concrete recurring problem
reported by independent users first.

## Historical revenue test — paused

The former plan was to sell three **149 € Agent Handoff Review** founding pilots
before building a hosted dashboard. Each pilot covered one immutable revision
of one Python/JavaScript/TypeScript repository, one handoff, no more than three
relevant directories or about 20,000 relevant LOC, a short prioritised report,
a tailored policy, one
controller-defined local gate, and a 30-minute handoff. The proposed 48-hour
clock would start only after payment, sanitised intake, and written scope
confirmation. Fix implementation and CI integration were separate work.

The former 14-day success criteria were:

- one paid pilot or three qualified conversations;
- one adversarially tested real handoff;
- two outside testers able to follow the quick start;
- zero open release-blocking security findings.

## Historical 14-day execution — not the current work queue

1. Finish threat models, archive and receipt recheck hardening.
2. Make test, lint, build, package-content, and end-to-end gates reproducible.
3. Dogfood one non-sensitive Hermes-to-worker handoff.
4. Publish `v0.1.0` as an explicitly early beta after technical checks and
   Maurice's approval, while keeping the missing outside validation visible.
5. Give the beta to two operators and fix onboarding friction before describing
   the quick start as independently validated.
6. Contact ten to fifteen relevant agent operators personally with the founding
   pilot, focusing on their workflow rather than broadcasting generic promotion.
7. Deliver the first pilot manually and record repeated work before automating it.
