# Agent Handoff Review

- **Client:** [name]
- **Review date:** [YYYY-MM-DD]
- **Reviewer:** Maurice Mohr
- **Repository / revision:** [repository and immutable commit]
- **Workflow:** [controller -> transport -> worker -> returned result]

## Executive summary

[Three to five plain-language sentences: what was reviewed, the most important
risk, what was delivered, and the remaining decision. Do not describe this review
as a certification, penetration test, or guarantee.]

**Recommended decision:** [use after fixes / limited pilot only / do not use yet]

| Severity | Open | Resolved during review |
|---|---:|---:|
| P0 — immediate disclosure or unintended execution | 0 | 0 |
| P1 — likely boundary bypass or false acceptance | 0 | 0 |
| P2 — hardening, observability, or usability gap | 0 | 0 |

## Scope and assumptions

Included:

- [one Python/JavaScript/TypeScript repository and immutable revision]
- [up to three relevant directories / about 20,000 relevant LOC]
- [one handoff path]
- [packet selection and transport]
- [worker result and controller verification]

Not included:

- penetration testing, malware analysis, dependency audit, legal/compliance
  advice, production secrets, or a guarantee against a compromised worker;
- systems and revisions not listed above.

## Trust boundary

| Component | Trust assumption | Data or authority exposed |
|---|---|---|
| Controller | trusted | source selection, expected digests, command policy |
| Transport | untrusted | packet and receipt bytes |
| Worker | untrusted | selected payload and sandbox permissions |
| Verification workspace | controller-selected | returned files and approved checks |

## Findings

### [P1-01] Short, specific title

- **Impact:** [what a realistic failure permits]
- **Evidence:** [file/line, command, or synthetic reproduction]
- **Root cause:** [why the boundary fails]
- **Recommendation:** [smallest reliable change]
- **Verification:** [exact command or test proving the fix]
- **Status:** [open / resolved / accepted risk]

## Delivered policy

### Included inputs

- `[path or glob]` — [reason]

### Denied inputs

- `[path or glob]` — [reason]

### Controller-owned checks

```bash
[exact reproducible command]
```

Explain which checks execute repository code and where isolation is required.

## Reproducible gate result

| Gate | Result | Evidence |
|---|---|---|
| Archive structure and exact member set | PASS/FAIL | [command/output digest] |
| Packet digest matches expected value | PASS/FAIL | [digest source] |
| Receipt schema and content digest | PASS/FAIL | [command] |
| Context matches controller expectations | PASS/FAIL/N/A | [values/source] |
| Evidence recheck coverage | reported/partial/full | [coverage object] |
| Controller test/CI policy | PASS/FAIL | [run URL or local command] |

## Residual risks

- Heuristic secret detection can miss unknown, encoded, split, or binary secrets.
- Approved commands may execute repository code and require a separate sandbox.
- Signatures attribute content to a key; they do not establish truth or safety.
- [workflow-specific residual risk]

## Handoff

- Delivered files: [list]
- Fix owner and due date: [list]
- Seven-day question window ends: [date]
- Client acknowledgement: [name/date; acknowledgement is not certification]
