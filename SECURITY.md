# Security policy

## Supported versions

This project is not publicly released yet. Until the first tagged release, only
the current `main` branch is eligible for security fixes.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that could expose files,
execute unintended code, bypass archive validation, or misrepresent a receipt as
independently verified.

After the repository is published, use GitHub's **Report a vulnerability** form
under the Security tab. Include:

- the affected command and version/commit;
- a minimal reproduction using synthetic data only;
- the expected and actual trust boundary;
- whether arbitrary file read/write or command execution is possible.

Do not include real credentials or private customer data. We will acknowledge a
complete report as soon as practical and coordinate disclosure after a fix is
available. This policy is not a bug-bounty promise.
