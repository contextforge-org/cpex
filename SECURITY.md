# Security Policy

## Supported Versions

| Version | Track            | Supported                          |
| ------- | ---------------- | ---------------------------------- |
| `0.2.x` | Rust (`main`)    | Yes (current development line)     |
| `0.1.x` | Python (`0.1.x`) | Maintainance mode (legacy)         |
| `< 0.1` | —                | No.                                |

Only the latest patch release of each supported minor version receives fixes.
CPEX is pre-`1.0`; APIs and the security model may change between minor versions.

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's **Private Vulnerability Reporting**:

1. Go to the [Security tab](https://github.com/contextforge-org/cpex/security) of the repository.
2. Click **Report a vulnerability** (or use
   <https://github.com/contextforge-org/cpex/security/advisories/new>).
3. Provide the details below.

This opens a private advisory visible only to you and the maintainers.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal proof of concept helps).
- Affected versions, crates, and configuration (e.g. which features / builtins).
- Any mitigations or workarounds you have identified.

## Response Process

- We will acknowledge your report, typically within a few business days.
- We will investigate, keep you updated on progress, and coordinate a fix and
  disclosure timeline with you.
- Prior to `v1.0.0` we work with reporters individually on timelines; we will
  credit you in the advisory unless you prefer to remain anonymous.

## Severity Classification

- **Critical** — Remote code execution, authentication/authorization bypass, or
  policy-enforcement bypass that defeats CPEX's core guarantees without user
  interaction.
- **High** — Privilege escalation, significant data exposure, or denial of
  service with amplification.
- **Medium** — Information disclosure of limited scope, or denial of service
  requiring sustained effort.
- **Low** — Issues requiring unlikely configurations or with minimal impact.

## Safe Harbor

We consider security research conducted in good faith under this policy to be
authorized. We will not pursue legal action against researchers who follow it
and report findings responsibly. Thank you for helping keep CPEX secure.
