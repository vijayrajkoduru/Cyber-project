# Security Policy

VulnusLab is a vulnerability-assessment platform, so we hold ourselves to the
standard we measure others against. This document covers how to report a security
issue and what we commit to in return.

## Reporting a vulnerability

Please report security issues privately. Do **not** open a public GitHub issue
for anything security-sensitive.

- Email: security@vulnuslab.com
- Include: a description, affected component/URL, reproduction steps, and impact.
- If you can, attach a proof-of-concept (redact any real customer data).

We support coordinated disclosure. Please give us a reasonable window to fix an
issue before any public write-up, and do not access, modify, or exfiltrate data
that is not yours while testing.

## Our commitments

- Acknowledge your report within 3 business days.
- Provide a triage assessment (severity + planned fix window) within 7 business days.
- Keep you updated through remediation and credit you (if you wish) once fixed.

## Scope

In scope:
- The VulnusLab application (`app.vulnuslab.com`) and its API (`/api/*`).
- The marketing site (`vulnuslab.com`).

Out of scope:
- Findings that require a compromised account, physical access, or social engineering.
- Volumetric DoS / DDoS.
- Reports from automated scanners with no demonstrated impact.
- The deliberately-vulnerable lab targets we bundle for testing (DVWA, Juice Shop,
  Metasploitable, etc.) — those are intentionally insecure.

## Safe harbor

We will not pursue or support legal action against researchers who:
- Make a good-faith effort to follow this policy,
- Avoid privacy violations, data destruction, and service degradation, and
- Give us a chance to remediate before public disclosure.

## Handling of customer data

- Scans are gated by an explicit per-scan authorization attestation, which is
  logged (who, what, when, from where).
- Customers can export (`GET /api/account/export`) and delete (`POST
  /api/account/delete`) their own data.
- Secrets are kept out of the repository; commits are scanned for secrets in CI
  (gitleaks) to prevent credential leakage.
