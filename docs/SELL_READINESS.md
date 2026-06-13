# VulnusLab — Build-to-Sell Readiness

Evidence-based audit (2026-06-13, 11-agent sweep of Cyber-project + vulnuslab-marketing +
vulnuslab-private). The scanning product is mature; the gaps are commercial plumbing.

## Already strong — DO NOT rebuild
- **Scanning engine** — 360+ real scanners across ~13 tiers, Kali-first + pure-Python fallback,
  NDJSON streaming orchestrator, VL-TURBO 60s caps, 256-thread pool. This is the moat.
- **Reports** — multiple PDF generators, AES-128 password-protected + HMAC-SHA256 signed PDFs,
  CSV/JSON/SARIF 2.1, HackerOne/Bugcrowd export, OWASP scorecard, CWE→PCI/HIPAA/SOC2/ISO/NIST/CIS/GDPR
  mapping, white-label branding API, scan history + diff. Gap is persistence/sharing, not quality.
- **Auth + multi-tenancy** — register/login/me, bcrypt, JWT (HS256 7d), user/admin/superadmin roles,
  per-user data isolation (userzone), encrypted credential vault, admin user management. (The
  "no auth" claim from the marketing-layer audit was wrong — it looked at the landing page, not the
  dashboard backend.)
- **Entitlements scaffolding** — users.plan field, JWT plan claim, frontend trial whitelist +
  tool-locking UI + "Upgrade to Pro" gating, admin plan-change/extend. Plumbing exists; only
  enforcement + expiry + a counter are missing.
- **Abuse primitives** — RFC-2606/6761 reserved-domain auto-skip, per-user/IP rate limit (100/hr),
  JWT-gated scans, append-only JSONL scan audit trail, and a consent_log backend (built but unwired).
- **Deployment** — single-VPS Docker Compose, 4 Uvicorn workers, healthchecks, mem limits, auto
  restart, post-deploy snapshot + auto-rollback, backup/restore endpoints. Good enough to launch.
- **Marketing site** — hero, trust bar, demo, 51-scanner grid, 3-tier pricing, testimonials, FAQ,
  contact form. Built; needs deploy + legal links + payment CTA.
- **Demo labs** — DVWA/Juice Shop/bWAPP/Mutillidae/WebGoat + DB/AD/OAuth/SAML/ICS/K8s auto-run in
  compose = a ready-made safe demo/onboarding sandbox at zero extra cost.

## Minimal path to first sale (the must-haves)
1. **[M] Payments** — pick a processor with HOSTED checkout (Razorpay primary for India MSME;
   Polar/Paddle as merchant-of-record fallback). Build `POST /api/payment/create-order` +
   signature-verified `POST /api/payment/webhook` that, on success, creates the user with plan +
   expiry. There is currently ZERO payment code; Lemon Squeezy rejected KYC. Hosted checkout = no
   PCI scope on you.
2. **[S] Transactional email** — one provider (SendGrid free / Zoho / Gmail SMTP) to send the
   credentials/welcome email after the webhook. No email service exists today; without it a paid
   customer never gets a login.
3. **[M] Entitlement enforcement** — add `subscription_expires_at` + a scan counter to users;
   implement `verify_scan_quota()` (confirmed no-op TODO at tools/_shared.py:133): block scans when
   expired or over the per-plan cap. You can't bill a metric you don't measure.
4. **[M] Legal pack** — Terms of Service, Privacy Policy, Acceptable Use / Scanning-Authorization
   clause, India DPDP statement. Serve at /terms, /privacy; link from footer + signup. Selling an
   offensive scanner with no ToS/AUP is uninsurable exposure.
5. **[S] Authorization gates** — DONE for the per-scan gate (commit 95ebe64b): an "I am authorized
   to scan this target" checkbox now gates Start in webapp + recon + ModuleAutoPanel (33 modules)
   and POSTs to the (previously dead) /api/scan/consent_log on every run. STILL PENDING: the
   ToS-acceptance checkbox on the signup form (depends on the legal pack #4 existing).
6. **[S] HTTPS verify/harden** — confirm TLS (likely Cloudflare-terminated for app.vulnuslab.com);
   set Cloudflare to Full (strict) so CF→origin is encrypted, force HTTP→HTTPS + HSTS. If the origin
   is plaintext-only behind flexible SSL, fix to full-strict.
7. **[M] Report persistence** — persist the generated PDF on scan completion with a stable Report ID
   + a re-download endpoint. Today reports live only in browser memory; close the tab = deliverable
   lost.
8. **[S] Deploy the marketing site** to vulnuslab.com with a payment CTA + legal links (content is
   already built).

## P1 — within weeks of launch
- [M] Password reset + email verification (needs the email service)
- [M] Server-side logout / JWT revocation (token blacklist) + /api/auth/logout
- [S] Account settings API (change password/email, self-serve delete + data export)
- [M] Billing self-service: GET /billing/status, upgrade/downgrade, cancel; instant checkout replaces
  the manual contact-form flow for paid plans
- [M] Auto-downgrade on expiry + dunning/past-due + 7-day expiry-warning email
- [M] Invoice generation + emailed receipts (GST-compliant numbering)
- [M] Per-customer scope whitelist + high-liability/private-IP blocklist (.gov/.mil/banks, RFC1918)
  enforced before run_all
- [M] Admin/sensitive-action audit logging (plan changes, backups, credential access, logins)
- [S] CI security gates: gitleaks + pip-audit + semgrep (tools already in the image, never run);
  move secrets out of repo + rotate exposed keys
- [M] New-user onboarding: empty-state "run your first scan" card, trial quota indicator + upsell,
  short first-run walkthrough
- [M] Automated daily DB backup to off-box (S3) + error capture (Sentry)
- [M] Sample PDF download + Security/Trust page + legal links on the marketing site

## P2 — scale / polish
- [L] Org/team workspaces + RBAC + invitations + seat enforcement (Team tier)
- [M] API keys for CI/CD service accounts + optional TOTP MFA
- [L] Unify PDF generators into one generateUniversalVLReport (all 26+ modules) + combined report +
  encrypted-at-rest storage
- [L] Founder business dashboard: MRR, churn, conversion, LTV, abuse alerts
- [M] Payment customer-portal + annual-prepay discount + add-on SKUs
- [M] Reliability scale-out: Redis rate limiting, tracing/correlation IDs, SQLite WAL+busy_timeout,
  Prometheus/Grafana, Alembic migrations
- [M] Data retention/auto-purge + customer data-export + DLP redaction of secrets found in results
- [M] SECURITY.md + disclosure policy; annual third-party pentest / bug bounty of the platform
- [L] SEO/content/analytics: blog, GA/Mixpanel funnel, OG/schema metadata, onboarding email sequence,
  fix the $29-vs-$49 pricing inconsistency
- [M] In-app onboarding depth: tooltips, "start here" recommender, finding-interpretation guide

## Non-code gaps the audit flagged (business, not build)
- **Tax/invoicing** — India GST applicability + GST-compliant invoice numbering; FEMA/LUT for export
  of services (selling internationally as a Udyam MSME); bookkeeping.
- **Support ops** — no helpdesk/ticketing/status page, yet PRICING.md promises 12h/1h SLAs for
  Team/Enterprise. Decide the support channel before promising SLAs.
- **Sales motion** — no CRM, no demo-booking calendar, no quote/order process for the custom
  Enterprise tier; the contact form has no documented follow-up.
- **Insurance** — professional indemnity / cyber / E&O for an offensive-scanning vendor; enterprise
  procurement often requires it.
- **Brand/IP** — VulnusLab trademark + domain/handle defense + brand kit ownership.
- **Data residency** — where customer data physically lives (a claim enterprises ask for) + a tested
  restore drill (RTO/RPO).
- **Pricing validation** — talk to real prospects before locking pricing; resolve the $29/$49
  inconsistency across the site/docs.
