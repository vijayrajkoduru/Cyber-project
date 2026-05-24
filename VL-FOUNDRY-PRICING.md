# VL-FOUNDRY Layer 8 — Pricing Tier Mapping

Concrete mapping of scanners to pricing tiers. Enforced at scan-request time
(quota check + scanner allow-list per plan).

---

## Tier ladder

| Tier | Price | Scans/mo | Targets | Modules |
|---|---|---|---|---|
| **Free** | $0 | 3 | 1 | Recon only |
| **Starter** | ₹2,499 / $29 | 50 | 5 | Recon + Vuln |
| **Pro** | ₹12,499 / $149 | 500 | 25 | All 3 + API |
| **Enterprise** | ₹74,999+ / $999+ | unlimited | unlimited | All + scheduled + SSO + SOC2 evidence pack |

## What each tier gets

### Free
- Recon module (all 41 scanners, but **Wayback / GitHub Leaks / Breach Search disabled**)
- Watermarked PDF
- 1 target per scan, 3 scans/month
- No API access
- 7-day report retention

### Starter
- Recon module — **full** (no scanner gating)
- Vuln module — **partial** (16 scanners, but `default_creds` brute-force capped at 50 attempts)
- Webapp module — **NOT included** (Pro+ only)
- Unwatermarked PDF
- API access (50 req/day)
- 30-day report retention

### Pro
- All 3 modules — **full**
- Branded PDF (customer logo on cover)
- All AI-curated wordlists (no caps)
- Authenticated scan (`authenticated_scan` scanner)
- API access (1000 req/day)
- Webhook callbacks
- 90-day report retention
- Slack / Teams integration

### Enterprise
- Everything in Pro
- Scheduled scans (cron)
- Multiple users + SSO (SAML / OIDC)
- SOC2 / PCI evidence pack (auto-generated audit artifacts per finding)
- Dedicated VPS or on-prem deployment option
- Custom CVE-2025 mappings
- Audit log export
- Priority support (4h response SLA)
- 365-day report retention

---

## Per-scanner gating

Most scanners are available at all tiers, but a few are gated:

| Scanner | Min tier | Reason |
|---|---|---|
| `webapp/authenticated_scan` | Pro | Requires customer auth credentials |
| `webapp/race_condition` | Pro | Can cause real DB writes if misused |
| `webapp/http_smuggling` | Pro | Could cause actual smuggling on misconfigured targets |
| `webapp/file_upload_bypass` | Pro | Same risk |
| `vuln/default_creds` (deep, 800 pairs) | Pro | Could lock accounts on customer infra |
| `vuln/snmp_enum` (120 strings) | Pro | Same lockout risk |
| `recon/wayback` | Starter | API rate-limited |
| `recon/github_leaks` | Starter | API rate-limited |
| `recon/breach_search` | Starter | Third-party data cost |

Free tier additionally gets:
- `default_creds` capped at 10 most-common pairs
- `snmp_enum` capped at 10 community strings
- All AI-curated wordlists capped at 50 entries

---

## Quota enforcement

Implemented in `tools/_shared.py::verify_scan_quota()`. Called by every
scanner via `Depends(verify_scan_quota)`. Reads `User.plan` + counts
`User.scans_this_month` against quota table above.

Returns 429 with JSON `{"detail": "Scan quota exceeded for Free plan",
"upgrade_url": "/billing"}` when hit.

---

## Upsell triggers (post-scan UI)

After every Free / Starter scan, show contextual upsell:

| Trigger | Upsell message |
|---|---|
| Free user finds 1+ CRITICAL | "Upgrade to Starter to scan all your assets" |
| Starter user runs out of scans | "Pro = 10x more scans + Webapp module" |
| Pro user with 25+ scans/mo | "Enterprise = unlimited + scheduled + SSO" |
| Customer reads PDF for >2 min | "Want this delivered to Slack every Friday? → Pro" |

---

## Revenue projections (sanity check)

Assuming:
- 100 Free users (free tier)
- 30 Starter users × $29 = $870/mo
- 10 Pro users × $149 = $1,490/mo
- 2 Enterprise × $999 = $1,998/mo

= **~$4,358/mo at 142 users.** Year 1 target: get to this in 6 months.

Cost (from VL-FOUNDRY.md Layer 12 cost model): ~$40/mo for 1,000 scans.
Even at 5× that scale, infra cost is < $200/mo → ~95% gross margin.

---

## Pricing update process

When prices change:
1. Update this file
2. Update billing system (Razorpay / Stripe)
3. Grandfather existing customers for 1 year
4. Announce 30 days before new pricing takes effect

Don't change tier→scanner gating mid-quarter without giving Pro+ customers
60-day notice. Trust-busting.
