# VulnusLab Pricing — DRAFT

> **Status:** scaffolding for sales conversation. Not yet published. Tune numbers
> based on customer feedback + 2-3 pilot customers' actual usage patterns.

## Tier comparison

| Capability | **Free** | **Pro** | **Team** | **Enterprise** |
|---|:-:|:-:|:-:|:-:|
| **Price (USD/month)** | $0 | $49 | $249 | Custom |
| **Scans per month** | 10 | 500 | 5,000 | Unlimited |
| Recon module (53 scanners) | ✅ | ✅ | ✅ | ✅ |
| Vuln module (198 scanners) | trial 7d | ✅ | ✅ | ✅ |
| Webapp module (64 scanners) | trial 7d | ✅ | ✅ | ✅ |
| OSINT + Mobile suite | — | ✅ | ✅ | ✅ |
| All 26 advisory-pack modules | — | ✅ | ✅ | ✅ |
| 144 live probes (Network/Cloud/APISec/...) | — | ✅ | ✅ | ✅ |
| Manual Pentest Checklist (78 cards) | — | ✅ | ✅ | ✅ |
| Combined PDF report (10 sections) | watermarked | ✅ | ✅ | ✅ |
| Compliance mapping (OWASP/CIS/NIST/PCI) | — | ✅ | ✅ | ✅ |
| Scan history (last 5 per module) | local only | local + cloud | ✅ | ✅ |
| Scan diff / remediation tracking | — | ✅ | ✅ | ✅ |
| CLI tool (CI/CD integration) | ✅ | ✅ | ✅ | ✅ |
| `/api/manifest` integration | ✅ | ✅ | ✅ | ✅ |
| Multi-user seats | 1 | 1 | up to 5 | unlimited |
| API rate limit (req/hour) | 60 | 600 | 3,000 | custom |
| Email support | community | 48hr SLA | 12hr SLA | 1hr SLA |
| SOC 2 report / DPA | — | — | ✅ | ✅ |
| Air-gap / self-hosted deploy | — | — | — | ✅ |
| Custom playbook authoring | — | — | — | ✅ |

## Pricing rationale (for sales conversations)

| Question | Answer |
|---|---|
| Why is Free so generous? | Lower friction to first scan. Most teams convert on PDF quality + remediation tracking, not feature gating. 10 scans/month = honest evaluation budget. |
| Why $49 → $249 jump (5×)? | Pro is solo consultant pricing. Team has multi-user + cloud history + scan diff for joint remediation review. The 5× isn't just seats — it's the team-collab features. |
| Why "Custom" for Enterprise? | Air-gap deploy + custom playbooks + SOC 2 negotiation needs human pricing. Don't anchor on a number — discover their budget first. |
| Competitive frame | Burp Pro = $475/yr (1 seat). Nessus Pro = $4,990/yr. Qualys/Tenable Enterprise = $30K+/yr. VulnusLab Team at $249/mo ($3K/yr) sits in the gap. |
| Trial mechanics | 7-day Vuln+Webapp trial unlocks the 2 most-asked modules. Recon free always = "evaluate forever" hook. |

## Annual / multi-year discounts

| Term | Discount |
|---|---:|
| Annual prepay | 17% off (2 months free) |
| 2-year prepay | 25% off |
| Non-profit / education | 50% off any tier |
| Open-source maintainers | 100% off Pro tier |

## Add-ons (any tier)

| Add-on | Price | Description |
|---|---:|---|
| Custom branding on PDF | $99/mo | Replace VulnusLab logo with customer's |
| Extra 1,000 scans | $29 | Burst purchase, no rollover |
| Dedicated EU region | $149/mo | EU data residency (Frankfurt) |
| White-label CLI | $499/mo | Resellers / partner programs |

## Sales metrics to track from day 1

- **Visitor → Free signup** rate (target: 5%)
- **Free → Pro conversion** within 30 days (target: 8%)
- **Pro → Team upgrade** within 6 months (target: 15%)
- **Annual prepay attach** rate (target: 35% of Pro+, 60% of Team+)
- **Monthly churn**, by tier (target: < 4% Pro, < 2% Team, < 1% Enterprise)
- **NRR (Net Revenue Retention)** (target: > 110% by month 12)

## Not deciding yet

- Per-target pricing (vs per-scan) — wait until pilot customers tell us they hate one model
- Free trial of Team tier — adds complexity, can A/B test in month 3
- Marketplace / partner revenue share — defer until 100+ paying customers
