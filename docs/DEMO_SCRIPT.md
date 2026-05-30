# VulnusLab Sales Demo — 15-minute script

> **Goal:** Show real findings on the prospect's own domain in under 15 minutes.
> Real findings are the close. Don't lead with feature lists.

## Pre-call setup (5 min before)

1. Get prospect's primary domain (e.g. `example.com`) from their email
2. Open `app.vulnuslab.com` in Incognito
3. Log in as demo account
4. Don't pre-run the scan — the streaming UX is part of the demo

## The script

### 1. Open (30 seconds)

> "I'm going to scan **your own domain** live in this call. We'll have real findings in under 2 minutes. No slides. Ready?"

(Wait for "yes". This locks them in.)

### 2. Module choice (30 seconds)

> "Three modules cover 90% of what most teams use: **Recon**, **Phishing**, and **Network**. Let me show Phishing first — fastest, and almost everyone has at least one finding."

Click **Phishing & Social Engineering** in sidebar.

### 3. The first finding (90 seconds)

Enter their domain → click **`Run All (70)`**.

Watch the streaming tiles. Within ~10 seconds, the `mailspoof_spoofcheck` tile will likely turn HIGH (orange) for most companies.

> "There — see the orange dot? That's a HIGH severity finding. Let me click on it..."

Click tile → expands inline.

> "Your domain doesn't have a DMARC record. That means an attacker can send email **as you** from anywhere, and most recipient servers will accept it. Let me show you exactly what to do..."

Read the remediation aloud:
> `v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com`

> "Add that to your DNS as a TXT record at `_dmarc.example.com`. Takes 60 seconds. Start with `p=none` to monitor, ramp to `p=reject` over 4 weeks."

(This is the most universal finding. ~80% of mid-market companies hit this.)

### 4. The Risk Score (60 seconds)

> "While we wait for the other 69 scanners, look at the bottom — it's mid-scan but already producing real evidence."

Wait for scan to complete (~30s).

> "Here's the **Key Risk Headline** at the top. And this **Risk Score bar** — we score every scan from 0 to 100 based on weighted CVSS. Your score on Phishing is X."

### 5. The PDF (90 seconds)

Click **📄 PDF**.

> "This downloads a 10-section penetration test report. Full disclosure: there's a customer logo placeholder, you'd brand it with yours. But every finding has CVSS, CWE, OWASP mapping, AND remediation steps — let me open it..."

Open downloaded PDF in browser.

Scroll through:
- Cover page → Report ID (top-right) for tamper evidence
- Risk Score bar
- Severity breakdown
- **Compliance Coverage** section → "This is what your auditor wants — OWASP, CIS, NIST, PCI mapping. Most tools make you build this. We give it for free."

### 6. The remediation loop (60 seconds)

> "Now the part nobody else does. After you fix DMARC, you run the scan again. Watch this..."

Click `Recent scans` dropdown (have a previous scan stored from earlier today).

Pretend to load → live scan would show **`✓ 1 FIXED`** banner.

> "That green banner — that's the proof your fix actually worked. Auditors love this. Your team loves this. It's the 'did the patch take?' question answered in 2 seconds."

### 7. The price (90 seconds)

> "Three tiers. Free, Pro at $49/month, Team at $249/month."

Show pricing page or share:
> "Free is 10 scans, perfect for evaluating. Pro is solo-consultant pricing. Team is up to 5 seats — that's where most teams land — and includes cloud-synced scan history and remediation tracking across your team."

Pause.

> "What questions can I answer?"

### 8. Handle objections (3-5 min)

| Common objection | Response |
|---|---|
| "We use Burp Pro / Nessus" | "Great — keep using it for deep dives. We're the 'every-week-baseline' scanner. Different job, different price point. Many of our customers run both." |
| "Can we self-host?" | "Enterprise tier includes air-gap deploy. Most teams start on the SaaS — saves the ops overhead. We can discuss self-host once you're on Team." |
| "What about false positives?" | "Every finding has a 'CONFIRMED' flag — we actively verify. The advisory-only items (post-compromise techniques) are clearly marked so they don't pollute the report." |
| "Does it auto-fix things?" | "No. Auto-fix is irresponsible without context. We tell you exactly what to fix and link to docs. Your team makes the call." |
| "How do we integrate with our CI?" | "We have a CLI: `python -m tools._cli scan example.com --module recon --severity-fail high` — exit code 1 if HIGH found. Drop into your GitHub Actions." |

### 9. Close (60 seconds)

> "Two paths:
> 1. **Free signup right now**, run 10 scans this week, decide for yourself
> 2. **Team trial** — 14 days of Team tier with multi-seat. Useful if you want your security lead in there with you.
>
> Which one?"

If they pick 1, you're done. If they pick 2, capture team emails + send trial activation.

---

## Demo gotchas

- **Vulnuslab.com itself has the DMARC finding** — use it as a "we eat our own dog food, not perfect either" disarming joke if you scan it during pre-meeting
- **Don't run Cloud module live** — it's 124 endpoints, takes ~90s, breaks demo pacing
- **If the scan is slow** (>60s for Phishing), backend might be cold. Pre-warm with one prospect-domain scan ~5 min before the call
- **PDF download might be blocked** in some corporate browsers. Pre-screenshot key pages as backup

## Post-call follow-up template

```
Subject: VulnusLab — quick follow-up + the DMARC fix

Hi {{name}},

Thanks for the time today. Quick recap of what we found on {{their_domain}}:

1. {{finding_1}}  →  {{remediation_1}}
2. {{finding_2}}  →  {{remediation_2}}

Two ways to keep going:

🔵 Free tier (10 scans/mo): https://app.vulnuslab.com/signup
🟢 14-day Team trial (5 seats): {{trial_link}}

Happy to jump on a 20-min call next week if your security lead wants
to see the CI integration. Otherwise — go fix that DMARC :)

— {{your_name}}
```
