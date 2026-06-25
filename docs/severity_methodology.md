# VulnusLab — Severity Methodology

This document defines how VulnusLab assigns a severity to every finding. It is
public-by-design: an enterprise security team can audit it and reproduce any
grade. Severity is decided by **one central policy** (`tools/_core/grade.py`),
not by individual scanners — so the same observation is always graded the same
way, regardless of which of the 200+ scanners produced it.

## Principle

> A scanner reports **what it observes**. A central policy decides **what it
> means**. Severity is a function of *what is exposed*, *how confirmed it is*,
> and *how much it helps an attacker* — never of a keyword match.

## Bands

| Severity | Meaning | Example |
|---|---|---|
| **CRITICAL** | Confirmed, directly exploitable, high impact | Cracked JWT secret; unauth RCE proven |
| **HIGH** | Confirmed exposure that **enables** compromise | Telnet/SMB/Redis internet-facing; confirmed SQLi |
| **MEDIUM** | Confirmed exposure that materially **aids** an attacker | No login rate-limiting; weak SPF/DMARC; DB port exposed |
| **LOW** | Hardening gap, no proven exploitability | Missing cookie flag/header; internal-looking name in a public list |
| **INFO** | Attack-surface **inventory**, or advisory-by-design | Subdomain/SAN/URL lists; "needs API key"; GeoDNS variance |
| **POSITIVE** | A good/secure configuration was confirmed | Registrar delete-lock present; all hardening headers set |

## The rules every scanner follows

1. **Inventory is not a vulnerability.** Knowing a subdomain, SAN, crawled URL,
   social handle, or historical IP exists is INFO — at most LOW when the surface
   is large enough to warrant a hardening note. It is **never** MEDIUM+.
   `grade.inventory(n, low_at=...)`

2. **Prove, don't guess.** A *confirmed* exposure is graded by impact; an
   *unconfirmed* signal is capped one band lower.
   `grade.exposure(confirmed=, impact="aids"|"enables"|"critical")`

3. **A good config is a POSITIVE, not a finding.** Protective controls
   (registrar locks, present headers, enforced policy) are reported as POSITIVE.
   `grade.protective()` — *this is why `clientDeleteProhibited` is POSITIVE, not a risk.*

4. **Advisory-by-design is INFO.** Anything that can't be detected from an
   external probe, or needs credentials/inputs not supplied, is INFO for
   awareness — never a graded gap. `grade.advisory()`

5. **Context decides impact.** A management port (SSH/FTP) reachable is LOW (often
   intended, e.g. git-over-SSH); the same scanner grades Redis/Telnet HIGH. CDN/
   cloud-edge observations are suppressed or downgraded.

## OWASP coverage grading

A report's OWASP-category grade **fails a category only on a MEDIUM+ finding**.
LOW/INFO items are shown as hardening/inventory and do not fail a category — so a
LOW-only scan is grade A, consistent with a MINIMAL risk score (not a "C").

## Roadmap (scoring engine)

`grade.py` is **Phase 1**: a central rubric the scanners call. Later phases add an
enrichment layer (EPSS/KEV exploitability, CDN/asset context), cross-source
correlation, and an asset/observation data model — so severity becomes a function
of `exposure × exploitability × asset-criticality × confidence`, the enterprise
standard.
