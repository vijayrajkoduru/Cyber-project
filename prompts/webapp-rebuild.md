# VulnusLab Web Application Pentesting — Full Rebuild Prompt

**Status:** authorized 2026-05-17. Production-ready from day 1. No beta phase.
**Recovery:** original module archived in `webapp-archive-pre-rebuild` branch.

Paste the block below into a fresh Claude session when ready to continue the rebuild.

---

```
REBUILD VulnusLab Web Application Pentesting — PRODUCTION-READY FROM DAY 1
No beta phase. No fake/lab-only validation. Public-launch quality on ship day.

═══════════════════════════════════════════════════════════════════════
CONTEXT — the product I'm paying for
═══════════════════════════════════════════════════════════════════════

I'm the solo founder of VulnusLab (app.vulnuslab.com). Customers will
sign up, enter THEIR OWN production website URL, optionally provide
login credentials, and get a useful pentest PDF within 10 minutes. They
pay for this. They don't tolerate:
  • False positives (wastes their dev team's time)
  • Crashes / "unknown error" / "FAILED" lines in their PDF
  • Scans that DoS their site / trigger their WAF / get them rate-limited
  • Scans that miss obvious bugs (look broken vs Burp/Acunetix)
  • Reports they can't hand to a dev to actually fix things

I am NOT building a beta. I am NOT building a research project. I am
NOT building "works on labs but you'll have to handle real sites later."
I am building the REAL THING that ships to paying customers on day one
and works against ANY website they point it at. Take full control of
the rebuild. Don't ask permission for sub-steps. Don't ship until the
production gate (Step 6) passes against REAL sites I own.

═══════════════════════════════════════════════════════════════════════
READ FIRST (memory — mandatory context)
═══════════════════════════════════════════════════════════════════════

  • C:\Users\vijay\.claude\projects\d--VulnusLab-Cyber-project\memory\MEMORY.md
  • project_pdf_vulntemplate.md
  • project_kali_architecture_complete.md
  • feedback_perfect_reports.md       (no truncation / placeholders)
  • feedback_real_findings_zero_fp.md (active verification, CONFIDENCE flag)
  • feedback_real_targets_not_labs.md (rank by impact on REAL customers)
  • feedback_score_every_report.md
  • feedback_terse_responses.md
  • feedback_autonomous_execution.md
  • project_deployment.md

Project root: D:\VulnusLab\Cyber-project (Windows). Backend on VPS.

═══════════════════════════════════════════════════════════════════════
STEP 1 — SAFE DELETION (recoverable)
═══════════════════════════════════════════════════════════════════════

    git checkout -b webapp-archive-pre-rebuild
    git push -u origin webapp-archive-pre-rebuild
    git checkout main

Delete:
  • tools/webapp/* (30 files)
  • WEBAPP_PHASES + WebAppModule in src/App.js
  • /api/webapp/ routes in main.py / autoloader

    git commit -m "Webapp module: delete pre-rebuild
                   (archived in webapp-archive-pre-rebuild)"

═══════════════════════════════════════════════════════════════════════
STEP 2 — PRODUCTION-SAFETY RULES (non-negotiable, real customers)
═══════════════════════════════════════════════════════════════════════

  1. RATE LIMIT — max 10 req/sec per target by default; user-configurable.
     Detect 429 → exponential backoff (2s, 4s, 8s, 16s, give up).
  2. WAF DETECTION — fingerprint Cloudflare/AWS WAF/Akamai/Imperva on
     first request. If WAF present, switch to low-and-slow + payload
     obfuscation. If 403 on 3 consecutive → stop scanner, "skipped_reason:
     WAF blocking, slow mode triggered".
  3. USER-AGENT — `VulnusLab/1.0 (+https://vulnuslab.com/scanner)`.
     Identifiable in target's access logs. Never spoof a browser UA.
  4. RESPECT robots.txt unless customer opts in with "aggressive=true".
  5. SCOPE LOCK — never leave target domain. No 3rd-party crawling.
  6. NO DESTRUCTION — only GET + idempotent login POST. Never DELETE/PUT/
     PATCH/state-changing POST.
  7. AUTH SAFETY — login ONCE, reuse session. Never trigger lockout.
  8. PAYLOAD MARKERS — `vulnuslab-<8hex>` so customer can verify findings
     in their logs.
  9. DEFAULT TIMEOUT — 10s per request.
  10. CIRCUIT BREAKER — 50%+ 5xx in any 60s window → pause 5 minutes.
  11. KILL SWITCH — UI "Stop Scan" aborts in-flight within 3s.
  12. AUTHORIZATION GATE — UI requires customer to tick "I have written
      authorization to scan this target" before scan starts. Log:
      customer_id, target_url, IP, timestamp, UA. Store in
      consent_audit.db. Used as legal proof if challenged.
  13. CONSENT EMAIL — first scan against a domain triggers an email to
      the customer with the target URL + scan ID, requiring them to
      reply YES within 24h. Subsequent scans against the same domain
      auto-approve.

═══════════════════════════════════════════════════════════════════════
STEP 3 — 65 SCANNERS / 9 PHASES (industry standard)
═══════════════════════════════════════════════════════════════════════

Build under tools/webapp/<name>.py — Kali-style isolation. Build
phase A FIRST — every later phase depends on it.

PHASE A — Discovery (10) — MUST work on real SPAs / SaaS / WP / APIs
  1.  spa_crawler         Playwright headless, follow React/Vue/Angular/
                          Next/Svelte routes, capture XHR/fetch. THE
                          FOUNDATION.
  2.  jsendpoints         Parse webpack/vite bundles for /api/* URLs
  3.  sitemap_robots
  4.  wayback             Archive.org historical endpoints
  5.  directory_brute     SecLists raft-medium + SPA baseline
  6.  backup_files        .bak/.old/.swp + SPA baseline
  7.  exposed_files       .env / .git/config / id_rsa / config.json
  8.  swagger_discovery
  9.  graphql_discovery   /graphql + introspection
  10. tech_stack          Wappalyzer-style fingerprint

PHASE B — Parameter discovery (5)
  11. param_mining
  12. param_wordlist      200+ common names against EVERY endpoint
  13. header_inject_points
  14. cookie_inject_points
  15. post_body_fields

PHASE C — Authentication (8)
  16. login_discovery
  17. credential_test     Wordlist (DISABLED by default)
  18. auth_login_flow     Persist session for all later phases
  19. jwt_security
  20. session_fixation
  21. password_reset
  22. oauth_bypass
  23. authenticated_scan  Re-run A+B+D AS USER

PHASE D — Injection (15)
  24-38. xss / sqli / nosqli / cmd_injection / ssti / ldap_injection /
         xpath_injection / xxe / lfi / rfi / ssrf (opt-in) /
         open_redirect / crlf_injection / host_header_inject /
         prototype_pollution

PHASE E — Access control (6)
  39-44. idor / mass_assignment / broken_object_auth / priv_escalation /
         forced_browsing / race_condition

PHASE F — Configuration (8)
  45-52. security_headers / cors / csp_bypass / cookie_security /
         http_methods / clickjacking / cache_poisoning / http_smuggling

PHASE G — Cryptography (3)
  53. ssl_deep            skipped_reason on HTTP-only
  54. weak_crypto
  55. js_secrets

PHASE H — Framework-specific (5)
  56-60. wpscan / drupal_scan / joomla_scan / laravel_debug /
         spring_actuator

PHASE I — Aggregators + match (5)
  61-65. nikto_aggregate / nuclei_aggregate / burp_lite / cve_match /
         retire_js

═══════════════════════════════════════════════════════════════════════
STEP 4 — ARCHITECTURE RULES
═══════════════════════════════════════════════════════════════════════

  • One file per scanner, tools/webapp/<name>.py
  • APIRouter at /api/webapp/<name>, register(app)
  • Lazy imports in route handler
  • Use tools._shared utilities
  • Failure quarantine
  • Zero-FP discipline, triple-verified
  • CONFIDENCE flag: "CONFIRMED" | "SUSPECTED"
  • SKIP only when genuinely N/A
  • Frontend: rebuild WEBAPP_PHASES + WebAppModule. Pass moduleConfig.
  • PDF: vulntemplate, 11 blocks, 5-col table

═══════════════════════════════════════════════════════════════════════
STEP 5 — DEV VERIFICATION (fast iteration — labs OK here)
═══════════════════════════════════════════════════════════════════════

  Scan A: http://lab_juiceshop:3000      → ≥30 findings, 0 FAILED
  Scan B: http://lab_webgoat:8080/WebGoat → ≥20 findings, 0 FAILED
  Scan C: http://testphp.vulnweb.com      → SQLi+XSS confirmed
  Scan D: http://demo.testfire.net        → ≥10 findings + auth works

═══════════════════════════════════════════════════════════════════════
STEP 6 — PRODUCTION GATE (REAL SITES I OWN — this is the SHIP gate)
═══════════════════════════════════════════════════════════════════════

  Site 1: https://vulnuslab.com        (Netlify marketing site)
  Site 2: https://accentlab.com        (other real site I own)
  Site 3: https://app.vulnuslab.com    (dashboard — recursive scan)
  Site 4: ONE real bug bounty target with explicit automation-allowed scope
  Site 5: ONE friend's real production site (signed email auth required)

Each:
    ☐ <8 min scan duration
    ☐ 0 CRITICAL/HIGH false positives
    ☐ 0 ops alerts triggered (verify with site owner)
    ☐ User-Agent identifies VulnusLab in target logs
    ☐ Score ≥95/100 on PDF
    ☐ Kill switch tested
    ☐ Authorization gate enforced

═══════════════════════════════════════════════════════════════════════
STEP 7 — SELF-SERVICE PRODUCT INFRASTRUCTURE (built BEFORE launch)
═══════════════════════════════════════════════════════════════════════

  A. SCAN INTAKE — URL + creds + authorization checkbox + email
  B. SCAN MONITORING — per-scan dashboard, circuit breaker, admin alerts
  C. POST-SCAN SUPPORT — "Was this finding accurate?" link + FP form
  D. PRICING + BILLING — Razorpay, 1 free scan, $49/$149/$499 tiers
  E. CUSTOMER SUCCESS — welcome emails, post-scan emails, direct support

═══════════════════════════════════════════════════════════════════════
STEP 8 — PUBLIC LAUNCH (NO PRIVATE BETA)
═══════════════════════════════════════════════════════════════════════

  • git tag v2.0-webapp-prod
  • Public signups open
  • Posts: X, LinkedIn, Reddit r/cybersecurity r/netsec, HN, ProductHunt
  • Monitor signup → first-scan funnel daily

═══════════════════════════════════════════════════════════════════════
STEP 9 — PRODUCTION MONITORING (every customer scan, ongoing)
═══════════════════════════════════════════════════════════════════════

  Daily: scans count, failures, FP reports, complaints, abuse@ emails
  Weekly: per-scanner FP rate (disable >5%), top 3 missing features
  Monthly: churn, findings-per-scan trend, revenue reinvest

═══════════════════════════════════════════════════════════════════════
PROHIBITED ACTIONS
═══════════════════════════════════════════════════════════════════════

  • Don't ask clarifying questions — make the reasonable call.
  • Don't skip Step 6 (real-site gate) to ship faster.
  • Don't ship without Step 7 (self-service infra).
  • Don't fake findings or pad counts.
  • Don't commit secrets / .env / users.db / VAULT_KEY.
  • Don't force-push to main.
  • Don't edit Netlify bundle directly.
  • Don't bypass production-safety rules for any reason.
  • Don't scan outside Step 5/6 targets.
  • Don't claim done if ANY scanner returns FAILED.
  • Don't call this a "beta" — it's the real product from day 1.
```
