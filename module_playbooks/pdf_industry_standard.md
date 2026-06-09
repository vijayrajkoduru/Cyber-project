# PDF Industry Standard — VulnusLab Customer Report Spec

Canonical reference for every customer-facing PDF report (Recon, Vuln, Webapp, Cloud, etc.).
Read FIRST before any PDF generator work. Same role as `module_playbooks/<module>.md` for scanners.

Benchmarks: Qualys VMDR, Tenable.io, Rapid7 InsightVM, Nessus Pro, Wiz, Burp Pro report templates.

---

## 1. Canonical Section Structure (13 sections, fixed order)

1. **Cover Page** — Target / Scan Date / Classification / Report Type / Authenticated flag. Posture banner (STRONG / MODERATE / WEAK / CRITICAL). Risk Score card with band legend. Baseline-vs-delta card.
2. **Document Control** — Report ID / Module / Version / Generator / Generation Time / Content Hash (SHA-256 prefix) / Scan Summary / Distribution / Retention / Next Re-test.
3. **Executive Summary** — Overall posture statement (2-3 sentences). Report Coverage bar (frameworks list — see §6).
4. **Engagement Scope** — Target / supplied inputs / Scan Date / Methodology / Frameworks / Engagement Type.
5. **Findings Distribution** — 6 buckets: CRITICAL / HIGH / MEDIUM / LOW / INFO / SCAFFOLD. Numbered tiles.
6. **Business Impact** — Plain-English paragraph tying findings to business risk. No findings → maintenance recommendation.
7. **Scan Coverage** — `N/M scanners completed` + breakdown: DATA / EMPTY / SKIPPED / ERROR. Legend below.
8. **Compliance Mapping** — Per-finding control mapping table. Empty-state allowed (no mappable findings).
9. **Per-Tool Intelligence** — PASS rollup (positive-only) + DATA rollup (findings) per tool. Plain text, no pills.
10. **Risk Rating Matrix** — Severity / CVSS Range / SLA / Finding count.
11. **Strategic Recommendations** — 3-5 bullets. No-finding case: monitoring + cadence advice.
12. **Conclusion & Re-test Cadence** — Recommended days / overall posture restatement / validity window.
13. **Appendix** — A. Methodology / B. References (OWASP, NIST, CIS, MITRE, CWE) / C. SBOM.

End marker: `- END OF <MODULE> SCANNING REPORT -` with support email.

---

## 2. Hard Rules (zero tolerance)

- **No text truncation.** Every wrapped line uses `splitTextToSize` with the actual `contentW`. Never single-line draw a string that could exceed page width. If we hit a line cap, bump the cap or shorten the source — never accept clipped text.
- **No placeholders shipped.** No `?`, `TBD`, `N/A` unless explicitly the empty state. If a count is missing, drop the sub-clause; don't ship `vs ? entries`.
- **No internal paths.** Never expose `module_playbooks/<x>.md`, file paths, repo names, container names, env-var names. Customer sees product surface only.
- **No fake frameworks.** Only list a compliance framework in Report Coverage IF we have actual mapping rules in `_cmpRules` / `_cmpCwe` for it. Auditor will spot-check; an unmapped framework = trust hit.
- **No emojis anywhere.** PDFs render boxes for unsupported glyphs. Use words: `PASS`, `FAIL`, `CONFIRMED`, `SUSPECTED`.
- **Plain text > pills > badges.** Per-finding compliance = wrapped plain text. Auditors scan left-to-right. Coloured pills add visual noise without info.
- **Dim internal notes.** Formula breakdowns, scope-adjustment math, hash prefixes → muted grey, smaller font. Never orange/red (reads as warning).
- **No chained exploitation.** VulnusLab is VA, not PT. Findings list what we found; never "next step: exploit X".

---

## 3. Cover Page Rules

- Posture banner (STRONG / MODERATE / WEAK / CRITICAL) maps from worst-severity finding count, not subjective.
- Risk Score: large numeral + band name + Report ID + finding count + scanner count.
- Band legend below: `0-20 MINIMAL — 20-40 LOW — 40-60 MODERATE — 60-80 HIGH — 80-100 CRITICAL`.
- Scope-adjustment line (if inputs missing) goes BELOW the bands legend in muted grey, NOT above the score.
- Baseline / Delta card: first scan → "No prior scan recorded". Subsequent → delta table (added / closed / unchanged x severity).

---

## 4. Findings Card Shape

Each CRITICAL/HIGH/MEDIUM/LOW finding must carry:

- **Name** (one-line title)
- **Severity** badge (colour-coded)
- **CVSS 3.1** score + vector string (e.g. `7.5 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **CWE** ID + name (e.g. `CWE-287 Improper Authentication`)
- **KEV flag** if in CISA KEV catalog (`KEV` chip)
- **EPSS score** if ≥ 0.1 (`EPSS 0.34` chip)
- **Evidence** (what we saw — verbatim where possible)
- **Remediation** (specific fix, not "patch your stack")
- **Compliance** (plain text, wrapped, 2 lines max)
- **References** (CVE link, vendor advisory, OWASP cheatsheet URL)

POSITIVE / INFO findings: name + severity + evidence only.

---

## 5. Per-Tool Intelligence

- **DATA rollup**: tool name + finding count + worst severity + one-line summary.
- **PASS rollup**: tool name + `PASS:` + one-line evidence ("Ports 389/636 closed or filtered").
- Every evidence line wrapped via `splitTextToSize` — NO right-edge clipping.
- Hyphen-prefix (`- Tool Name`) OK; informal but readable. Drop if going formal.
- Group by tier OR by status (DATA → EMPTY → SKIPPED). Pick one and stick to it.

---

## 6. Report Coverage Bar (frameworks list)

- Single instance, top of Executive Summary.
- Plain text, two-tone: bold `REPORT COVERAGE` label + framework names joined by ` - `.
- **Only list frameworks we actually map** in `_cmpRules` / `_cmpCwe`. Audit truth: open the code, grep the rules, that's the list.
- Wrap onto N lines as needed — NEVER truncate the last entry. Bump `splitTextToSize` line cap if needed.
- Approved 20 (as of 2026-06-09): OWASP Top 10, OWASP API Top 10, OWASP LLM Top 10, PCI DSS 4.0, HIPAA, SOC 2, GDPR Art.32, ISO 27001, ISO/IEC 42001, NIST SP 800-53, NIST CSF 2.0, NIST AI RMF, NIST SSDF, CIS Controls v8, FedRAMP, FIPS 140-3, CISA KEV / BOD 22-01, SLSA L1-L3, IEC 62443, AWS WAF / IAM.
- Removed (2026-06-09 — no mapping rules): HITRUST, COBIT, PSD2.

---

## 7. Compliance Mapping Section

- Per-finding row: Finding name | Severity | Mapped controls (plain text, wrapped).
- Empty state: green banner `No findings mapped to compliance controls — No CRITICAL/HIGH/MEDIUM/LOW finding carried a control-mappable signature.`
- Source of truth: `_cmpRules` (regex → framework controls) + `_cmpCwe` (CWE → framework controls) in the generator.
- Citation format: `OWASP A06 - NIST SI-2 - CIS 7.1 - PCI 6.3.3 - SOC2 CC7.1`. Specific control IDs, not framework names alone.

---

## 8. Customer Language Rules

- **Module name**: `Vulnerability Scanning` — NOT `Vulnerability Scanning (module_playbooks/02_vuln.md)`.
- **Authenticated**: `No - public surface only` / `Yes - credentials supplied` — not `false` / `true`.
- **Engagement type**: `Black-box (public surface only)` / `Grey-box` / `White-box`.
- **Methodology**: Cite framework names (PTES / OWASP / NIST SP 800-115 / MITRE ATT&CK), not internal tool names.
- **Recommendations**: Action verbs ("Disable anonymous bind", "Restrict TCP 389/636"). Never "consider", "may want to".
- **Re-test cadence**: Explicit days (`90 days drift monitoring`), tied to overall posture band.

---

## 9. Anti-Patterns (do not ship)

- Badge wall (20 circular compliance icons across two rows) — verbose, no signal.
- Coloured per-finding framework pills — auditors prefer plain text.
- Fake framework list (HITRUST/COBIT shown but never cited) — trust hit on first audit.
- Truncated coverage bar (last framework cut mid-word) — looks like our pipeline broke.
- `?` placeholders (`vs ? KEV entries`) — looks like missing data, not empty state.
- Internal paths in customer fields (`module_playbooks/02_vuln.md`) — leaks implementation.
- Orange/red-styled informational notes (formula breakdown) — false-alarm signal.
- Cross-module chained exploitation suggestions — see [[no-chained-exploitation]].
- Emojis anywhere — see [[never-use-emojis]].

---

## 10. Definition of Done (run before showing the user)

1. **No truncation**: every multi-line block uses `splitTextToSize`; line caps verified against worst-case input.
2. **No placeholders**: grep generator for `?`, `TBD`, `XXX`, `FIXME`.
3. **Coverage = mappings**: every framework in Report Coverage has a rule in `_cmpRules` or `_cmpCwe`.
4. **No internal paths**: grep generator for `module_playbooks`, file paths, container names.
5. **Sections render with empty state**: every section has an empty-state branch (no findings → green "STRONG" banner, not blank).
6. **CVSS + CWE + KEV + EPSS** present on every CRITICAL/HIGH/MEDIUM/LOW finding.
7. **End marker present**: `- END OF <MODULE> SCANNING REPORT -` + support email.

If any check fails, fix BEFORE showing the PDF to the user.

---

## 11. Generator Reference

The codebase currently has **8 PDF generators** (legacy from organic growth). Target end-state is **ONE generator** (`generateUniversalVLReport`) with module-specific content rendered via opt-in plug-in sections.

**Current state:**
- `generateUniversalVLReport` (line ~13174): Vuln + Webapp + Cloud + K8s + OSINT + API Sec + AI/LLM + Mobile (20+ modules)
- `generateReconReport` (line ~8936): Recon only
- `generatePDF` (line ~783): Pentest module
- `generateModuleReport` (line ~2594), `generateShellReport` (~4897), `generateManualTestsReport` (~6402), `generateOsintPdf` (~6814), `generateVulnReport` (~15699, legacy), `generateOsintReport` (~15737), `generateMobileReport` (~15842, alias)
- Shared chrome: `_vlDrawBrandedCover` + `_vlDrawBrandedFooter` (line ~8856) — used by Recon + Universal only

**Opt-in sections in Universal** (toggle via `opts.sections.<name>`, default true):
- `owaspTop10` — OWASP Top 10 Coverage with letter-grade A-F (auto-computed from CWE-XX in findings)
- `toolsUsed` — Tools Used transparency table (every scanner listed + FREE label)
- (more to come in Phase 2)

## 12. Consolidation Roadmap (single template for all modules)

Goal: kill 7 of 8 generators. Every module routes through `generateUniversalVLReport`. Module-specific content opts in via `opts.sections.<name>`.

**Phase 1 (shipped 2026-06-09):**
- Shared chrome helpers: cover + footer
- Opt-in OWASP Top 10 Coverage section in Universal
- Opt-in Tools Used table in Universal

**Phase 2 (next):**
- Port Pentest's Compliance Coverage 8-framework section → Universal opt-in
- Port Pentest's Verification Audit "what was tested" section → Universal opt-in
- Port Pentest's Pentest Coverage Matrix bar chart → Universal opt-in
- Migrate webapp/pentest module's `dlPDF` to call `generateUniversalVLReport` with `sections: { owaspTop10: true, toolsUsed: true, complianceWide: true, verifAudit: true, coverageMatrix: true }`
- Test against app.vulnuslab.com Pentest run — verify output matches current `generatePDF` quality
- Delete `generatePDF`

**Phase 3:**
- Port Recon's unique sections (Coverage Gaps / WHOIS Lookup / ASN Intel / Asset Inventory / Per-Scanner Intel) → Universal opt-in
- Migrate Recon's `dlPDF` to Universal with `sections: { coverageGaps: true, whoisLookup: true, asnIntel: true, assetInventory: true, perScannerIntel: true }`
- Delete `generateReconReport`

**Phase 4:**
- Audit `generateModuleReport`, `generateShellReport`, `generateManualTestsReport`, `generateOsintPdf`, `generateVulnReport`, `generateOsintReport`, `generateMobileReport` — most are legacy unused or alias.
- Delete unused, migrate the rest if callsites remain.

Per-phase effort estimate: 2-4 hours each (real testing across multiple modules is what takes time).

---

## 13. Change Log

- 2026-06-09 morning: Initial spec seeded from Vuln PDF gap review.
- 2026-06-09 evening: Added Section 11 (8-generator audit) + Section 12 (consolidation roadmap). Shipped Phase 1: shared chrome helpers (`_vlDrawBrandedCover` + `_vlDrawBrandedFooter`) + opt-in OWASP Top 10 + Tools Used sections in Universal.
