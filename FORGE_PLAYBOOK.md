# VulnusLab — Module Forge Playbook

The canonical recipe that took Recon to 154/154 real. Apply this 20+ times.

After each module reaches 100% real, deploy it to VPS, lock it from regression,
move to the next.

---

## Mission

Every module ships with:

- Every technique either **real-probed**, **honestly-not-implemented**, or **advisory-by-design**
- Zero fake CRITICAL findings
- Zero false positives
- Reproducible scans
- PDF that matches the Webapp canonical template
- Locked from regression via CI gate

---

## The 7-check Definition of Done (per scanner)

Self-verify EVERY scanner against these before marking it done. No exceptions.

- [ ] **Precondition gate** present — returns NOT_APPLICABLE if input missing
- [ ] **Real execution** — subprocess / socket / lib call actually runs (not a constant return)
- [ ] **Output parsed structurally** — JSON / XML / typed dict, not regex over stdout
- [ ] **CONFIRMED-only when observation matches condition** — severity derived from data
- [ ] **SUSPECTED path** has explicit downgrade reason
- [ ] **NEGATIVE returns POSITIVE finding** — good state is visible in PDF
- [ ] **Test fixture exists** — captured real tool output under `tests/fixtures/<scanner>/`

If any check fails → do not merge.

---

## The 12-step Module Forge Playbook

Apply in order, per module.

### Step 1 — Read & categorize the playbook (1–2 hrs)

- [ ] Open `module_playbooks/<NN>_<module>.md`
- [ ] List every technique in a spreadsheet: `slug | title | category | tool | input_needed | severity`
- [ ] Categorize each:
  - **A. Externally observable** — works from hostname/IP only (forge first)
  - **B. Requires customer input** — image_ref / Dockerfile / kubeconfig / etc. (forge after UI exists)
  - **C. Advisory-by-design** — post-compromise / engagement-only (label and skip)
- [ ] Decide tool per technique (Trivy, Nuclei, custom, etc.)

**Output**: complete forge plan for the module.

### Step 2 — Set up the tier structure (Kali-style architecture)

- [ ] Create `tools/<module>/tier1_<group>/`, `tier2_<group>/`, etc.
- [ ] Each tier maps to a section in the playbook
- [ ] One scanner per file inside its tier
- [ ] `__init__.py` in each tier enables auto-discovery
- [ ] File naming: `<scanner_slug>.py`

**Pattern**: matches existing `tools/recon/tier1_passive/`, `tier2_subdomain/`, etc.

### Step 3 — Install required tools on VPS

- [ ] List every binary needed (Trivy, Hadolint, kube-bench, etc.)
- [ ] Update `Dockerfile` with explicit install blocks (one per tool, version pinned)
- [ ] On VPS: `docker compose build backend && docker compose up -d backend`
- [ ] Verify each: `docker exec vulnuslab_backend <tool> --version`

**Acceptance**: every required tool invokable from inside backend container.

### Step 4 — Wire the framework guardrails (one-time, then reused)

If not already in place:

- [ ] `tools/_framework/preconditions.py` — declarative input rules
- [ ] `tools/_framework/evidence.py` — `Evidence` dataclass + `is_real()` method
- [ ] `tools/_framework/status.py` — Status enum
- [ ] Severity-derives-from-status rule in `wrap_finding()`
- [ ] PDF guard refuses to render CONFIRMED finding with non-real evidence
- [ ] Pre-commit hook blocks PRs without test fixtures

**Acceptance**: framework physically prevents scaffold fakes from regressing.

### Step 5 — Forge each scanner (the inner loop, repeated N times)

For each technique in the forge plan:

#### 5a. Write the probe

- [ ] File: `tools/<module>/<tier>/<slug>.py`
- [ ] Imports: `_pack_common._build_resp`, `_shared.wrap_finding`, framework helpers
- [ ] Function: `def _probe(target, req) -> dict:`
- [ ] Precondition gate FIRST (return NOT_APPLICABLE if input missing)
- [ ] Real execution: socket / HTTP / subprocess / library call
- [ ] Capture: command, started_at, duration_ms, stdout, stderr
- [ ] Parse output into typed dict (`evidence.parsed`)
- [ ] Derive severity from observation

#### 5b. Self-verify with 7-check DoD (above)

#### 5c. Register in PROBES dict

- [ ] Add `<slug>: _probe_<name>` to module's PROBES dict
- [ ] Remove slug from advisory T list (or leave it — probe takes precedence)

#### 5d. Test on real target

- [ ] Positive case: vulnerable target → must produce CONFIRMED
- [ ] Negative case: clean target → must produce POSITIVE
- [ ] Error case: unreachable → must produce `[PROBE ERROR]` INFO, not crash

**Per-scanner effort**: 15–45 min hand-written, 8–15 min AI-assisted.

### Step 6 — Wire orchestrator (auto-discovery + streaming)

- [ ] `tools/<module>/__init__.py` auto-imports every tier's scanners
- [ ] Module's pack file calls `make_advisory_router(...)` with PROBES dict
- [ ] `endpoints/<module>_flow.py` exposes `/api/<module>/run_all` NDJSON stream
- [ ] Reuse `run_module_streaming(module_name, target, jwt)` from Recon
- [ ] Test:
  ```
  curl -N -H "Authorization: Bearer $JWT" \
       -X POST https://api.vulnuslab.com/api/<module>/run_all \
       -d '{"target":"example.com"}'
  ```

**Acceptance**: streams real events for every forged scanner.

### Step 7 — Apply VL-TURBO (fast-streaming)

Per `project_vl_turbo_process.md`:

- [ ] `async def` → `def` for any scanner using blocking subprocess
- [ ] Per-scanner wall-clock cap (60s default via `VL_TURBO_SCANNER_TIMEOUT`)
- [ ] Wrap subprocess in `ThreadPoolExecutor` for parallel fan-out
- [ ] Bump tier concurrency (`VL_TURBO_TIER_CONCURRENCY=12`)
- [ ] Enable 24h cache (`VL_TURBO_CACHE_TTL=86400`)
- [ ] Verify full module scan < 5 min

**Acceptance**: full module run_all beats 60s TTFB.

### Step 8 — Apply VL-PRIME (rate-limit + auth)

Per `feedback_vlprime_ratelimit_fanout_gotcha.md`:

- [ ] Confirm rate limiter exempts internal IPs (127.0.0.1, 172.x, 10.x, 192.168.x)
- [ ] JWT bearer forwards through fan-out
- [ ] Test under 5 concurrent /run_all → no 429s internally

**Acceptance**: no rate-limit storms on internal fan-out.

### Step 9 — Wire VL-FLOW (frontend panel)

Per `feedback_recon_scanner_3patch_pattern.md`:

In `src/App.js`, add three things:

- [ ] `<MODULE>_PHASES = [...]` array listing each tier
- [ ] `_PHASE_DEFS = {...}` mapping tier → metadata (label, color, icon)
- [ ] `SECTION_OF = {...}` mapping each scanner slug → tier
- [ ] Reuse `ModuleAutoPanel` component (auto-loads /run_all/tiers + streams)
- [ ] Verify per-scanner tile UI: dot + glyph + name + badge + count + elapsed + Details

**Acceptance**: dashboard sidebar shows module → tier nav works → live tiles stream.

### Step 10 — PDF integration (canonical Webapp template)

Per `project_pdf_vulntemplate.md` (17 sections, Webapp = canon):

- [ ] Apply 8-step "apply vulntemplate" process (`feedback_vulntemplate_apply_process.md`):
  1. Anchor scoping (no global var collisions)
  2. No duplicate consts
  3. `docker builder prune -af` between rebuilds
  4. Grep string literals, not var names
  5. Incognito test (cache bypass)
  6. Sections always render with empty-state
  7. Risk Score Bar + Key Risk Headline + Compliance Coverage + Report ID/Hash
  8. Verify all 17 sections appear
- [ ] Map every finding to real OWASP / NIST / PCI / CIS — no blanket CWE-1395
- [ ] Test PDF against a real scan

**Acceptance**: PDF matches Webapp canon structurally + visually + all 17 sections present.

### Step 11 — Validation regimen

- [ ] **Positive case**: vulnerable target where each finding SHOULD fire
  - Container → Kubernetes Goat / vulhub
  - Webapp → DVWA / Juice Shop / WebGoat
  - Cloud → flAWS / CloudGoat
  - Mobile → InsecureBankv2 / OVAA (already in Dockerfile)
  - Vuln → Metasploitable
  - Network → HackTheBox VM
- [ ] **Negative case**: hardened target → 0 fake CRITICALs, only POSITIVE / INFO
- [ ] **Wrong-target case**: e.g. Container against `example.com` → 0 CRITICAL, all NOT_APPLICABLE
- [ ] **Reproducibility**: same scan twice → same parsed findings
- [ ] **Performance**: within wall-clock budget
- [ ] **PDF inspection**: download report, verify every section + scanner row + watermark + hash

**Acceptance**: real findings on vulnerable target, zero FP on clean, honest NOT_APPLICABLE on wrong-type.

### Step 12 — Mark complete + lock

- [ ] Update memory: `project_<module>_module_complete.md` — slug count, session date
- [ ] Add CI gate: module-specific test failing if scaffold endpoint reappears
- [ ] Run scoreboard: `python scripts/forge_status.py` should show `<module>: X/X = 100%`
- [ ] Commit: `<module>: VL-FORGE complete — N/N real probes, 0 scaffolds`
- [ ] Push, deploy on VPS, verify, screenshot the green scoreboard

**Acceptance**: 100% real for this module. Locked.

---

## The forge order (next 6 months solo)

Apply 12-step playbook in this order. Check off as each completes.

| # | Module | Sessions | Status | Cumulative |
|---|---|---|---|---|
| 0 | Recon | 37 (done) | **DONE 154/154** | 37 |
| 1 | Container/K8s (continue from 21/103) | 12 | In progress | 49 |
| 2 | Webapp (finish from ~12/30) | 8 | Pending | 57 |
| 3 | Network (finish) | 6 | Pending | 63 |
| 4 | Cloud (Prowler-backed) | 10 | Pending | 73 |
| 5 | APISec | 8 | Pending | 81 |
| 6 | OSINT | 5 | Pending | 86 |
| 7 | Supply Chain | 5 | Pending | 91 |
| 8 | Vuln (Nuclei + OpenVAS) | 20 | Pending | 111 |
| 9 | AI-LLM (Garak) | 5 | Pending | 116 |
| 10 | Mobile (MobSF + apkleaks) | 10 | Pending | 126 |
| 11 | Password Attacks | 5 | Pending | 131 |
| 12 | Auth Attacks | 8 | Pending | 139 |
| 13 | Wireless (needs PCAP input UX) | 15 | Pending | 154 |
| 14 | Firmware (EMBA + binwalk) | 10 | Pending | 164 |
| 15 | IoT/OT | 8 | Pending | 172 |
| 16 | Active Directory external | 8 | Pending | 180 |
| 17 | Hybrid Identity | 8 | Pending | 188 |
| 18 | SSPM | 8 | Pending | 196 |
| 19 | Exploit / Metasploit / System / Client-Side / BoF | 8 | Pending | 204 |
| 20 | Advisory-by-design batch (Privesc, Post-Exploit, Pivot, Tunnel, AV-Evasion, Phishing, Red-Team) | 5 | Pending | **209 sessions** |

**Pace estimates:**
- Solo, 1 session/day: ~7 months
- Solo, AI-assisted forge: ~3.5–4 months
- + 1 contractor parallel: ~3 months

---

## Non-negotiables (do not skip)

1. **Every scanner ships with a test fixture.** No exceptions.
2. **7-check DoD self-verification before merge.** Run it. Don't merge if any fails.
3. **Wrong-target test passes.** Each module against a wrong target → 0 CRITICAL.
4. **Severity is derived from observation.** Never from playbook tuple. Framework enforces.

---

## Shortcuts to reuse (don't rebuild)

- `ModuleAutoPanel` in App.js — every module gets streaming UI free
- `make_advisory_router` + PROBES dict — pattern proven
- VL-TURBO / VL-PRIME / VL-FLOW — inherited framework-level
- Webapp PDF template — canonical, apply 8-step process
- AI-curated wordlists under `tools/_payloads/<module>/` — pattern from `project_offline_ai_curation_recon.md`
- `_scaffold_response()` in `_pack_common.py` — already returns honest INFO for un-forged endpoints

---

## Per-module trackers

Mark off as each step completes per module.

### Container/K8s — IN PROGRESS (21/103 real)

- [x] Step 1 — Read & categorize playbook (24_container_k8s.md, 103 techniques)
- [ ] Step 2 — Tier structure (currently single pack file; refactor to tiers later)
- [x] Step 3 — Some tools installed (nmap, nuclei); MISSING: Trivy, Grype, Hadolint, kube-bench, Cosign, Syft
- [x] Step 4 — Framework guardrails (`_scaffold_response` added 2026-06-01)
- [ ] Step 5 — 82 scanners still to forge:
  - 7 externally-observable remaining
  - ~50 need image_ref input
  - ~25 need kubeconfig input
- [ ] Step 6 — Orchestrator (already wired via existing pack)
- [ ] Step 7 — VL-TURBO applied
- [ ] Step 8 — VL-PRIME applied
- [ ] Step 9 — VL-FLOW 3-patch in App.js (already exists for module)
- [ ] Step 10 — PDF canonical template applied
- [ ] Step 11 — Validation against Kubernetes Goat + Vulhub
- [ ] Step 12 — Mark complete + CI lock

### Webapp — PARTIAL (~12/30 real)

- [ ] Step 1 — Read 03_webapp.md, categorize remaining techniques
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install ZAP, sqlmap, sslyze, WPScan, dalfox, XSStrike
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Forge remaining ~18 scanners
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template (already canon for this module)
- [ ] Step 11 — Validation against DVWA + Juice Shop + WebGoat
- [ ] Step 12 — Mark complete + CI lock

### Network — PARTIAL

- [ ] Step 1 — Read 16_network.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install masscan, naabu, amass, hping3
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Forge remaining scanners
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation against HackTheBox VM
- [ ] Step 12 — Mark complete + CI lock

### Cloud — MOSTLY SCAFFOLD (~4/80 real)

- [ ] Step 1 — Read 21_cloud.md
- [ ] Step 2 — Tier structure (AWS / GCP / Azure tiers)
- [ ] Step 3 — Install Prowler, ScoutSuite, MicroBurst, GCPBucketBrute, tfsec
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Build customer cloud-credential input UX FIRST, then forge
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation against flAWS + CloudGoat
- [ ] Step 12 — Mark complete + CI lock

### APISec — PARTIAL

- [ ] Step 1 — Read 22_apisec.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install Schemathesis, Akto, kiterunner, arjun
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Build OpenAPI spec input UI, then forge
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation against vAPI / DVAPI
- [ ] Step 12 — Mark complete + CI lock

### OSINT — PARTIAL

- [ ] Step 1 — Read 04_osint.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install SpiderFoot, recon-ng + API key vault (HIBP, Shodan, VirusTotal)
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Forge remaining scanners
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation
- [ ] Step 12 — Mark complete + CI lock

### Supply Chain — SCAFFOLD

- [ ] Step 1 — Read 25_supply_chain.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install gitleaks, trufflehog, Scorecard, dependency-check
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Build repo_url input UI; forge against GitHub API
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation
- [ ] Step 12 — Mark complete + CI lock

### Vuln — ARCHIVED, 0/200 real

- [ ] Step 1 — Read 02_vuln.md (~200 techniques)
- [ ] Step 2 — Recover archived scanners from `_archive/` OR forge from scratch
- [ ] Step 3 — Install Nuclei (already), OpenVAS / GVM (heavy install), NVD client
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Forge per Nuclei templates + OpenVAS NVTs
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation against Metasploitable
- [ ] Step 12 — Mark complete + CI lock

### AI-LLM — SCAFFOLD

- [ ] Step 1 — Read 23_ai_llm.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install Garak, promptbench
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Build LLM endpoint input UI; forge against customer endpoint
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation
- [ ] Step 12 — Mark complete + CI lock

### Mobile — PARTIAL

- [ ] Step 1 — Read 05_mobile.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install MobSF (sidecar), AndroBugs, QARK; apkleaks + androguard already installed
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Build APK / IPA upload UI; forge against uploaded artifact
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation against InsecureBankv2 / OVAA (samples already in Dockerfile)
- [ ] Step 12 — Mark complete + CI lock

### Password Attacks — SCAFFOLD

- [ ] Step 1 — Read 08_password.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install hashcat, john, hydra
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Build wordlist / hash input UI; forge
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation
- [ ] Step 12 — Mark complete + CI lock

### Auth Attacks — SCAFFOLD

- [ ] Step 1 — Read 17_auth_attacks.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install hydra; Nuclei templates for auth
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Forge web login bruteforce + JWT + OAuth probes
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation
- [ ] Step 12 — Mark complete + CI lock

### Wireless — SCAFFOLD (0/57 real)

- [ ] Step 1 — Read 18_wireless.md (57 techniques)
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install aircrack-ng, wifite, reaver, bully, hcxtools, hashcat, bettercap
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Build PCAP upload UI; forge crack-from-pcap probes; advisory-label the rest
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation against captured handshake PCAP
- [ ] Step 12 — Mark complete + CI lock

### Firmware — SCAFFOLD

- [ ] Step 1 — Read 31_firmware.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install binwalk, EMBA, FACT (heavy)
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Build firmware upload UI; forge analysis probes
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation
- [ ] Step 12 — Mark complete + CI lock

### IoT / OT — SCAFFOLD

- [ ] Step 1 — Read 30_iot_ot.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install mqtt-pwn, modbus-cli, coap-shark
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Forge protocol-specific probes
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation
- [ ] Step 12 — Mark complete + CI lock

### Active Directory external — SCAFFOLD

- [ ] Step 1 — Read 19_ad.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install Impacket, BloodHound, SharpHound, Certipy, kerbrute
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Build domain-cred input UI; forge external-observable AD probes
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation against lab AD
- [ ] Step 12 — Mark complete + CI lock

### Hybrid Identity — SCAFFOLD

- [ ] Step 1 — Read 28_hybrid_identity.md
- [ ] Step 2 — Tier structure
- [ ] Step 3 — Install ROADtools, AADInternals
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Build Entra/AAD cred input UI; forge probes
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation
- [ ] Step 12 — Mark complete + CI lock

### SSPM — SCAFFOLD

- [ ] Step 1 — Read 29_sspm.md
- [ ] Step 2 — Tier structure per SaaS (Slack / GitHub / Google Workspace / etc.)
- [ ] Step 3 — Custom API clients per SaaS (no single tool)
- [x] Step 4 — Framework guardrails
- [ ] Step 5 — Build SaaS OAuth flow per platform; forge probes
- [ ] Step 6 — Orchestrator
- [ ] Step 7 — VL-TURBO
- [ ] Step 8 — VL-PRIME
- [ ] Step 9 — VL-FLOW 3-patch
- [ ] Step 10 — PDF canonical template
- [ ] Step 11 — Validation
- [ ] Step 12 — Mark complete + CI lock

### Exploit / Metasploit / System / Client-Side / BoF — SCAFFOLD batch

- [ ] Wrap Metasploit module index (msfconsole automation)
- [ ] CVE → Metasploit module mapping
- [ ] Advisory-label the post-compromise portions
- [x] Step 4 — Framework guardrails
- [ ] Steps 5–12 per the batch

### Advisory-by-design batch (Privesc / Post-Exploit / Pivot / Tunnel / AV-Evasion / Phishing / Red-Team)

- [ ] Create new `_advisory_by_design_response()` helper in `_pack_common.py`
- [ ] Returns INFO with `[ADVISORY: requires engagement / session]` marker
- [ ] Re-tag all these modules' endpoints to use this helper
- [ ] Document in PDF that these modules are reference-only

---

## Daily / weekly cadence

### Daily (per session)

- [ ] Open the current module's tracker section above
- [ ] Pick next pending step
- [ ] Apply 12-step playbook for that step
- [ ] Self-verify with 7-check DoD
- [ ] Commit on VPS, push, deploy
- [ ] Mark step complete in this file

### Weekly

- [ ] Run `python scripts/forge_status.py` — score every module
- [ ] Review forge order; re-prioritize if customer demand shifts
- [ ] Snapshot scoreboard for changelog

### Per module complete

- [ ] Step 12 lock applied
- [ ] Memory file updated
- [ ] Scoreboard hits 100% for that module
- [ ] Move to next module in forge order

---

## Done definition (the finish line)

The whole project is "100% real where real is possible" when:

- [ ] All 31 modules' trackers checked off
- [ ] All forgeable scanners CONFIRMED-capable
- [ ] All advisory-by-design modules clearly labeled
- [ ] Scoreboard: `~1,040 real / ~1,500 total = ~70%` (the ceiling — rest is intentionally advisory)
- [ ] Customer scanning any real target gets only real findings + honest NOT_APPLICABLE + advisory-by-design markers
- [ ] Zero fake CRITICAL findings physically possible (framework enforces)
- [ ] CI gates locked
- [ ] PDF reports inspected by external CISO and judged credible
- [ ] First 10 paying customers retained for 3+ months

---

## Notes for next sessions

- I (Claude) will write code directly into the right files, not give snippets to paste
- After each module hits Step 12, deploy on VPS + screenshot scoreboard
- This file is the source of truth — update checkboxes per session
- If the plan changes, update this file BEFORE writing new code
