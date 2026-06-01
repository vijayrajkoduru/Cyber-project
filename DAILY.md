
---

## Quick Commands (typed from anywhere on the VPS)

Run `vlhelp` to see the list any time.

### Health & Monitoring
| Command | What it does |
|---------|--------------|
| `vlhealth` | 5-second health check |
| `vlcheck` | Full morning check — health + backups + disk + users + cron log |
| `vllogs [N]` | Tail backend logs (default 50 lines) |

### Backup Audit
| Command | What it does |
|---------|--------------|
| `vlbackups` | One-line summary across all 3 tiers |
| `vlaudit` | Detailed per-tier breakdown |
| `vlvault` | Latest VAULT manifest + last cron run |
| `vltools` | Tool snapshot count per category |

### Actions
| Command | What it does |
|---------|--------------|
| `vlsync` | Force-run VAULT sync NOW |
| `vlsnap <user>` | Take a manual snapshot for a user |
| `vlrestore <user>` | Restore a user from their latest snapshot |
| `vlrestart` | Rebuild + restart backend |

### User Management
| Command | What it does |
|---------|--------------|
| `vlusers` | List all users + snapshot counts |
| `vlhelp` | Print this cheat sheet |



_Added 2026-05-16:_ `vltoolsync` — explicit tier-1 sync (restart backend → re-snapshot all tools)

SERVER SLOW

# 1. See what's eating resources
docker stats --no-stream

# 2. If backend memory >3GB or CPU >150% sustained → restart it
docker compose restart backend

# 3. If load avg >3.0 on 2-core VPS → too many concurrent scans
uptime

# 4. If disk full → clean docker
docker system prune -af --volumes

# 5. If frontend slow but backend healthy → restart nginx
docker compose restart frontend

---

# VL-FORGE — Tool Building Process

**Named 2026-05-23 after shipping WHOIS + DNS Records + DNS Recon through the pattern.**

To build any new VulnusLab scanner tool, say to Claude: **"Forge X"** where X is the tool name. Claude runs the full pattern below + self-verifies 7/7 silently + only shows you a PDF that already passes all checks.

## What "Forge X" triggers (5 components)

```
┌──────────────────────────────────────────────────────────┐
│                      VL-FORGE                            │
│                                                          │
│  1. FRAMEWORK   tools/_framework/                        │
│                 scanner.py · gathering.py · parsers.py   │
│                 · findings.py — write once, reuse        │
│                                                          │
│  2. PATTERN     Per-tool file = gather() + INTEL_FIELDS  │
│                                + run_scanner()           │
│                 ~80-200 lines per tool                   │
│                                                          │
│  3. RULES LIB   tools/_payloads/<tool>_findings.py       │
│                 Declarative findings library             │
│                                                          │
│  4. RENDERER    renderToolFindingsAndIntel() in App.js   │
│                 PDF section auto-generated               │
│                                                          │
│  5. 7-CHECK     Self-verify BEFORE showing you the PDF   │
└──────────────────────────────────────────────────────────┘
```

## The 7-Check (Definition of Done)

A tool is DONE (ships, no more polish) when it ticks all 7:

| # | Criterion |
|---|---|
| 1 | Endpoint returns 200 in <30s on a public domain |
| 2 | ≥3 distinct data sources fired in parallel |
| 3 | ≥5 findings rules in library |
| 4 | Response shape: `{findings[], intel{}, sources_used[]}` + flat fields |
| 5 | PDF section renders without errors |
| 6 | Graceful degrade on IP / lab target (`skipped_reason`) |
| 7 | Real-world scan returns sensible output |

Anything beyond these 7 = future polish, NOT a blocker.

## Commands you can give Claude

| You say | Claude does |
|---|---|
| **Forge Subdomain Discovery** | Build one tool through full VL-FORGE |
| **Forge TLS + WAF** | Batch 2 related tools (shared infra) |
| **Forge Port-Scan family** | Build Fast/Deep/Service/OS/Banner as one batch |
| **Forge DNS family** | Subdomains + Cert Trans + Zone Transfer + Amass |
| **Forge all Tier 1** | All 5 high-impact tools (1-2 day batch) |
| **Re-forge X** | Re-apply pattern to an existing tool (polish) |
| **Forge status** | Show which tools done + remaining |

## Forge SCOPE hierarchy (small → big)

| Command | Scope | Calendar time | What you get per session |
|---|---|---|---|
| **Forge `<tool>`** | 1 tool | 30-90 min | 1 tool fully verified + shipped |
| **Forge family `<name>`** | 3-6 related tools, shared infra | 1-2 days | All tools in family, batched |
| **Forge tier `<N>`** | 5-7 tools in same impact tier | 2-4 days | One PDF after the batch completes |
| **Forge module `<name>`** | ALL remaining tools in a module | 2-4 weeks | Multiple batches with checkpoints |
| **Forge all** | Every remaining tool across every module | 6-10 weeks | Big commitment — multi-month roadmap |

## What "Forge module Recon" actually means

It commits to building all 32 remaining Recon tools but executed as 5 batches:

```
Batch 1 (Tier 1, 5 tools)  →  ship checkpoint  →  you say "next" or "pause"
Batch 2 (Tier 2, 7 tools)  →  ship checkpoint  →  you say "next" or "pause"
Batch 3 (Tier 3, 5 tools)  →  ship checkpoint
Batch 4 (Tier 4, 5 tools)  →  ship checkpoint
Batch 5 (Tier 5, 6 tools)  →  module complete
```

Each batch = self-verified 7/7 per tool + one PDF showing the batch result.

## Recommended starting points

- **Today**: `Forge tier 1` — 9 high-impact tools in 2-3 days
- **This week**: `Forge family DNS` — Subdomains + Cert Trans + Zone Transfer + Amass
- **This month**: `Forge module Recon` — finish all 32 tools

## Module list for Forge module commands

- `Forge module Recon`    — 32 tools remaining (3 done)
- `Forge module Webapp`   — 54 tools to re-forge through framework
- `Forge module Vuln`     — 9 tools (already AI-wired, light polish)
- `Forge module OSINT`    — 11 tools, framework-wrap
- `Forge module Exploit`  — 7 tools (already complete)
- `Forge module BOF`      — 7 phases (already complete)

## Tools already FORGED (3 — done)

- WHOIS Lookup       (2026-05-22) — 6 sources, 29 rules
- DNS Records        (2026-05-23) — 11 sources, 22 rules
- DNS Recon          (2026-05-23) — 8 sources, 13 rules

## Tools REMAINING (32) — by Tier

**Tier 1 (high customer value):**
Subdomain Discovery · Cert Transparency · WAF/CDN Fingerprint · TLS Deep Audit · Port-Scan family (Fast/Deep/Service/OS/Banner)

**Tier 2 (web content discovery):**
Directory Enumeration · JS Endpoint Extractor · Wayback Machine · robots+sitemap · BFS Crawler · Parameter Discovery · Favicon Fingerprint

**Tier 3 (cloud + infra):**
Cloud Bucket Finder · Bucket Permissions · ASN/IP Ownership · CDN Origin Discovery · DNS Zone Transfer

**Tier 4 (threat intel + passive):**
OSINT Harvesting · Shodan Lookup · Free Shodan (InternetDB) · CVE Matching (NVD) · Deep Subdomain (amass)

**Tier 5 (app-specific):**
Source Map Exposure · API Docs Discovery · WordPress wp-json Enum · Admin Panel Exposure · JS Library CVE · Git Repo Exposure

## Deploy pattern after a Forge

After Claude pushes a Forged tool:

```bash
cd /root/Cyber-project && git pull
docker compose build backend frontend
docker compose up -d --force-recreate backend frontend
```

Then in browser: hard refresh (Ctrl+Shift+R) → run scan → download PDF.

## Per-tool file layout (the template)

```
tools/recon/<tool>.py                  scanner — ~30-200 lines
tools/_payloads/<tool>_findings.py     rules — declarative library
src/App.js                             one line added — renderToolFindingsAndIntel call
```

That's everything. After Forge, you get one PDF, decide ship or next tool, no gap-spotting required.
