
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

## What "Forge module `<name>`" actually means

It commits to taking one module to 100.0 on the scoreboard, executed as
tier-by-tier batches:

```
Batch 1 (tier 1)  →  ship checkpoint  →  you say "next" or "pause"
Batch 2 (tier 2)  →  ship checkpoint  →  you say "next" or "pause"
...                →  module hits 100.0 on .vl-foundry-scores.json
```

Each batch = self-verified 7/7 per tool + scoreboard re-scored. **All modules
are currently at 100.0** (see status below), so today "Forge `<module>`" means
hold-the-line / regression-fix work, not net-new building.

## VL-FORGE status — SOURCE OF TRUTH

> ⚠️ **Do not hardcode "remaining" counts here — they go stale.** The
> authoritative scoreboard is `.vl-foundry-scores.json` (written by
> `scripts/pre_commit_score.py`). For a live per-layer breakdown of any module:
>
> ```bash
> python scripts/score_module.py <module> --verbose
> ```

**As of 2026-06-28: ALL 24 modules score 100.0 — the forge roadmap is complete.**

recon · network · webapp · vuln · cloud · container_k8s · osint · apisec ·
exploit · bof · password · pivot · tunnel · iot_ot · and all `mobile_*` —
every one at 100.0.

History: Recon was the first module forged (154/154 real across ~30 sessions,
mid-2026). The final gaps were closed on 2026-06-28 — pivot & tunnel
(78.3→100, canonical PROBES dict), container_k8s & cloud (wired real probes
that were missing from the techniques list), webapp (97.9→100: wired 3
forgotten scanners + good-state findings + a scorer that now recognizes
route-aliases, aggregators, and nuclei/Playwright patterns), and vuln (→100).

If a module ever dips below 100, it's almost always **L4 orchestrator** — a
real probe present in PROBES but missing from the `T`/techniques list the
orchestrator fans out, or a filename/route alias — not real quality debt.

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
