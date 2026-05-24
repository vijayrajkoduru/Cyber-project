#!/usr/bin/env python3
"""VL-FOUNDRY module scaffolder — bootstrap a NEW module from Recon's canon.

Recon scored 99.2/100 because it uses one repeatable pattern:
  • scanner file:  async gather(ctx) + INTEL_FIELDS + run_scanner() wrapper
  • findings file: a list of rule_*(s) → {name, severity, evidence, ...}
  • orchestrator:  <MODULE>_TOOLS_BY_TIER + 3 endpoints
  • frontend:      <MODULE>_PHASES + section headers + PDF callsite

This script generates ALL of that for a brand-new module in one command.

Usage:
  python scripts/forge_module.py <module> --tiers tier1_passive tier2_active

Example:
  python scripts/forge_module.py mobile --tiers \\
    tier1_apk_static tier2_apk_dynamic tier3_api_traffic

Produces:
  tools/<module>/                          — package + tier subdirs
  tools/<module>/<tier>/<starter>.py       — one starter scanner per tier
  tools/_payloads/<module>/                — wordlist package
  tools/_payloads/<starter>_findings.py    — findings rule library
  endpoints/<module>_orchestrator.py       — NDJSON + buffered + tiers routes
  VL-FOUNDRY-CHECKLIST-<module>.md         — copy of the per-forge checklist
  scripts/_FORGE_OUTPUT_<module>.md        — copy-paste snippets for App.js

After running:
  1. Fill in each starter scanner's gather() body
  2. Paste the App.js snippets where indicated
  3. Run: python scripts/score_module.py <module> --verbose
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent


# ─────────────────── TEMPLATES ───────────────────

ORCHESTRATOR_TPL = '''"""{Module} module orchestrator — VL-FOUNDRY scaffold.

POST /api/{module}/run_all          — NDJSON stream
POST /api/{module}/run_all_buffered — single big JSON
GET  /api/{module}/run_all/tiers    — tier discovery
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import (
    run_module_parallel, run_module_streaming,
)

router = APIRouter()


{MODULE}_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {{
{tier_dict_body}
}}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in {MODULE}_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class {Module}RunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 6
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in {MODULE}_TOOLS_BY_TIER:
                tools.extend({MODULE}_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {{}}), jwt


@router.post("/api/{module}/run_all")
async def {module}_run_all(req: {Module}RunAllRequest, request: Request,
                           _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 6, 12))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="{module}",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt,
    )
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={{"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"}})


@router.post("/api/{module}/run_all_buffered")
async def {module}_run_all_buffered(req: {Module}RunAllRequest, request: Request,
                                    _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 6, 12))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="{module}",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/{module}/run_all/tiers")
async def {module}_run_all_tiers():
    return {{
        "tiers": [{{"id": tid, "tools": [n for n, _ in t], "count": len(t)}}
                   for tid, t in {MODULE}_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in {MODULE}_TOOLS_BY_TIER.values()),
    }}


def register(app):
    app.include_router(router)
'''


SCANNER_TPL = '''"""{scanner} — VL-FOUNDRY scaffold (Recon canon pattern).

Route: /api/{module}/{scanner}

Pattern: async gather(ctx) populates ctx.state + ctx.source(),
then run_scanner() applies FINDING_RULES to emit findings.

TODO: implement gather() — populate ctx.state with collected facts.
TODO: edit tools/_payloads/{scanner}_findings.py — add rule_* functions.
"""
import asyncio

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.{scanner}_findings import {SCANNER}_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    """Collect facts about ctx.host. Use ctx.state[k]=v + ctx.source('name').

    Example:
        r = await asyncio.to_thread(some_external_lookup, ctx.host)
        if r:
            ctx.state["{scanner}_data"] = r
            ctx.source("external-api")
    """
    # TODO: implement scan logic
    pass


# What to show in the report — list of (display_label, state_key) pairs
INTEL_FIELDS = [
    # ("Total found", "{scanner}_total"),
    # ("Severity hint", "{scanner}_severity_hint"),
]


@router.post("/api/{module}/{scanner}")
async def {module}_{scanner}(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(
        host=host, tool="{scanner}",
        gather_func=gather,
        finding_rules={SCANNER}_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
'''


FINDINGS_TPL = '''"""{scanner} — findings rules library (VL-FOUNDRY canon).

Each rule_*(s) function reads the state dict populated by gather() and
returns a finding dict OR None. Each finding MUST include:
  name, severity (POSITIVE/INFO/LOW/MEDIUM/HIGH/CRITICAL)
  evidence (what was observed — passes Layer 6 check #6)
  remediation (how to fix — passes Layer 6 check #5)
Optional: cvss, cwe, owasp

Collected into {SCANNER}_FINDING_RULES = [rule_a, rule_b, ...].
"""


def rule_positive_emit(s):
    """Layer 6 check #3 — POSITIVE finding when scan is clean.

    Reads ctx.state. Return None if anything was actually found (other
    rules will emit those); return POSITIVE if state is empty.
    """
    if s.get("{scanner}_total"):
        return None  # actual findings exist, let other rules speak
    return {{
        "name": "{scanner} — no exposure detected",
        "severity": "POSITIVE",
        "evidence": "scan completed with zero hits",
        "remediation": "No action required — re-run quarterly.",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
    }}


# TODO: add real rules below, e.g.
#
# def rule_exposed_admin(s):
#     hits = s.get("{scanner}_admin_paths") or []
#     if not hits: return None
#     return {{
#         "name": f"{{len(hits)}} admin path(s) exposed",
#         "severity": "HIGH",
#         "cvss": "7.5",
#         "cwe": "CWE-538",
#         "owasp": "A05:2021",
#         "evidence": ", ".join(hits[:5]),
#         "remediation": "Move admin paths behind auth; add robots.txt noindex.",
#     }}


{SCANNER}_FINDING_RULES = [
    rule_positive_emit,
    # TODO: add more rule_* functions here as you write them
]
'''


CHECKLIST_TPL = '''# {Module} Module — VL-FOUNDRY Forge Checklist

Generated by scripts/forge_module.py. Tick boxes as you complete each layer.

---

## Layer 1 — Module Role
- [ ] Customer question: _________________
- [ ] PTES/NIST phase: ___________________
- [ ] Why it exists (3 bullets)
- [ ] What it isn't (3 bullets)
- [ ] Run ordering vs other modules

## Layer 2 — Tool Catalogue
{tier_checklist}

## Layer 3 — PDF Report
- [ ] `generate{Module}Report` function in src/App.js (port from Webapp canon)
- [ ] All 17 sections render
- [ ] Per-finding fields: severity, CVSS, CWE, OWASP, remediation, evidence

## Layer 4 — Orchestrator
- [x] endpoints/{module}_orchestrator.py created (by scaffolder)
- [ ] {MODULE}_TOOLS_BY_TIER populated with real scanners
- [ ] POST /api/{module}/run_all stream returns NDJSON
- [ ] Concurrency cap set + wall-clock timeout

## Layer 5 — AI Curation
- [ ] tools/_payloads/{module}/ wordlists committed
- [ ] tools/_gen/gen_{module}_assets.py for refresh

## Layer 6 — Quality bar (7-check DoD)
- [ ] precheck via safe_get/recon_host/ScanContext
- [ ] uniform_shape via run_scanner
- [ ] POSITIVE emit when clean
- [ ] severity / CVSS / CWE / OWASP on findings
- [ ] remediation per finding
- [ ] evidence_marker per finding
- [ ] wall-clock cap per scanner

## Layer 7 — Frontend
- [ ] {MODULE}_PHASES array in src/App.js (snippets in _FORGE_OUTPUT_{module}.md)
- [ ] {MODULE}_SECTION_HEADERS dict
- [ ] Module appears in nav

## Layer 22 — UI Integration
- [ ] generate{Module}Report( called from a button (>= 2 occurrences)
- [ ] {MODULE}_PHASES consumed by a component (>= 2 occurrences)
- [ ] fetch(/api/{module}/run_all) appears in App.js

## Final gate
- [ ] python scripts/score_module.py {module} >= 85
- [ ] python scripts/e2e_test.py {module} exit 0
- [ ] PDF renders all 17 sections
- [ ] Status matrix in VL-FOUNDRY.md updated
'''


APPJS_SNIPPET_TPL = '''# Manual App.js wiring snippets for `{module}` module
# Generated 2026-05-24 by forge_module.py

Paste the following into `src/App.js`. Look for the existing nav-related
constants and insert in the same region.

## 1) PHASES array (put near other *_PHASES arrays)

```javascript
// ═══════════════════════════════════════════════════════════════
//  {MODULE} MODULE — VL-FOUNDRY forge
// ═══════════════════════════════════════════════════════════════
const {MODULE}_PHASES = [
{phases_array}
];

const {MODULE}_SECTION_HEADERS = {{
{section_headers}
}};
```

## 2) PDF generator (put near other generate*Report functions)

Copy `generateOsintReport` or `generateVulnReport` as a starting point;
rename to `generate{Module}Report`; update title + INTEL_FIELDS + the 12
per-tool sections to match your scanners.

## 3) UI consumer (Layer 22 gate)

Make sure your {Module} tab component:
  • Imports/uses {MODULE}_PHASES (the second reference satisfies the
    "PHASES consumed" check)
  • Calls fetch("/api/{module}/run_all", ...) to fan out
  • Wires a "Download PDF" button to generate{Module}Report(...)

## 4) Re-score

After paste:
```bash
python scripts/score_module.py {module} --verbose
```

Target: >= 85. Layer 22 must show 3/3.
'''


# ─────────────────── SCAFFOLD LOGIC ───────────────────

def scaffold_module(module: str, tiers: list[str]) -> dict:
    """Create the entire module skeleton. Returns dict of paths created."""
    cap = module.capitalize()
    MOD = module.upper()

    created = []

    # 1. tools/<module>/ package + tier subdirs
    base = ROOT / "tools" / module
    base.mkdir(exist_ok=True)
    (base / "__init__.py").write_text(
        f'"""{cap} module scanners — VL-FOUNDRY scaffold."""\n',
        encoding="utf-8")
    created.append(str(base / "__init__.py"))

    starters = []  # (tier, scanner_name)
    for t in tiers:
        td = base / t
        td.mkdir(exist_ok=True)
        (td / "__init__.py").write_text("", encoding="utf-8")
        created.append(str(td / "__init__.py"))
        # One starter scanner per tier
        starter = f"{t}_starter"
        starters.append((t, starter))
        (td / f"{starter}.py").write_text(
            SCANNER_TPL.format(scanner=starter, SCANNER=starter.upper(),
                                module=module),
            encoding="utf-8")
        created.append(str(td / f"{starter}.py"))

    # 2. tools/_payloads/<module>/ package
    payloads = ROOT / "tools" / "_payloads" / module
    payloads.mkdir(exist_ok=True)
    (payloads / "__init__.py").write_text(
        f'"""{cap} AI-curated wordlists — VL-FOUNDRY Layer 5."""\n',
        encoding="utf-8")
    created.append(str(payloads / "__init__.py"))

    # 3. tools/_payloads/<scanner>_findings.py for each starter
    for _, scanner in starters:
        fp = ROOT / "tools" / "_payloads" / f"{scanner}_findings.py"
        fp.write_text(
            FINDINGS_TPL.format(scanner=scanner, SCANNER=scanner.upper()),
            encoding="utf-8")
        created.append(str(fp))

    # 4. endpoints/<module>_orchestrator.py
    tier_body = ",\n".join(
        f'    "{t}": [\n        ("{s}", "/api/{module}/{s}"),\n    ]'
        for t, s in starters
    )
    orch_path = ROOT / "endpoints" / f"{module}_orchestrator.py"
    orch_path.write_text(
        ORCHESTRATOR_TPL.format(
            Module=cap, module=module, MODULE=MOD,
            tier_dict_body=tier_body,
        ), encoding="utf-8")
    created.append(str(orch_path))

    # 5. Checklist
    tier_lines = "\n".join(
        f"### {t}\n- [ ] `{s}.py` — fill in gather() + finding rules"
        for t, s in starters
    )
    chk_path = ROOT / f"VL-FOUNDRY-CHECKLIST-{module}.md"
    chk_path.write_text(
        CHECKLIST_TPL.format(
            Module=cap, module=module, MODULE=MOD,
            tier_checklist=tier_lines,
        ), encoding="utf-8")
    created.append(str(chk_path))

    # 6. App.js snippets (manual paste required)
    phases_arr = ",\n".join(
        f'  {{name:"{s.replace("_", " ").title()}", tool:"{s}", '
        f'endpoint:"/api/{module}/{s}", icon:"🔹"}}'
        for _, s in starters
    )
    section_headers = ",\n".join(
        f'  "{t}": {{label:"Tier {i+1} — {t.replace("_", " ").title()}", '
        f'color:"#3b82f6"}}'
        for i, (t, _) in enumerate(starters)
    )
    snip_path = ROOT / "scripts" / f"_FORGE_OUTPUT_{module}.md"
    snip_path.write_text(
        APPJS_SNIPPET_TPL.format(
            module=module, Module=cap, MODULE=MOD,
            phases_array=phases_arr, section_headers=section_headers,
        ), encoding="utf-8")
    created.append(str(snip_path))

    return {"created": created, "starters": starters}


def main():
    ap = argparse.ArgumentParser(
        description="Scaffold a new VL-FOUNDRY module from Recon's canon")
    ap.add_argument("module", help="Module name (lowercase, e.g. mobile, cloud)")
    ap.add_argument("--tiers", nargs="+", required=True,
                    help="Tier names (e.g. tier1_passive tier2_active)")
    args = ap.parse_args()

    if (ROOT / "tools" / args.module).exists():
        sys.exit(f"tools/{args.module}/ already exists. Refusing to overwrite.")

    result = scaffold_module(args.module, args.tiers)

    print(f"\n✓ Forged module '{args.module}' with {len(result['starters'])} starter scanners.")
    print(f"\nCreated {len(result['created'])} files:")
    for p in result["created"]:
        print(f"  {p}")

    print(f"\nNext steps:")
    print(f"  1. Fill in each tools/{args.module}/<tier>/<starter>.py gather() body")
    print(f"  2. Add real rule_*() functions to each "
          f"tools/_payloads/<starter>_findings.py")
    print(f"  3. Paste App.js snippets from "
          f"scripts/_FORGE_OUTPUT_{args.module}.md")
    print(f"  4. Run: python scripts/score_module.py {args.module} --verbose")
    print(f"  5. When score >= 85: commit + push + deploy")


if __name__ == "__main__":
    main()
