# VulnusLab Module Build Playbook

Master reference for building any new module from scratch — without AI forge.
Use this as a checklist OR paste it as a prompt to any AI assistant to build a module.

---

## INPUTS YOU PROVIDE

1. **Module name** (snake_case, e.g. `cloud_security`, `iot_static`, `web3_audit`)
2. **Module type** — one of:
   - **passive** — scans 3rd-party APIs by domain (like OSINT, Recon)
   - **active** — probes a live target by URL/IP (like Webapp, Vuln)
   - **binary-static** — analyzes uploaded files (like §1 mobile_static)
3. **Scanner list** — array of `{name, tooling, expected_findings}` (typically 8-15 scanners)
4. **Module role** — one-sentence customer question this module answers

---

## PHASE 0 — Decide module shape (5 min)

| Question | If YES | If NO |
|---|---|---|
| Does it need uploaded files (APK/IPA/PE/ELF/PDF)? | Type = **binary-static** | Skip to next |
| Does it probe customer infra directly (HTTP/TCP)? | Type = **active** | Skip to next |
| Does it only hit 3rd-party APIs by domain? | Type = **passive** | — |

This determines the input the scanners take:
- **passive/active:** scanners take `req.target` (a domain or URL)
- **binary-static:** scanners take `req.target` = uploaded file path

---

## PHASE 1 — External CLI tools (only if scanners need them)

**Skip this phase if all scanners are pure Python.**

### 1.1 — Update `Dockerfile` with apt + pip installs

Add a `RUN` block (place AFTER the base `apt-get install` and BEFORE `WORKDIR /app`):

```dockerfile
# ── <MODULE_NAME> external tooling ─────────────────────────────────
RUN apt-get update -q -o Acquire::Retries=3 \
 && apt-get install -y -q --no-install-recommends \
        TOOL1 TOOL2 TOOL3 \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        PYLIB1 PYLIB2
```

### 1.2 — Update `tools/_framework/tool_versions.json`

For each CLI tool, add:

```json
{
  "name": "TOOL_NAME",
  "min_version": "X.Y",
  "check_cmd": ["TOOL_NAME", "--version"],
  "parse_re": "VERSION_REGEX",
  "required": false,
  "used_by": ["<MODULE_NAME>"]
}
```

### 1.3 — Rebuild backend Docker (FORCE — Docker cache often lies)

```bash
docker rmi cyber-project-backend --force
docker compose build --no-cache --pull backend
docker compose up -d --force-recreate backend
sleep 40
docker compose exec backend bash -c "which TOOL1 TOOL2"
```

The final `which` MUST print paths. If empty, Phase 1 is not done.

---

## PHASE 2 — File upload pipeline (only for binary-static modules)

**Skip this phase for passive/active modules.**

### 2.1 — Add upload endpoint

In `endpoints/<module>_orchestrator.py`:

```python
from fastapi import UploadFile, File
import uuid
from pathlib import Path

UPLOAD_DIR = Path("/uploads") / "<module>"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

@router.post("/api/<module>/upload")
async def <module>_upload(file: UploadFile = File(...), _=Depends(verify_scan_quota)):
    if file.size and file.size > 100 * 1024 * 1024:  # 100 MB cap
        return {"detail": "File too large (max 100MB)"}, 413
    # Read first 4 bytes to verify magic (APK/IPA = PK\x03\x04)
    head = await file.read(4)
    if head[:2] != b"PK":
        return {"detail": "Invalid file format"}, 400
    scan_id = uuid.uuid4().hex[:12]
    out_path = UPLOAD_DIR / f"{scan_id}_{file.filename}"
    await file.seek(0)
    with out_path.open("wb") as f:
        while chunk := await file.read(1024 * 1024):
            f.write(chunk)
    return {"scan_id": scan_id, "apk_path": str(out_path), "filename": file.filename}
```

### 2.2 — Add Docker volume in `docker-compose.yml`

```yaml
services:
  backend:
    volumes:
      - uploads:/uploads
volumes:
  uploads:
```

### 2.3 — Frontend file upload button (Phase 7 details)

---

## PHASE 3 — Module skeleton (15 min)

### 3.1 — Directory structure

```
tools/<module>/__init__.py
tools/<module>/<tier1_name>/__init__.py
tools/<module>/<tier2_name>/__init__.py
tools/<module>/<tier3_name>/__init__.py
tools/<module>/<tier4_name>/__init__.py
```

Each `__init__.py` is just:
```python
"""<module> module — <tier> scanners."""
```

### 3.2 — Orchestrator file

`endpoints/<module>_orchestrator.py`:

```python
"""<Module> module orchestrator."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()

<MODULE>_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "<tier1_id>": [
        ("<scanner1_name>", "/api/<module>/<scanner1_name>"),
        ("<scanner2_name>", "/api/<module>/<scanner2_name>"),
        ("<scanner3_name>", "/api/<module>/<scanner3_name>"),
    ],
    # ... repeat for tier2, tier3, tier4
}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in <MODULE>_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class <Module>RunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 6
    options: Optional[dict] = None


def _resolve(req, request: Request):
    tools = (
        [t for tid in req.tiers for t in <MODULE>_TOOLS_BY_TIER.get(tid, [])]
        if req.tiers else _all_tools()
    )
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/<module>/run_all")
async def <module>_run_all(req: <Module>RunAllRequest, request: Request,
                           _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 6, 12))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="<module>",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt,
    )
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"})


@router.post("/api/<module>/run_all_buffered")
async def <module>_run_all_buffered(req: <Module>RunAllRequest, request: Request,
                                    _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 6, 12))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="<module>",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/<module>/run_all/tiers")
async def <module>_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in <MODULE>_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in <MODULE>_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
```

---

## PHASE 4 — Write each scanner (~30 min each)

### Template A — Passive/active scanner (HTTP-based)

`tools/<module>/<tier>/<scanner_name>.py`:

```python
"""<scanner_name> — <one-line role>."""
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host, safe_get
from tools._framework import ScanContext, run_scanner
from tools._payloads.<scanner_name>_findings import <SCANNER_UPPER>_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    """Populate ctx.state with collected facts."""
    host = ctx.host
    # YOUR LOGIC: call safe_get(url, req=ctx.req, timeout=5), parse, populate state
    # Example:
    # r = safe_get(f"https://api.example.com/lookup?q={host}", timeout=5)
    # if r and r.status_code == 200:
    #     ctx.state["<scanner_name>_data"] = r.json()
    #     ctx.source("example-api")
    ctx.state["<scanner_name>_total"] = 0  # update with real count


INTEL_FIELDS = [
    # ("Display label", "state_key"),
]


@router.post("/api/<module>/<scanner_name>")
async def <module>_<scanner_name>(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(
        host=host, tool="<scanner_name>",
        gather_func=gather,
        finding_rules=<SCANNER_UPPER>_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
```

### Template B — Binary-static scanner (file input)

```python
"""<scanner_name> — <one-line role>."""
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.<scanner_name>_findings import <SCANNER_UPPER>_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    """Read uploaded binary at ctx.host (= apk_path); populate ctx.state."""
    apk_path = ctx.host
    if not Path(apk_path).is_file():
        ctx.state["<scanner_name>_total"] = 0
        ctx.source("file-not-found")
        return

    try:
        result = subprocess.run(
            ["<CLI_TOOL>", "<args>", str(apk_path)],
            capture_output=True, text=True, timeout=60,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        ctx.state["<scanner_name>_error"] = str(e)
        return

    # Parse result.stdout, populate ctx.state[*] keys
    ctx.source("<CLI_TOOL>")
    ctx.state["<scanner_name>_total"] = 0  # real count


INTEL_FIELDS = [
    # ("Display label", "state_key"),
]


@router.post("/api/<module>/<scanner_name>")
async def <module>_<scanner_name>(req: ScanRequest, _=Depends(verify_scan_quota)):
    apk_path = req.target  # caller passes the uploaded file path
    return await run_scanner(
        host=apk_path, tool="<scanner_name>",
        gather_func=gather,
        finding_rules=<SCANNER_UPPER>_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
```

### Critical gotchas to avoid (learned the hard way)

1. **`run_scanner()` parameter names are EXACT** — `host=`, `tool=`, `gather_func=`, `finding_rules=`, `intel_fields=`, `flat_field_keys=`. **No `req=`, no `scanner_name=`, no `gather_fn=`, no `scan_fn=`, no `rules=`.**
2. **Every scanner file MUST end with** `def register(app): app.include_router(router)` — autoloader skips files without it.
3. **Every subprocess call MUST have a timeout** — use `timeout=60` (or 120 for MobSF).
4. **Handle FileNotFoundError + TimeoutExpired silently** — don't crash the scan because one tool is missing.
5. **Don't import other scanners** — scanners are isolated. Shared infra goes in `tools/_framework/`.

---

## PHASE 5 — Write findings rules (per scanner)

`tools/_payloads/<scanner_name>_findings.py`:

```python
"""<scanner_name> — findings rules library."""


def rule_positive_emit(s):
    """POSITIVE finding when scan ran cleanly."""
    if s.get("<scanner_name>_total"):
        return None  # other rules will speak
    return {
        "name": "<scanner_name> — no exposure detected",
        "severity": "POSITIVE",
        "evidence": "scan completed with zero hits",
        "remediation": "No action required.",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
    }


def rule_<finding_name>(s):
    """<What this rule fires on>."""
    hits = s.get("<state_key>") or []
    if not hits:
        return None
    return {
        "name": f"<finding title> — {len(hits)} match(es)",
        "severity": "HIGH",        # POSITIVE/INFO/LOW/MEDIUM/HIGH/CRITICAL
        "cvss": "7.5",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "evidence": "; ".join(str(h)[:80] for h in hits[:5]),
        "remediation": "Specific actionable fix",
    }


<SCANNER_UPPER>_FINDING_RULES = [
    rule_positive_emit,
    rule_<finding_name>,
    # add more rules
]
```

---

## PHASE 6 — Sidebar entry + tab routing in `src/App.js`

### 6.1 — Add to sidebar list (around line 100-130)

```javascript
{ id:"<module>", icon:"<emoji>", label:"<Display Name>", cat:"<scan|advanced|...>", free:false },
```

### 6.2 — Add PHASES array (near OSINT_PHASES)

```javascript
const <MODULE>_PHASES = [
  {name:"<Scanner Display Name>", tool:"<scanner_name>", endpoint:"/api/<module>/<scanner_name>", icon:"<emoji>"},
  // ... 12 entries total
];

const <MODULE>_SECTION_HEADERS = {
  "<tier1_id>": {label:"Tier 1 - <Label>", color:"#3b82f6"},
  "<tier2_id>": {label:"Tier 2 - <Label>", color:"#8b5cf6"},
  "<tier3_id>": {label:"Tier 3 - <Label>", color:"#ef4444"},
  "<tier4_id>": {label:"Tier 4 - <Label>", color:"#06b6d4"},
};
```

### 6.3 — Add tab routing (around line 15315)

```javascript
<div style={{display: active==="<module>" ? "block" : "none"}}>
  <<Module>Module token={token} apiUrl={API}/>
</div>
```

### 6.4 — Component (model after `OsintModule` for passive, `MobileModule` for binary-static)

Pass `MOBILE_PHASES`-style array + endpoint → ModuleShell handles the UI rendering.

---

## PHASE 7 — PDF generator

### 7.1 — Add to App.js (near `generateOsintReport`)

```javascript
function generate<Module>Report({target, allResults, date, authenticated, pdfConfig}) {
  // Easiest path: alias to generateOsintReport for now
  return generateOsintReport({target, allResults, date, authenticated, pdfConfig});
}
```

### 7.2 — For canonical 17-section PDF

Copy `generatePDF` (line ~761 in App.js) — it's the Webapp canon. Rename + customize per-tool sections to match your 12 scanners.

The 17 sections are:
1. Cover page
2. Info table
3. Trust statement
4. Key Risk Headline
5. Executive Summary
6. OWASP Top 10 Grade
7. Compliance Coverage (8 frameworks)
8. Remediation Diff
9. Risk Score Bar (0-100)
10. Severity Breakdown
11. Tier Coverage matrix
12. Per-Tool Sections
13. Detailed Findings
14. Recommendations
15. Verification Audit
16. Appendix
17. Border + Footer (Report ID + Content Hash)

---

## PHASE 8 — Deploy + verify

### 8.1 — Local push

```bash
git add -A && git commit -m "Add <module> module — N scanners across N tiers"
git push origin main
```

### 8.2 — On VPS

```bash
cd ~/Cyber-project && git pull --rebase
docker rmi cyber-project-backend cyber-project-frontend --force
docker compose build --no-cache --pull backend frontend
docker compose up -d --force-recreate backend frontend
sleep 40
```

### 8.3 — Verify backend loaded all scanners

```bash
docker compose logs backend 2>&1 | grep "Loaded tool: tools.<module>" | wc -l
# Should print 12 (or however many scanners you wrote)
```

### 8.4 — Verify routes exist

```bash
curl -sS http://localhost:8000/api/<module>/run_all/tiers | python3 -m json.tool
# Should show 4 tiers with 12 tools
```

### 8.5 — Smoke test (one scanner without auth)

```bash
curl -sS -X POST http://localhost:8000/api/<module>/<scanner_name> \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com"}' -m 30
# Should return {"detail":"Missing Authorization header"} — proves route exists + works
```

### 8.6 — Score the module

```bash
python scripts/score_module.py <module> --verbose 2>&1 | head -30
```

Target: ≥85/100. Common failures:
- L4 orchestrator <100% → scanner not in `_TOOLS_BY_TIER` dict
- L7 frontend <100% → scanner not in `<MODULE>_PHASES` array
- L22 UI integration <100% → missing `generate<Module>Report` call or `<MODULE>_PHASES` reference or `/api/<module>/run_all` fetch

### 8.7 — Browser test

Open `https://app.vulnuslab.com` in Incognito → log in → click new module tab → scan a target → download PDF.

---

## COMMON BUGS — Pre-flight checklist before deploying

| Symptom | Fix |
|---|---|
| `tool has no register(app)` in logs | Add `def register(app): app.include_router(router)` at end of scanner file |
| `TypeError: run_scanner() got unexpected keyword argument` | Check parameter names: `host`, `tool`, `gather_func`, `finding_rules`, `intel_fields`, `flat_field_keys` |
| `ImportError: cannot import name X_FINDING_RULES` | Variable name in findings file must match `<SCANNER_UPPER>_FINDING_RULES` exactly |
| `Loaded tool: tools.<module>` shows 0 in logs | Check `__init__.py` exists in module + tier dirs |
| 404 on every scanner endpoint | Backend container is stale — `docker rmi` + `docker compose build --no-cache` |
| 500 on every scanner endpoint | Backend logs will show traceback — usually missing dep or wrong subprocess args |
| Frontend tile shows "Not Found" after scan | Click Tool Refresh button first (clears cache from old scans) |
| PDF looks generic, not 17 sections | `generate<Module>Report` not wired — points at ModuleShell default. Wire it explicitly. |
| `Built 0.0s` despite `--no-cache` | Docker layer cache — run `docker rmi cyber-project-backend --force` first |

---

## TIME BUDGET

| Module type | Realistic time |
|---|---|
| Pure passive (HTTP only) | 6-8 hours |
| Binary-static (with upload pipeline) | 12-16 hours |
| Active (probes customer infra) | 8-12 hours |

Split across 2-3 sessions to avoid burnout. Don't try to do it all in one sitting.

---

## REFERENCE FILES (read these first)

| File | Why |
|---|---|
| `tools/recon/tier4_web/wayback.py` | Reference passive scanner (99/100 module) |
| `tools/_framework/scanner.py` | `ScanContext` + `run_scanner` API |
| `tools/_framework/findings.py` | How `FINDING_RULES` get applied |
| `endpoints/recon_orchestrator.py` | Reference orchestrator pattern |
| `src/App.js:761` (generatePDF) | Reference 17-section PDF (Webapp canon) |
| `src/App.js:11307` (OSINT_PHASES) | Reference PHASES array pattern |
| `mobile_ruff.md` | If building a mobile module — 131-technique reference |

---

## END

Copy this entire playbook as a prompt to any AI to scaffold a new module. Replace `<module>`, `<tier>`, `<scanner_name>` etc. with your real values.

The framework infrastructure (`tools/_framework/`, `scripts/score_module.py`, `scripts/deploy.sh`, `scripts/smoke_test.sh`, `scripts/doctor.py`) is preserved. Use those gates after each phase.
