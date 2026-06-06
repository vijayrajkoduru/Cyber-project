"""Recon module orchestrator — auto-discovers real scanners from tools/recon/tier*/."""
from typing import Optional
from pathlib import Path
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()

# ── Auto-discovery ──────────────────────────────────────────
# Walks tools/recon/tier*_*/ at import time.
# Excludes scaffold files (those with "scaffold" markers) so run_all only dispatches
# real, working scanners. As you replace scaffolds with real code, they auto-register
# on the next backend restart. No manual list-keeping.

_SCAFFOLD_MARKERS = ('state["scaffold"]', '"Scaffold:', 'scaffold = True', "ctx.source(\"scaffold")

def _is_scaffold(py_file: Path) -> bool:
    try:
        txt = py_file.read_text(encoding="utf-8")
        return any(m in txt for m in _SCAFFOLD_MARKERS)
    except Exception:
        return True  # if unreadable, skip safely

def _discover_recon_tools():
    out = {}
    recon_root = Path(__file__).resolve().parent.parent / "tools" / "recon"
    if not recon_root.is_dir():
        return out
    for tier_dir in sorted(recon_root.glob("tier*_*"),
                            key=lambda p: int(p.name.split("_",1)[0].replace("tier",""))):
        tools = []
        for f in sorted(tier_dir.glob("*.py")):
            if f.name == "__init__.py" or f.name.startswith("_"):
                continue
            if _is_scaffold(f):
                continue  # skip until real
            tool_name = f.stem
            tools.append((tool_name, f"/api/recon/{tool_name}"))
        if tools:
            out[tier_dir.name] = tools
    return out

RECON_TOOLS_BY_TIER = _discover_recon_tools()


def _all_tools():
    out = []
    for tier in RECON_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class RunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 8
    # AUTHED-RECON-V1 (2026-06-06): customer-supplied login session for
    # authenticated recon. Captured by frontend via POST /api/scan/login,
    # then echoed into this request so every web-facing scanner crawls the
    # post-login surface. Both fields optional — unauthenticated scan is
    # the default.
    auth_cookie: Optional[str] = None       # e.g. "PHPSESSID=abc; token=xyz"
    auth_bearer: Optional[str] = None       # e.g. "eyJhbGci..." (JWT/OAuth)


@router.post("/api/recon/run_all")
async def recon_run_all(req: RunAllRequest, request: Request, _=Depends(verify_scan_quota)):
    tools = []
    if req.tiers:
        for t in req.tiers:
            if t in RECON_TOOLS_BY_TIER:
                tools.extend(RECON_TOOLS_BY_TIER[t])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization", "")
    jwt = auth.split(" ",1)[1].strip() if auth.lower().startswith("bearer ") else None
    gen = run_module_streaming(target=req.target, tools=tools, module_name="recon",
                                concurrency=max(1, min(req.concurrency or 8, 16)),
                                auth_cookie=req.auth_cookie,
                                auth_bearer=req.auth_bearer,
                                jwt_token=jwt)
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store", "Connection":"keep-alive"})


@router.get("/api/recon/run_all/tiers")
async def recon_tiers():
    return {
        "tiers": [{"id": k, "tools": [n for n,_ in v], "count": len(v)} for k,v in RECON_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(v) for v in RECON_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
