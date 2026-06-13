"""Quantum Readiness orchestrator — auto-discovers scanners from
tools/quantum_readiness/tier*_*/. Mirrors the Recon orchestrator pattern;
no cross-module imports (VL-CORE module isolation)."""
from typing import Optional
from pathlib import Path
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming

router = APIRouter()

_SCAFFOLD_MARKERS = ('state["scaffold"]', '"Scaffold:', 'scaffold = True', 'ctx.source("scaffold')


def _is_scaffold(py_file: Path) -> bool:
    try:
        txt = py_file.read_text(encoding="utf-8")
        return any(m in txt for m in _SCAFFOLD_MARKERS)
    except Exception:
        return True


def _discover_tools():
    out = {}
    root = Path(__file__).resolve().parent.parent / "tools" / "quantum_readiness"
    if not root.is_dir():
        return out
    for tier_dir in sorted(root.glob("tier*_*"),
                           key=lambda p: int(p.name.split("_", 1)[0].replace("tier", ""))):
        tools = []
        for f in sorted(tier_dir.glob("*.py")):
            if f.name == "__init__.py" or f.name.startswith("_"):
                continue
            if _is_scaffold(f):
                continue
            tools.append((f.stem, f"/api/quantum_readiness/{f.stem}"))
        if tools:
            out[tier_dir.name] = tools
    return out


QR_TOOLS_BY_TIER = _discover_tools()


def _all_tools():
    out = []
    for tier in QR_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class RunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 12


@router.post("/api/quantum_readiness/run_all")
async def qr_run_all(req: RunAllRequest, request: Request, _=Depends(verify_scan_quota)):
    tools = []
    if req.tiers:
        for t in req.tiers:
            if t in QR_TOOLS_BY_TIER:
                tools.extend(QR_TOOLS_BY_TIER[t])
    else:
        tools = _all_tools()
    concurrency = max(1, min(req.concurrency or 12, 24))
    gen = run_module_streaming(target=req.target, tools=tools,
                               module_name="quantum_readiness", concurrency=concurrency)
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store", "Connection": "keep-alive"})


@router.get("/api/quantum_readiness/run_all/tiers")
async def qr_tiers():
    return {
        "tiers": [{"id": k, "tools": [n for n, _ in v], "count": len(v)} for k, v in QR_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(v) for v in QR_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
