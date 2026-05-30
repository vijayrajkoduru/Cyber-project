"""Vuln module orchestrator - auto-discovers real scanners from tools/vuln/tier*_*/."""
from typing import Optional
from pathlib import Path
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming

router = APIRouter()


def _discover_vuln_tools():
    out = {}
    root = Path(__file__).resolve().parent.parent / "tools" / "vuln"
    if not root.is_dir():
        return out
    for tier_dir in sorted(root.glob("tier*_*"),
                           key=lambda p: int(p.name.split("_", 1)[0].replace("tier", ""))):
        tools = []
        for fp in sorted(tier_dir.glob("*.py")):
            if fp.name == "__init__.py" or fp.name.startswith("_"):
                continue
            tools.append((fp.stem, f"/api/vuln/{fp.stem}"))
        if tools:
            out[tier_dir.name] = tools
    return out


VULN_TOOLS_BY_TIER = _discover_vuln_tools()


def _all_tools():
    out = []
    for v in VULN_TOOLS_BY_TIER.values():
        out.extend(v)
    return out


class RunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 8


@router.post("/api/vuln/run_all")
async def vuln_run_all(req: RunAllRequest, request: Request, _=Depends(verify_scan_quota)):
    tools = []
    if req.tiers:
        for t in req.tiers:
            if t in VULN_TOOLS_BY_TIER:
                tools.extend(VULN_TOOLS_BY_TIER[t])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization", "")
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    gen = run_module_streaming(target=req.target, tools=tools, module_name="vuln",
                               concurrency=max(1, min(req.concurrency or 8, 16)), jwt_token=jwt)
    return StreamingResponse(gen, media_type="application/x-ndjson",
                             headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store",
                                      "Connection": "keep-alive"})


@router.get("/api/vuln/run_all/tiers")
async def vuln_tiers():
    return {"tiers": [{"id": k, "tools": [n for n, _ in v], "count": len(v)}
                      for k, v in VULN_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(v) for v in VULN_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
