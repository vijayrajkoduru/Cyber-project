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
    # VL-TURBO 2.0 default — matches Webapp orchestrator. 214 scanners across
    # 15 tiers benefit from higher in-flight parallelism on dispatch.
    concurrency: Optional[int] = 24
    # Authenticated scan (so behind-login web tiers + safe_get/safe_post get the
    # session) and advanced inputs (so the SCA / container / IaC / cloud-native
    # tiers actually receive an image / repo / manifest to analyse — without
    # these they silently skip).
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None
    image_ref: Optional[str] = None
    dockerfile_text: Optional[str] = None
    pod_spec_yaml: Optional[str] = None
    kubeconfig: Optional[str] = None
    repo_url: Optional[str] = None
    options: Optional[dict] = None


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
    # VL-TURBO 2.0 — default concurrency 8 -> 24 (cap 16 -> 32). Vuln has
    # 214 scanners; old caps left the orchestrator dispatching <8% of the
    # tool surface in parallel, leaving most wall-clock time waiting on
    # HTTP/DNS. Matching Webapp's 24/32 cuts run_all from ~12min to ~4min.
    concurrency = max(1, min(req.concurrency or 24, 32))
    extra = {}
    for k in ("image_ref", "dockerfile_text", "pod_spec_yaml", "kubeconfig", "repo_url"):
        v = getattr(req, k, None)
        if v:
            extra[k] = v
    if req.options:
        extra.update(req.options)
    gen = run_module_streaming(target=req.target, tools=tools, module_name="vuln",
                               concurrency=concurrency,
                               auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
                               extra_body=(extra or None), jwt_token=jwt)
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
