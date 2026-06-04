"""Metasploit module orchestrator — 11_metasploit.md (67 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.metasploit.metasploit_pack import TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_auxiliary",   0, 10),
    ("tier2_exploits",   10, 21),
    ("tier3_payloads",   21, 30),
    ("tier4_post_exploit", 30, 40),
    ("tier5_encoders",   40, 46),
    ("tier6_db",         46, 52),
    ("tier7_meterpreter", 52, 62),
    ("tier8_modern_evasion", 62, 67),
]

METASPLOIT_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/metasploit/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class MetasploitRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in METASPLOIT_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/metasploit/run_all")
async def metasploit_run_all(req: MetasploitRunAllRequest, request: Request,
                              _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="metasploit", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/metasploit/run_all/tiers")
async def metasploit_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in METASPLOIT_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in METASPLOIT_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
