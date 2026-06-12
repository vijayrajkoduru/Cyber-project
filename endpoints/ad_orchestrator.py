"""ad module orchestrator - Active Directory attacks.

Per module_playbooks/19_ad.md - 11 sections, 132 techniques.

VA-not-PT: scanners DETECT conditions; they never exploit, relay, coerce, or
chain. Graded severities are emitted only when a probe actually observed the
condition on the live target. Techniques that cannot be honestly probed from an
external SaaS (domain creds / on-host / LAN adjacency / active exploitation /
destructive) are surfaced as honest INFO advisories by the offensive_advisory
scanner.

Live-probe scanners (real detection, no exploitation):
  - §1 Discovery: ldap_anon_enum, smb_signing_check, dc_discovery,
                  enum4linux_ng_audit, smb_os_fingerprint (SMBv1 + OS),
                  smb_null_session (null-session SMB/RPC),
                  ldap_signing_check (LDAPS / cleartext-LDAP downgrade surface)
  - §2/§3 Cred:   netexec_smb_spray (input-driven), asrep_roast (AS-REP
                  roastable detection), kerberos_userenum (KDC username enum)
  - §6 AD CS:     certipy_find (templates, creds optional),
                  adcs_web_enrollment (ESC8 HTTP-NTLM relay surface, no creds)
Advisory-by-design (honest INFO catalogue): offensive_advisory.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


AD_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_discovery": [
        ("ldap_anon_enum",         "/api/ad/ldap_anon_enum"),
        ("smb_signing_check",      "/api/ad/smb_signing_check"),
        ("dc_discovery",           "/api/ad/dc_discovery"),
        ("enum4linux_ng_audit",    "/api/ad/enum4linux_ng_audit"),
        ("smb_os_fingerprint",     "/api/ad/smb_os_fingerprint"),
        ("smb_null_session",       "/api/ad/smb_null_session"),
        ("ldap_signing_check",     "/api/ad/ldap_signing_check"),
        ("offensive_advisory",     "/api/ad/offensive_advisory"),
    ],
    "tier2_cred_access": [
        ("netexec_smb_spray",      "/api/ad/netexec_smb_spray"),
        ("asrep_roast",            "/api/ad/asrep_roast"),
    ],
    "tier3_kerberoast": [
        ("kerberos_userenum",      "/api/ad/kerberos_userenum"),
    ],
    "tier6_adcs": [
        ("certipy_find",           "/api/ad/certipy_find"),
        ("adcs_web_enrollment",    "/api/ad/adcs_web_enrollment"),
    ],
}


def _all_tools():
    out = []
    for tier in AD_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class AdRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 4
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in AD_TOOLS_BY_TIER:
                tools.extend(AD_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/ad/run_all")
async def ad_run_all(req: AdRunAllRequest, request: Request,
                       _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    gen = run_module_streaming(target=req.target, tools=tools, module_name="ad",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/ad/run_all_buffered")
async def ad_run_all_buffered(req: AdRunAllRequest, request: Request,
                                _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    return await run_module_parallel(target=req.target, tools=tools, module_name="ad",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/ad/run_all/tiers")
async def ad_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in AD_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in AD_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
