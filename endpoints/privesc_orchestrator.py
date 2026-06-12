"""privesc module orchestrator - Privilege-Escalation enumeration probes.

Per module_playbooks/12_privesc.md - 7 sections, 88 techniques.
Starter set (5 scanners) covers the highest-impact playbook items:
  - tier1_linux: linpeas_remote_audit (§1 #1), suid_binary_audit (§4 #52),
                 sudo_misconfig_audit (§4 #48-50),
                 kernel_exploit_check (§6 #73-77)
  - tier2_windows: winpeas_check (§2 #19)

Concurrency is LOW (2) for the same reason as the password module —
running multiple PEASS scripts against the same target simultaneously
causes resource contention on the customer's box (LinPEAS/WinPEAS each
fork hundreds of subprocesses) and trips fail2ban / Sysmon rate limits.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


PRIVESC_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_linux": [
        ("linpeas_remote_audit",       "/api/privesc/linpeas_remote_audit"),
        ("suid_binary_audit",          "/api/privesc/suid_binary_audit"),
        ("sudo_misconfig_audit",       "/api/privesc/sudo_misconfig_audit"),
        ("kernel_exploit_check",       "/api/privesc/kernel_exploit_check"),
        # Credential-less remote probe: SSH banner -> OpenSSH EOL +
        # §1/§4/§7 advisory-by-design catalogue.
        ("ssh_privesc_surface_probe",  "/api/privesc/ssh_privesc_surface_probe"),
    ],
    "tier2_windows": [
        ("winpeas_check",              "/api/privesc/winpeas_check"),
        # Credential-less remote probe: HTTP OS fingerprint -> §2/§3/§5/§6
        # advisory-by-design catalogue keyed to the inferred OS family.
        ("os_fingerprint_privesc_advisory",
         "/api/privesc/os_fingerprint_privesc_advisory"),
    ],
    "tier3_container": [
        # Credential-less remote probe: exposed Docker API / kubelet / k8s API
        # (graded only when answering UNAUTHENTICATED) + §7 advisory catalogue.
        ("container_privesc_surface_probe",
         "/api/privesc/container_privesc_surface_probe"),
    ],
}


def _all_tools():
    out = []
    for tier in PRIVESC_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class PrivescRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 2
    options: Optional[dict] = None


def _resolve(req: PrivescRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in PRIVESC_TOOLS_BY_TIER:
                tools.extend(PRIVESC_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    # Nest customer options so each scanner reads via req.options (the
    # orchestrator flattens extra_body into the per-tool body).
    extra: dict = {}
    if req.options:
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/privesc/run_all")
async def privesc_run_all(req: PrivescRunAllRequest, request: Request,
                           _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    # Hard-clamp concurrency to 2 (privesc rule: PEASS scripts are heavy).
    concurrency = max(1, min(req.concurrency or 2, 2))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="privesc",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )
    return StreamingResponse(
        gen,
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control":     "no-store, no-transform",
            "Connection":        "keep-alive",
        },
    )


@router.post("/api/privesc/run_all_buffered")
async def privesc_run_all_buffered(req: PrivescRunAllRequest, request: Request,
                                    _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 2, 2))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="privesc",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )


@router.get("/api/privesc/run_all/tiers")
async def privesc_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in PRIVESC_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in PRIVESC_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
