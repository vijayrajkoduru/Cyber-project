"""metasploit module orchestrator - Metasploit Framework lite wrapper.

Per module_playbooks/11_metasploit.md - 8 sections, 78 techniques.
Starter set (5 scanners) covers the highest-impact playbook items
that a LITE wrapper (no MSF bundled in the scanner image) can drive:

  tier1_msf_core (§1 Auxiliary / §6 Database):
        msf_module_inventory  - module catalog health check
        msf_auxiliary_scan    - run a single auxiliary/* module
        msfdb_status_audit    - PostgreSQL backend health
  tier2_payloads (§3 Payloads / §4 Post-Exploitation):
        msf_payload_generation_test  - benign msfvenom calc.exe test
        msf_post_exploitation_modules_list - post/* catalog inventory

The image does NOT bundle Metasploit Framework itself (4 GB + a
PostgreSQL backend). Every probe checks for msfconsole/msfvenom/msfdb
via shutil.which() and emits an INFO finding with installer
instructions when the binary is missing.

ScanRequest.options carries per-probe knobs:
  - options.module           auxiliary module path for msf_auxiliary_scan
  - options.RHOSTS           target list override
  - options.RPORT            module RPORT override
  - options.module_options   dict of "SET name value" pairs
  - options.timeout_sec      wall-clock cap per probe

Concurrency = 2 because msfconsole takes 30-60s to boot and consumes
~600 MB of RAM per process; running > 2 in parallel on a typical 4 GB
scanner host will swap and time out the entire batch.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


METASPLOIT_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_msf_core": [
        ("msf_module_inventory", "/api/metasploit/msf_module_inventory"),
        ("msf_auxiliary_scan",   "/api/metasploit/msf_auxiliary_scan"),
        ("msfdb_status_audit",   "/api/metasploit/msfdb_status_audit"),
    ],
    "tier2_payloads": [
        ("msf_payload_generation_test",
         "/api/metasploit/msf_payload_generation_test"),
        ("msf_post_exploitation_modules_list",
         "/api/metasploit/msf_post_exploitation_modules_list"),
    ],
}


def _all_tools():
    out = []
    for tier in METASPLOIT_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class MetasploitRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 2
    options: Optional[dict] = None


def _resolve(req: MetasploitRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in METASPLOIT_TOOLS_BY_TIER:
                tools.extend(METASPLOIT_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    # Nest customer options so each scanner reads via req.options
    extra: dict = {}
    if req.options:
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/metasploit/run_all")
async def metasploit_run_all(req: MetasploitRunAllRequest, request: Request,
                              _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    # Hard-clamp concurrency to 2 - msfconsole boots are heavy
    # (~600 MB RAM, 30-60s warm-up); > 2 parallel processes will
    # swap a 4 GB scanner host and time out the batch.
    concurrency = max(1, min(req.concurrency or 2, 2))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="metasploit",
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


@router.post("/api/metasploit/run_all_buffered")
async def metasploit_run_all_buffered(req: MetasploitRunAllRequest, request: Request,
                                       _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 2, 2))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="metasploit",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )


@router.get("/api/metasploit/run_all/tiers")
async def metasploit_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in METASPLOIT_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in METASPLOIT_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
