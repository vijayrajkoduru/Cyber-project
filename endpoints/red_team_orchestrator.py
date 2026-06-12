"""red_team module orchestrator - Adversary Emulation / detection-baseline.

Per module_playbooks/27_red_team.md - 8 sections, 88 techniques.

Scanner set (8 scanners across 4 tiers):
  - tier1_simulation (3 LOUD signal emitters, customer-owned receivers):
        atomic_red_team_runner (SSH/WinRM Atomic Red Team subset),
        c2_beacon_test (jittered HTTPS + DNS C2 beacons),
        exfil_dns_simulation (chunked base32 DNS exfil)
  - tier2_detection (2 detection-test/rollup):
        lateral_pivot_signal_check (impacket PtH signals -> 4625),
        mitre_attack_simulation_summary (Navigator JSON layer)
  - tier3_c2_infra (2 REAL, QUIET external-exposure probes — read-only HTTP
        GET + passive TLS cert read; graded findings fire ONLY on a unique
        product/C2 signature confirmed live on the target):
        c2_framework_exposure (Cobalt Strike/Sliver/Mythic/Empire/Havoc/
            Metasploit/Merlin/GoPhish exposed control planes),
        detection_tooling_exposure (exposed Splunk/Kibana/Elastic/Grafana/
            Graylog/Wazuh/CALDERA/Navigator consoles)
  - tier4_advisory (1 honest advisory-by-design INFO pack):
        red_team_advisory_pack (every playbook technique that genuinely
            cannot be probed from an external VA scan — on-host emulation,
            active C2 operation, threat-actor TTP chains, SIEM-internal
            detection engineering, purple-team workflow, manual plans)

Concurrency = 2 (the tier1/tier2 probes emit LOUD signals — running too
many in parallel floods the customer's SIEM and triggers rate-limited
alerting; the clamp is module-wide and harmless for the quiet tier3/tier4
read-only probes).

Customer input pattern: ScanRequest.options.* carries all customer-owned
targets (c2_callback_url, c2_dns_domain, exfil_dns_domain, lateral_target,
atomic_user/password/os/port). Targets are ALWAYS customer-supplied —
the probes never auto-discover internal infrastructure.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


RED_TEAM_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_simulation": [
        ("atomic_red_team_runner",         "/api/red_team/atomic_red_team_runner"),
        ("c2_beacon_test",                 "/api/red_team/c2_beacon_test"),
        ("exfil_dns_simulation",           "/api/red_team/exfil_dns_simulation"),
    ],
    "tier2_detection": [
        ("lateral_pivot_signal_check",     "/api/red_team/lateral_pivot_signal_check"),
        ("mitre_attack_simulation_summary","/api/red_team/mitre_attack_simulation_summary"),
    ],
    # tier3_c2_infra — REAL external exposure detection (read-only HTTP GET +
    # passive TLS read). Graded findings only fire on a unique product/C2
    # signature confirmed live on the target; otherwise INFO/POSITIVE.
    "tier3_c2_infra": [
        ("c2_framework_exposure",          "/api/red_team/c2_framework_exposure"),
        ("detection_tooling_exposure",     "/api/red_team/detection_tooling_exposure"),
    ],
    # tier4_advisory — honest advisory-by-design INFO catalogue for the
    # playbook techniques that genuinely cannot be probed from an external VA
    # scan (on-host emulation, active C2 operation, threat-actor TTP chains,
    # SIEM-internal detection engineering, purple-team workflow, manual plans).
    "tier4_advisory": [
        ("red_team_advisory_pack",         "/api/red_team/red_team_advisory_pack"),
    ],
}


def _all_tools():
    out = []
    for tier in RED_TEAM_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class RedTeamRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 2
    options: Optional[dict] = None


def _resolve(req: RedTeamRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in RED_TEAM_TOOLS_BY_TIER:
                tools.extend(RED_TEAM_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    extra: dict = {}
    if req.options:
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/red_team/run_all")
async def red_team_run_all(req: RedTeamRunAllRequest, request: Request,
                            _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    # Hard-clamp concurrency to 2 (red-team probes emit LOUD signals; running
    # too many in parallel will flood the customer's SIEM + dilute signal
    # correlation for detection-engineering validation).
    concurrency = max(1, min(req.concurrency or 2, 2))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="red_team",
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


@router.post("/api/red_team/run_all_buffered")
async def red_team_run_all_buffered(req: RedTeamRunAllRequest, request: Request,
                                     _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 2, 2))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="red_team",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )


@router.get("/api/red_team/run_all/tiers")
async def red_team_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in RED_TEAM_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in RED_TEAM_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
