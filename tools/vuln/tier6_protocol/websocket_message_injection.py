"""WebSocket message injection - advisory. VL-FORGE Vuln tier6_protocol (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: wscat fuzz (WS endpoint required)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "websocket_message_injection: wscat fuzz (WS endpoint required)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/websocket_message_injection")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="websocket_message_injection",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
