"""Wi-Fi WPS PIN attack - advisory (access-gated). VL-FORGE Vuln tier15_wireless_iot.
Requires physical RF radio / LAN proximity; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: reaver / bully"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("wifi_wps_pin: requires physical RF radio / LAN proximity - not applicable to an "
                                   "external URL scan. Canonical check: reaver / bully")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/wifi_wps_pin")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="wifi_wps_pin",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
