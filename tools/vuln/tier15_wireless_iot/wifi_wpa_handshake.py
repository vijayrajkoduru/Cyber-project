"""Wi-Fi WPA2/3 weak handshake - advisory (access-gated). VL-FORGE Vuln tier15_wireless_iot.
Requires physical RF radio / LAN proximity; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: aircrack-ng + hashcat"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("wifi_wpa_handshake: requires physical RF radio / LAN proximity - not applicable to an "
                                   "external URL scan. Canonical check: aircrack-ng + hashcat")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/wifi_wpa_handshake")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="wifi_wpa_handshake",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
