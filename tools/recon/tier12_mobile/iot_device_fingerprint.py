"""iot_device_fingerprint — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    key = os.environ.get("SHODAN_API_KEY","")
    if not key:
        ctx.state["api_key_configured"] = False; ctx.source("SHODAN_API_KEY not set"); return
    h = ctx.host
    code, d = await get_json(f"https://api.shodan.io/shodan/host/{h}?key={key}")
    iot_tags = []
    if isinstance(d, dict):
        for svc in d.get("data",[]):
            prod = (svc.get("product") or "").lower()
            for iot_marker in ("camera","router","printer","modem","iot","scada","plc","bms","industrial"):
                if iot_marker in prod or iot_marker in (svc.get("title","") or "").lower():
                    iot_tags.append({"port":svc.get("port"),"product":svc.get("product"),"marker":iot_marker}); break
    ctx.state["api_key_configured"] = True
    ctx.state["iot_devices"] = iot_tags
    ctx.source("Shodan host product+title — IoT pattern match")

RULES = [
    lambda s: {"name":"IoT/embedded device exposed to internet","severity":"HIGH",
        "evidence":f"Devices: {s.get('iot_devices')}",
        "remediation":"Audit each device. IoT/SCADA should never be internet-facing. Use VPN + jump host.",
        "cwe":"CWE-668","owasp":"A05:2021"
    } if s.get("iot_devices") else None,
]

@router.post("/api/recon/iot_device_fingerprint")
async def recon_iot_device_fingerprint(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="iot_device_fingerprint",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("IoT Devices","iot_devices")])

def register(app):
    app.include_router(router)
