"""Network-device mgmt fingerprint (HTTP Server header). VL-FORGE Vuln tier2 §2 #23."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get
router = APIRouter()
_DEV = {"mikrotik":"MikroTik RouterOS","routeros":"MikroTik RouterOS","cisco":"Cisco","fortigate":"FortiGate","pfsense":"pfSense","ubiquiti":"Ubiquiti EdgeOS","draytek":"DrayTek","zyxel":"Zyxel","huawei":"Huawei","mikrotik httpproxy":"MikroTik"}
async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    r = await asyncio.to_thread(http_get, base + "/")
    if not r:
        ctx.state["tested"] = 0; return
    ctx.source("http"); ctx.state["probed"] = 1
    hdrs = r.get("headers", {})
    sig = (hdrs.get("server","") + " " + hdrs.get("www-authenticate","")).lower()
    ctx.state["devices"] = sorted({v for k, v in _DEV.items() if k in sig})
def _r(s):
    d = s.get("devices") or []
    if not d: return None
    return {"name": f"Network-device management interface exposed: {', '.join(d)}", "severity": "MEDIUM", "cvss": 6.1, "cwe": "CWE-1395",
            "evidence": f"Server/WWW-Authenticate identifies network gear: {', '.join(d)}. Mgmt UI should not be internet-facing.",
            "remediation": "Restrict device management to a VPN/management VLAN; apply vendor security advisories."}
def _r_clean(s):
    if not s.get("probed") or (s.get("devices") or []): return None
    return {"name": "No network-device management interface fingerprinted", "severity": "POSITIVE", "evidence": "No router/firewall vendor signature in HTTP banners."}
FINDING_RULES = [_r, _r_clean]; INTEL_FIELDS = [("Devices","devices")]
@router.post("/api/vuln/network_device_cve")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="network_device_cve", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
