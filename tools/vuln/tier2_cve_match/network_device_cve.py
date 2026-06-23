"""Network-device mgmt fingerprint (HTTP Server header). VL-FORGE Vuln tier2 §2 #23."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get
from tools._vl_core.verify import vl_verify
router = APIRouter()
_DEV = {"mikrotik":"MikroTik RouterOS","routeros":"MikroTik RouterOS","cisco":"Cisco","fortigate":"FortiGate","pfsense":"pfSense","ubiquiti":"Ubiquiti EdgeOS","draytek":"DrayTek","zyxel":"Zyxel","huawei":"Huawei","mikrotik httpproxy":"MikroTik"}
# Optional version capture so a confirmed fingerprint+version could be graded.
_DEV_VER = re.compile(r"(routeros|fortigate|mikrotik|draytek|zyxel)[/ ]v?(\d+\.\d+(?:\.\d+)?)", re.I)
def _word(token, blob):
    return re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", blob) is not None
async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    r = await asyncio.to_thread(http_get, base + "/")
    if not r:
        ctx.state["tested"] = 0; return
    ctx.source("http"); ctx.state["probed"] = 1
    hdrs = r.get("headers", {})
    # ZERO-FP: match ONLY the Server / WWW-Authenticate banner (a real device
    # fingerprint surface), and use a word-boundary match so a bare 'cisco' or
    # 'huawei' substring inside an unrelated token does not fire. We do NOT
    # scan body text - vendor names in editorial copy are the classic FP here.
    sig = (hdrs.get("server","") + " " + hdrs.get("www-authenticate","")).lower()
    ctx.state["devices"] = sorted({v for k, v in _DEV.items() if _word(k, sig)})
    mv = _DEV_VER.search(sig)
    if mv: ctx.state["device_version"] = f"{mv.group(1)} {mv.group(2)}"
def _r(s):
    d = s.get("devices") or []
    if not d: return None
    # ZERO-FP: this is a vendor FINGERPRINT only - no firmware/version and no
    # affected-range check. A device banner is not proof of a specific CVE, so
    # this is reference-only LOW. The real risk here is exposure (mgmt UI
    # reachable), which is what the evidence calls out; CVE grading would
    # require a confirmed firmware version inside an affected range.
    vt = s.get("device_version")
    extra = f" Version observed: {vt} (still version-inferred, not range-confirmed)." if vt else ""
    return {"name": f"Network-device management interface exposed: {', '.join(d)}", "severity": "LOW", "cwe": "CWE-1395",
            "evidence": f"Server/WWW-Authenticate identifies network gear: {', '.join(d)}. Mgmt UI should not be internet-facing.{extra} Fingerprint only - verify firmware against vendor advisories before treating any CVE as applicable.",
            "remediation": "Restrict device management to a VPN/management VLAN; confirm the firmware version and apply vendor security advisories."}
def _r_clean(s):
    if not s.get("probed") or (s.get("devices") or []): return None
    return {"name": "No network-device management interface fingerprinted", "severity": "POSITIVE", "evidence": "No router/firewall vendor signature in HTTP banners."}
FINDING_RULES = [_r, _r_clean]; INTEL_FIELDS = [("Devices","devices")]
@router.post("/api/vuln/network_device_cve")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="network_device_cve", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
