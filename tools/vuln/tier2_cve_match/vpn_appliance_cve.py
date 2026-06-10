"""VPN/edge appliance fingerprint -> KEV-heavy CVE reference. VL-FORGE Vuln tier2 §2 #22."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get
from tools._vl_core.verify import vl_verify
router = APIRouter()
_SIGS = [("Fortinet FortiGate SSL-VPN","/remote/login",["fortinet","fgt_lang","sslvpn"],"CVE-2024-21762 / CVE-2022-40684 (KEV)"),
         ("Pulse Connect Secure","/dana-na/auth/url_default/welcome.cgi",["dana-na","pulse"],"CVE-2021-22893 / CVE-2019-11510 (KEV)"),
         ("Citrix NetScaler / ADC Gateway","/vpn/index.html",["netscaler","citrix"],"CVE-2023-3519 / CVE-2019-19781 (KEV)"),
         ("Ivanti Connect Secure","/api/v1/totp/user-backup-code/",["ivanti"],"CVE-2024-21887 / CVE-2023-46805 (KEV)"),
         ("SonicWall SSL-VPN","/cgi-bin/welcome",["sonicwall"],"CVE-2021-20016")]
async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    found = []
    for name, path, kws, ref in _SIGS:
        r = await asyncio.to_thread(http_get, base + path)
        if not r: continue
        blob = (str(r.get("headers", {})) + (r.get("body", "") or "")[:4000]).lower()
        if any(k in blob for k in kws):
            found.append({"name": name, "ref": ref})
    ctx.source("http"); ctx.state["probed"] = 1; ctx.state["appliances"] = found
def _r(s):
    f = s.get("appliances") or []
    if not f: return None
    x = f[0]
    return {"name": f"Internet-exposed VPN/edge appliance: {x['name']}", "severity": "MEDIUM", "cvss": 6.5, "cwe": "CWE-1395",
            "evidence": f"Appliance login surface detected (SUSPECTED - verify firmware): {x['name']}. Associated KEV CVEs: {x['ref']}.",
            "remediation": "Confirm firmware patch level; these appliances are heavily targeted (CISA KEV). Restrict mgmt access, enable MFA."}
def _r_clean(s):
    if not s.get("probed") or (s.get("appliances") or []): return None
    return {"name": "No known VPN/edge appliance login surface exposed", "severity": "POSITIVE", "evidence": "No Fortinet/Pulse/Citrix/Ivanti/SonicWall signatures matched."}
FINDING_RULES = [_r, _r_clean]; INTEL_FIELDS = []
@router.post("/api/vuln/vpn_appliance_cve")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="vpn_appliance_cve", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
