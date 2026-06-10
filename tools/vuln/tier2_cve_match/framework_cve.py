"""Framework/language version -> NVD CVE. VL-FORGE Vuln tier2 §2 #18."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get
from tools.vuln._cve_intel import high_cves
router = APIRouter()
_VER = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]*?)[/ ]v?(\d+\.\d+(?:\.\d+)?)")
_FWH = ("x-powered-by","x-aspnet-version","x-aspnetmvc-version","x-runtime","x-drupal-dynamic-cache")
_CK = {"laravel_session":"Laravel","jsessionid":"Java/Servlet","phpsessid":"PHP","csrftoken":"Django","rack.session":"Ruby/Rack","connect.sid":"Express/Connect","ci_session":"CodeIgniter"}
async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    r = await asyncio.to_thread(http_get, base + "/")
    if not r:
        ctx.state["tested"] = 0; return
    ctx.source("http"); ctx.state["tested"] = 1
    hdrs = r.get("headers", {})
    fwb = [hdrs[h] for h in _FWH if hdrs.get(h)]
    setck = (hdrs.get("set-cookie", "") or "").lower()
    ctx.state["fw_banners"] = fwb
    ctx.state["fw_cookies"] = sorted({n for k, n in _CK.items() if k in setck})
    hits = []
    for b in fwb:
        for m in _VER.finditer(b):
            h = await asyncio.to_thread(high_cves, m.group(1), m.group(2))
            if h:
                hits.append({"product": f"{m.group(1)} {m.group(2)}", "count": len(h), "top": h[:3]}); break
    ctx.state["cve_hits"] = hits
def _r_cve(s):
    h = s.get("cve_hits") or []
    if not h: return None
    x = h[0]; top = ", ".join(f"{c} ({sc})" for c, sc in x["top"])
    return {"name": f"Framework '{x['product']}' maps to {x['count']} high-severity CVE(s)", "severity": "MEDIUM", "cvss": 6.5, "cwe": "CWE-1395",
            "evidence": f"NVD: {top}. Version-inferred - confirm patch level.", "remediation": "Upgrade the framework; remove version-revealing headers."}
def _r_disc(s):
    b = s.get("fw_banners") or []
    if not b or (s.get("cve_hits") or []): return None
    return {"name": f"Framework version disclosed: {b[0][:80]}", "severity": "LOW", "cwe": "CWE-200",
            "evidence": f"Headers: {', '.join(b)[:160]}", "remediation": "Remove X-Powered-By / X-AspNet-Version / X-Runtime."}
def _r_ck(s):
    fc = s.get("fw_cookies") or []
    if not fc or (s.get("fw_banners") or []): return None
    return {"name": f"Framework identified via session cookie: {', '.join(fc)}", "severity": "INFO", "cwe": "CWE-200",
            "evidence": f"Set-Cookie reveals: {', '.join(fc)}.", "remediation": "Rename default session cookies to reduce fingerprinting."}
def _r_clean(s):
    if (s.get("tested") or 0) < 1 or (s.get("fw_banners") or []) or (s.get("fw_cookies") or []): return None
    return {"name": "No web framework version disclosed", "severity": "POSITIVE", "evidence": "No framework headers / identifiable session cookies exposed."}
FINDING_RULES = [_r_cve, _r_disc, _r_ck, _r_clean]; INTEL_FIELDS = [("Framework headers","fw_banners"),("Framework cookies","fw_cookies")]
@router.post("/api/vuln/framework_cve")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="framework_cve", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
