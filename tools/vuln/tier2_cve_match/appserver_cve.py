"""App-server banner -> NVD CVE (Tomcat/JBoss/Jetty/WebLogic/WebSphere). VL-FORGE Vuln tier2 §2 #20."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get
from tools.vuln._cve_intel import high_cves
from tools._vl_core.verify import vl_verify
router = APIRouter()
_VER = re.compile(r"([A-Za-z][A-Za-z0-9_+.-]*?)[/ ]v?(\d+\.\d+(?:\.\d+)?)")
_APP = ["tomcat","coyote","jboss","wildfly","jetty","weblogic","websphere","glassfish","resin"]
async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    r = await asyncio.to_thread(http_get, base + "/")
    if not r:
        ctx.state["tested"] = 0; return
    ctx.source("http"); ctx.state["probed"] = 1
    hdrs = r.get("headers", {}); cand = [hdrs[h] for h in ("server","x-powered-by") if hdrs.get(h)]
    blob = " ".join(cand).lower()
    ctx.state["appserver"] = sorted({a for a in _APP if a in blob})
    for b in cand:
        for m in _VER.finditer(b):
            if m.group(1).lower() in _APP:
                h = await asyncio.to_thread(high_cves, m.group(1), m.group(2))
                if h:
                    ctx.state["version"] = f"{m.group(1)} {m.group(2)}"; ctx.state["cve_top"] = [f"{c} ({s})" for c, s in h[:3]]; ctx.state["cve_count"] = len(h)
                    return
def _r_cve(s):
    if not s.get("cve_top"): return None
    # ZERO-FP: these CVE ids come from an NVD KEYWORD search on the banner
    # "<product> <version>" - they are candidate CVEs for the product, NOT
    # proof that THIS version is affected. NVD keyword search returns CVEs
    # across unrelated versions (and sometimes unrelated products), and we do
    # not range-check the detected version against each CVE's affected range.
    # So this is a version-INFERRED association -> LOW, not MEDIUM. A graded
    # finding requires the exact version to be confirmed inside an affected
    # range, which this banner-only path cannot establish.
    return {"name": f"App server '{s.get('version')}' has candidate CVEs (version-inferred, not range-confirmed)", "severity": "LOW", "cwe": "CWE-1395",
            "evidence": f"NVD keyword candidates: {', '.join(s['cve_top'])}. Version-inferred, NOT range-confirmed - verify the exact version against each CVE's affected range before treating as exploitable.", "remediation": "Confirm the exact app-server build; if it falls inside an affected range, upgrade and remove management endpoints from public access."}
def _r_disc(s):
    if not (s.get("appserver") or []) or s.get("cve_top"): return None
    return {"name": f"Application server disclosed: {', '.join(s['appserver'])}", "severity": "LOW", "cwe": "CWE-200",
            "evidence": f"Server/X-Powered-By reveals app server: {', '.join(s['appserver'])}.", "remediation": "Suppress app-server identification headers."}
def _r_clean(s):
    if not s.get("probed") or (s.get("appserver") or []) or s.get("cve_top"): return None
    return {"name": "No application-server banner disclosed", "severity": "POSITIVE", "evidence": "No Tomcat/JBoss/Jetty/WebLogic/WebSphere identification exposed."}
FINDING_RULES = [_r_cve, _r_disc, _r_clean]; INTEL_FIELDS = [("App server","appserver"),("Version","version")]
@router.post("/api/vuln/appserver_cve")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="appserver_cve", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
