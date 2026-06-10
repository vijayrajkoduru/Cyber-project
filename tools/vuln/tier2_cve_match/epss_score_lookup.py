"""Banner -> NVD CVE -> FIRST EPSS exploit-probability enrichment. VL-FORGE Vuln tier2 §2 #26."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get
from tools.vuln._cve_intel import nvd_cves, epss_scores
router = APIRouter()
_VER = re.compile(r"([A-Za-z][A-Za-z0-9_+.-]*?)[/ ]v?(\d+\.\d+(?:\.\d+)?)")
async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    r = await asyncio.to_thread(http_get, base + "/")
    if not r:
        ctx.state["tested"] = 0; return
    ctx.source("http"); ctx.state["tested"] = 1
    hdrs = r.get("headers", {})
    banners = [hdrs[h] for h in ("server","x-powered-by","x-aspnet-version","x-generator") if hdrs.get(h)]
    ctx.state["banners"] = banners
    products = [(m.group(1), m.group(2)) for b in banners for m in _VER.finditer(b)]
    if not products: return
    prod, ver = products[0]; ctx.state["product"] = f"{prod} {ver}"
    cves = await asyncio.to_thread(nvd_cves, prod, ver)
    ids = [c for c, _ in cves]
    if not ids:
        ctx.state["cve_count"] = 0; return
    cvss_map = dict(cves)
    ep = await asyncio.to_thread(epss_scores, ids[:30])
    scored = [{"cve": c, "epss": p, "cvss": cvss_map.get(c, 0.0)} for c, (p, _) in ep.items()]
    scored.sort(key=lambda x: -x["epss"])
    ctx.state["cve_count"] = len(ids)
    ctx.state["high_epss"] = [s for s in scored if s["epss"] >= 0.10]
def _r_high(s):
    he = s.get("high_epss") or []
    if not he: return None
    lst = ", ".join(f"{x['cve']} (EPSS {x['epss']*100:.1f}%, CVSS {x['cvss']})" for x in he[:4])
    sev = "HIGH" if he[0]["epss"] >= 0.5 else "MEDIUM"
    return {"name": f"{len(he)} CVE(s) on '{s.get('product','')}' have elevated exploit probability (EPSS)",
            "severity": sev, "cvss": max(t["cvss"] for t in he) or 7.0, "cwe": "CWE-1395",
            "evidence": f"FIRST EPSS: {lst}. Version-inferred - confirm patch level.",
            "remediation": "Prioritise patching CVEs with high EPSS first; upgrade to the latest release."}
def _r_clean(s):
    if (s.get("tested") or 0) < 1 or (s.get("high_epss") or []): return None
    if not s.get("product"):
        return {"name": "No version banner to score against EPSS", "severity": "POSITIVE",
                "evidence": "No server/framework version disclosed - nothing to map to EPSS."}
    return {"name": f"'{s.get('product')}' has no high-EPSS CVEs", "severity": "POSITIVE",
            "evidence": f"{s.get('cve_count',0)} candidate CVE(s); none with EPSS >= 10%."}
FINDING_RULES = [_r_high, _r_clean]; INTEL_FIELDS = [("Detected product", "product")]
@router.post("/api/vuln/epss_score_lookup")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="epss_score_lookup", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
