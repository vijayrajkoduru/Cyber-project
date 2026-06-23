"""Tech Stack Detect v2 — VL-FORGE. Wappalyzer-style + header/JS fingerprint."""
import asyncio, requests, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
router=APIRouter()
_SIGS={
    "WordPress":[r"wp-content",r"wp-includes",r"wp-json"],
    "Drupal":[r"sites/default/files",r"X-Drupal"],
    "Joomla":[r"/media/system/js/",r"option=com_"],
    "Magento":[r"/skin/frontend/",r"Mage\.Cookies"],
    "Shopify":[r"cdn\.shopify\.com"],
    "React":[r"react-dom",r"__REACT_DEVTOOLS"],
    "Vue.js":[r"vuejs\.org",r"__vue__"],
    "Angular":[r"ng-version",r"ng-controller"],
    "Next.js":[r"_next/static",r"__NEXT_DATA__"],
    "Bootstrap":[r"bootstrap.*\.css"],
    "jQuery":[r"jquery.*\.js"],
    "Cloudflare":[r"cloudflare",r"cf-ray"],
    "Nginx":[r"server:\s*nginx"],
    "Apache":[r"server:\s*apache"],
    "IIS":[r"server:\s*microsoft-iis"],
    "PHP":[r"X-Powered-By:\s*PHP",r"PHPSESSID"],
    "ASP.NET":[r"X-AspNet-Version",r"__VIEWSTATE"],
    "Express.js":[r"X-Powered-By:\s*Express"],
}
# Techs whose SINGLE marker is unique+authoritative (header/CDN host) — a lone
# match is acceptable proof. Everything else requires >=2 corroborating
# markers, OR (for multi-pattern techs) a single STRONG header marker.
_SINGLE_OK={"Shopify","Express.js","Nginx","Apache","IIS","Cloudflare"}
# Strong header-only markers that are authoritative even alone (server-set,
# not echoable from a request body / 404 page).
_STRONG_MARKERS=[r"X-Drupal",r"X-AspNet-Version",r"X-Powered-By:\s*PHP",
    r"X-Powered-By:\s*Express",r"ng-version",r"__NEXT_DATA__",r"cf-ray",
    r"server:\s*nginx",r"server:\s*apache",r"server:\s*microsoft-iis"]
def _g(u):
    try:
        return requests.get(u,timeout=10,verify=False,allow_redirects=True,
            headers={"User-Agent":"VulnusLab/1.0"})
    except Exception: return None
async def gather(ctx):
    r=await asyncio.to_thread(_g,web_url(ctx.host))
    if not r: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True
    blob=r.text[:50000]+"\n"+"\n".join(f"{k}: {v}" for k,v in r.headers.items())
    blob_low=blob.lower()
    detected=[]
    for tech,patterns in _SIGS.items():
        matched=[p for p in patterns if re.search(p,blob,re.I)]
        if not matched: continue
        # Zero-FP gate: a lone substring on a body (e.g. 'wp-content' echoed by a
        # 404/search page) is NOT proof. Require one of:
        #   - >=2 corroborating markers, OR
        #   - a single authoritative server-set header marker, OR
        #   - the tech is in the single-OK allowlist (unique CDN host / Server).
        strong=any(re.search(sm,blob,re.I) for sm in _STRONG_MARKERS
                   if sm in patterns)
        if len(matched)>=2 or strong or tech in _SINGLE_OK:
            detected.append(tech)
    detected=sorted(set(detected))
    if detected: ctx.source(f"detected-{len(detected)}")
    ctx.state["technologies"]=detected
    ctx.state["tech_count"]=len(detected)
def _r_old_tech(s):
    techs=s.get("technologies") or []
    old=[t for t in techs if t in ("jQuery","Joomla","Drupal","IIS","ASP.NET")]
    if not old: return None
    return {"name":f"Legacy technologies detected: {', '.join(old)}","severity":"LOW","cwe":"CWE-1104",
        "evidence":f"All detected: {techs}",
        "remediation":"Verify each is current version. Legacy frameworks often have unpatched CVEs."}
def _r_detected(s):
    n=s.get("tech_count",0)
    if n==0: return None
    return {"name":f"Technology stack: {', '.join(s.get('technologies') or [])}","severity":"INFO",
        "cwe":"T1592.002","evidence":f"{n} technologies detected"}
def _r_clean(s):
    if s.get("tech_count",0)>0: return None
    return {"name":"No common technology fingerprints detected","severity":"INFO",
        "evidence":"Custom-built or well-hidden stack"}
FINDING_RULES=[_r_old_tech,_r_detected,_r_clean]
INTEL_FIELDS=[("Technologies","technologies"),("Tech count","tech_count")]
@router.post("/api/recon/tech_stack_detect")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="tech_stack_detect",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["technologies","tech_count"])
def register(app): app.include_router(router)
