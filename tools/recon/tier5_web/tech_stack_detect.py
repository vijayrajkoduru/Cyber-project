"""Tech Stack Detect v2 — VL-FORGE. Wappalyzer-style + header/JS fingerprint."""
import asyncio, requests, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner
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
def _g(u):
    try:
        return requests.get(u,timeout=10,verify=False,allow_redirects=True,
            headers={"User-Agent":"VulnusLab/1.0"})
    except: return None
async def gather(ctx):
    r=await asyncio.to_thread(_g,web_url(ctx.host))
    if not r: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True
    blob=r.text[:50000]+"\n"+"\n".join(f"{k}: {v}" for k,v in r.headers.items())
    blob_low=blob.lower()
    detected=[]
    for tech,patterns in _SIGS.items():
        for p in patterns:
            if re.search(p,blob,re.I):
                detected.append(tech); break
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
def _r_chain_handoff(s):
    techs=s.get("technologies") or []
    if not techs: return None
    tech_set={t.lower() for t in techs}
    chain_next=[]
    if "wordpress" in tech_set:
        chain_next.extend(["cms_fingerprint_cve","wp_plugin_brute"])
    if "drupal" in tech_set or "joomla" in tech_set:
        chain_next.append("cms_fingerprint_cve")
    if "apache" in tech_set:
        chain_next.append("http_server_cve")
    if "nginx" in tech_set:
        chain_next.append("http_server_cve")
    if any(t in tech_set for t in ("tomcat","jboss","jetty","weblogic")):
        chain_next.append("appserver_cve")
    if any("spring" in t for t in tech_set):
        chain_next.append("spring4shell_verify")
    if any("log4j" in t for t in tech_set):
        chain_next.append("log4shell_verify")
    framework_markers=("wordpress","drupal","joomla","magento","shopify","asp.net","express.js","php")
    if any(t in tech_set for t in framework_markers):
        chain_next.extend(["patator_http_form_brute","jwt_forge_audit"])
    if any("graphql" in t for t in tech_set):
        chain_next.append("graphql_intro_check")
    seen=set(); deduped=[]
    for n in chain_next:
        if n not in seen:
            seen.add(n); deduped.append(n)
    if not deduped: return None
    return {
        "name":"Cross-module chain handoff - tech stack maps to follow-up scanners",
        "severity":"INFO",
        "evidence":f"Detected stack: {', '.join(techs)}; suggests {len(deduped)} follow-up scanner(s)",
        "remediation":"Each identified technology has known CVEs and configuration issues. Run the suggested follow-up scanners to verify patch level and find applicable exploits.",
        "cwe":"CWE-1006",
        "chain_next":deduped,
        "discovery_method":"tech_stack_to_cve_chain",
        "source_stage":"chain_handoff",
        "confidence":"INFO",
    }
FINDING_RULES=[_r_old_tech,_r_detected,_r_clean,_r_chain_handoff]
INTEL_FIELDS=[("Technologies","technologies"),("Tech count","tech_count")]
@router.post("/api/recon/tech_stack_detect")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="tech_stack_detect",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["technologies","tech_count"])
def register(app): app.include_router(router)

async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "tech_stack_detect", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}
from tools._methodology import chain_registry
chain_registry.register("tech_stack_detect", _chain_callable)
