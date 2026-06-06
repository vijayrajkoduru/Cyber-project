"""CORS Misconfig v2 — VL-FORGE. Test Origin reflection / wildcard."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _g(u,origin):
    try:
        return requests.get(u,timeout=8,verify=False,allow_redirects=False,
            headers={"User-Agent":"VulnusLab/1.0","Origin":origin})
    except: return None
async def gather(ctx):
    base=web_url(ctx.host)
    evil="https://attacker.example.com"
    null_o="null"
    res_evil,res_null,res_apex=await asyncio.gather(
        asyncio.to_thread(_g,base,evil),
        asyncio.to_thread(_g,base,null_o),
        asyncio.to_thread(_g,base,base))
    if not res_evil: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True
    ctx.source("cors-probe")
    aco_evil=(res_evil.headers if res_evil else {}).get("Access-Control-Allow-Origin","")
    aco_null=(res_null.headers if res_null else {}).get("Access-Control-Allow-Origin","")
    aco_apex=(res_apex.headers if res_apex else {}).get("Access-Control-Allow-Origin","")
    acc_evil=(res_evil.headers if res_evil else {}).get("Access-Control-Allow-Credentials","")
    ctx.state.update({"acao_evil":aco_evil,"acao_null":aco_null,"acao_apex":aco_apex,
        "credentials_allowed":acc_evil.lower()=="true",
        "reflects_evil":evil in aco_evil,"wildcard":aco_apex=="*",
        "accepts_null":aco_null==null_o})
def _r_reflect(s):
    if not s.get("reflects_evil"): return None
    sev="CRITICAL" if s.get("credentials_allowed") else "HIGH"
    return {"name":"CORS reflects arbitrary Origin","severity":sev,
        "cvss":9.0 if s.get("credentials_allowed") else 7.5,
        "cwe":"CWE-942","owasp":"A05:2021",
        "evidence":f"ACAO: {s.get('acao_evil')} | Credentials: {s.get('credentials_allowed')}",
        "remediation":"Whitelist allowed origins, never reflect arbitrary Origin headers."}
def _r_null(s):
    if not s.get("accepts_null"): return None
    return {"name":"CORS accepts 'null' Origin","severity":"HIGH","cwe":"CWE-942",
        "evidence":"Sandboxed iframes/file:// can bypass SOP",
        "remediation":"Never allow Origin: null."}
def _r_wildcard(s):
    if not s.get("wildcard"): return None
    sev="HIGH" if s.get("credentials_allowed") else "INFO"
    return {"name":f"CORS uses wildcard '*'","severity":sev,
        "evidence":f"Credentials with wildcard: {s.get('credentials_allowed')}",
        "remediation":"If credentials needed, list specific origins."}
def _r_safe(s):
    if s.get("reflects_evil") or s.get("accepts_null") or s.get("wildcard"): return None
    if not s.get("reachable"): return None
    return {"name":"CORS configuration safe","severity":"POSITIVE","evidence":"No reflection/null/wildcard issues"}
def _r_chain_handoff(s):
    if not s.get("reachable"): return None
    chain_next=[]
    issues=[]
    reflects=s.get("reflects_evil")
    accepts_null=s.get("accepts_null")
    creds=s.get("credentials_allowed")
    wildcard=s.get("wildcard")
    acao_evil=s.get("acao_evil","")
    acao_apex=s.get("acao_apex","")
    if reflects:
        for n in ("cors_preflight_audit","session_predict_audit"):
            if n not in chain_next: chain_next.append(n)
        issues.append("ACAO reflects attacker origin")
    if accepts_null:
        if "postmessage_audit" not in chain_next: chain_next.append("postmessage_audit")
        issues.append("ACAO=null accepted")
    if creds and reflects:
        for n in ("session_predict_audit","jwt_forge_audit"):
            if n not in chain_next: chain_next.append(n)
        issues.append("Credentials allowed with reflection")
    if wildcard:
        for n in ("graphql_intro_check","api_endpoint_brute"):
            if n not in chain_next: chain_next.append(n)
        issues.append("Wildcard ACAO")
    if reflects and not (acao_evil or acao_apex):
        if "patator_http_form_brute" not in chain_next: chain_next.append("patator_http_form_brute")
        issues.append("CORS preflight bypassed")
    if not (acao_evil or acao_apex or s.get("acao_null","")):
        if "api_endpoint_brute" not in chain_next: chain_next.append("api_endpoint_brute")
        issues.append("No CORS headers at all")
    if not chain_next: return None
    return {
        "name":"Cross-module chain handoff - CORS posture maps to follow-up scanners",
        "severity":"INFO",
        "evidence":f"CORS issues: {', '.join(issues)}; suggests {len(chain_next)} follow-up scanner(s)",
        "remediation":"CORS misconfig commonly enables cross-origin data theft. Run client-side + auth audits.",
        "cwe":"CWE-1006",
        "chain_next":chain_next,
        "discovery_method":"cors_to_client_side_chain",
        "source_stage":"chain_handoff",
        "confidence":"INFO",
    }
FINDING_RULES=[_r_reflect,_r_null,_r_wildcard,_r_safe,_r_chain_handoff]
INTEL_FIELDS=[("ACAO evil","acao_evil"),("ACAO null","acao_null"),
    ("Credentials","credentials_allowed"),("Reflects","reflects_evil")]
@router.post("/api/recon/cors_misconfig")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="cors_misconfig",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["reflects_evil","wildcard","credentials_allowed"])
def register(app): app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration - chain handoff entry point.
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "cors_misconfig", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}


from tools._methodology import chain_registry
chain_registry.register("cors_misconfig", _chain_callable)
