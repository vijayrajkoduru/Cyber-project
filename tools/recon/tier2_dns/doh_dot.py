"""DoH/DoT Support v2 — VL-FORGE. DNS-over-HTTPS / DNS-over-TLS probe."""
import asyncio, socket, ssl, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _dot_probe(host):
    try:
        c=ssl.create_default_context()
        with socket.create_connection((host,853),timeout=5) as s:
            with c.wrap_socket(s,server_hostname=host) as ss:
                return {"connected":True,"tls_version":ss.version()}
    except Exception as e:
        return {"connected":False,"error":type(e).__name__}
def _doh_probe(host):
    try:
        url=f"https://{host}/dns-query"
        r=requests.get(url,params={"name":host,"type":"A"},
            headers={"Accept":"application/dns-json","User-Agent":"VulnusLab/1.0"},
            timeout=6,verify=False)
        return {"status":r.status_code,"content_type":r.headers.get("Content-Type","")}
    except Exception:
        return {"status":0}
async def gather(ctx):
    dot,doh=await asyncio.gather(
        asyncio.to_thread(_dot_probe,ctx.host),
        asyncio.to_thread(_doh_probe,ctx.host))
    ctx.state["dot_supported"]=dot.get("connected") or False
    ctx.state["doh_supported"]=doh.get("status")==200 and "json" in doh.get("content_type","")
    ctx.state["dot_result"]=dot
    ctx.state["doh_result"]=doh
    if dot.get("connected"): ctx.source("dot-port-853")
    if ctx.state["doh_supported"]: ctx.source("doh-dns-query")
    ctx.state["reachable"]=ctx.state["dot_supported"] or ctx.state["doh_supported"]
def _r_both(s):
    if not (s.get("dot_supported") and s.get("doh_supported")): return None
    return {"name":"DoT + DoH both supported","severity":"POSITIVE",
        "evidence":"Privacy-preserving DNS available via TLS:853 + HTTPS /dns-query"}
def _r_only_dot(s):
    if not s.get("dot_supported") or s.get("doh_supported"): return None
    return {"name":"DoT supported (DoH not detected)","severity":"INFO",
        "evidence":"Port 853 accepts TLS"}
def _r_only_doh(s):
    if not s.get("doh_supported") or s.get("dot_supported"): return None
    return {"name":"DoH supported (DoT not detected)","severity":"INFO",
        "evidence":"/dns-query returned valid JSON"}
def _r_neither(s):
    if s.get("dot_supported") or s.get("doh_supported"): return None
    return {"name":"Neither DoT nor DoH supported","severity":"LOW","cwe":"CWE-319",
        "evidence":"Standard plain-text DNS only (port 53)",
        "remediation":"Configure DNS provider to support encrypted DNS — better user privacy."}
FINDING_RULES=[_r_both,_r_only_dot,_r_only_doh,_r_neither]
INTEL_FIELDS=[("DoT","dot_supported"),("DoH","doh_supported"),
    ("DoT result","dot_result"),("DoH result","doh_result")]
@router.post("/api/recon/doh_dot")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="doh_dot",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["dot_supported","doh_supported"])
def register(app): app.include_router(router)
