"""Service Version Detect v2 — VL-FORGE. Banner-based version fingerprinting."""
import asyncio, socket, re
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
_PROBES={22:b"",80:b"GET / HTTP/1.0\r\n\r\n",443:b"",21:b"",25:b"",110:b"",
    143:b"",6379:b"INFO\r\n",11211:b"version\r\n",27017:b""}
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
def _grab(ip,port,payload=b"",timeout=4):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip,port))
            if payload: s.send(payload)
            return s.recv(4096).decode("utf-8",errors="ignore")
    except: return ""
def _parse_version(banner):
    patterns=[r"OpenSSH[_\- ]([\d.]+)",r"nginx/([\d.]+)",r"Apache/([\d.]+)",
        r"Postfix",r"Microsoft IIS/([\d.]+)",r"Server: ([^\r\n]+)",
        r"redis_version:([\d.]+)",r"VERSION ([\d.]+)"]
    for p in patterns:
        m=re.search(p,banner)
        if m: return m.group(0)[:80]
    return None
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip"]=ips[0]
    ctx.source(f"target-{ips[0]}")
    services={}
    for port,payload in _PROBES.items():
        banner=await asyncio.to_thread(_grab,ips[0],port,payload)
        if banner:
            services[port]={"banner":banner[:200],"version":_parse_version(banner)}
            ctx.source(f"port-{port}")
    ctx.state["services"]=services
    ctx.state["service_count"]=len(services)
def _r_versions(s):
    svcs=s.get("services") or {}
    versioned=[(p,d["version"]) for p,d in svcs.items() if d.get("version")]
    if not versioned: return None
    return {"name":f"Service versions disclosed on {len(versioned)} port(s)","severity":"LOW","cwe":"CWE-200",
        "evidence":"; ".join(f":{p} = {v}" for p,v in versioned[:5]),
        "remediation":"Hide version banners. nginx: server_tokens off; Apache: ServerTokens Prod"}
def _r_count(s):
    n=s.get("service_count",0)
    if n==0: return None
    return {"name":f"{n} service banner(s) grabbed","severity":"INFO",
        "evidence":f"Ports: {list((s.get('services') or {}).keys())}"}
FINDING_RULES=[_r_versions,_r_count]
INTEL_FIELDS=[("Target IP","ip"),("Services","services"),("Service count","service_count")]
@router.post("/api/recon/service_version_detect")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="service_version_detect",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["services","service_count"])
def register(app): app.include_router(router)
