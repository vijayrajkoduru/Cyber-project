"""ASN v2 — VL-FORGE. Team Cymru + RIPE bulk ASN lookup."""
import asyncio, shutil, requests
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
_WB=shutil.which("whois")
async def _cymru(ip):
    if not _WB: return None
    try:
        proc=await asyncio.create_subprocess_exec(_WB,"-h","whois.cymru.com",f" -v {ip}",
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        out,_=await asyncio.wait_for(proc.communicate(),timeout=10)
        raw=out.decode("utf-8",errors="ignore")
        for line in raw.splitlines():
            if "|" not in line: continue
            p=[x.strip() for x in line.split("|")]
            if len(p)>=7 and p[0].isdigit():
                return {"asn":"AS"+p[0],"prefix":p[1],"country":p[2],"registry":p[3],"org":p[6]}
    except: pass
    return None
async def _resolve(host):
    try:
        r=dns.asyncresolver.Resolver(); r.timeout=4; r.lifetime=6
        ans=await r.resolve(host,"A")
        return [str(x).rstrip(".") for x in ans]
    except: return []
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ips"]=ips; ctx.source(f"dns-{len(ips)}")
    res=await asyncio.gather(*[_cymru(ip) for ip in ips[:5]],return_exceptions=True)
    asns=[r for r in res if isinstance(r,dict)]
    if asns: ctx.source(f"cymru-{len(asns)}")
    ctx.state["asn_data"]=asns
    ctx.state["asn_count"]=len(set(a["asn"] for a in asns if a.get("asn")))
    if asns:
        primary=asns[0]
        ctx.state.update({"asn":primary["asn"],"asn_org":primary["org"],
            "asn_country":primary["country"],"asn_registry":primary["registry"]})
def _r_done(s):
    if not s.get("asn"): return None
    return {"name":f"Hosted on {s['asn']} ({s['asn_org']})","severity":"INFO","cwe":"T1590.005",
        "evidence":f"Country: {s.get('asn_country')}, registry: {s.get('asn_registry')}"}
def _r_multi(s):
    n=s.get("asn_count") or 0
    if n<2: return None
    return {"name":f"Multi-ASN hosting ({n} distinct ASNs)","severity":"INFO",
        "evidence":f"IPs span {n} networks — common for CDN/multi-region",
        "remediation":"Not necessarily an issue; verify intentional."}
def _r_un(s):
    if s.get("reachable"): return None
    return {"name":"No A records resolved","severity":"INFO","evidence":"DNS resolution failed"}
def _r_no_asn(s):
    if s.get("asn") or not s.get("reachable"): return None
    return {"name":"ASN lookup returned no data","severity":"INFO","cwe":"T1590.005",
        "evidence":"Cymru returned no AS — could indicate Cloudflare/CDN obscuring",
        "remediation":"Investigate via Shodan or origin_ip_bypass scanner"}
FINDING_RULES=[_r_done,_r_multi,_r_un,_r_no_asn]
INTEL_FIELDS=[("Reachable","reachable"),("Resolved IPs","ips"),("ASN","asn"),
    ("ASN org","asn_org"),("Country","asn_country"),("Registry","asn_registry"),("ASN count","asn_count")]
@router.post("/api/recon/asn")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="asn",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["asn","asn_org","ips"])
def register(app): app.include_router(router)
