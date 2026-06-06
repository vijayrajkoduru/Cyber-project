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
                return {"asn":"AS"+p[0],"prefix":p[2],"country":p[3],"registry":p[4],"org":p[6]}
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
def _r_chain_handoff(s):
    org=(s.get("asn_org") or "").lower()
    country=(s.get("asn_country") or "").upper()
    asn=s.get("asn") or ""
    asn_count=s.get("asn_count") or 0
    if not asn and asn_count<2: return None
    chain_next=[]
    reasons=[]
    cloud_kw=["amazon","aws","microsoft","azure","google","gcp","digitalocean","cloudflare","linode","oracle cloud","alibaba"]
    hosting_kw=["hosting","ovh","hetzner","leaseweb","godaddy","namecheap","dreamhost","bluehost","contabo","vultr"]
    isp_kw=["telecom","broadband","comcast","verizon","at&t","spectrum","reliance","airtel","bsnl","jio","vodafone","bt group"]
    if any(k in org for k in cloud_kw):
        for n in ("s3_bucket_enum","azure_blob_enum","gcs_bucket_enum"):
            if n not in chain_next: chain_next.append(n)
        reasons.append("cloud-provider ASN -> bucket enum")
    if any(k in org for k in hosting_kw):
        if "reverse_ip" not in chain_next: chain_next.append("reverse_ip")
        reasons.append("hosting ASN -> reverse_ip co-hosted")
    if any(k in org for k in isp_kw):
        if "ipv6_alive_enum" not in chain_next: chain_next.append("ipv6_alive_enum")
        reasons.append("ISP/residential ASN -> ipv6_alive_enum")
    if asn_count>=2:
        for n in ("anycast_detect","cloudfront_disco"):
            if n not in chain_next: chain_next.append(n)
        reasons.append(f"multi-homed ({asn_count} ASNs) -> anycast/cloudfront")
    registry=(s.get("asn_registry") or "").upper()
    reg_country_map={"ARIN":"US","RIPE":"EU","APNIC":"AP","LACNIC":"LA","AFRINIC":"AF"}
    expected=reg_country_map.get(registry)
    if expected and country and expected not in ("EU","AP","LA","AF") and country!=expected:
        if "geoip" not in chain_next: chain_next.append("geoip")
        reasons.append(f"ASN country {country} differs from registry {registry}")
    if asn_count>=3:
        if "reverse_ip" not in chain_next: chain_next.append("reverse_ip")
        reasons.append("many neighbors -> reverse_ip peer enum")
    if not chain_next: return None
    return {
        "name":"Cross-module chain handoff - ASN ownership maps to follow-up scanners",
        "severity":"INFO",
        "evidence":f"ASN: {asn or 'multi'}; org: {s.get('asn_org') or 'n/a'}; suggests {len(chain_next)} follow-up scanner(s) [{'; '.join(reasons)}]",
        "remediation":"ASN reveals hosting infrastructure. Cloud ASNs = bucket enum. Multi-ASN = anycast detect.",
        "cwe":"CWE-1006",
        "chain_next":chain_next,
        "discovery_method":"asn_to_hosting_chain",
        "source_stage":"chain_handoff",
        "confidence":"INFO",
    }
FINDING_RULES=[_r_done,_r_multi,_r_un,_r_no_asn,_r_chain_handoff]
INTEL_FIELDS=[("Reachable","reachable"),("Resolved IPs","ips"),("ASN","asn"),
    ("ASN org","asn_org"),("Country","asn_country"),("Registry","asn_registry"),("ASN count","asn_count")]
@router.post("/api/recon/asn")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="asn",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["asn","asn_org","ips"])
def register(app): app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "asn", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}


from tools._methodology import chain_registry
chain_registry.register("asn", _chain_callable)
