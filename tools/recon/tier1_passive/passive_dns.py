"""Passive DNS v2 — VL-FORGE. Historical IP records via free passive DNS APIs."""
import asyncio, requests, json, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _g(u,h=None,t=12):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"VulnusLab/1.0",**(h or {})})
        if r.status_code==200: return r.json() if "json" in r.headers.get("Content-Type","") else r.text
    except: pass
    return None
async def gather(ctx):
    host=ctx.host
    # Multiple passive DNS sources
    otx=os.environ.get("OTX_API_KEY","")
    pdns_otx=await asyncio.to_thread(_g,f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/passive_dns",
        {"X-OTX-API-KEY":otx} if otx else None)
    pdns_threatcrowd=await asyncio.to_thread(_g,f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={host}")
    historical_ips=set()
    if pdns_otx and isinstance(pdns_otx,dict):
        ctx.source("otx-pdns")
        for e in pdns_otx.get("passive_dns",[]) or []:
            ip=e.get("address","")
            if ip: historical_ips.add(ip)
    if pdns_threatcrowd and isinstance(pdns_threatcrowd,dict):
        ctx.source("threatcrowd")
        for r in pdns_threatcrowd.get("resolutions",[]) or []:
            ip=r.get("ip_address","")
            if ip: historical_ips.add(ip)
    ctx.state.update({"historical_ips":sorted(historical_ips)[:30],
        "historical_ip_count":len(historical_ips),"reachable":bool(historical_ips)})
def _r_historical(s):
    n=s.get("historical_ip_count") or 0
    if n==0: return None
    sev="INFO" if n<5 else ("LOW" if n<20 else "MEDIUM")
    return {"name":f"{n} historical IPs in passive DNS","severity":sev,"cwe":"T1590.005",
        "evidence":"Sample: "+", ".join((s.get("historical_ips") or [])[:5]),
        "remediation":"Old IPs may still serve content / have origin-IP leaks. Check via origin_ip_bypass."}
def _r_clean(s):
    if (s.get("historical_ip_count") or 0)>0: return None
    return {"name":"No passive DNS history","severity":"POSITIVE",
        "evidence":"OTX + ThreatCrowd both empty"}
def _r_chain_handoff(s):
    chain_next=[]
    reasons=[]
    hist_ips=s.get("historical_ips") or []
    hist_ip_count=s.get("historical_ip_count") or 0
    hist_subs=s.get("historical_subdomains") or []
    hist_sub_count=s.get("historical_subdomain_count") or len(hist_subs)
    current_ip=s.get("current_ip") or ""
    hist_cnames=s.get("historical_cnames") or []
    hist_mx_changes=s.get("historical_mx_changes") or 0
    hist_ns_changes=s.get("historical_ns_changes") or 0
    first_seen_recent=s.get("first_seen_recent") or 0
    if hist_sub_count>0:
        for n in ("subdomain_bruteforce","subdomain_takeover","tcp_port_scan"):
            if n not in chain_next: chain_next.append(n)
        reasons.append(f"{hist_sub_count} historical subdomain(s)")
    if hist_ip_count>0 and current_ip and current_ip not in hist_ips:
        for n in ("tcp_port_scan","cloudfront_disco"):
            if n not in chain_next: chain_next.append(n)
        reasons.append(f"{hist_ip_count} historical IP(s) differ from current {current_ip}")
    if first_seen_recent>0:
        if "subdomain_takeover" not in chain_next: chain_next.append("subdomain_takeover")
        reasons.append(f"{first_seen_recent} record(s) first-seen <30d")
    cloud_markers=("s3","amazonaws","herokuapp","github.io","githubusercontent","azurewebsites","cloudfront","netlify","vercel","pages.dev")
    cloud_cnames=[c for c in hist_cnames if any(m in str(c).lower() for m in cloud_markers)]
    if cloud_cnames:
        if "subdomain_takeover" not in chain_next: chain_next.append("subdomain_takeover")
        reasons.append(f"{len(cloud_cnames)} cloud CNAME(s)")
    if hist_mx_changes>0:
        if "phishing_email_posture" not in chain_next: chain_next.append("phishing_email_posture")
        reasons.append(f"{hist_mx_changes} historical MX change(s)")
    if hist_ns_changes>0:
        for n in ("zone_transfer","dnssec"):
            if n not in chain_next: chain_next.append(n)
        reasons.append(f"{hist_ns_changes} historical NS change(s)")
    if not chain_next: return None
    return {
        "name":f"Cross-module chain handoff - historical DNS reveals {len(chain_next)} forgotten assets",
        "severity":"INFO",
        "evidence":f"Historical DNS shows {'; '.join(reasons)}; suggests {len(chain_next)} follow-up scanner(s): "+", ".join(chain_next),
        "remediation":"Historical DNS often reveals decommissioned-but-still-reachable assets. Cross-check + port scan + takeover audit each.",
        "cwe":"CWE-1006",
        "chain_next":chain_next,
        "discovery_method":"passive_dns_to_historical_asset_chain",
        "source_stage":"chain_handoff",
        "confidence":"INFO",
    }
FINDING_RULES=[_r_historical,_r_clean,_r_chain_handoff]
INTEL_FIELDS=[("Historical IPs","historical_ip_count"),("Sample","historical_ips")]
@router.post("/api/recon/passive_dns")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="passive_dns",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["historical_ips","historical_ip_count"])
def register(app): app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "passive_dns", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}


from tools._methodology import chain_registry
chain_registry.register("passive_dns", _chain_callable)
