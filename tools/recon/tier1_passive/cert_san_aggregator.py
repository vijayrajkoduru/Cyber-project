"""Cert SAN Aggregator v2 — VL-FORGE. Pull SAN list from live cert + CT logs."""
import asyncio
import ssl
import socket
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
def _live_cert(host):
    try:
        c=ssl.create_default_context(); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE
        with socket.create_connection((host,443),timeout=6) as s:
            with c.wrap_socket(s,server_hostname=host) as ss:
                cert=ss.getpeercert()
                return [x[1] for x in (cert.get("subjectAltName") or []) if x[0]=="DNS"]
    except Exception: return []
def _ct_sans(host):
    try:
        r=requests.get(f"https://crt.sh/?q={host}&output=json",timeout=15)
        if r.status_code==200:
            data=r.json()
            sans=set()
            for e in data[:200]:
                nv=(e.get("name_value","") or "")
                for n in nv.split("\n"):
                    n=n.strip().lower()
                    if n and "*" not in n: sans.add(n)
            return sorted(sans)
    except Exception: pass
    return []
async def gather(ctx):
    host=ctx.host
    live,ct=await asyncio.gather(
        asyncio.to_thread(_live_cert,host),
        asyncio.to_thread(_ct_sans,host))
    if live: ctx.source("live-cert-tls")
    if ct: ctx.source(f"ct-logs ({len(ct)})")
    merged=set(live) | set(ct)
    ctx.state.update({"live_sans":live,"ct_sans":ct[:50],"all_sans":sorted(merged)[:100],
        "san_count":len(merged),"live_san_count":len(live),"ct_san_count":len(ct),
        "reachable":bool(merged)})
def _r_many(s):
    n=s.get("san_count") or 0
    if n<10: return None
    sev="INFO" if n<50 else ("LOW" if n<200 else "MEDIUM")
    return {"name":f"{n} SANs across CT + live cert","severity":sev,"cwe":"T1596.001",
        "evidence":"Sample: "+", ".join((s.get("all_sans") or [])[:5]),
        "remediation":"SAN list = subdomain attack surface map."}
def _r_diff(s):
    live=set(s.get("live_sans") or [])
    ct=set(s.get("ct_sans") or [])
    only_ct = ct - live
    if len(only_ct)<5: return None
    return {"name":f"{len(only_ct)} subdomains in CT but not live cert","severity":"LOW",
        "evidence":"Sample: "+", ".join(list(only_ct)[:5]),
        "remediation":"Old/decommissioned subdomains? Check for orphan DNS records."}
def _r_clean(s):
    if (s.get("san_count") or 0)>0: return None
    return {"name":"No SAN data","severity":"INFO","evidence":"Cert + CT both empty"}
FINDING_RULES=[_r_many,_r_diff,_r_clean]
INTEL_FIELDS=[("Total SANs","san_count"),("Live cert SANs","live_san_count"),
    ("CT log SANs","ct_san_count")]
@router.post("/api/recon/cert_san_aggregator")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="cert_san_aggregator",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["all_sans","live_sans","san_count"])
def register(app): app.include_router(router)
