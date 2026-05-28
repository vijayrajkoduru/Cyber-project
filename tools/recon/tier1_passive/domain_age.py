"""Domain Age v2 — VL-FORGE. Combine whois + RDAP + python-whois for age calc."""
import asyncio, requests
from datetime import datetime
try: import whois as pywhois
except: pywhois=None
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _rdap(h):
    try:
        r=requests.get(f"https://rdap.org/domain/{h}",timeout=10,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200: return r.json()
    except: pass
    return None
def _pyw(h):
    if not pywhois: return None
    try: return pywhois.whois(h)
    except: return None
def _parse(v):
    if not v: return None
    if isinstance(v,datetime): return v
    if isinstance(v,list) and v: v=v[0]
    if isinstance(v,str):
        for fmt in ("%Y-%m-%dT%H:%M:%S","%Y-%m-%d %H:%M:%S","%Y-%m-%dT%H:%M:%SZ","%d-%b-%Y","%Y-%m-%d"):
            try: return datetime.strptime(v[:19],fmt)
            except: continue
    return None
async def gather(ctx):
    host=ctx.host
    rdap,pyw=await asyncio.gather(asyncio.to_thread(_rdap,host),asyncio.to_thread(_pyw,host))
    created=expires=None
    if pyw:
        ctx.source("python-whois")
        created=_parse(getattr(pyw,"creation_date",None))
        expires=_parse(getattr(pyw,"expiration_date",None))
    if rdap:
        ctx.source("rdap")
        for ev in (rdap.get("events") or []):
            a=(ev.get("eventAction") or "").lower()
            d=_parse(ev.get("eventDate"))
            if not created and a=="registration": created=d
            if not expires and a=="expiration": expires=d
    now=datetime.utcnow()
    age=(now-created).days if created else None
    dte=(expires-now).days if expires else None
    ctx.state.update({"creation_date":created.isoformat() if created else None,
        "expiration_date":expires.isoformat() if expires else None,
        "age_days":age,"days_to_expiry":dte,"reachable":bool(created or expires)})
def _r_nrd(s):
    a=s.get("age_days")
    if a is None or a>30: return None
    return {"name":f"Newly registered domain ({a} days)","severity":"MEDIUM","cwe":"CWE-1325",
        "evidence":f"Created: {s.get('creation_date')}",
        "remediation":"NRDs are phishing-prone. Treat with caution."}
def _r_young(s):
    a=s.get("age_days")
    if a is None or a<=30 or a>180: return None
    return {"name":f"Young domain ({a} days)","severity":"LOW",
        "evidence":f"Created: {s.get('creation_date')}"}
def _r_age(s):
    a=s.get("age_days")
    if a is None or a<180: return None
    y=a//365
    return {"name":f"Domain age: {y}y {a%365}d","severity":"INFO",
        "evidence":f"Created: {s.get('creation_date')}"}
def _r_unkown(s):
    if s.get("age_days") is not None: return None
    return {"name":"Domain age not determinable","severity":"INFO",
        "evidence":"WHOIS + RDAP both lacked creation date"}
FINDING_RULES=[_r_nrd,_r_young,_r_age,_r_unkown]
INTEL_FIELDS=[("Created","creation_date"),("Expires","expiration_date"),
    ("Age (days)","age_days"),("Days to expiry","days_to_expiry")]
@router.post("/api/recon/domain_age")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="domain_age",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["creation_date","expiration_date","age_days"])
def register(app): app.include_router(router)
