"""Firebase Open DB Check v2 — VL-FORGE (real probe)."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
def _check(url):
    try:
        r=requests.get(url,timeout=6,headers={"User-Agent":"VulnusLab/1.0"})
        return {"status":r.status_code,"body_len":len(r.content),
            "open":r.status_code==200 and (r.text or "")!="null"}
    except: return None
async def gather(ctx):
    org=ctx.host.split(".")[0]
    cands=[f"https://{org}.firebaseio.com/.json",f"https://{org}-prod.firebaseio.com/.json",
        f"https://{org}-dev.firebaseio.com/.json",f"https://{org}-staging.firebaseio.com/.json",
        f"https://{org}-default-rtdb.firebaseio.com/.json"]
    res=await asyncio.gather(*[asyncio.to_thread(_check,u) for u in cands])
    open_dbs=[]; existing=[]
    for u,r in zip(cands,res):
        if not r: continue
        if r.get("open") and r.get("body_len",0)>2:
            open_dbs.append({"url":u,"size":r["body_len"]})
        elif r.get("status") in (200,401,403):
            existing.append({"url":u,"status":r["status"]})
    if open_dbs: ctx.source(f"open-firebase-{len(open_dbs)}")
    ctx.state.update({"open_dbs":open_dbs,"existing":existing,
        "open_count":len(open_dbs),"existing_count":len(existing)})
def _r_open(s):
    o=s.get("open_dbs") or []
    if not o: return None
    return {"name":f"Firebase DB OPEN to public read ({len(o)})","severity":"CRITICAL","cvss":9.5,
        "cwe":"CWE-284","owasp":"A05:2021",
        "evidence":"; ".join(f"{x['url']} ({x['size']}B)" for x in o),
        "remediation":"Set Firebase rules: '.read': 'auth != null'. Audit data exposed."}
def _r_exists(s):
    e=s.get("existing") or []
    if not e or s.get("open_count",0)>0: return None
    return {"name":f"{len(e)} Firebase projects exist (locked)","severity":"INFO",
        "evidence":", ".join(x["url"].replace(".firebaseio.com/.json","") for x in e[:5])}
FINDING_RULES=[_r_open,_r_exists]
INTEL_FIELDS=[("Open DBs","open_count"),("Existing","existing_count")]
@router.post("/api/recon/firebase_open_db_check")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="firebase_open_db_check",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["open_dbs","existing"])
def register(app): app.include_router(router)
