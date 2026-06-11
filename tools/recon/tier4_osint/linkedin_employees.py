"""LinkedIn Employees v2 — VL-FORGE OSINT via Hunter.io fallback."""
import asyncio, requests, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
def _g(u,h=None,t=12):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"VulnusLab/1.0",**(h or {})})
        if r.status_code==200: return r.json() if "json" in r.headers.get("Content-Type","") else r.text
    except: pass
    return None
async def gather(ctx):
    h=ctx.host
    # Bing scrape as fallback (no key needed)
    bing=await asyncio.to_thread(_g,f"https://www.bing.com/search?q=site%3Alinkedin.com+%22{h}%22&count=30")
    employees=set()
    if bing and isinstance(bing,str):
        ctx.source("bing-linkedin")
        for m in re.findall(r"linkedin\.com/in/([\w\-]+)",bing[:50000]):
            employees.add(m)
        for m in re.findall(r"linkedin\.com/company/([\w\-]+)",bing[:50000]):
            ctx.state.setdefault("companies",set()).add(m)
    # Hunter.io if keyed
    hunter_key=os.environ.get("HUNTER_API_KEY","")
    if hunter_key:
        ctx.state["hunter_keyed"]=True
        d=await asyncio.to_thread(_g,
            f"https://api.hunter.io/v2/domain-search?domain={h}&limit=50&api_key={hunter_key}")
        if d and isinstance(d,dict):
            ctx.source("hunter.io")
            for em in d.get("data",{}).get("emails",[]):
                pos=em.get("position","")
                first=em.get("first_name","")
                last=em.get("last_name","")
                if first or last:
                    ctx.state.setdefault("hunter_employees",[]).append({
                        "name":f"{first} {last}".strip(),"position":pos,"email":em.get("value","")})
    if isinstance(ctx.state.get("companies"),set):
        ctx.state["companies"]=sorted(ctx.state["companies"])[:10]
    ctx.state["linkedin_handles"]=sorted(employees)[:30]
    ctx.state["employee_count"]=len(employees)+len(ctx.state.get("hunter_employees") or [])
def _r_employees(s):
    n=s.get("employee_count",0)
    if n==0: return None
    return {"name":f"{n} employees discoverable via OSINT","severity":"INFO","cwe":"T1591.004",
        "evidence":f"LinkedIn handles: {len(s.get('linkedin_handles') or [])}, Hunter.io: {len(s.get('hunter_employees') or [])}",
        "remediation":"Public employee data feeds phishing campaigns. Train staff on spear-phishing."}
def _r_no_hunter(s):
    if s.get("hunter_keyed"): return None
    return {"name":"HUNTER_API_KEY not set","severity":"INFO",
        "evidence":"Free tier: 25/month at hunter.io for deeper employee intel"}
FINDING_RULES=[_r_employees,_r_no_hunter]
INTEL_FIELDS=[("Employee count","employee_count"),("LinkedIn handles","linkedin_handles"),
    ("Hunter employees","hunter_employees"),("Companies","companies")]
@router.post("/api/recon/linkedin_employees")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="linkedin_employees",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["linkedin_handles","hunter_employees","employee_count"])
def register(app): app.include_router(router)
