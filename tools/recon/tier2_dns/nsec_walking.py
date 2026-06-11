"""NSEC Walking v2 — VL-FORGE. DNSSEC zone enumeration via NSEC/NSEC3."""
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def _q(h,rt):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        return [str(x) for x in await r.resolve(h,rt)]
    except: return []
async def gather(ctx):
    nsec=await _q(ctx.host,"NSEC")
    nsec3=await _q(ctx.host,"NSEC3")
    nsec3param=await _q(ctx.host,"NSEC3PARAM")
    if nsec: ctx.source(f"nsec-{len(nsec)}")
    if nsec3: ctx.source(f"nsec3-{len(nsec3)}")
    if nsec3param: ctx.source("nsec3param")
    # Check NSEC3 iterations (high = harder to brute, low = easier)
    iter_count=None; salt=None
    if nsec3param:
        parts=nsec3param[0].split()
        if len(parts)>=4:
            try:
                iter_count=int(parts[2])
                salt=parts[3]
            except: pass
    ctx.state.update({"nsec_records":nsec,"nsec3_records":nsec3,
        "nsec3param":nsec3param,"nsec3_iterations":iter_count,"nsec3_salt":salt,
        "reachable":bool(nsec or nsec3 or nsec3param)})
def _r_nsec_walk(s):
    if not (s.get("nsec_records") or []): return None
    return {"name":"NSEC zone-walking possible","severity":"MEDIUM","cwe":"CWE-200",
        "owasp":"A05:2021",
        "evidence":"Plain NSEC records — full zone enumerable via chained queries",
        "remediation":"Migrate to NSEC3 with iterations >= 100."}
def _r_weak_nsec3(s):
    it=s.get("nsec3_iterations")
    if it is None or it >= 100: return None
    return {"name":f"Weak NSEC3 iteration count ({it})","severity":"LOW","cwe":"CWE-326",
        "evidence":f"Iterations={it} (recommended: ≥100)",
        "remediation":"Increase NSEC3 iterations to slow brute-force enumeration."}
def _r_nsec3_strong(s):
    it=s.get("nsec3_iterations")
    if it is None or it < 100: return None
    return {"name":f"NSEC3 with strong iterations ({it})","severity":"POSITIVE",
        "evidence":f"Salt: {s.get('nsec3_salt')}"}
def _r_no_dnssec_nsec(s):
    if s.get("reachable"): return None
    return {"name":"No NSEC/NSEC3 records","severity":"INFO",
        "evidence":"DNSSEC not deployed or zone-walking already prevented"}
FINDING_RULES=[_r_nsec_walk,_r_weak_nsec3,_r_nsec3_strong,_r_no_dnssec_nsec]
INTEL_FIELDS=[("NSEC","nsec_records"),("NSEC3","nsec3_records"),
    ("Iterations","nsec3_iterations"),("Salt","nsec3_salt")]
@router.post("/api/recon/nsec_walking")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="nsec_walking",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["nsec_records","nsec3_records","nsec3_iterations"])
def register(app): app.include_router(router)
