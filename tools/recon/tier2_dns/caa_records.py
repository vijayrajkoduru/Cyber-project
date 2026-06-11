"""CAA Records v2 — VL-FORGE. Certificate Authority Authorization."""
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def _q(h,rt="CAA"):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        return [str(x) for x in await r.resolve(h,rt)]
    except Exception: return []
async def gather(ctx):
    caa=await _q(ctx.host,"CAA")
    if not caa:
        # Check parent zone
        parts=ctx.host.split(".")
        if len(parts)>2:
            caa_parent=await _q(".".join(parts[1:]),"CAA")
            if caa_parent: ctx.source("caa-parent-zone")
            ctx.state["caa_parent"]=caa_parent
    if caa: ctx.source(f"caa-{len(caa)}")
    issuers=[]; iodef=None; issuewild=[]
    for r in caa:
        parts=r.split()
        if len(parts)>=3:
            tag=parts[1].lower()
            val=parts[2].strip('"')
            if "issue" in tag and "wild" not in tag: issuers.append(val)
            elif "issuewild" in tag: issuewild.append(val)
            elif "iodef" in tag: iodef=val
    ctx.state.update({"caa_records":caa,"reachable":bool(caa),"issuers":issuers,
        "issuewild_allowed":issuewild,"iodef":iodef,"any_ca_allowed":not caa})
def _r_no_caa(s):
    if (s.get("caa_records") or []) or (s.get("caa_parent") or []): return None
    return {"name":"No CAA records (any CA can issue cert)","severity":"LOW","cwe":"CWE-295",
        "evidence":"Apex + parent zone lack CAA",
        "remediation":"Add CAA: '0 issue \"letsencrypt.org\"' to restrict cert issuance."}
def _r_no_iodef(s):
    if not (s.get("caa_records") or []): return None
    if s.get("iodef"): return None
    return {"name":"CAA present but no iodef incident URL","severity":"INFO",
        "evidence":"iodef= specifies where CAs report policy violations",
        "remediation":"Add 'iodef' tag: '0 iodef \"mailto:security@<domain>\"'"}
def _r_caa_present(s):
    if not (s.get("caa_records") or []): return None
    return {"name":f"CAA restricts cert issuance to: {', '.join(s.get('issuers') or [])}",
        "severity":"POSITIVE","evidence":f"{len(s['caa_records'])} CAA record(s)"}
def _r_wildcard_unrestricted(s):
    if not (s.get("caa_records") or []): return None
    if (s.get("issuewild_allowed") or []): return None
    if not (s.get("issuers") or []): return None
    return {"name":"Wildcard cert issuance unrestricted","severity":"INFO","cwe":"CWE-295",
        "evidence":"No issuewild= tag — wildcards inherit from issue=",
        "remediation":"Add '0 issuewild \";\"' to forbid wildcards, or explicit allowed CA."}
FINDING_RULES=[_r_no_caa,_r_wildcard_unrestricted,_r_no_iodef,_r_caa_present]
INTEL_FIELDS=[("CAA records","caa_records"),("Issuers allowed","issuers"),
    ("Wildcard allowed","issuewild_allowed"),("iodef","iodef")]
@router.post("/api/recon/caa_records")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="caa_records",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["caa_records","issuers"])
def register(app): app.include_router(router)
