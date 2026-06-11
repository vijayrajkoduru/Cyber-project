"""Email Security v2 — VL-FORGE. SPF + DMARC + DKIM + MTA-STS + BIMI."""
import asyncio
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
_DKIM_SELECTORS=["default","google","selector1","selector2","s1","s2","mail","dkim","k1"]
async def _q(h,rt="TXT"):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        return [str(x).strip('"') for x in await r.resolve(h,rt)]
    except Exception: return []
async def gather(ctx):
    h=ctx.host
    apex_txt,dmarc_txt,mta_sts,bimi,mx=await asyncio.gather(
        _q(h),_q(f"_dmarc.{h}"),_q(f"_mta-sts.{h}"),_q(f"default._bimi.{h}"),_q(h,"MX"))
    spf=next((t for t in apex_txt if t.lower().startswith("v=spf1")),None)
    dmarc=next((t for t in dmarc_txt if "v=DMARC1" in t),None)
    mta_sts_rec=next((t for t in mta_sts if "v=STSv1" in t),None)
    bimi_rec=next((t for t in bimi if "v=BIMI1" in t),None)
    if spf: ctx.source("spf")
    if dmarc: ctx.source("dmarc")
    if mta_sts_rec: ctx.source("mta-sts")
    if bimi_rec: ctx.source("bimi")
    if mx: ctx.source(f"mx-{len(mx)}")
    # DKIM probe (9 common selectors)
    dkim_results=await asyncio.gather(*[_q(f"{s}._domainkey.{h}") for s in _DKIM_SELECTORS])
    dkim_selectors_found=[s for s,r in zip(_DKIM_SELECTORS,dkim_results) if any("v=DKIM1" in t for t in r)]
    if dkim_selectors_found: ctx.source(f"dkim-{len(dkim_selectors_found)}")
    spf_strict=bool(spf and (" -all" in spf or "-all" in spf.split()))
    dmarc_policy=("reject" if dmarc and "p=reject" in dmarc else
                  "quarantine" if dmarc and "p=quarantine" in dmarc else
                  "none" if dmarc and "p=none" in dmarc else None)
    ctx.state.update({"spf_record":spf,"spf_strict":spf_strict,
        "dmarc_record":dmarc,"dmarc_policy":dmarc_policy,
        "mta_sts_record":mta_sts_rec,"bimi_record":bimi_rec,
        "mx_records":mx,"dkim_selectors":dkim_selectors_found,
        "reachable":bool(mx or spf or dmarc)})
def _r_no_spf(s):
    if s.get("spf_record"): return None
    if not s.get("mx_records"): return None
    return {"name":"No SPF record","severity":"HIGH","cvss":7.0,"cwe":"CWE-290",
        "owasp":"A07:2021","evidence":"Domain has MX but no SPF — email spoofable",
        "remediation":"Publish 'v=spf1 mx -all' TXT record."}
def _r_weak_spf(s):
    spf=s.get("spf_record")
    if not spf or s.get("spf_strict"): return None
    return {"name":"SPF uses weak ~all/?all/+all","severity":"MEDIUM","cwe":"CWE-290",
        "evidence":f"SPF: {spf[:120]}","remediation":"Tighten to '-all'."}
def _r_no_dmarc(s):
    if s.get("dmarc_record"): return None
    if not s.get("mx_records"): return None
    return {"name":"No DMARC record","severity":"HIGH","cwe":"CWE-290","owasp":"A07:2021",
        "evidence":"_dmarc lookup returned nothing",
        "remediation":"Add 'v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>'."}
def _r_dmarc_none(s):
    if s.get("dmarc_policy")!="none": return None
    return {"name":"DMARC policy is 'none' (monitoring only)","severity":"MEDIUM",
        "evidence":s.get("dmarc_record","")[:120],
        "remediation":"Move to p=quarantine then p=reject after rua review."}
def _r_dmarc_strict(s):
    if s.get("dmarc_policy") not in ("quarantine","reject"): return None
    return {"name":f"DMARC policy: {s['dmarc_policy']}","severity":"POSITIVE",
        "evidence":"Anti-spoofing enforced"}
def _r_no_dkim(s):
    if s.get("dkim_selectors"): return None
    if not s.get("mx_records"): return None
    return {"name":"No DKIM selectors found (9 probed)","severity":"MEDIUM","cwe":"CWE-290",
        "evidence":"None of: default, google, selector1/2, s1/2, mail, dkim, k1",
        "remediation":"Configure DKIM at mail provider, publish public key in DNS."}
def _r_dkim_present(s):
    sel=s.get("dkim_selectors") or []
    if not sel: return None
    return {"name":f"DKIM configured ({len(sel)} selector(s))","severity":"POSITIVE",
        "evidence":f"Selectors: {', '.join(sel)}"}
def _r_no_mta_sts(s):
    if s.get("mta_sts_record"): return None
    if not s.get("mx_records"): return None
    return {"name":"No MTA-STS policy","severity":"LOW","cwe":"CWE-319",
        "evidence":"_mta-sts subdomain lacks STSv1 record",
        "remediation":"Configure MTA-STS to enforce TLS on inbound email."}
def _r_bimi(s):
    if not s.get("bimi_record"): return None
    return {"name":"BIMI configured","severity":"POSITIVE",
        "evidence":"Brand Indicators for Message Identification — logo in inbox"}
FINDING_RULES=[_r_no_spf,_r_weak_spf,_r_no_dmarc,_r_dmarc_none,_r_dmarc_strict,
    _r_no_dkim,_r_dkim_present,_r_no_mta_sts,_r_bimi]
INTEL_FIELDS=[("SPF","spf_record"),("SPF strict","spf_strict"),
    ("DMARC policy","dmarc_policy"),("DKIM selectors","dkim_selectors"),
    ("MTA-STS","mta_sts_record"),("BIMI","bimi_record"),("MX","mx_records")]
@router.post("/api/recon/email_security")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="email_security",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["spf_record","dmarc_record","dkim_selectors","mx_records"])
def register(app): app.include_router(router)
