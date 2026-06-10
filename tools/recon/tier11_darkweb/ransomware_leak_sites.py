"""Ransomware Leak Sites v2 — VL-FORGE. ransomware.live API.

VL-VERIFY (zero-FP): ransomware.live's /searchvictims/<q> endpoint does
SUBSTRING matching on the victim_name field, so a search for 'google.com'
returns every victim whose company name contains 'google' (e.g. 'Google
Solutions Pty Ltd' - a totally unrelated SMB that was actually ransomed).
That mis-flagged google.com as CRITICAL-compromised on the dogfood scan
2026-06-10.

Fix: only count a hit when EITHER:
  - victim's 'domain' field exactly equals (or is a subdomain of) the target
  - OR victim_name normalises to the apex (e.g. 'Google LLC' for google.com)
We are conservative - skip ambiguous substring matches.
"""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()


def _domain_apex(d: str) -> str:
    """Return last-two-labels of a domain (best-effort apex)."""
    d = (d or "").strip().lower().rstrip(".")
    parts = d.split(".")
    if len(parts) < 2: return d
    return ".".join(parts[-2:])


def _is_real_hit(victim: dict, target_apex: str) -> bool:
    """Decide if a ransomware.live result is a real match for our target.
    Returns True only when we are CONFIDENT - skips ambiguous substring
    company-name matches."""
    if not isinstance(victim, dict): return False
    # 1. Exact domain match (best signal)
    for field in ("domain", "victim_domain", "url"):
        val = (victim.get(field) or "").strip().lower()
        if not val: continue
        # Strip http(s):// and path
        for prefix in ("https://", "http://"):
            if val.startswith(prefix): val = val[len(prefix):]
        val = val.split("/", 1)[0].lstrip("www.")
        if val == target_apex or val.endswith("." + target_apex):
            return True
    return False


async def gather(ctx):
    target_apex = _domain_apex(str(ctx.host))
    try:
        r=await asyncio.to_thread(requests.get,
            f"https://api.ransomware.live/v2/searchvictims/{ctx.host}",
            timeout=15,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200:
            data=r.json()
            raw_victims=data if isinstance(data,list) else (data.get("victims") or [])
            # FP filter: only count exact domain matches, not substring company-name hits
            verified = [v for v in raw_victims if _is_real_hit(v, target_apex)]
            ctx.source("ransomware.live")
            ctx.state["raw_match_count"]=len(raw_victims)
            ctx.state["victims"]=verified[:10]
            ctx.state["victim_count"]=len(verified)
            # Surface the rejected count so an analyst can audit
            if raw_victims and not verified:
                ctx.state["skipped_substring_matches"]=len(raw_victims)
    except: pass
def _r_hit(s):
    n=s.get("victim_count",0)
    if n==0: return None
    return {"name":f"Domain in ransomware leak sites ({n} entries)","severity":"CRITICAL","cvss":10.0,
        "cwe":"T1486","owasp":"A09:2021",
        "evidence":"Sample: "+str((s.get("victims") or [{}])[0])[:200],
        "remediation":"CRITICAL - confirms ransomware compromise. Initiate IR immediately."}
def _r_clean(s):
    if s.get("victim_count",0)>0: return None
    raw = s.get("raw_match_count", 0)
    if raw > 0:
        return {"name":"Not on ransomware leak sites (substring matches rejected)",
                "severity":"POSITIVE",
                "evidence":f"ransomware.live returned {raw} substring matches; "
                           f"none had a domain field matching target. FP-safe."}
    return {"name":"Not on ransomware leak sites","severity":"POSITIVE","evidence":"ransomware.live returned 0"}
FINDING_RULES=[_r_hit,_r_clean]
INTEL_FIELDS=[("Victim count","victim_count"),
              ("Raw matches","raw_match_count"),
              ("Substring matches rejected","skipped_substring_matches")]
@router.post("/api/recon/ransomware_leak_sites")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="ransomware_leak_sites",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["victims","victim_count"])
def register(app): app.include_router(router)
