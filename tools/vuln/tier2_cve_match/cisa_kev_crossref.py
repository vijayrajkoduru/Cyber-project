"""CISA KEV cross-reference vs detected tech. VL-FORGE Vuln tier2 §2 #25."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import run_scanner
from tools.vuln._vuln_common import http_get
from tools.vuln._cve_intel import kev_catalog, detect_tech_tokens, TECH_ALIASES
router = APIRouter()
async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    r = await asyncio.to_thread(http_get, base + "/")
    if not r:
        ctx.state["tested"] = 0; return
    ctx.source("http"); ctx.state["tested"] = 1
    hdrs = r.get("headers", {})
    banners = [hdrs[h] for h in ("server","x-powered-by","x-generator","x-aspnet-version") if hdrs.get(h)]
    techs = detect_tech_tokens(banners, r.get("body", "") or "")
    ctx.state["techs"] = sorted(techs)
    if not techs: return
    kev = await asyncio.to_thread(kev_catalog)
    ctx.state["kev_size"] = len(kev)
    matches, seen = [], set()
    for e in kev:
        prod = (e.get("product") or "").lower(); vend = (e.get("vendorProject") or "").lower()
        hit = next((t for t in techs if any(tok in prod or tok in vend for tok in TECH_ALIASES.get(t, [t]))), None)
        cid = e.get("cveID", "")
        if hit and cid and cid not in seen:
            seen.add(cid)
            matches.append({"cve": cid, "product": e.get("product", ""), "ransomware": (e.get("knownRansomwareCampaignUse") or "Unknown")})
    ctx.state["matches"] = matches[:10]
def _r_kev(s):
    m = s.get("matches") or []
    if not m: return None
    lst = ", ".join(f"{x['cve']} ({x['product']})" for x in m[:4])
    ranso = any(x["ransomware"].lower() == "known" for x in m)
    # Product-level fingerprint match is SUSPECTED, not confirmed. Cap at
    # MEDIUM (not HIGH) until version is verified - aligns with industry VA
    # severity conventions where unverified findings stay below HIGH.
    # Ransomware-linked KEVs still escalate to HIGH because the impact
    # justifies the operational urgency even on suspected matches.
    sev, cvss = ("HIGH", 8.1) if ranso else ("MEDIUM", 5.8)
    return {"name": f"Detected tech matches {len(m)} CISA KEV entry(ies) - known-exploited class present",
            "severity": sev, "cvss": cvss, "cwe": "CWE-1395",
            "evidence": f"KEV match (product-level, SUSPECTED - verify version): {lst}." + (" Ransomware-linked." if ranso else ""),
            "remediation": "Confirm running version; if affected, patch immediately (CISA KEV / BOD 22-01)."}
def _r_clean(s):
    if (s.get("tested") or 0) < 1 or (s.get("matches") or []): return None
    techs = ', '.join(s.get('techs') or []) or 'none'
    kev_size = s.get('kev_size')
    tail = f"; checked vs {kev_size} KEV entries" if isinstance(kev_size, int) and kev_size > 0 else "; checked against the CISA KEV catalog"
    return {"name": "No detected technology matches the CISA KEV catalog", "severity": "POSITIVE",
            "evidence": f"Detected: {techs}{tail}."}
FINDING_RULES = [_r_kev, _r_clean]; INTEL_FIELDS = [("Detected technologies", "techs")]
@router.post("/api/vuln/cisa_kev_crossref")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="cisa_kev_crossref", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
