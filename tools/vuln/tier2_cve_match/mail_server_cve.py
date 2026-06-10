"""SMTP/IMAP/POP banner -> NVD CVE. VL-FORGE Vuln tier2 §2 #21."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools.vuln._cve_intel import tcp_banner, high_cves
router = APIRouter()
_PORTS = [(25,"SMTP"),(587,"SMTP"),(143,"IMAP"),(110,"POP3"),(993,"IMAPS"),(995,"POP3S")]
_VER = re.compile(r"([A-Za-z][A-Za-z0-9_+.-]*?)[/ ]v?(\d+\.\d+(?:\.\d+)?)")
_KNOWN = ["postfix","exim","sendmail","dovecot","exchange","zimbra","courier","qmail"]
async def gather(ctx):
    host = str(ctx.host); banners = []
    for port, label in _PORTS:
        ok, data = await asyncio.to_thread(tcp_banner, host, port, b"", 4)
        if ok and data.strip():
            banners.append(f"{port}/{label}: {data.strip().splitlines()[0][:200]}")
    ctx.source("tcp"); ctx.state["probed"] = 1; ctx.state["banners"] = banners
    soft = sorted({k for b in banners for k in _KNOWN if k in b.lower()})
    ctx.state["software"] = soft
    hits = []
    for b in banners:
        for m in _VER.finditer(b):
            if m.group(1).lower() in _KNOWN:
                h = await asyncio.to_thread(high_cves, m.group(1), m.group(2))
                if h: hits.append({"product": f"{m.group(1)} {m.group(2)}", "count": len(h), "top": h[:3]}); break
    ctx.state["cve_hits"] = hits
def _r_cve(s):
    h = s.get("cve_hits") or []
    if not h: return None
    x = h[0]; top = ", ".join(f"{c} ({sc})" for c, sc in x["top"])
    return {"name": f"Mail server '{x['product']}' maps to {x['count']} high-severity CVE(s)", "severity": "MEDIUM", "cvss": 5.9, "cwe": "CWE-1395",
            "evidence": f"NVD: {top}. Version-inferred from mail banner - confirm patch level.", "remediation": "Upgrade the mail server; suppress banner version strings."}
def _r_disc(s):
    if not (s.get("software") or []) or (s.get("cve_hits") or []): return None
    return {"name": f"Mail server software disclosed: {', '.join(s['software'])}", "severity": "LOW", "cwe": "CWE-200",
            "evidence": f"Banners: {' | '.join(s.get('banners') or [])[:200]}", "remediation": "Suppress software/version in SMTP/IMAP/POP greetings."}
def _r_clean(s):
    if not s.get("probed") or (s.get("banners") or []): return None
    return {"name": "No mail-service banners exposed", "severity": "POSITIVE", "evidence": "No SMTP/IMAP/POP service returned an identifiable banner."}
FINDING_RULES = [_r_cve, _r_disc, _r_clean]; INTEL_FIELDS = [("Mail banners","banners")]
@router.post("/api/vuln/mail_server_cve")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="mail_server_cve", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
