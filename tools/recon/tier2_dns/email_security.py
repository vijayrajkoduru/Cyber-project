"""email_security — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    txt = await query(h, "TXT")
    spf = next((t for t in txt if "v=spf1" in t.lower()), "")
    dmarc_txt = await query(f"_dmarc.{h}", "TXT")
    dmarc = next((t for t in dmarc_txt if "v=DMARC1" in t), "")
    # DKIM — probe common selectors in parallel
    sels = ("selector1","selector2","google","default","mail","s1","s2","k1")
    dkim_results = await asyncio.gather(*[query(f"{s}._domainkey.{h}","TXT") for s in sels])
    dkim_found = [sels[i] for i,r in enumerate(dkim_results) if r]
    ctx.state["spf"] = spf
    ctx.state["dmarc"] = dmarc
    ctx.state["dkim_selectors"] = dkim_found
    spf_low = spf.lower()
    ctx.state["spf_permissive"] = ("+all" in spf_low) or ("?all" in spf_low)
    ctx.state["dmarc_none"] = "p=none" in dmarc.lower()
    ctx.source("TXT records: SPF / DMARC / DKIM selector enum")

RULES = [
    lambda s: {"name":"No SPF record","severity":"MEDIUM",
        "evidence":"No SPF (v=spf1) TXT record — domain can be spoofed in email",
        "remediation":"Publish SPF: 'v=spf1 include:_spf.google.com -all' (adjust for your sender)",
        "cwe":"CWE-290","owasp":"N/A"
    } if not s.get("spf") else None,
    lambda s: {"name":"SPF permits all senders (+all / ?all)","severity":"HIGH",
        "evidence":f"SPF policy is permissive: {s.get('spf')}",
        "remediation":"Use '-all' or '~all' to reject/softfail unauthorized senders",
        "cwe":"CWE-290","owasp":"N/A"
    } if s.get("spf_permissive") else None,
    lambda s: {"name":"No DMARC record","severity":"MEDIUM",
        "evidence":"No DMARC at _dmarc.<domain> — no policy + no reports for spoofed mail",
        "remediation":"Add 'v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>'",
        "cwe":"CWE-290","owasp":"N/A"
    } if not s.get("dmarc") else None,
    lambda s: {"name":"DMARC policy is none (monitoring only)","severity":"LOW",
        "evidence":f"DMARC: {s.get('dmarc')} — p=none means no enforcement",
        "remediation":"Upgrade to p=quarantine then p=reject after monitoring reports",
        "cwe":"CWE-290","owasp":"N/A"
    } if s.get("dmarc") and s.get("dmarc_none") else None,
]

@router.post("/api/recon/email_security")
async def recon_email_security(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="email_security",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("SPF","spf"),("DMARC","dmarc"),("DKIM Selectors","dkim_selectors")])

def register(app):
    app.include_router(router)
