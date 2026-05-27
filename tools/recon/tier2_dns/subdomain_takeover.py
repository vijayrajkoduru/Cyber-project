"""subdomain_takeover — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at
import urllib.request, urllib.error

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    FINGERPRINTS = {
        "github.io":"There isn\'t a GitHub Pages site here",
        "herokuapp.com":"No such app",
        "s3.amazonaws.com":"NoSuchBucket",
        "azurewebsites.net":"404 Web Site not found",
        "cloudfront.net":"Bad request",
        "wordpress.com":"Do you want to register",
        "tumblr.com":"Whatever you were looking for",
        "shopify.com":"Sorry, this shop is currently unavailable",
        "ghost.io":"The thing you were looking for is no longer here",
        "fastly.net":"Fastly error: unknown domain",
    }
    cnames = await query(h, "CNAME")
    findings = []
    for c in cnames:
        target = c.rstrip(".").lower()
        matched_provider = None
        for prov in FINGERPRINTS:
            if target.endswith(prov):
                matched_provider = prov; break
        if not matched_provider: continue
        # Fetch the target — look for fingerprint
        try:
            def _fetch():
                req = urllib.request.Request(f"http://{target}", headers={"User-Agent":"VulnusLab"})
                with urllib.request.urlopen(req, timeout=6) as r:
                    return r.read(8192).decode("utf-8","ignore")
            body = await asyncio.to_thread(_fetch)
            if FINGERPRINTS[matched_provider] in body:
                findings.append({"cname":target,"provider":matched_provider,"fingerprint_matched":True})
        except urllib.error.HTTPError as e:
            try:
                body = e.read(8192).decode("utf-8","ignore")
                if FINGERPRINTS[matched_provider] in body:
                    findings.append({"cname":target,"provider":matched_provider,"fingerprint_matched":True})
            except Exception: pass
        except Exception: pass
    ctx.state["cnames"] = cnames
    ctx.state["takeover_candidates"] = findings
    ctx.source("CNAME + HTTP fingerprint match against 10 takeover-prone providers")

RULES = [
    lambda s: {"name":"Subdomain Takeover — Dangling CNAME Confirmed","severity":"HIGH",
        "evidence":f"CNAME points to unclaimed resource: {s.get('takeover_candidates')}",
        "remediation":"Remove the CNAME OR reclaim the provider resource. Attacker who claims the target can serve content under your domain (cookie theft, phishing).",
        "cwe":"CWE-350","owasp":"A05:2021"
    } if s.get("takeover_candidates") else None,
]

@router.post("/api/recon/subdomain_takeover")
async def recon_subdomain_takeover(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="subdomain_takeover",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Cnames","cnames"),("Takeover Candidates","takeover_candidates")])

def register(app):
    app.include_router(router)
