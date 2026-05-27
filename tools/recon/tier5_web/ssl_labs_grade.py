"""ssl_labs_grade — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import urllib.request, json

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host.replace("http://","").replace("https://","").split("/")[0]
    grade = ""; details = {}
    try:
        def _api():
            url = f"https://api.ssllabs.com/api/v3/analyze?host={h}&fromCache=on&maxAge=24"
            with urllib.request.urlopen(url, timeout=10) as r:
                return json.loads(r.read())
        d = await asyncio.to_thread(_api)
        if d.get("status") == "READY":
            ep = (d.get("endpoints") or [{}])[0]
            grade = ep.get("grade","")
            details = {"hasWarnings":ep.get("hasWarnings"),"isExceptional":ep.get("isExceptional")}
    except Exception as e:
        ctx.state["error"] = str(e)[:120]
    ctx.state["grade"] = grade
    ctx.state["details"] = details
    ctx.source("SSL Labs API (cached)")

RULES = [
    lambda s: {"name":f"SSL Labs grade {s.get('grade')} — below B","severity":"MEDIUM",
        "evidence":f"SSL Labs assigned grade {s.get('grade')} — TLS configuration has weaknesses",
        "remediation":"Review SSL Labs full report at https://ssllabs.com/ssltest/ and remediate",
        "cwe":"CWE-326","owasp":"A02:2021"
    } if s.get("grade") in ("C","D","E","F","T") else None,
]

@router.post("/api/recon/ssl_labs_grade")
async def recon_ssl_labs_grade(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="ssl_labs_grade",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Grade","grade"),("Details","details")])

def register(app):
    app.include_router(router)
