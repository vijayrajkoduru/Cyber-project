"""cors_misconfig — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    misconfigs = []
    # Reflect arbitrary Origin
    code, hdrs, _ = await fetch(base, headers={"Origin":"https://evil.example.com"})
    aco = hdrs.get("Access-Control-Allow-Origin","") or hdrs.get("access-control-allow-origin","")
    acc = (hdrs.get("Access-Control-Allow-Credentials","") or hdrs.get("access-control-allow-credentials","")).lower()
    if aco == "https://evil.example.com" and acc == "true":
        misconfigs.append({"type":"reflected_origin_with_credentials","detail":"ACAO reflects arbitrary origin with credentials=true"})
    elif aco == "*" and acc == "true":
        misconfigs.append({"type":"wildcard_with_credentials","detail":"ACAO=* with credentials=true (invalid per spec)"})
    elif aco == "null":
        misconfigs.append({"type":"null_origin","detail":"ACAO=null — bypassable from sandboxed iframes"})
    ctx.state["aco"] = aco
    ctx.state["acc"] = acc
    ctx.state["misconfigs"] = misconfigs
    ctx.source("CORS probe with arbitrary Origin header")

RULES = [
    lambda s: {"name":"CORS misconfiguration: " + s.get('misconfigs',[{}])[0].get('type',''),"severity":"HIGH",
        "evidence":f"Detail: {s.get('misconfigs')}",
        "remediation":"Whitelist specific origins. Never reflect Origin header. Never combine ACAO=* with credentials.",
        "cwe":"CWE-942","owasp":"A05:2021"
    } if s.get("misconfigs") else None,
]

@router.post("/api/recon/cors_misconfig")
async def recon_cors_misconfig(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="cors_misconfig",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Aco","aco"),("Acc","acc"),("Misconfigs","misconfigs")])

def register(app):
    app.include_router(router)
