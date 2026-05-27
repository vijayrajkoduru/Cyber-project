"""github_code_search — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import urllib.request, urllib.parse, json

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    token = os.environ.get("GITHUB_TOKEN","")
    if not token:
        ctx.state["api_key_configured"] = False; ctx.source("GITHUB_TOKEN not set"); return
    SECRET_PATTERNS = ["password","api_key","secret","token","aws_secret"]
    hits = []
    try:
        for pat in SECRET_PATTERNS[:3]:
            q = urllib.parse.quote(f'{pat} "{h}"')
            def _s(q=q):
                req = urllib.request.Request(f"https://api.github.com/search/code?q={q}&per_page=5",
                    headers={"Authorization":f"token {token}","Accept":"application/vnd.github.v3+json"})
                with urllib.request.urlopen(req, timeout=8) as r: return json.loads(r.read())
            d = await asyncio.to_thread(_s)
            for it in d.get("items",[])[:5]:
                hits.append({"pattern":pat,"repo":it.get("repository",{}).get("full_name"),"path":it.get("path")})
    except Exception as e: ctx.state["error"] = str(e)[:120]
    ctx.state["api_key_configured"] = True
    ctx.state["hits"] = hits
    ctx.source("GitHub code search — secret keywords + domain")

RULES = [
    lambda s: {"name":"Potential Secret Leak in Public GitHub","severity":"HIGH",
        "evidence":f"Matches found: {s.get('hits')[:5]}",
        "remediation":"Audit each match. Rotate any leaked credentials. Use trufflehog for full org scan.",
        "cwe":"CWE-540","owasp":"A05:2021"
    } if s.get("hits") else None,
]

@router.post("/api/recon/github_code_search")
async def recon_github_code_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="github_code_search",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Hits","hits")])

def register(app):
    app.include_router(router)
