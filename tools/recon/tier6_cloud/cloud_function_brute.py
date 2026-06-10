"""Cloud Function URL Brute — Route: /api/recon/cloud_function_brute
Generates likely cloud function URLs (AWS Lambda, GCF, Azure Functions) from cloud_function_patterns.txt."""
import asyncio
from pathlib import Path
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()
_PAYLOAD = Path(__file__).resolve().parent.parent.parent / "_payloads" / "recon" / "cloud_function_patterns.txt"
_TO, _CONC = 4, 20

def _load():
    try:
        if _PAYLOAD.exists():
            return [l.strip() for l in _PAYLOAD.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")]
    except Exception: pass
    return ["{org}.lambda-url.us-east-1.on.aws","{org}-{region}.cloudfunctions.net",
            "{org}.azurewebsites.net","{org}.netlify.app","{org}.vercel.app"]

def _get(url):
    try:
        return requests.get(url, timeout=_TO, verify=False, allow_redirects=False,
                            headers={"User-Agent":"VulnusLab/1.0"})
    except Exception: return None

def _probe(url):
    r = _get(url)
    if not r: return None
    if r.status_code in (404, 0, 503, 502): return None
    return {"url": url, "status": r.status_code,
            "server": r.headers.get("Server","")[:40]}

async def gather(ctx: ScanContext):
    org = (ctx.host or "").split(".")[0]
    if not org:
        ctx.state["target_reachable"] = False; return
    ctx.state["target_reachable"] = True
    patterns = _load()
    urls = set()
    for p in patterns:
        u = p.replace("{org}", org).replace("{region}","us-central1")
        if not u.startswith("http"): u = "https://" + u
        urls.add(u)
    urls = list(urls)
    ctx.state["probed"] = len(urls)
    ctx.source(f"patterns ({len(urls)})")
    sem = asyncio.Semaphore(_CONC)
    async def one(u):
        async with sem: return await asyncio.to_thread(_probe, u)
    results = await asyncio.gather(*[one(u) for u in urls])
    hits = [h for h in results if h]
    ctx.state["hits"] = hits
    ctx.state["hits_count"] = len(hits)
    if hits: ctx.source(f"cloud-fns ({len(hits)})")

def r_exposed(s):
    h = s.get("hits") or []
    if not h: return None
    return {"name": f"Cloud function URL(s) responsive ({len(h)})",
            "severity": "MEDIUM", "cvss": 5.0, "cwe": "CWE-200",
            "cwe_name": "Information Exposure",
            "owasp": "A05:2021 — Security Misconfiguration",
            "evidence": "; ".join(f"{h2['url']} ({h2['status']}, {h2['server']})" for h2 in h[:5]),
            "remediation": "Audit each cloud function URL — verify it requires auth and isn't an info leak. Restrict to known clients via IAM / API Gateway."}

def r_clean(s):
    if not s.get("target_reachable"): return None
    if s.get("hits"): return None
    return {"name":"No cloud function URLs found","severity":"POSITIVE",
            "evidence":f"Probed {s.get('probed',0)} AWS/GCF/Azure/Netlify/Vercel patterns."}

def r_unreach(s):
    if s.get("target_reachable"): return None
    return {"name":"Target name unparseable","severity":"INFO","evidence":"Could not derive org slug"}

FINDING_RULES = [r_exposed, r_clean, r_unreach]
INTEL_FIELDS = [("Target reachable","target_reachable"),("Patterns probed","probed"),
                ("Functions found","hits_count")]

@router.post("/api/recon/cloud_function_brute")
async def recon_cloud_function_brute(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="cloud_function_brute",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["hits"])

def register(app): app.include_router(router)
