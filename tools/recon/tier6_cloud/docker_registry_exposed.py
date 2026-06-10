"""docker_registry_exposed — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import socket

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host.replace("http://","").replace("https://","").split("/")[0].split(":")[0]
    exposed = False; repos = []
    def _probe():
        try:
            with socket.create_connection((h, 5000), timeout=3): return True
        except Exception: return False
    if await asyncio.to_thread(_probe):
        for scheme in ("https","http"):
            c, _, b = await fetch(f"{scheme}://{h}:5000/v2/_catalog", timeout=4)
            if c == 200 and b"repositories" in b:
                exposed = True
                import json
                try: repos = json.loads(b.decode("utf-8","ignore")).get("repositories",[])[:10]
                except: pass
                break
    ctx.state["registry_exposed"] = exposed
    ctx.state["repositories"] = repos
    ctx.source("Docker Registry v2 catalog probe on port 5000")

RULES = [
    lambda s: {"name":"Docker Registry Anonymous Access — repositories listable","severity":"HIGH",
        "evidence":f"Unauthenticated /v2/_catalog returned: {s.get('repositories')}",
        "remediation":"Enable auth (REGISTRY_AUTH=htpasswd or token), restrict to private network",
        "cwe":"CWE-306","owasp":"A07:2021"
    } if s.get("registry_exposed") else None,
]

@router.post("/api/recon/docker_registry_exposed")
async def recon_docker_registry_exposed(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="docker_registry_exposed",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Registry Exposed","registry_exposed"),("Repositories","repositories")])

def register(app):
    app.include_router(router)
