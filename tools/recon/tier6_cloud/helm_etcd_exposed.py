"""helm_etcd_exposed — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import socket

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host.replace("http://","").replace("https://","").split("/")[0].split(":")[0]
    findings = []
    for port, svc in [(2379,"etcd-client"),(44134,"tiller (Helm 2)"),(8080,"helm-controller")]:
        def _probe(p=port):
            try:
                with socket.create_connection((h, p), timeout=3): return True
            except Exception: return False
        if await asyncio.to_thread(_probe):
            findings.append({"port":port,"service":svc})
    ctx.state["exposed"] = findings
    ctx.source("Helm/etcd default port probes")

RULES = [
    lambda s: {"name":"etcd/Tiller Exposed to Internet","severity":"HIGH",
        "evidence":f"Reachable: {s.get('exposed')}",
        "remediation":"etcd 2379 must be private + mTLS only. Tiller (Helm 2) is EOL — upgrade to Helm 3.",
        "cwe":"CWE-306","owasp":"A05:2021"
    } if s.get("exposed") else None,
]

@router.post("/api/recon/helm_etcd_exposed")
async def recon_helm_etcd_exposed(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="helm_etcd_exposed",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Exposed","exposed")])

def register(app):
    app.include_router(router)
