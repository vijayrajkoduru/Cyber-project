"""k8s_api_exposure — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import socket

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host.replace("http://","").replace("https://","").split("/")[0].split(":")[0]
    exposed = []
    for port, label in [(6443,"kube-apiserver"),(10250,"kubelet"),(2379,"etcd-client"),(2380,"etcd-peer")]:
        def _probe(p=port):
            try:
                with socket.create_connection((h, p), timeout=3): return True
            except Exception: return False
        if await asyncio.to_thread(_probe):
            # Confirm with HTTP probe
            c, _, b = await fetch(f"https://{h}:{port}/healthz", timeout=4)
            if c == 200 and b"ok" in b.lower(): exposed.append({"port":port,"service":label,"healthz":True})
            elif c: exposed.append({"port":port,"service":label,"healthz":False,"status":c})
    ctx.state["exposed_endpoints"] = exposed
    ctx.source("Kubernetes control-plane port probe")

RULES = [
    lambda s: {"name":"Kubernetes Control Plane Exposed to Internet","severity":"HIGH",
        "evidence":f"K8s ports reachable: {s.get('exposed_endpoints')}",
        "remediation":"Restrict 6443/10250/2379 to private network. Use VPN/bastion for kubectl. Audit with kube-bench.",
        "cwe":"CWE-668","owasp":"A05:2021"
    } if s.get("exposed_endpoints") else None,
]

@router.post("/api/recon/k8s_api_exposure")
async def recon_k8s_api_exposure(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="k8s_api_exposure",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Exposed Endpoints","exposed_endpoints")])

def register(app):
    app.include_router(router)
