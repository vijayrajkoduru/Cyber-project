"""helm_etcd_exposed — VL-FORGE Recon (real, zero-FP).

ZERO-FP-V1 (2026-06-06): port-open alone is NOT proof of helm/etcd.
Previously this scanner reported HIGH on any Cloudflare-fronted target
because Cloudflare's edge proxies port 8080 with a generic 200 response.
Now requires PROTOCOL-SPECIFIC RESPONSE for each port:

  etcd 2379  ->  GET /version returns JSON with 'etcdserver' key
  Tiller 44134 ->  responds to gRPC magic bytes (HTTP/2 preface)
  Helm 8080  ->  body contains 'Helm' or '/api/charts' returns JSON

If no protocol match, the open port is NOT counted as helm/etcd exposure.
"""
import asyncio, json, socket
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch


router = APIRouter()


async def _verify_etcd(host: str, port: int) -> dict | None:
    """etcd v3 publishes /version; v2 publishes /v2/keys. Real etcd returns
    JSON with 'etcdserver' or 'etcdcluster' keys."""
    for path in ("/version", "/v2/keys"):
        code, _, body = await fetch(f"http://{host}:{port}{path}", timeout=4)
        if code in (200, 401, 403) and body:
            try:
                text = body.decode("utf-8", "ignore")
                if "etcdserver" in text or "etcdcluster" in text or text.strip().startswith("{"):
                    if "etcd" in text.lower():
                        return {"path": path, "evidence": text[:200]}
            except Exception:
                pass
    return None


async def _verify_helm(host: str, port: int) -> dict | None:
    """Helm chart-repo / controller responds with chart index or has 'helm'
    in body. A generic Cloudflare 200 on port 8080 will NOT contain 'helm'."""
    code, _, body = await fetch(f"http://{host}:{port}/", timeout=4)
    if code not in (200, 401, 403) or not body:
        return None
    text = body.decode("utf-8", "ignore").lower()
    # Helm chart repo has index.yaml; Tiller has gRPC. Look for unambiguous markers.
    helm_markers = ("helm chart", "tiller", "helm.sh", "chartmuseum",
                    "x-helm-version", '"apiversion":"v2"')
    if any(m in text for m in helm_markers):
        return {"path": "/", "evidence": text[:200]}
    # Also check the chart index path
    code2, _, body2 = await fetch(f"http://{host}:{port}/index.yaml", timeout=4)
    if code2 == 200 and body2:
        t2 = body2.decode("utf-8", "ignore")
        if "apiVersion" in t2 and "entries" in t2:
            return {"path": "/index.yaml", "evidence": t2[:200]}
    return None


async def _verify_tiller(host: str, port: int) -> dict | None:
    """Tiller (Helm 2) speaks gRPC over HTTP/2. Probing for the HTTP/2
    preface is the safest signal short of actually doing gRPC handshake."""
    # gRPC servers respond to HTTP/2 client preface with HTTP/2 SETTINGS frame.
    # A plain TCP probe is the closest non-disruptive signal.
    def _probe():
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.settimeout(2)
            # Send HTTP/2 connection preface
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            data = s.recv(64)
            s.close()
            # HTTP/2 SETTINGS frame starts with length-3-byte + type=0x04
            if data and len(data) >= 9 and data[3] == 0x04:
                return {"path": "TCP/gRPC preface", "evidence": "HTTP/2 SETTINGS frame received"}
        except Exception:
            pass
        return None
    return await asyncio.to_thread(_probe)


_VERIFIERS = {
    2379:  ("etcd-client",     _verify_etcd),
    44134: ("tiller (Helm 2)", _verify_tiller),
    8080:  ("helm-controller", _verify_helm),
}


async def gather(ctx: ScanContext):
    h = ctx.host.replace("http://","").replace("https://","").split("/")[0].split(":")[0]
    ctx.state["host_probed"] = h
    verified = []
    port_open_only = []
    for port, (svc, verifier) in _VERIFIERS.items():
        # Step 1: is port open at all?
        def _probe(p=port):
            try:
                with socket.create_connection((h, p), timeout=3):
                    return True
            except Exception:
                return False
        if not await asyncio.to_thread(_probe):
            continue
        # Step 2: ZERO-FP-V1 gate - verify protocol response, not just open port.
        proof = await verifier(h, port)
        if proof:
            verified.append({"port": port, "service": svc, "proof": proof})
        else:
            port_open_only.append({"port": port, "service": svc,
                                    "note": "TCP open but no protocol-level confirmation - likely CDN edge or unrelated service"})
    ctx.state["exposed"] = verified
    ctx.state["port_open_no_proof"] = port_open_only
    ctx.source("Helm/etcd protocol-verified probes")


RULES = [
    # Only HIGH when protocol-verified. Bare open ports go to INFO-only
    # intel below, not HIGH findings.
    lambda s: {"name":"etcd/Tiller/Helm controller exposed (protocol-verified)","severity":"HIGH",
        "evidence":f"Verified: {s.get('exposed')}",
        "remediation":"etcd 2379 must be private + mTLS only. Tiller (Helm 2) is EOL — upgrade to Helm 3. Helm controller (8080) must require auth.",
        "cwe":"CWE-306","owasp":"A05:2021"
    } if s.get("exposed") else None,
]


@router.post("/api/recon/helm_etcd_exposed")
async def recon_helm_etcd_exposed(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="helm_etcd_exposed",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Verified exposed","exposed"),
                                            ("Port open no proof","port_open_no_proof")])


def register(app):
    app.include_router(router)
