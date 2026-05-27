"""ssl_tls_audit — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import ssl, socket

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host.replace("http://","").replace("https://","").split("/")[0]
    if ":" in h: h, port = h.split(":")[0], int(h.split(":")[1])
    else: port = 443
    def _probe():
        try:
            ctxt = ssl.create_default_context()
            ctxt.check_hostname = False; ctxt.verify_mode = ssl.CERT_NONE
            with socket.create_connection((h, port), timeout=6) as sock:
                with ctxt.wrap_socket(sock, server_hostname=h) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    return {
                        "version": ssock.version(),
                        "cipher": list(ssock.cipher() or []),
                        "issuer": dict(x[0] for x in cert.get("issuer",[])) if cert else {},
                        "subject": dict(x[0] for x in cert.get("subject",[])) if cert else {},
                        "notAfter": cert.get("notAfter",""),
                        "san": [v for k,v in cert.get("subjectAltName",[])][:10],
                    }
        except Exception as e:
            return {"error": str(e)[:120]}
    res = await asyncio.to_thread(_probe)
    ctx.state.update(res)
    ctx.state["weak_protocol"] = res.get("version","") in ("TLSv1","TLSv1.1","SSLv3","SSLv2")
    ctx.source("TLS handshake + cert chain probe")

RULES = [
    lambda s: {"name":f"Weak TLS protocol: {s.get('version')}","severity":"HIGH",
        "evidence":f"Server negotiated {s.get('version')} — deprecated, vulnerable to BEAST/POODLE",
        "remediation":"Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2+ minimum",
        "cwe":"CWE-326","owasp":"A02:2021"
    } if s.get("weak_protocol") else None,
]

@router.post("/api/recon/ssl_tls_audit")
async def recon_ssl_tls_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="ssl_tls_audit",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Version","version"),("Cipher","cipher"),("Issuer","issuer"),("Subject","subject"),("Notafter","notAfter"),("SAN","san")])

def register(app):
    app.include_router(router)
