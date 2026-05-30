"""HTTP/2 enabled -> Rapid Reset (CVE-2023-44487) advisory. VL-FORGE Vuln tier6 - §6 #91."""
import asyncio
import socket
import ssl
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


def _alpn(host, timeout=6):
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        c.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        return None
    try:
        with socket.create_connection((host, 443), timeout=timeout) as s:
            with c.wrap_socket(s, server_hostname=host) as ss:
                return ss.selected_alpn_protocol()
    except Exception:
        return None


async def gather(ctx):
    proto = await asyncio.to_thread(_alpn, str(ctx.host))
    if proto is None:
        ctx.state["tested"] = 0
        return
    ctx.source("tls-alpn")
    ctx.state["tested"] = 1
    ctx.state["alpn"] = proto


def _r_h2(s):
    if s.get("alpn") != "h2":
        return None
    return {"name": "HTTP/2 enabled - verify Rapid Reset patch (CVE-2023-44487)", "severity": "LOW", "cvss": 3.7,
            "cwe": "CWE-400", "evidence": "ALPN negotiated h2; Rapid Reset DoS affects unpatched HTTP/2 stacks",
            "remediation": "Ensure server/CDN patched for CVE-2023-44487 (nginx>=1.25.3; most CDNs auto-mitigated)."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("alpn") == "h2":
        return None
    return {"name": "HTTP/2 not negotiated", "severity": "POSITIVE", "evidence": f"ALPN: {s.get('alpn') or 'http/1.1'}"}


FINDING_RULES = [_r_h2, _r_clean]
INTEL_FIELDS = [("ALPN protocol", "alpn")]


@router.post("/api/vuln/http2_rapid_reset")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="http2_rapid_reset",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
