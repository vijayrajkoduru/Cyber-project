"""HTTP/2 enabled -> Rapid Reset (CVE-2023-44487) advisory. VL-FORGE Vuln tier6 - §6 #91.

VL-VERIFY (zero-FP): the bare 'HTTP/2 is enabled, verify your patch' finding
fires on every HTTPS site that supports h2. That includes Google (who
DISCOVERED and patched CVE-2023-44487 before public disclosure), Cloudflare,
AWS CloudFront, etc. Calling Google 'needs to verify the patch' is absurd.
Fix: identify the edge-server provider from the TLS peer certificate's
issuer / SNI hostname / Server header; suppress the finding when it is a
known-patched major CDN/cloud.
"""
import asyncio
import socket
import ssl
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


# Provider -> patched-since description. Each of these auto-mitigated
# CVE-2023-44487 well before public disclosure.
_KNOWN_PATCHED_PROVIDERS = {
    "cloudflare":      "Cloudflare (auto-mitigated 2023-08)",
    "google":          "Google (disclosed + patched 2023-08, was the discoverer)",
    "gws":             "Google Web Server (GWS - patched at disclosure)",
    "amazon":          "AWS CloudFront / ALB (auto-mitigated 2023-10)",
    "cloudfront":      "AWS CloudFront (auto-mitigated 2023-10)",
    "akamai":          "Akamai (auto-mitigated 2023-10)",
    "fastly":          "Fastly (auto-mitigated 2023-10)",
    "azureedge":       "Azure Front Door (auto-mitigated 2023-10)",
    "azurefd":         "Azure Front Door (auto-mitigated 2023-10)",
    "microsoft":       "Microsoft edge (patched at disclosure)",
    "netlify":         "Netlify (uses managed nginx/H2, auto-mitigated)",
    "vercel":          "Vercel (uses managed edge, auto-mitigated)",
}


def _alpn_and_cert(host, timeout=6):
    """Return (alpn_proto, server_cert_issuer_lower, server_header_lower)."""
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        c.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        return None, "", ""
    try:
        with socket.create_connection((host, 443), timeout=timeout) as s:
            with c.wrap_socket(s, server_hostname=host) as ss:
                alpn = ss.selected_alpn_protocol()
                # Grab cert issuer (in plain form is a tuple of tuples)
                issuer_str = ""
                try:
                    cert = ss.getpeercert()
                    issuer = cert.get("issuer", ()) if cert else ()
                    issuer_str = " ".join(
                        v for tup in issuer for k, v in tup if isinstance(v, str)
                    ).lower()
                except Exception:
                    pass
                # Send a tiny GET to grab the Server header
                server_hdr = ""
                try:
                    ss.send(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    data = ss.recv(2000).decode("utf-8", "ignore")
                    for line in data.split("\r\n"):
                        if line.lower().startswith("server:"):
                            server_hdr = line[7:].strip().lower()
                            break
                except Exception:
                    pass
                return alpn, issuer_str, server_hdr
    except Exception:
        return None, "", ""


async def gather(ctx):
    proto, issuer, server = await asyncio.to_thread(_alpn_and_cert, str(ctx.host))
    if proto is None:
        ctx.state["tested"] = 0
        return
    ctx.source("tls-alpn")
    ctx.state["tested"] = 1
    ctx.state["alpn"] = proto
    ctx.state["cert_issuer"] = issuer[:200]
    ctx.state["server_header"] = server[:80]
    # Provider fingerprint
    blob = f"{issuer} {server}".lower()
    patched_label = next((label for key, label in _KNOWN_PATCHED_PROVIDERS.items()
                           if key in blob), None)
    ctx.state["patched_provider"] = patched_label


def _r_h2(s):
    if s.get("alpn") != "h2":
        return None
    patched = s.get("patched_provider")
    if patched:
        # Known-patched provider - downgrade to POSITIVE info, not LOW.
        return {"name": f"HTTP/2 enabled on known-patched edge: {patched}",
                "severity": "POSITIVE",
                "evidence": f"CVE-2023-44487 (Rapid Reset) was auto-mitigated by this provider. "
                             f"Cert issuer: {(s.get('cert_issuer') or '')[:80]}; "
                             f"Server header: {(s.get('server_header') or '')[:60]}"}
    # Unknown provider - keep the verify-your-patch advisory
    return {"name": "HTTP/2 enabled - verify Rapid Reset patch (CVE-2023-44487)", "severity": "LOW", "cvss": 3.7,
            "cwe": "CWE-400",
            "evidence": ("ALPN negotiated h2; Rapid Reset DoS affects unpatched HTTP/2 stacks. "
                          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L EPSS: 94.5% CISA KEV: yes"),
            "remediation": "Ensure server/CDN patched for CVE-2023-44487 (nginx>=1.25.3; most CDNs auto-mitigated)."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("alpn") == "h2":
        return None
    return {"name": "HTTP/2 not negotiated", "severity": "POSITIVE", "evidence": f"ALPN: {s.get('alpn') or 'http/1.1'}"}


FINDING_RULES = [_r_h2, _r_clean]
INTEL_FIELDS = [("ALPN protocol", "alpn")]


@router.post("/api/vuln/http2_rapid_reset")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="http2_rapid_reset",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
