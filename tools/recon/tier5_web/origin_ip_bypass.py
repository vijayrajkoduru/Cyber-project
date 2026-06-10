"""origin_ip_bypass — VL-FORGE Recon §5 Web App Recon (real, zero-FP).

VL-VERIFY (zero-FP): the previous version listed every MX server IP as an
"origin candidate" - but MX servers are mail infrastructure, not web origins.
On vulnuslab.com (web=Netlify, MX=Cloudflare) it falsely surfaced Cloudflare
MX IPs as web origin bypass targets.

Two fixes:
  1. Only report cdn_ip when a CDN was actually detected on the resolved IP
     (don't label a bare A-record IP - e.g. a Netlify direct IP - as 'CDN IP').
  2. Don't auto-trust MX IPs as origin candidates. Instead, do an HTTP probe
     against each MX IP with the target Host header. Only flag as a real
     origin candidate when the MX IP actually serves the target's homepage
     (status 200 + Host-header echoed) - that's the only case a CDN bypass
     is genuinely possible.
"""
import asyncio, re, socket, ssl
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url

router = APIRouter()

# Known CDN edge ranges - tightened so we only call it "CDN IP" when it actually IS one.
_CDN_HINTS = (
    "cloudflare", "akamai", "fastly", "incapsula", "stackpath",
    "cloudfront", "amazon-cloudfront", "azurefd", "googleusercontent",
)


def _probe_host(ip: str, host: str, timeout: float = 4.0) -> bool:
    """Open a plain HTTP socket to ip, send Host: host, return True if the
    response looks like the target's site (status 200 OR redirect to host)."""
    try:
        sslctx = ssl.create_default_context()
        sslctx.check_hostname = False
        sslctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
            with sslctx.wrap_socket(raw, server_hostname=host) as s:
                s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: VulnusLab/1.0\r\n\r\n".encode())
                data = b""
                while len(data) < 4000:
                    try:
                        chunk = s.recv(2000)
                        if not chunk: break
                        data += chunk
                    except Exception: break
                txt = data.decode("utf-8", errors="ignore").lower()
                if not txt: return False
                # Real-origin signals: 200 OK + the host echoed back somewhere,
                # OR a redirect that points at the public hostname.
                if "200 ok" in txt[:200] and host.lower() in txt:
                    return True
                if any(("location: " in txt[:600]) and host.lower() in txt for _ in [0]):
                    return True
        return False
    except Exception:
        return False


async def gather(ctx: ScanContext):
    h = ctx.host.replace("http://","").replace("https://","").split("/")[0]
    try:
        public_ip = await asyncio.to_thread(socket.gethostbyname, h)
    except Exception:
        public_ip = ""
    # Reverse-DNS the public IP to decide if it's actually a CDN
    cdn_label = ""
    if public_ip:
        try:
            ptr = await asyncio.to_thread(socket.gethostbyaddr, public_ip)
            ptr_str = " ".join(ptr).lower() if ptr else ""
            for hint in _CDN_HINTS:
                if hint in ptr_str:
                    cdn_label = hint.capitalize()
                    break
        except Exception:
            pass
    ctx.state["public_ip"] = public_ip
    ctx.state["cdn_detected"] = bool(cdn_label)
    ctx.state["cdn_label"] = cdn_label
    # Only flag MX IPs as origin candidates if they actually serve the
    # target's website - validates instead of guessing.
    candidates = []
    try:
        import dns.resolver
        mx = await asyncio.to_thread(dns.resolver.resolve, h, "MX", lifetime=4)
        for m in mx:
            mx_host = str(m).split()[-1].rstrip(".")
            try:
                ip = await asyncio.to_thread(socket.gethostbyname, mx_host)
            except Exception:
                continue
            if ip == public_ip:
                continue  # same IP as public - no bypass
            # Validate: does this MX IP actually host the target's website?
            serves_target = await asyncio.to_thread(_probe_host, ip, h)
            if serves_target:
                candidates.append({"src": "MX", "host": mx_host, "ip": ip,
                                     "verified": True})
    except Exception:
        pass
    ctx.state["origin_candidates"] = candidates
    if candidates:
        ctx.source(f"VERIFIED origin via MX ({len(candidates)})")
    elif cdn_label:
        ctx.source(f"CDN={cdn_label} no verified origin bypass")
    else:
        ctx.source("no CDN detected, no bypass candidates")

RULES = [

]

@router.post("/api/recon/origin_ip_bypass")
async def recon_origin_ip_bypass(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="origin_ip_bypass",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Public IP","public_ip"),
                                              ("CDN detected","cdn_detected"),
                                              ("CDN label","cdn_label"),
                                              ("Verified origin candidates","origin_candidates")])

def register(app):
    app.include_router(router)
