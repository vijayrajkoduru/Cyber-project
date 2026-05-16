"""recon_os -- isolated tool (Kali-style architecture).

Route: /api/recon/os
Split from recon_module.py monolith by scripts/split_recon_module.py.
Failure here is quarantined by the healing autoloader -- other tools unaffected.
"""

import asyncio
import base64
import datetime
import hashlib
import re
import socket
from typing import Optional
import requests
import dns.resolver
import dns.asyncresolver
import whois as whois_lib
from fastapi import APIRouter, Depends
from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host, safe_get, web_url,
)
import aiohttp as _aiohttp_crawl
import ssl as _ssl_mod

from fastapi import APIRouter, Depends

router = APIRouter()

@router.post("/api/recon/os")
async def recon_os(req: ScanRequest, _=Depends(verify_scan_quota)):
    """Passive OS fingerprint via ICMP ping TTL.

    Initial TTL values are OS-typical:
      64  -> Linux/Unix/macOS/Android
      128 -> Windows
      255 -> Cisco IOS / older Solaris / BSD variants
    """
    import subprocess
    import re as _re
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}: {e}"}
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            capture_output=True, timeout=5,
        )
        out = (r.stdout or b"").decode("utf-8", errors="ignore") + (r.stderr or b"").decode("utf-8", errors="ignore")
        m = _re.search(r"ttl[=\s]+(\d+)", out, _re.I)
        if not m:
            return {"ok": True, "ip": ip, "os": None,
                    "skipped_reason": "Could not parse TTL from ping output (ICMP may be blocked / no ping binary)"}
        ttl = int(m.group(1))
        if 33 <= ttl <= 64:
            os_guess, confidence = "Linux / Unix / macOS / Android (initial TTL 64)", "high"
        elif 65 <= ttl <= 128:
            os_guess, confidence = "Windows (initial TTL 128)", "high"
        elif 129 <= ttl <= 255:
            os_guess, confidence = "Cisco IOS / older Solaris / BSD (initial TTL 255)", "medium"
        elif ttl <= 32:
            os_guess, confidence = "Linux / Unix (TTL 64 with many hops)", "low"
        else:
            os_guess, confidence = "Unknown", "none"
        return {
            "ok": True,
            "ip": ip,
            "ttl_observed": ttl,
            "os": os_guess,
            "confidence": confidence,
            "method": "passive TTL fingerprint via ICMP ping",
            "engine": "pure-Python (subprocess ping + TTL bucket analysis)",
        }
    except Exception as e:
        return {"ok": False, "ip": ip,
                "skipped_reason": f"ping failed: {e} (ICMP may be blocked or no ping binary in container)"}


def register(app):
    app.include_router(router)
