"""recon_shodan -- isolated tool (Kali-style architecture).

Route: /api/recon/shodan
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

@router.post("/api/recon/shodan")
async def recon_shodan(req: ScanRequest, _=Depends(verify_scan_quota)):
    api_key = getattr(req, "api_key", "") or ""
    if not api_key:
        return {"ok": False, "skipped_reason": "No Shodan API key configured — set in Settings"}
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}"}
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=15)
        if r.status_code != 200:
            return {"ok": False, "skipped_reason": f"Shodan API returned {r.status_code}"}
        d = r.json()
        return {
            "ok": True, "ip": d.get("ip_str", ip), "org": d.get("org"),
            "isp": d.get("isp"), "country": d.get("country_name"),
            "city": d.get("city"), "os": d.get("os"),
            "ports": d.get("ports", []),
        }
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Shodan query failed: {e}"}


def register(app):
    app.include_router(router)
