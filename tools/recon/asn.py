"""recon_asn -- isolated tool (Kali-style architecture).

Route: /api/recon/asn
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

@router.post("/api/recon/asn")
async def recon_asn(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}: {e}"}
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if r.status_code != 200:
            return {"ok": False, "skipped_reason": f"ipinfo returned {r.status_code}"}
        d = r.json()
        return {"ok": True, "ip": ip, "asn": d.get("org", ""),
                "country": d.get("country"), "city": d.get("city"),
                "region": d.get("region"), "hostname": d.get("hostname")}
    except Exception as e:
        return {"ok": False, "skipped_reason": f"ASN lookup failed: {e}"}


def register(app):
    app.include_router(router)
