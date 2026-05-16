"""recon_internetdb -- isolated tool (Kali-style architecture).

Route: /api/recon/internetdb
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

@router.post("/api/recon/internetdb")
async def recon_internetdb(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}: {e}"}
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if r.status_code == 404:
            return {"ok": True, "ip": ip, "skipped_reason": "No InternetDB record for this IP"}
        if r.status_code != 200:
            return {"ok": False, "skipped_reason": f"InternetDB returned {r.status_code}"}
        d = r.json()
        return {"ok": True, "ip": ip,
                "ports": d.get("ports", []), "cves": d.get("vulns", []),
                "hostnames": d.get("hostnames", []), "tags": d.get("tags", [])}
    except Exception as e:
        return {"ok": False, "skipped_reason": f"InternetDB query failed: {e}"}


def register(app):
    app.include_router(router)
