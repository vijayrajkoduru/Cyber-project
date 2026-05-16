"""recon_crtsh -- isolated tool (Kali-style architecture).

Route: /api/recon/crtsh
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

@router.post("/api/recon/crtsh")
async def recon_crtsh(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{host}&output=json",
            timeout=20,
            headers={"User-Agent": "VulnusLab/1.0"},
        )
        if r.status_code != 200:
            return {"ok": False, "subdomains": [],
                    "skipped_reason": f"crt.sh returned {r.status_code}"}
        data = r.json()
    except Exception as e:
        return {"ok": False, "subdomains": [],
                "skipped_reason": f"crt.sh query failed: {e}"}

    subs = set()
    for entry in data:
        for line in str(entry.get("name_value", "")).split("\n"):
            line = line.strip().lower().lstrip("*.")
            if line and line.endswith(host):
                subs.add(line)
    return {"ok": True, "subdomains": sorted(subs)}


def register(app):
    app.include_router(router)
