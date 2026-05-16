"""recon_dnsrecon -- isolated tool (Kali-style architecture).

Route: /api/recon/dnsrecon
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

@router.post("/api/recon/dnsrecon")
async def recon_dnsrecon(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    records = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5
            ans = resolver.resolve(host, rtype)
            for r in ans:
                records.append({"type": rtype, "name": host, "address": r.to_text()})
        except Exception:
            pass
    return {"ok": True, "records": records}


def register(app):
    app.include_router(router)
