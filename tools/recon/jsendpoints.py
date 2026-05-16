"""recon_jsendpoints -- isolated tool (Kali-style architecture).

Route: /api/recon/jsendpoints
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

@router.post("/api/recon/jsendpoints")
async def recon_jsendpoints(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req, allow_redirects=True)
    if r is None:
        return {"ok": False, "endpoints": [], "skipped_reason": f"Could not reach {base}"}
    js_urls = re.findall(r'src=["\']([^"\']+\.js)', r.text)
    endpoints = set()
    for js_url in js_urls[:5]:
        full = js_url if js_url.startswith("http") else f"{base}/{js_url.lstrip('/')}"
        rjs = safe_get(full, req=req)
        if rjs is None:
            continue
        for m in re.findall(r'["\']/(api/[a-zA-Z0-9_/.-]+)', rjs.text):
            endpoints.add("/" + m)
    return {"ok": True, "endpoints": sorted(endpoints), "js_files": len(js_urls)}


def register(app):
    app.include_router(router)
