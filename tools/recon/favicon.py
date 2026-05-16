"""recon_favicon -- isolated tool (Kali-style architecture).

Route: /api/recon/favicon
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

def _murmur3_32(data, seed=0):
    """Pure-Python MurmurHash3 32-bit (Shodan favicon hash format)."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed
    rounded_end = (length // 4) * 4
    for i in range(0, rounded_end, 4):
        k1 = (data[i] & 0xff) | ((data[i+1] & 0xff) << 8) | ((data[i+2] & 0xff) << 16) | (data[i+3] << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = (((k1 << 15) | (k1 >> 17)) * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 3
    if tail >= 3: k1 = (data[rounded_end + 2] & 0xff) << 16
    if tail >= 2: k1 |= (data[rounded_end + 1] & 0xff) << 8
    if tail >= 1:
        k1 |= (data[rounded_end] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = (((k1 << 15) | (k1 >> 17)) * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    if h1 >= 0x80000000:
        h1 = -(0x100000000 - h1)
    return h1

@router.post("/api/recon/favicon")
async def recon_favicon(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(f"{base}/favicon.ico", req=req)
    if r is None or r.status_code != 200 or not r.content:
        return {"ok": True, "favicon": None, "skipped_reason": "No favicon found at /favicon.ico"}
    import base64 as _b64
    b64_content = _b64.encodebytes(r.content)
    shodan_hash = _murmur3_32(b64_content)
    return {"ok": True,
            "found": True,
            "favicon": {
                "md5": hashlib.md5(r.content).hexdigest(),
                "shodan_hash": shodan_hash,
                "shodan_query": f"http.favicon.hash:{shodan_hash}",
                "size": len(r.content),
            }}


def register(app):
    app.include_router(router)
