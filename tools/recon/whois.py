"""recon_whois -- isolated tool (Kali-style architecture).

Route: /api/recon/whois
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

@router.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        w = whois_lib.whois(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"WHOIS query failed: {e}"}

    def _first(v):
        return v[0] if isinstance(v, list) and v else v

    def _iso(d):
        d = _first(d)
        if isinstance(d, datetime.datetime):
            return d.isoformat()
        return str(d) if d else None

    return {
        "ok": True,
        "domain": host,
        "registrar": _first(w.registrar),
        "created": _iso(w.creation_date),
        "expires": _iso(w.expiration_date),
        "updated": _iso(w.updated_date),
        "name_servers": sorted({str(n).lower() for n in (w.name_servers or [])}),
        "registrant": _first(w.registrant_name) or _first(w.org),
        "country": _first(w.country),
    }


def register(app):
    app.include_router(router)
