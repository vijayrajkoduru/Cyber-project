"""recon_robotsmap -- isolated tool (Kali-style architecture).

Route: /api/recon/robotsmap
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

@router.post("/api/recon/robotsmap")
async def recon_robotsmap_impl(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    disallow, sitemaps, well_known = [], [], []
    r = safe_get(f"{base}/robots.txt", req=req)
    if r is not None and r.status_code == 200:
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                p = line.split(":", 1)[1].strip()
                if p:
                    disallow.append(p)
            elif line.lower().startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
    if not sitemaps:
        rs = safe_get(f"{base}/sitemap.xml", req=req)
        if rs is not None and rs.status_code == 200:
            sitemaps.append(f"{base}/sitemap.xml")
    sec = safe_get(f"{base}/.well-known/security.txt", req=req)
    if sec is not None and sec.status_code == 200:
        well_known.append("/.well-known/security.txt")
    return {"ok": True, "disallow": disallow, "sitemaps": sitemaps, "well_known": well_known}



# VLERR-WRAP-V1
@router.post("/api/recon/robotsmap")
async def recon_robotsmap(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await recon_robotsmap_impl(req, _)
    except Exception as _e:
        return {"ok": False,
                 "skipped_reason": f"robotsmap scanner failed: {type(_e).__name__}: {str(_e)[:200]}",
                 "error": str(_e)[:300]}

def register(app):
    app.include_router(router)
