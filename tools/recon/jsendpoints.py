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

async def recon_jsendpoints_impl(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req, allow_redirects=True)
    if r is None:
        return {"ok": False, "paths": [], "discovered": [], "js_files": [],
                "skipped_reason": f"Could not reach {base}"}

    # Pull every <script src="..."> off the page. Resolve relative paths
    # against the base so a SPA-style "/static/js/main.abc.js" still loads.
    raw_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
    js_files = []
    for src in raw_srcs:
        if src.lower().endswith(".js") or ".js?" in src.lower():
            full = src if src.startswith("http") else f"{base}/{src.lstrip('/')}"
            if full not in js_files:
                js_files.append(full)

    # Internal paths (start with "/") used for downstream WebApp scanners.
    paths = set()
    # All discovered URLs incl. external ones — useful for SSRF allow-listing,
    # 3rd-party SDK enumeration, and overall attack surface.
    discovered = set()

    # Regex for any URL/path inside a JS string literal. Two flavours:
    #   "/api/v1/users"     → internal API path
    #   "https://x.com/..." → external URL referenced from JS
    PATH_RE = re.compile(r'["\'](/[a-zA-Z0-9_\-./?=&%]{2,200})["\']')
    URL_RE  = re.compile(r'["\'](https?://[^"\'\s<>]{4,250})["\']')

    for js_url in js_files[:8]:
        rjs = safe_get(js_url, req=req)
        if rjs is None:
            continue
        for m in PATH_RE.findall(rjs.text):
            if any(m.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif",
                                               ".svg", ".woff", ".woff2", ".ttf",
                                               ".css", ".map", ".ico")):
                continue
            paths.add(m)
            discovered.add(m)
        for u in URL_RE.findall(rjs.text):
            discovered.add(u)

    return {
        "ok":         True,
        "paths":      sorted(paths),
        "discovered": sorted(discovered),
        "js_files":   js_files,
        "engine":     "pure-Python (regex extraction across <script src> tags)",
    }


# VLERR-WRAP-V1
@router.post("/api/recon/jsendpoints")
async def recon_jsendpoints(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await recon_jsendpoints_impl(req, _)
    except Exception as _e:
        return {"ok": False, "paths": [], "discovered": [], "js_files": [],
                "skipped_reason": f"jsendpoints scanner failed: {type(_e).__name__}: {str(_e)[:200]}",
                "error": str(_e)[:300]}


def register(app):
    app.include_router(router)
