"""recon_params -- isolated tool (Kali-style architecture).

Route: /api/recon/params
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

_COMMON_PARAMS = [
    "id","user","username","page","query","search","q","url","redirect","return","next","filename",
    "file","path","name","email","type","category","action","method","token","key","api_key","auth",
    "session","sid","lang","locale","language","country","region","format","view","tab","sort","order",
    "limit","offset","start","end","from","to","since","until","date","callback","jsonp","output","debug",
    "test","admin","cmd","command","exec","system","data","value","param","arg","input","content",
    "title","message","comment","body","subject","ref","source","src","dest","destination",
]

@router.post("/api/recon/params")
async def recon_params(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req)
    if r is None:
        return {"ok": False, "params": [], "skipped_reason": f"Could not reach {base}"}

    # Step 1 — regex extract from HTML (passive, fast)
    params = set()
    sources = {"query": 0, "form": 0, "js": 0, "reflected": 0}
    for m in re.findall(r'<input[^>]+name=["\']([^"\']+)', r.text or "", re.I):
        if m not in params:
            params.add(m); sources["form"] += 1
    for m in re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{0,30})=', r.text or ""):
        if m not in params:
            params.add(m); sources["query"] += 1

    # Step 2 — Arjun-style reflection probe (active, slower)
    # Inject each common param with a unique canary, look for reflection.
    import uuid
    reflection_params = []
    baseline_body = (r.text or "")[:50000]
    baseline_len = len(baseline_body)

    for pname in _COMMON_PARAMS:
        canary = f"arjncan{uuid.uuid4().hex[:10]}xy"
        probe_url = f"{base}?{pname}={canary}"
        pr = safe_get(probe_url, req=req, timeout=6)
        if pr is None:
            continue
        body = pr.text or ""
        # Reflection found?
        if canary in body and pname not in params:
            params.add(pname)
            sources["reflected"] += 1
            reflection_params.append(pname)
        # Significant length diff also suggests param is processed
        elif abs(len(body) - baseline_len) > 200 and pname not in params:
            # softer signal — add but mark as probable
            params.add(pname)
            sources["js"] += 1

    return {
        "ok": True,
        "params": sorted(params)[:200],
        "sources": sources,
        "reflected_params": reflection_params,
        "wordlist_size": len(_COMMON_PARAMS),
        "engine": "pure-Python regex extract + Arjun-style reflection probe",
    }


def register(app):
    app.include_router(router)
