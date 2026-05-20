"""recon_cloudbuckets -- isolated tool (Kali-style architecture).

Route: /api/recon/cloudbuckets
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

# CLOUDBUCKETS-AI-PATTERNS-V1
import pathlib as _pl, json as _json
def _load_ai_patterns():
    try:
        f = _pl.Path(__file__).parent.parent / "_payloads" / "recon" / "cloud_bucket_patterns.json"
        if f.exists(): return _json.loads(f.read_text())
    except Exception: pass
    return None
_AI_BUCKET_PATTERNS = _load_ai_patterns()

    ScanRequest, verify_scan_quota, recon_host, safe_get, web_url,
)
import aiohttp as _aiohttp_crawl
import ssl as _ssl_mod

from fastapi import APIRouter, Depends

router = APIRouter()

@router.post("/api/recon/cloudbuckets")
async def recon_cloudbuckets(req: ScanRequest, _=Depends(verify_scan_quota)):
    name = recon_host(req.target).split(".")[0]
    _suffixes = ["", "-prod", "-production", "-staging", "-stage", "-dev", "-development",
                 "-test", "-testing", "-qa", "-uat", "-sandbox", "-backup", "-backups",
                 "-uploads", "-files", "-data", "-assets", "-media", "-images", "-img",
                 "-public", "-private", "-internal", "-secure", "-archive", "-logs",
                 "-cdn", "-static", "-app", "-web", "-www"]
    _prefixes = ["", "prod-", "staging-", "dev-", "test-", "backup-"]
    candidates = []
    for pfx in _prefixes:
        for sfx in _suffixes:
            bn = pfx + name + sfx
            candidates.append(f"https://{bn}.s3.amazonaws.com")
            candidates.append(f"https://s3.amazonaws.com/{bn}")
            candidates.append(f"https://storage.googleapis.com/{bn}")
            candidates.append(f"https://{bn}.blob.core.windows.net")
            candidates.append(f"https://{bn}.digitaloceanspaces.com")
            candidates.append(f"https://{bn}.linodeobjects.com")
            candidates.append(f"https://s3.wasabisys.com/{bn}")
    # Parallel async HEAD probes with short timeout — 90 candidates resolve in ~5s total
    async def _probe_bucket(url):
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=4)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.head(url, allow_redirects=False) as r:
                    return (url, r.status)
        except Exception:
            return (url, None)
    results = await asyncio.gather(*[_probe_bucket(u) for u in candidates])
    existing, open_buckets = [], []
    for url, status in results:
        if status in (200, 403):
            existing.append({"url": url, "status": status})
            if status == 200:
                open_buckets.append(url)
    return {"ok": True, "existing": existing, "open": open_buckets, "tested": len(candidates)}


def register(app):
    app.include_router(router)
