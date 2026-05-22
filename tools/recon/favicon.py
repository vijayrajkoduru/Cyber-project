"""Favicon Fingerprint v2 — VL-FORGE pattern.

Route: /api/recon/favicon

Sources (parallel):
  1. Fetch /favicon.ico from base URL
  2. MurmurHash3 hash (Shodan-style favicon fingerprint)
  3. MD5 hash (alternative fingerprint)
  4. Tech-stack lookup against known-favicon DB
"""
import asyncio
import base64
import codecs
import hashlib

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.favicon_findings import (
    FAVICON_FINDING_RULES, FAVICON_HASHES,
)

router = APIRouter()


def _mmh3_hash(data: bytes) -> int:
    """MurmurHash3 32-bit (Shodan favicon hash). Pure-Python implementation."""
    try:
        import mmh3
        # mmh3 lib expects base64-encoded data per Shodan convention
        b64 = base64.encodebytes(data)
        return mmh3.hash(b64)
    except ImportError:
        # Fallback: implement minimal MMH3 32-bit
        return _mmh3_fallback(data)


def _mmh3_fallback(data: bytes) -> int:
    """Pure-Python MurmurHash3 32-bit. Used if mmh3 lib unavailable."""
    seed = 0
    # Shodan convention: hash the base64-encoded favicon
    data = base64.encodebytes(data)
    length = len(data)
    h1 = seed
    rounded_end = length & 0xFFFFFFFC
    for i in range(0, rounded_end, 4):
        k1 = (data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24)) & 0xFFFFFFFF
        k1 = (k1 * 0xcc9e2d51) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * 0x1b873593) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
    k1 = 0
    val = length & 0x03
    if val == 3: k1 = (data[rounded_end + 2] & 0xFF) << 16
    if val in (2, 3): k1 |= (data[rounded_end + 1] & 0xFF) << 8
    if val in (1, 2, 3):
        k1 |= data[rounded_end] & 0xFF
        k1 = (k1 * 0xcc9e2d51) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * 0x1b873593) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    # Convert to signed 32-bit (matches Shodan format)
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")

    def _fetch_favicon():
        for path in ("/favicon.ico", "/favicon.png", "/apple-touch-icon.png"):
            try:
                r = requests.get(base + path, timeout=10, verify=False,
                                  headers={"User-Agent": "VulnusLab/1.0"})
                if r.status_code == 200 and len(r.content) > 0:
                    ct = (r.headers.get("Content-Type") or "").lower()
                    if "image" in ct or "icon" in ct or path.endswith(".ico"):
                        return r.content, path
            except Exception:
                continue
        return None, None

    ctx.state["base_reachable"] = True

    favicon_data, found_path = await asyncio.to_thread(_fetch_favicon)
    if not favicon_data:
        ctx.state["favicon_found"] = False
        return

    ctx.source(f"favicon-fetch ({found_path})")
    ctx.state["favicon_found"] = True
    ctx.state["favicon_path"] = found_path
    ctx.state["favicon_size_bytes"] = len(favicon_data)

    # MurmurHash3 (Shodan favicon hash)
    mmh3_hash = _mmh3_hash(favicon_data)
    ctx.state["mmh3_hash"] = mmh3_hash
    ctx.source("mmh3-fingerprint")

    # MD5 + SHA256
    ctx.state["md5_hash"] = hashlib.md5(favicon_data).hexdigest()
    ctx.state["sha256_hash"] = hashlib.sha256(favicon_data).hexdigest()
    ctx.source("md5-sha256-fingerprint")

    # Tech-stack lookup
    tech = FAVICON_HASHES.get(mmh3_hash)
    if tech:
        ctx.state["identified_tech"] = tech
        ctx.source("favicon-tech-match")

    # Backwards-compat for frontend isEmpty (looks at `d.found`)
    ctx.state["found"] = True
    ctx.state["shodan_hash"] = mmh3_hash


INTEL_FIELDS = [
    ("Favicon path",        "favicon_path"),
    ("MurmurHash3 (Shodan)", "mmh3_hash"),
    ("MD5",                  "md5_hash"),
    ("Size bytes",           "favicon_size_bytes"),
    ("Identified tech",      "identified_tech"),
]


@router.post("/api/recon/favicon")
async def recon_favicon(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(
        host=host, tool="favicon",
        gather_func=gather,
        finding_rules=FAVICON_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["found", "shodan_hash", "favicon_found"],
    )


def register(app):
    app.include_router(router)
