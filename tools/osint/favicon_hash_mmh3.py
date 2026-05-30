"""Favicon mmh3 hash fingerprint — playbook §2 #32.

Computes the Shodan-style favicon hash (mmh3 32-bit signed of the
base64-encoded favicon bytes). This hash is queryable on Shodan / Censys
to find every host serving the same favicon — useful for finding fortifying
infrastructure (other prod servers running the same app), or finding
the customer's hidden assets behind Cloudflare/proxy via the origin
favicon hash.

Real probe. Zero false positives. Pure Python — mmh3 is the only dep.
"""
import asyncio
import base64
import socket
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 12


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip()
    if not target:
        return standard_response(
            tool="favicon_hash_mmh3", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty target")

    # Build favicon URL
    if not target.startswith(("http://", "https://")):
        target = "https://" + target.rstrip("/")
    url = target.rstrip("/") + "/favicon.ico"

    r = safe_get(url, req=req, timeout=8,
                  headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="favicon_hash_mmh3", target=req.target,
            findings=[wrap_finding(
                f"No favicon at {url}",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No favicon = no Shodan-pivotable fingerprint. "
                            "Some apps deliberately omit; this is fine.",
                evidence_marker=f"GET /favicon.ico → HTTP {r.status_code if r else 'no-conn'}")],
            tests_performed=1, vulnerable=False,
            tests_summary="No favicon present")

    try:
        import mmh3
    except ImportError:
        return standard_response(
            tool="favicon_hash_mmh3", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="mmh3 Python lib not installed on backend")

    # Shodan-format: base64 of bytes, line-broken every 76 chars + final newline
    b64 = base64.encodebytes(r.content).decode()
    h = mmh3.hash(b64)

    findings = [wrap_finding(
        f"Favicon mmh3 hash = {h} (Shodan-pivotable fingerprint)",
        severity="INFO", cwe="CWE-200",
        remediation="Anyone can query Shodan with: http.favicon.hash:{} to find "
                    "every other host serving the same favicon. If you want this "
                    "asset to be unique on the internet, use a custom favicon. "
                    "If you're hiding origin behind Cloudflare, your origin server "
                    "MUST serve a different favicon (or none).".format(h),
        evidence_marker=(
            f"mmh3 hash: {h} | size: {len(r.content)}B | "
            f"shodan query: http.favicon.hash:{h} | "
            f"censys query: services.http.response.favicons.md5_hash"
        ))]

    return standard_response(
        tool="favicon_hash_mmh3", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"favicon mmh3 hash = {h}",
        raw_data={"hash": h, "size": len(r.content), "url": url})


@router.post("/api/osint/favicon_hash_mmh3")
async def scan_favicon_hash_mmh3(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="favicon_hash_mmh3", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
