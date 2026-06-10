"""Reverse-image-search URL generator — playbook §6 #78.

Reverse image search APIs (TinEye/Yandex/Google Lens) require paid API
keys or scrape-blocked endpoints. This tool returns the direct search
URLs analysts can click — best balance of "no false positives" + "actually
useful". The target = image URL.

Pure-Python URL synthesis. Useful but limited; for fully-automated reverse
search, customer needs TinEye API key (set via auth_bearer).
"""
import asyncio
import urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 5


def _do_scan(req: ScanRequest) -> dict:
    url = (req.target or "").strip()
    if not url.startswith(("http://", "https://")):
        return standard_response(
            tool="reverse_image_search", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="target must be image URL")

    enc = urllib.parse.quote(url, safe="")
    search_urls = {
        "Yandex":         f"https://yandex.com/images/search?rpt=imageview&url={enc}",
        "TinEye":         f"https://www.tineye.com/search?url={enc}",
        "Google Lens":    f"https://lens.google.com/uploadbyurl?url={enc}",
        "Bing":           f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&q=imgurl:{enc}",
        "SauceNAO":       f"https://saucenao.com/search.php?url={enc}",
        "IQDB (anime)":   f"https://iqdb.org/?url={enc}",
    }

    findings = [wrap_finding(
        f"Reverse-image search URLs for {url[:60]}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Click each URL to verify image provenance. Yandex is "
                    "often best for face matching (less filtering than Google). "
                    "TinEye is strongest for finding earliest appearance / source. "
                    "Use these manually — none of these services have free APIs.",
        evidence_marker=" | ".join(f"{k}: {v}" for k, v in search_urls.items()))]

    return standard_response(
        tool="reverse_image_search", target=req.target, findings=findings,
        tests_performed=len(search_urls), vulnerable=False,
        tests_summary=f"{len(search_urls)} reverse-image search URLs generated",
        raw_data={"search_urls": search_urls, "image_url": url})


@router.post("/api/osint/reverse_image_search")
@vl_verify()
async def scan_reverse_image_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="reverse_image_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
