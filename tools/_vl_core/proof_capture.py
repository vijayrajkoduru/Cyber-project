"""proof_capture - turn an ALREADY-CONFIRMED visual finding into a screenshot
proof.

The capture is subordinate to the detection, never the detector:
  1. The finding must already be confirmed by its scanner's normal logic.
  2. capture_proof() re-verifies the finding's signal at capture time, AND
  3. runs the SPA / catch-all canary before screenshotting.

So a screenshot can never manufacture a false positive - it only illustrates a
true one. Degrades to None when headless Chromium is unavailable, so a missing
browser never breaks a scan.
"""
from __future__ import annotations

import base64
import html as _html
import re
from typing import Optional, Tuple

try:
    import requests
except Exception:                       # pragma: no cover
    requests = None

from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary

_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 VulnusLab/1.0")


def _origin(url: str) -> str:
    m = re.match(r"(https?://[^/]+)", url)
    return m.group(1) if m else url


def _fetch(url: str, timeout: int = 8):
    """Return (body_text, status, content_type) or (None, 0, '')."""
    if requests is None:
        return None, 0, ""
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": _UA}, allow_redirects=True)
        return (r.text or ""), r.status_code, r.headers.get("Content-Type", "")
    except Exception:
        return None, 0, ""


def _screenshot(url: Optional[str] = None, html_text: Optional[str] = None,
                width: int = 1024, height: int = 680,
                timeout_ms: int = 12000) -> Optional[bytes]:
    """JPEG bytes for either a live URL (navigate) or inline HTML
    (set_content). None on any failure - including Chromium not installed."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
            try:
                page = browser.new_context(
                    viewport={"width": width, "height": height},
                    ignore_https_errors=True, user_agent=_UA).new_page()
                if html_text is not None:
                    page.set_content(html_text, timeout=timeout_ms,
                                     wait_until="domcontentloaded")
                else:
                    page.goto(url, timeout=timeout_ms,
                              wait_until="domcontentloaded")
                    try:
                        page.wait_for_timeout(1000)   # let above-the-fold paint
                    except Exception:
                        pass
                img = page.screenshot(type="jpeg", quality=55, full_page=False)
            finally:
                browser.close()
        return img
    except Exception:
        return None


def _to_dataurl(jpeg: bytes) -> str:
    return "data:image/jpeg;base64," + base64.b64encode(jpeg).decode("ascii")


def _pre_html(title: str, text: str) -> str:
    """Render a text artifact (e.g. a source map's JSON) into a readable page
    so the screenshot shows the actual exposed content regardless of how the
    server set Content-Type / Content-Disposition."""
    body = _html.escape(text[:4000])
    return ("<html><head><meta charset='utf-8'><style>"
            "body{margin:0;font:12px Consolas,Menlo,monospace;"
            "background:#0b1020;color:#d7e0f0}"
            "h4{margin:0;padding:8px 12px;background:#1e3a8a;color:#fff;"
            "font:bold 12px Arial}"
            "pre{margin:0;padding:12px;white-space:pre-wrap;word-break:break-all}"
            "</style></head><body><h4>" + _html.escape(title) +
            "</h4><pre>" + body + "</pre></body></html>")


def capture_context(url: str) -> Optional[str]:
    """Plain homepage / context snapshot - NOT finding proof. Returns a
    'data:image/jpeg;base64,...' string, or None."""
    img = _screenshot(url=url)
    return _to_dataurl(img) if img else None


def capture_proof(url: str, kind: str, timeout: int = 8) -> Tuple[Optional[str], str]:
    """Capture a screenshot PROOF for a confirmed visual finding.

    Returns (data_url, caption) on success, or (None, reason) on skip/failure.
    The reason is safe to drop on the floor - a missing proof image must never
    remove or weaken the underlying (already-confirmed) finding.
    """
    body, status, _ctype = _fetch(url, timeout)
    if body is None:
        return None, "artifact unreachable at capture time"

    k = (kind or "").lower()
    head = body[:4000]

    # Text artifact (source map): render the JSON itself - that IS the proof.
    if k in ("sourcemap", "source_map"):
        if not ('"mappings"' in head and '"version"' in head):
            return None, "not source-map JSON at capture time"
        caption = f"Source map served at {url} - exposes original source file paths."
        img = _screenshot(html_text=_pre_html(f"GET {url}  ->  {status}", body))
        return (_to_dataurl(img), caption) if img else (None, "headless browser unavailable")

    # Page-type artifacts: signal recheck, then SPA/catch-all gate, then navigate.
    if k in ("dir_listing", "directory_listing"):
        if not re.search(r"index of\s|directory listing", head, re.I):
            return None, "no directory-listing markers at capture time"
        caption = f"Directory listing enabled at {url}."
    elif k in ("panel", "login", "admin_panel"):
        if not re.search(r'type=["\']?password', head, re.I):
            return None, "no authentication form at capture time"
        caption = f"Authentication panel exposed at {url}."
    elif k in ("page", "host"):
        if not (status and status < 500 and len(body) > 0):
            return None, "host not serving content at capture time"
        caption = f"Live surface reachable and serving content at {url}."
    else:
        return None, f"unknown proof kind: {kind}"

    spa = detect_spa_catchall_sync(_origin(url))
    if spa.get("is_spa") and is_same_as_canary(body, spa.get("canary_body", "")):
        return None, "catch-all/SPA response - suppressed (would be a false positive)"

    img = _screenshot(url=url)
    return (_to_dataurl(img), caption) if img else (None, "headless browser unavailable")
