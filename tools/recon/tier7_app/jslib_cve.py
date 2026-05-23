"""JS Library CVE v2 — VL-FORGE pattern.

Route: /api/recon/jslib_cve

Sources (parallel):
  1. Base HTML fetch + <script src=> extraction
  2. JS file fetch + version-signature matching (Retire.js style)
  3. Per-library version → CVE lookup
"""
import asyncio
import re
from urllib.parse import urljoin, urlparse

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier5_findings import JSLIB_CVE_FINDING_RULES

router = APIRouter()


# Retire.js-style signatures: (library_name, regex_to_match_in_js_text_or_filename,
#                              regex_to_extract_version, [(version_range, CVE_list)])
_LIB_SIGNATURES = [
    ("jquery", r"jquery[\.\-]([\d\.]+)(?:\.min)?\.js",
     r"jQuery\s+JavaScript Library v?([\d\.]+)|/\*!\s*jQuery v([\d\.]+)",
     [("<3.5.0", ["CVE-2020-11023", "CVE-2020-11022"])]),
    ("lodash", r"lodash[\.\-]([\d\.]+)(?:\.min)?\.js",
     r"lodash\s+v?([\d\.]+)|/\*\*\s*\@license\s+Lodash\s+([\d\.]+)",
     [("<4.17.21", ["CVE-2021-23337", "CVE-2020-8203"])]),
    ("angular", r"angular[\.\-]([\d\.]+)(?:\.min)?\.js",
     r"AngularJS\s+v([\d\.]+)|@version\s+v?([\d\.]+)",
     [("<1.8.0", ["CVE-2020-7676"])]),
    ("bootstrap", r"bootstrap[\.\-]([\d\.]+)(?:\.min)?\.js",
     r"Bootstrap v([\d\.]+)|\*\s*Bootstrap\s+v?([\d\.]+)",
     [("<4.3.1", ["CVE-2019-8331"])]),
    ("vue", r"vue[\.\-]([\d\.]+)(?:\.min)?\.js",
     r"Vue\.js v([\d\.]+)|\*\*\s*\*\s*Vue\.js v([\d\.]+)",
     []),
    ("react", r"react[\.\-]?([\d\.]+)?(?:\.min)?\.js",
     r"react\.development\.js[^\n]*v([\d\.]+)|@version\s+([\d\.]+)",
     []),
    ("moment", r"moment[\.\-]([\d\.]+)(?:\.min)?\.js",
     r"moment\.js\s+version?\s+([\d\.]+)|//!\s*version\s*:\s*([\d\.]+)",
     [("<2.29.4", ["CVE-2022-31129"])]),
    ("axios", r"axios[\.\-]([\d\.]+)(?:\.min)?\.js",
     r"axios v([\d\.]+)|\*\s*Axios\s+v([\d\.]+)",
     [("<0.21.1", ["CVE-2020-28168"])]),
]


def _fetch(url):
    try:
        r = requests.get(url, timeout=8, verify=False,
                          headers={"User-Agent": "VulnusLab/1.0"})
        return r if r.status_code == 200 else None
    except Exception:
        return None


def _detect_libs_in_text(text, filename):
    """Return list of {name, version, cves[]} found in JS text or filename."""
    libs = []
    for lib_name, filename_re, version_re, cve_ranges in _LIB_SIGNATURES:
        # First try filename match (e.g., jquery-3.5.1.min.js)
        m = re.search(filename_re, filename, re.I)
        version = m.group(1) if m and m.group(1) else None
        # Else try content extraction
        if not version:
            m = re.search(version_re, text)
            if m:
                version = m.group(1) or (m.group(2) if m.lastindex >= 2 else None)
        if not version: continue
        # CVE matching (simple lexicographic comparison for "<X.Y.Z" ranges)
        cves = []
        try:
            cur = tuple(int(p) for p in version.split(".")[:3])
            for cve_range, cve_list in cve_ranges:
                if cve_range.startswith("<"):
                    upper = cve_range[1:].split(".")
                    target = tuple(int(p) for p in upper)
                    if cur < target:
                        cves.extend(cve_list)
        except Exception:
            pass
        libs.append({"name": lib_name, "version": version, "cves": cves})
    return libs


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    parsed = urlparse(base)

    base_resp = await asyncio.to_thread(_fetch, base)
    if not base_resp:
        return
    ctx.state["base_reachable"] = True
    ctx.source("html-fetch")

    # Extract JS URLs
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                           base_resp.text or "", re.I):
        src = m.group(1)
        if src.startswith("//"): src = parsed.scheme + ":" + src
        elif src.startswith("/"): src = parsed.scheme + "://" + parsed.netloc + src
        elif not src.startswith("http"): src = urljoin(base + "/", src)
        js_urls.add(src)

    js_urls = list(js_urls)[:20]

    js_responses = await asyncio.gather(*[
        asyncio.to_thread(_fetch, url) for url in js_urls
    ])

    libs_detected = []
    seen = set()
    for url, resp in zip(js_urls, js_responses):
        if not resp: continue
        filename = url.rsplit("/", 1)[-1]
        text = resp.text or ""
        libs = _detect_libs_in_text(text, filename)
        for lib in libs:
            key = (lib["name"], lib["version"])
            if key in seen: continue
            seen.add(key)
            libs_detected.append(lib)

    ctx.state["libs_detected"] = libs_detected
    ctx.state["vulnerable_libs"] = [l for l in libs_detected if l.get("cves")]
    ctx.state["signatures_loaded"] = len(_LIB_SIGNATURES)
    ctx.state["js_files_scanned"] = len(js_urls)
    if js_urls: ctx.source(f"js-fetch ({len(js_urls)})")
    if libs_detected: ctx.source(f"retire-js-sig-match ({len(libs_detected)})")


INTEL_FIELDS = [
    ("Signatures loaded",  "signatures_loaded"),
    ("JS files scanned",   "js_files_scanned"),
    ("Libraries detected", "libs_display"),
    ("Vulnerable libs",     "vuln_display"),
]


@router.post("/api/recon/jslib_cve")
async def recon_jslib_cve(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        libs = ctx.state.get("libs_detected") or []
        if libs:
            ctx.state["libs_display"] = ", ".join(
                f"{l['name']} {l['version']}" for l in libs[:6])
        v = ctx.state.get("vulnerable_libs") or []
        if v:
            ctx.state["vuln_display"] = "; ".join(
                f"{l['name']} {l['version']} -> {len(l.get('cves') or [])} CVE"
                for l in v[:3])

    return await run_scanner(
        host=host, tool="jslib_cve",
        gather_func=gather_with_display,
        finding_rules=JSLIB_CVE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["libs_detected", "vulnerable_libs"],
    )


def register(app):
    app.include_router(router)
