"""JS Endpoint Extractor v2 — VL-FORGE pattern.

Route: /api/recon/jsendpoints

Sources (parallel):
  1. Base HTML <script src=> extraction
  2. Parallel fetch + regex on each JS file
  3. Source-map .map file accessibility probe
  4. Secret scanning per JS file (AWS / GitHub / Google / OpenAI tokens)

Findings (5 rules):
  CRITICAL: hardcoded secrets in JS
  HIGH    : sensitive endpoints (/admin / /internal / /debug) leaked
  MEDIUM  : source maps exposed
  INFO    : total endpoints + JS files scanned
"""
import asyncio
import re
from urllib.parse import urljoin, urlparse

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.jsendpoints_findings import (
    JS_ENDPOINTS_FINDING_RULES, classify_endpoint, scan_for_secrets,
)

router = APIRouter()


_ENDPOINT_PATTERNS = [
    r"fetch\(\s*['\"]([^'\"]+)['\"]",
    r"axios\.\w+\(\s*['\"]([^'\"]+)['\"]",
    r"XMLHttpRequest.*open\(\s*['\"]\w+['\"]\s*,\s*['\"]([^'\"]+)['\"]",
    r"['\"]/(api|v[12]|graphql|rest)/[^'\"]+['\"]",
]


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    parsed = urlparse(base)

    def _fetch(url):
        # 6s timeout — 20 JS files in parallel, total budget ~6-12s even on slow
        # targets. Was 10s which combined with secondary .map probes risked hitting
        # the 300s frontend ceiling on Cloudflare-rate-limited targets.
        try:
            r = requests.get(url, timeout=6, verify=False,
                              headers={"User-Agent": "VulnusLab/1.0"})
            return r if r.status_code == 200 else None
        except Exception:
            return None

    base_resp = await asyncio.to_thread(_fetch, base)
    if not base_resp:
        return
    ctx.source("html-fetch")

    # Extract same-origin JS URLs
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                           base_resp.text or "", re.I):
        src = m.group(1)
        if src.startswith("//"): src = parsed.scheme + ":" + src
        elif src.startswith("/"): src = parsed.scheme + "://" + parsed.netloc + src
        elif not src.startswith("http"): src = urljoin(base + "/", src)
        try:
            if urlparse(src).netloc == parsed.netloc:
                js_urls.add(src)
        except Exception:
            continue

    js_urls = list(js_urls)[:20]

    js_responses = await asyncio.gather(*[
        asyncio.to_thread(_fetch, url) for url in js_urls
    ])

    endpoints = set()
    secrets_found = []
    source_maps_found = []

    for url, resp in zip(js_urls, js_responses):
        if not resp: continue
        text = resp.text or ""
        for pat in _ENDPOINT_PATTERNS:
            for m in re.finditer(pat, text):
                ep = m.group(1) if m.lastindex else m.group(0)
                ep = ep.strip('"\' ')[:200]
                if len(ep) > 3:
                    endpoints.add(ep)
        secrets_found.extend(scan_for_secrets(text, url.rsplit("/", 1)[-1]))
        if "sourceMappingURL=" in text:
            map_match = re.search(r"sourceMappingURL=([^\s]+\.map)", text)
            if map_match:
                map_url = urljoin(url, map_match.group(1))
                map_resp = await asyncio.to_thread(_fetch, map_url)
                if map_resp:
                    source_maps_found.append(map_url)

    if js_urls: ctx.source(f"js-fetch-{len(js_urls)}")
    if endpoints: ctx.source(f"endpoint-extract-{len(endpoints)}")
    if secrets_found: ctx.source(f"secret-scan-{len(secrets_found)}")
    if source_maps_found: ctx.source(f"source-map-probe-{len(source_maps_found)}")

    sensitive = []
    for ep in endpoints:
        why = classify_endpoint(ep)
        if why:
            sensitive.append({"path": ep, "why": why})

    ctx.state["endpoints"] = sorted(endpoints)
    ctx.state["js_files_scanned"] = len(js_urls)
    ctx.state["sensitive_endpoints"] = sensitive
    ctx.state["secrets_found"] = secrets_found
    ctx.state["source_maps_found"] = source_maps_found
    ctx.state["paths"] = sorted(endpoints)
    ctx.state["discovered"] = sorted(endpoints)


INTEL_FIELDS = [
    ("JS files scanned",    "js_files_scanned"),
    ("Endpoints extracted", "endpoint_count_display"),
    ("Sensitive endpoints", "sensitive_count_display"),
    ("Secrets in JS",       "secrets_display"),
    ("Source maps exposed", "source_maps_display"),
    ("Sample endpoints",    "sample_endpoints_display"),
]


@router.post("/api/recon/jsendpoints")
async def recon_jsendpoints(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        eps = ctx.state.get("endpoints") or []
        if eps:
            ctx.state["endpoint_count_display"] = f"{len(eps)} unique"
            ctx.state["sample_endpoints_display"] = ", ".join(eps[:5])
        se = ctx.state.get("sensitive_endpoints") or []
        if se:
            ctx.state["sensitive_count_display"] = (
                f"{len(se)} flagged: " +
                ", ".join(e["path"][:30] for e in se[:3]))
        secs = ctx.state.get("secrets_found") or []
        if secs:
            ctx.state["secrets_display"] = (
                f"{len(secs)} potential: " +
                ", ".join(s["kind"] for s in secs[:3]))
        sm = ctx.state.get("source_maps_found") or []
        if sm:
            ctx.state["source_maps_display"] = ", ".join(
                s.rsplit("/", 1)[-1] for s in sm[:3])

    return await run_scanner(
        host=host, tool="jsendpoints",
        gather_func=gather_with_display,
        finding_rules=JS_ENDPOINTS_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["paths", "discovered", "endpoints", "js_files_scanned"],
    )


def register(app):
    app.include_router(router)
