"""BFS Crawler v2 — VL-FORGE pattern.

Route: /api/recon/crawl

Same-origin BFS crawl up to 3 hops. Extracts URLs, forms, login pages,
upload endpoints, external domains, hidden inputs.

Sources (parallel):
  1. HTTP fetch with BFS expansion (link graph traversal)
  2. Form extraction (<form action= + input names)
  3. External-domain link aggregation
"""
import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.crawl_findings import CRAWL_FINDING_RULES

router = APIRouter()


def _fetch(url, timeout=8):
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                          headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            return r.text or ""
        return None
    except Exception:
        return None


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    base_origin = urlparse(base).netloc

    visited = set()
    to_visit = deque([(base, 0)])
    max_hops = 3
    max_urls = 80
    forms = []
    login_forms = []
    upload_forms = []
    external_domains = set()
    hidden_input_count = 0
    depth_reached = 0

    while to_visit and len(visited) < max_urls:
        url, depth = to_visit.popleft()
        if url in visited or depth > max_hops:
            continue
        visited.add(url)
        depth_reached = max(depth_reached, depth)

        text = await asyncio.to_thread(_fetch, url)
        if not text: continue

        # Anchor hrefs
        for m in re.finditer(r'href=["\']([^"\']+)["\']', text, re.I):
            href = m.group(1)
            if href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
                continue
            target = urljoin(url, href)
            tnetloc = urlparse(target).netloc
            if tnetloc and tnetloc != base_origin:
                external_domains.add(tnetloc)
            elif tnetloc == base_origin and target not in visited:
                if depth + 1 <= max_hops and len(visited) < max_urls:
                    to_visit.append((target, depth + 1))

        # Form extraction
        for m in re.finditer(r'<form[^>]*>(.*?)</form>', text, re.I | re.S):
            form_html = m.group(0)
            action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            action = action_m.group(1) if action_m else url
            full_action = urljoin(url, action)
            forms.append(full_action)
            # Detect login forms (has password input)
            if re.search(r'type=["\']password["\']', form_html, re.I):
                login_forms.append(full_action)
            # Detect upload forms (has type="file")
            if re.search(r'type=["\']file["\']', form_html, re.I):
                upload_forms.append(full_action)
            # Count hidden inputs
            hidden_input_count += len(re.findall(
                r'type=["\']hidden["\']', form_html, re.I))

    ctx.state["urls_crawled"] = sorted(visited)
    ctx.state["total"] = len(visited)
    ctx.state["depth_reached"] = depth_reached
    ctx.state["forms"] = forms
    ctx.state["login_forms"] = login_forms
    ctx.state["upload_forms"] = upload_forms
    ctx.state["external_domains"] = sorted(external_domains)
    ctx.state["hidden_input_count"] = hidden_input_count

    if visited:
        ctx.source(f"bfs-crawl-{len(visited)}-urls")
    if forms:
        ctx.source(f"form-extract-{len(forms)}")
    if external_domains:
        ctx.source(f"external-domain-aggregate")


INTEL_FIELDS = [
    ("URLs crawled",        "total"),
    ("Depth reached",        "depth_reached"),
    ("Forms found",          "forms_count_display"),
    ("Login pages",          "login_pages_display"),
    ("Upload endpoints",    "upload_endpoints_display"),
    ("External domains",    "external_domains_display"),
    ("Hidden inputs",        "hidden_input_count"),
]


@router.post("/api/recon/crawl")
async def recon_crawl(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        forms = ctx.state.get("forms") or []
        if forms: ctx.state["forms_count_display"] = f"{len(forms)} forms"
        li = ctx.state.get("login_forms") or []
        if li: ctx.state["login_pages_display"] = ", ".join(li[:3])
        up = ctx.state.get("upload_forms") or []
        if up: ctx.state["upload_endpoints_display"] = ", ".join(up[:3])
        ext = ctx.state.get("external_domains") or []
        if ext: ctx.state["external_domains_display"] = ", ".join(ext[:6])

    return await run_scanner(
        host=host, tool="crawl",
        gather_func=gather_with_display,
        finding_rules=CRAWL_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["total", "urls_crawled"],
    )


def register(app):
    app.include_router(router)
