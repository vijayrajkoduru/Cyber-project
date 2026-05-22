"""Parameter Discovery v2 — VL-FORGE pattern.

Route: /api/recon/params

Sources (parallel):
  1. HTML form input names extraction
  2. URL query string params from anchor hrefs
  3. JS literal extraction (potential ?param= references)
"""
import asyncio
import re
from urllib.parse import urlparse, parse_qs

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.params_findings import (
    PARAMS_FINDING_RULES, is_sensitive_param,
)

router = APIRouter()


def _fetch(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                          headers={"User-Agent": "VulnusLab/1.0"})
        return r.text or "" if r.status_code == 200 else ""
    except Exception:
        return ""


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    text = await asyncio.to_thread(_fetch, base)
    if not text:
        return
    ctx.source("html-fetch")

    params = set()

    # Form input names
    form_count = 0
    for m in re.finditer(r'<form[^>]*>(.*?)</form>', text, re.I | re.S):
        form_html = m.group(0)
        form_count += 1
        for im in re.finditer(r'name=["\']([a-zA-Z][\w\-]*)["\']', form_html):
            params.add(im.group(1))
    if form_count:
        ctx.source(f"form-extract-{form_count}")

    # URL query params from anchor hrefs
    href_params_found = 0
    for hm in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', text):
        try:
            q = urlparse(hm.group(1)).query
            for name in parse_qs(q).keys():
                params.add(name)
                href_params_found += 1
        except Exception:
            continue
    if href_params_found:
        ctx.source("url-query-extract")

    # JS literal extraction (e.g. {param: 'foo'} or 'foo='+value)
    js_literal_count = 0
    for m in re.finditer(r"[\"\']([a-zA-Z][\w\-]{1,30})[\"\']:\s*", text):
        name = m.group(1)
        if len(name) >= 3 and not name.isupper():
            params.add(name)
            js_literal_count += 1
            if js_literal_count >= 100: break
    if js_literal_count:
        ctx.source(f"js-literal-extract-{js_literal_count}")

    # Sort + classify sensitive
    sorted_params = sorted(params)
    sensitive = [p for p in sorted_params if is_sensitive_param(p)]

    ctx.state["params"] = sorted_params
    ctx.state["sensitive_params"] = sensitive
    ctx.state["forms_count"] = form_count


INTEL_FIELDS = [
    ("Parameters found",     "params_count_display"),
    ("Sensitive parameters", "sensitive_display"),
    ("Forms analyzed",       "forms_count"),
    ("Sample parameters",    "sample_params_display"),
]


@router.post("/api/recon/params")
async def recon_params(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        params = ctx.state.get("params") or []
        if params:
            ctx.state["params_count_display"] = f"{len(params)} unique"
            ctx.state["sample_params_display"] = ", ".join(params[:10])
        sp = ctx.state.get("sensitive_params") or []
        if sp:
            ctx.state["sensitive_display"] = ", ".join(sp)

    return await run_scanner(
        host=host, tool="params",
        gather_func=gather_with_display,
        finding_rules=PARAMS_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["params"],
    )


def register(app):
    app.include_router(router)
