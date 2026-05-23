"""WordPress wp-json Enum v2 — VL-FORGE pattern.

Route: /api/recon/wpjson_enum

Sources (parallel):
  1. WordPress detection (wp-json + generator meta tag)
  2. User enumeration via /wp-json/wp/v2/users
  3. Plugins/themes enumeration via wp-json
  4. Version detection (readme.html + generator tag)
"""
import asyncio
import re

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier5_findings import WPJSON_FINDING_RULES

router = APIRouter()


def _http_get(url, timeout=8):
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                          headers={"User-Agent": "VulnusLab/1.0"})
        return r
    except Exception:
        return None


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")

    # Phase 1: Detect WordPress via wp-json + base HTML generator meta
    wp_json_resp, base_resp = await asyncio.gather(
        asyncio.to_thread(_http_get, base + "/wp-json"),
        asyncio.to_thread(_http_get, base),
    )

    wp_detected = False
    wp_version = None

    if wp_json_resp and wp_json_resp.status_code == 200:
        try:
            data = wp_json_resp.json()
            if isinstance(data, dict) and ("name" in data or "url" in data):
                wp_detected = True
                ctx.source("wp-json-root-api")
        except Exception:
            pass

    # Generator meta tag in HTML
    if base_resp and base_resp.status_code == 200:
        m = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"',
                       base_resp.text or "")
        if m:
            wp_detected = True
            wp_version = m.group(1)
            ctx.source("wp-generator-tag")

    ctx.state["wp_detected"] = wp_detected
    ctx.state["wp_version"] = wp_version

    if not wp_detected:
        return

    # Phase 2: Enumerate users + plugins (parallel)
    users_resp, plugins_html_resp = await asyncio.gather(
        asyncio.to_thread(_http_get, base + "/wp-json/wp/v2/users"),
        asyncio.to_thread(_http_get, base),
    )

    # Users
    if users_resp and users_resp.status_code == 200:
        try:
            users_data = users_resp.json()
            if isinstance(users_data, list):
                ctx.state["users"] = users_data[:50]
                ctx.source(f"wp-users-enum ({len(users_data)})")
        except Exception:
            pass

    # Plugins (heuristic from <link rel="stylesheet" href="...wp-content/plugins/PLUGIN/...">)
    plugins = set()
    if plugins_html_resp and plugins_html_resp.status_code == 200:
        for m in re.finditer(r"wp-content/plugins/([^/]+)/",
                              plugins_html_resp.text or ""):
            plugins.add(m.group(1))
    if plugins:
        ctx.state["plugins"] = sorted(plugins)
        ctx.source(f"plugin-enum ({len(plugins)})")

    # Version outdated heuristic — anything <6.0 is old
    if wp_version:
        try:
            major = int(wp_version.split(".")[0])
            if major < 6:
                ctx.state["wp_outdated"] = True
        except Exception:
            pass


INTEL_FIELDS = [
    ("WordPress detected", "wp_detected"),
    ("WordPress version",  "wp_version"),
    ("Users enumerated",   "users_count_display"),
    ("Plugins detected",   "plugins_display"),
]


@router.post("/api/recon/wpjson_enum")
async def recon_wpjson_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        users = ctx.state.get("users") or []
        if users:
            ctx.state["users_count_display"] = (
                f"{len(users)}: " +
                ", ".join(u.get("slug", "?") for u in users[:5]))
        plugins = ctx.state.get("plugins") or []
        if plugins:
            ctx.state["plugins_display"] = ", ".join(plugins[:5])

    return await run_scanner(
        host=host, tool="wpjson_enum",
        gather_func=gather_with_display,
        finding_rules=WPJSON_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["users", "wp_version", "plugins"],
    )


def register(app):
    app.include_router(router)
