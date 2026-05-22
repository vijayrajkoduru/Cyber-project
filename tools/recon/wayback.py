"""Wayback Machine v2 — VL-FORGE pattern.

Route: /api/recon/wayback

Sources:
  1. Wayback CDX API — all archived URLs for domain
  2. URL classification — sensitive admin/internal/debug URLs
  3. Param scan — sensitive token/key params in historical query strings
  4. Archive age estimation
"""
import asyncio
import datetime
import re
from urllib.parse import urlparse

import requests

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.wayback_findings import (
    WAYBACK_FINDING_RULES, classify_url, extract_sensitive_param_names,
)

router = APIRouter()


def _fetch_wayback(host, limit=5000):
    """Fetch Wayback CDX index. Returns list of {url, timestamp} dicts."""
    try:
        # CDX API: returns lines, first is column header
        url = (f"http://web.archive.org/cdx/search/cdx?"
                f"url={host}/*&output=json&limit={limit}&collapse=urlkey"
                f"&fl=timestamp,original,statuscode")
        r = requests.get(url, timeout=20, verify=False,
                          headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code != 200: return []
        data = r.json()
        if len(data) <= 1: return []
        rows = data[1:]  # skip header row
        out = []
        for row in rows:
            if len(row) >= 2:
                out.append({"timestamp": row[0], "url": row[1],
                            "status": row[2] if len(row) > 2 else ""})
        return out
    except Exception:
        return []


async def gather(ctx: ScanContext):
    host = ctx.host

    snapshots = await asyncio.to_thread(_fetch_wayback, host)
    if not snapshots:
        return

    ctx.source(f"wayback-cdx-api ({len(snapshots)} snapshots)")
    ctx.state["total_snapshots"] = len(snapshots)

    # Classify forgotten admin/internal URLs
    forgotten_admin = []
    sensitive_params_history = []
    seen_paths = set()

    for snap in snapshots:
        url = snap.get("url", "")
        path = urlparse(url).path
        if path in seen_paths: continue
        seen_paths.add(path)

        why = classify_url(url)
        if why and any(w in why for w in ("admin", "internal", "debug")):
            forgotten_admin.append({"url": url[:200], "why": why,
                                     "timestamp": snap.get("timestamp", "")})
            if len(forgotten_admin) >= 20: break

        sps = extract_sensitive_param_names(url)
        sensitive_params_history.extend(sps)

    ctx.state["forgotten_admin"] = forgotten_admin
    ctx.state["sensitive_params_history"] = sensitive_params_history

    # Oldest snapshot age
    if snapshots:
        try:
            oldest_ts = min(s.get("timestamp", "99999999") for s in snapshots)
            if oldest_ts and len(oldest_ts) >= 4:
                year = int(oldest_ts[:4])
                ctx.state["oldest_snapshot_year"] = year
                ctx.state["oldest_snapshot_years"] = (
                    datetime.datetime.utcnow().year - year)
                ctx.source("archive-age-derivation")
        except Exception:
            pass

    # Backwards-compat: top-level `total` field for existing dashboard tile
    ctx.state["total"] = len(snapshots)
    ctx.state["interesting_total"] = len(forgotten_admin) + len(set(sensitive_params_history))


INTEL_FIELDS = [
    ("Total snapshots",        "total_snapshots"),
    ("Forgotten admin URLs",  "forgotten_admin_display"),
    ("Sensitive params seen", "sensitive_params_display"),
    ("Oldest snapshot",        "oldest_age_display"),
]


@router.post("/api/recon/wayback")
async def recon_wayback(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        fa = ctx.state.get("forgotten_admin") or []
        if fa:
            ctx.state["forgotten_admin_display"] = (
                f"{len(fa)} URLs: " + ", ".join(f["url"][:60] for f in fa[:3]))
        sp = ctx.state.get("sensitive_params_history") or []
        if sp:
            ctx.state["sensitive_params_display"] = (
                f"{len(set(sp))} unique: " + ", ".join(set(sp)))
        oa = ctx.state.get("oldest_snapshot_years")
        oy = ctx.state.get("oldest_snapshot_year")
        if oa is not None and oy:
            ctx.state["oldest_age_display"] = f"{oy} ({oa} years old)"

    return await run_scanner(
        host=host, tool="wayback",
        gather_func=gather_with_display,
        finding_rules=WAYBACK_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["total", "interesting_total"],
    )


def register(app):
    app.include_router(router)
