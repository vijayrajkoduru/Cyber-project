"""Source Map Exposure v2 — VL-FORGE pattern.

Route: /api/recon/sourcemap

Sources (parallel):
  1. Direct probe of common webpack/vite/parcel/rollup .map paths
  2. Base HTML scrape — find //# sourceMappingURL= references
  3. Probe each discovered .map for accessibility
"""
import asyncio
import re

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier5_findings import SOURCEMAP_FINDING_RULES

router = APIRouter()


_COMMON_MAP_PATHS = [
    "/static/js/main.js.map", "/static/js/bundle.js.map",
    "/static/js/runtime.js.map", "/static/js/vendor.js.map",
    "/static/js/app.js.map", "/static/js/chunk.js.map",
    "/dist/main.js.map", "/dist/bundle.js.map",
    "/build/main.js.map", "/build/bundle.js.map",
    "/assets/main.js.map", "/assets/index.js.map",
    "/js/main.js.map", "/js/bundle.js.map", "/js/app.js.map",
    "/_next/static/chunks/main.js.map",  # Next.js
    "/main.js.map", "/app.js.map", "/bundle.js.map",
]


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")

    def _check(url):
        try:
            r = requests.get(url, timeout=8, verify=False, allow_redirects=False,
                              headers={"User-Agent": "VulnusLab/1.0"})
            if r.status_code == 200:
                # Verify it's actually a source map (JSON with version/sources)
                text = (r.text or "")[:500]
                if '"version"' in text or '"sources"' in text or '"mappings"' in text:
                    return {"url": url, "size": len(r.content)}
        except Exception:
            pass
        return None

    ctx.state["base_reachable"] = True

    # Probe common paths in parallel
    results = await asyncio.gather(*[
        asyncio.to_thread(_check, base + path) for path in _COMMON_MAP_PATHS
    ])
    maps_with_size = [r for r in results if r]
    maps_found = [m["url"] for m in maps_with_size]

    # Additionally scrape base HTML for sourceMappingURL hints
    try:
        r = await asyncio.to_thread(
            requests.get, base, timeout=8, verify=False,
            headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            for m in re.finditer(r"sourceMappingURL=([^\s]+\.map)", r.text or ""):
                map_path = m.group(1)
                if not map_path.startswith("http"):
                    if map_path.startswith("/"):
                        map_url = base + map_path
                    else:
                        map_url = base + "/" + map_path.lstrip("./")
                else:
                    map_url = map_path
                if map_url not in maps_found:
                    discovered = await asyncio.to_thread(_check, map_url)
                    if discovered:
                        maps_with_size.append(discovered)
                        maps_found.append(map_url)
    except Exception:
        pass

    ctx.state["maps_found"] = maps_found
    ctx.state["maps_with_size"] = maps_with_size
    ctx.state["paths_probed"] = len(_COMMON_MAP_PATHS)
    ctx.source(f"common-path-probe ({len(_COMMON_MAP_PATHS)})")
    if maps_found:
        ctx.source(f"map-validation ({len(maps_found)})")


INTEL_FIELDS = [
    ("Paths probed",        "paths_probed"),
    ("Source maps found",   "maps_count_display"),
    ("Maps + size",          "maps_size_display"),
]


@router.post("/api/recon/sourcemap")
async def recon_sourcemap(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        mf = ctx.state.get("maps_found") or []
        if mf: ctx.state["maps_count_display"] = f"{len(mf)} exposed"
        ms = ctx.state.get("maps_with_size") or []
        if ms:
            ctx.state["maps_size_display"] = "; ".join(
                f"{m['url'].rsplit('/', 1)[-1]} ({m['size']}B)"
                for m in ms[:5])

    return await run_scanner(
        host=host, tool="sourcemap",
        gather_func=gather_with_display,
        finding_rules=SOURCEMAP_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["maps_found"],
    )


def register(app):
    app.include_router(router)
