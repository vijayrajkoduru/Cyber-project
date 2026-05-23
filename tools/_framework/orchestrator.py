"""VL-FORGE Orchestrator v2 — parallel multi-tool dispatch.

The v1 framework (scanner.py) runs ONE tool per HTTP call. With 41 recon
tools the frontend has to fire 41 sequential POSTs, total scan time ~5 min.

v2 collapses that to ONE frontend POST that fans out internally to all N
tool endpoints in parallel. Backend keeps a connection pool + per-tier
concurrency limit so we don't hammer the target or external APIs.

Module-agnostic — same orchestrator works for Recon, Webapp, Cloud, etc.
Each module just provides a list of (tool_name, endpoint_path) tuples.

Usage:

    from tools._framework.orchestrator import run_module_parallel

    @router.post("/api/recon/run_all")
    async def recon_run_all(req: ScanRequest, _=Depends(verify_scan_quota)):
        tools = [
            ("whois",        "/api/recon/whois"),
            ("dns",          "/api/recon/dns"),
            # ... all 41 ...
        ]
        return await run_module_parallel(
            target=req.target, tools=tools, concurrency=8,
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
        )

Returns: { "module": "...", "target": "...", "duration_sec": 38.4,
           "tools": {"whois": {...whois result...}, ...},
           "summary": {...aggregate counts...} }
"""
import asyncio
import datetime
import json
import os
import time
from typing import AsyncIterator, Optional

import httpx


# Backend dispatch — talk to OUR OWN routes via localhost so each tool's
# existing handler runs unchanged. uvicorn handles localhost calls in-process
# with negligible overhead (<1ms per call).
_INTERNAL_BASE = os.environ.get("VLFORGE_INTERNAL_BASE", "http://127.0.0.1:8000")
# Per-tool timeout. Slowest tools (gobuster, amass) take ~60-90s on real
# Cloudflare-fronted targets; cap at 240s so no tool blocks the run forever.
_PER_TOOL_TIMEOUT = 240.0


async def _dispatch_one(
    client: httpx.AsyncClient,
    tool_name: str,
    endpoint: str,
    body: dict,
    sem: asyncio.Semaphore,
    headers: Optional[dict] = None,
) -> tuple[str, dict, float]:
    """Send one tool request through the semaphore-limited pool.
    Returns (tool_name, response_json_or_error_dict, duration_sec)."""
    t0 = time.monotonic()
    async with sem:
        try:
            r = await client.post(endpoint, json=body, timeout=_PER_TOOL_TIMEOUT,
                                   headers=headers or None)
            r.raise_for_status()
            return tool_name, r.json(), time.monotonic() - t0
        except httpx.TimeoutException:
            return tool_name, {
                "ok": False, "_failed": True,
                "error": f"{tool_name} timed out after {int(_PER_TOOL_TIMEOUT)}s",
                "findings": [], "tool": tool_name,
            }, time.monotonic() - t0
        except httpx.HTTPStatusError as e:
            return tool_name, {
                "ok": False, "_failed": True,
                "error": f"{tool_name} returned HTTP {e.response.status_code}",
                "findings": [], "tool": tool_name,
            }, time.monotonic() - t0
        except Exception as e:
            return tool_name, {
                "ok": False, "_failed": True,
                "error": f"{tool_name} dispatch error: {type(e).__name__}: {str(e)[:160]}",
                "findings": [], "tool": tool_name,
            }, time.monotonic() - t0


async def run_module_parallel(
    target: str,
    tools: list[tuple[str, str]],
    module_name: str = "recon",
    concurrency: int = 8,
    auth_cookie: Optional[str] = None,
    auth_bearer: Optional[str] = None,
    extra_body: Optional[dict] = None,
    jwt_token: Optional[str] = None,
) -> dict:
    """Fan out target to all tool endpoints in parallel; aggregate results.

    Args:
      target:      hostname / URL to scan
      tools:       list of (tool_name, endpoint_path) — e.g. [("whois", "/api/recon/whois"), ...]
      module_name: label for the aggregated response ("recon" / "webapp" / etc.)
      concurrency: max in-flight tool requests at once. 8 is a sane default —
                    high enough for parallelism, low enough to not overload
                    the target's WAF.
      auth_cookie / auth_bearer: forwarded into each tool's body for
                    authenticated scans (cookie capture from SPA login flow).
      extra_body:  per-tool body fields (api_key for Shodan, etc.).

    Returns: {
       "module":       module_name,
       "target":       target,
       "started_at":   ISO timestamp,
       "duration_sec": float,
       "concurrency":  int,
       "total_tools":  int,
       "tools":        { tool_name: result_dict, ... },
       "timing":       { tool_name: duration_sec, ... },
       "summary": {
           "ok":          count of tools that completed cleanly,
           "failed":      count with _failed: True,
           "skipped":     count with _skipped: True or skipped_reason set,
           "total_findings": across all tools,
           "by_severity": { CRITICAL, HIGH, MEDIUM, LOW, INFO, POSITIVE },
       }
    }
    """
    started_at = datetime.datetime.utcnow().isoformat() + "Z"
    t0 = time.monotonic()

    # Build per-tool body — every tool accepts the same ScanRequest shape
    # so we send the same body to all of them.
    base_body = {"target": target}
    if auth_cookie: base_body["auth_cookie"] = auth_cookie
    if auth_bearer: base_body["auth_bearer"] = auth_bearer
    if extra_body:  base_body.update(extra_body)

    # AUTH-FORWARDING-V1 — every tool route has Depends(verify_scan_quota)
    # so internal calls MUST carry the user's JWT or they return 401 (which is
    # what caused 41/41 FAILED on the 08:40 juiceshop scan). Forward exactly
    # the same Authorization header the user sent to /api/recon/run_all.
    internal_headers: dict = {}
    if jwt_token:
        internal_headers["Authorization"] = f"Bearer {jwt_token}"

    # Single HTTP/2 connection pool, reused across all 41 calls. Massive win
    # over each tool opening its own socket.
    limits = httpx.Limits(
        max_keepalive_connections=concurrency * 2,
        max_connections=concurrency * 3,
    )
    sem = asyncio.Semaphore(concurrency)

    results: dict = {}
    timings: dict = {}

    async with httpx.AsyncClient(
        base_url=_INTERNAL_BASE,
        limits=limits,
        timeout=httpx.Timeout(_PER_TOOL_TIMEOUT, connect=10.0),
        # Internal localhost calls — no need to verify own certs.
        verify=False,
    ) as client:
        tasks = [
            _dispatch_one(client, tool_name, endpoint, base_body, sem,
                            headers=internal_headers)
            for tool_name, endpoint in tools
        ]
        # As each task completes we record the result so partial progress is
        # captured even if the caller's request is cancelled mid-run.
        for coro in asyncio.as_completed(tasks):
            tool_name, result, dur = await coro
            results[tool_name] = result
            timings[tool_name] = round(dur, 2)

    duration = round(time.monotonic() - t0, 2)

    # ── Summary aggregation ────────────────────────────────────────
    ok_count, failed_count, skipped_count = 0, 0, 0
    total_findings = 0
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
               "INFO": 0, "POSITIVE": 0}
    for tool_name, r in results.items():
        if not isinstance(r, dict):
            continue
        if r.get("_failed"):
            failed_count += 1
            continue
        if r.get("_skipped") or r.get("skipped_reason"):
            skipped_count += 1
            continue
        ok_count += 1
        for f in (r.get("findings") or []):
            total_findings += 1
            sev = (f.get("severity") or "").upper()
            if sev in by_sev: by_sev[sev] += 1

    return {
        "module":       module_name,
        "target":       target,
        "started_at":   started_at,
        "duration_sec": duration,
        "concurrency":  concurrency,
        "total_tools":  len(tools),
        "tools":        results,
        "timing":       timings,
        "summary": {
            "ok":             ok_count,
            "failed":         failed_count,
            "skipped":        skipped_count,
            "total_findings": total_findings,
            "by_severity":    by_sev,
        },
    }


# ─────────────────────────────────────────────────────────────────
# STREAMING VARIANT — for Cloudflare-fronted dashboards
# ─────────────────────────────────────────────────────────────────
# Cloudflare's free tier kills any connection that takes >100s to send
# its FIRST byte. The buffered run_module_parallel above collects all 41
# tool results before returning, so first byte = last byte = ~60-120s in.
# That always exceeds the 100s TTFB ceiling and the request 504s.
#
# This generator yields ONE newline-delimited JSON object per tool the
# moment it completes (plus opening + closing summary events). First byte
# goes out within ~1-3s when whois/dns/dnsrecon finish — well under the
# 100s ceiling — and Cloudflare keeps the connection alive as long as
# bytes keep flowing.
#
# Event types yielded (one per line, NDJSON):
#   {"event":"scan_started", "module":..., "target":..., "total_tools":...}
#   {"event":"tool_complete", "tool":..., "duration_sec":..., "result":{...}}
#   {"event":"scan_complete", "duration_sec":..., "summary":{...}, "timing":{...}}
async def run_module_streaming(
    target: str,
    tools: list[tuple[str, str]],
    module_name: str = "recon",
    concurrency: int = 8,
    auth_cookie: Optional[str] = None,
    auth_bearer: Optional[str] = None,
    extra_body: Optional[dict] = None,
    jwt_token: Optional[str] = None,
) -> AsyncIterator[bytes]:
    """NDJSON-streaming version of run_module_parallel. Yields utf-8 bytes."""
    started_at = datetime.datetime.utcnow().isoformat() + "Z"
    t0 = time.monotonic()

    base_body: dict = {"target": target}
    if auth_cookie: base_body["auth_cookie"] = auth_cookie
    if auth_bearer: base_body["auth_bearer"] = auth_bearer
    if extra_body:  base_body.update(extra_body)

    internal_headers: dict = {}
    if jwt_token:
        internal_headers["Authorization"] = f"Bearer {jwt_token}"

    # Emit opening event IMMEDIATELY so first byte goes out within ~1ms of
    # the request reaching FastAPI. Cloudflare's TTFB clock stops here.
    opening = {
        "event":       "scan_started",
        "module":      module_name,
        "target":      target,
        "started_at":  started_at,
        "concurrency": concurrency,
        "total_tools": len(tools),
        "tool_names":  [name for name, _ in tools],
    }
    yield (json.dumps(opening) + "\n").encode("utf-8")

    limits = httpx.Limits(
        max_keepalive_connections=concurrency * 2,
        max_connections=concurrency * 3,
    )
    sem = asyncio.Semaphore(concurrency)

    # Accumulate results so we can emit the final summary
    results: dict = {}
    timings: dict = {}

    async with httpx.AsyncClient(
        base_url=_INTERNAL_BASE,
        limits=limits,
        timeout=httpx.Timeout(_PER_TOOL_TIMEOUT, connect=10.0),
        verify=False,
    ) as client:
        # KEEPALIVE-V1 — Cloudflare's idle-connection timeout (~100s between
        # bytes) was killing scans where the slowest tool (gobuster) finished
        # >100s after the second-slowest. Emit a heartbeat event every 15s so
        # the proxy sees data flowing even during long waits.
        task_objs = [
            asyncio.create_task(_dispatch_one(
                client, tool_name, endpoint, base_body, sem,
                headers=internal_headers))
            for tool_name, endpoint in tools
        ]
        pending = set(task_objs)
        while pending:
            done_set, pending = await asyncio.wait(
                pending, timeout=15.0, return_when=asyncio.FIRST_COMPLETED)
            if not done_set:
                # 15s elapsed with no tool finishing — emit heartbeat
                hb = {
                    "event":        "heartbeat",
                    "elapsed_sec":  round(time.monotonic() - t0, 2),
                    "completed":    len(results),
                    "total":        len(tools),
                    "in_flight":    len(pending),
                }
                yield (json.dumps(hb) + "\n").encode("utf-8")
                continue
            for task in done_set:
                tool_name, result, dur = task.result()
                results[tool_name] = result
                timings[tool_name] = round(dur, 2)
                event = {
                    "event":        "tool_complete",
                    "tool":         tool_name,
                    "duration_sec": round(dur, 2),
                    "result":       result,
                }
                yield (json.dumps(event) + "\n").encode("utf-8")

    # Final summary aggregation
    ok_count, failed_count, skipped_count = 0, 0, 0
    total_findings = 0
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
               "INFO": 0, "POSITIVE": 0}
    for r in results.values():
        if not isinstance(r, dict): continue
        if r.get("_failed"):
            failed_count += 1; continue
        if r.get("_skipped") or r.get("skipped_reason"):
            skipped_count += 1; continue
        ok_count += 1
        for f in (r.get("findings") or []):
            total_findings += 1
            sev = (f.get("severity") or "").upper()
            if sev in by_sev: by_sev[sev] += 1

    closing = {
        "event":        "scan_complete",
        "module":       module_name,
        "target":       target,
        "duration_sec": round(time.monotonic() - t0, 2),
        "total_tools":  len(tools),
        "timing":       timings,
        "summary": {
            "ok":             ok_count,
            "failed":         failed_count,
            "skipped":        skipped_count,
            "total_findings": total_findings,
            "by_severity":    by_sev,
        },
    }
    yield (json.dumps(closing) + "\n").encode("utf-8")
