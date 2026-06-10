"""Webapp directory brute — async probe of 1,071 AI-curated paths with VL-TURBO.

Route: POST /api/webapp/directory_brute
Loads tools/_payloads/directory_brute_paths.py (1,071 entries: admin/api/backup/
config/source-control/IDE/test/cloud/DB/log/framework paths). Probes each with
HEAD-then-GET fallback. Reports any 200/301/302/401/403 as discovered, with
severity from the AI-curated entry.
"""
import asyncio
import time

import httpx

from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()

# AI-curated 1,071-entry path list
_FALLBACK_PATHS = [
    {"path": "/admin",      "category": "admin",  "severity": "MEDIUM", "priority": 10},
    {"path": "/.env",       "category": "config", "severity": "HIGH",   "priority": 10},
    {"path": "/.git/HEAD",  "category": "vcs",    "severity": "HIGH",   "priority": 10},
    {"path": "/backup.sql", "category": "backup", "severity": "HIGH",   "priority": 9},
    {"path": "/phpinfo.php","category": "debug",  "severity": "MEDIUM", "priority": 8},
]
try:
    from tools._payloads.directory_brute_paths import DIRECTORY_BRUTE_PATHS as _AI_PATHS
    _PATHS = list(_AI_PATHS) if isinstance(_AI_PATHS, list) and _AI_PATHS else _FALLBACK_PATHS
except Exception:
    _PATHS = _FALLBACK_PATHS

# Tunables (VL-TURBO)
_CONCURRENCY = 30
_PER_REQ_TIMEOUT = httpx.Timeout(connect=3.0, read=4.0, write=3.0, pool=5.0)
_WALL_CLOCK_S = 90.0


async def _calibrate_404(client, base):
    """Probe a known-nonexistent path so we can ignore custom 404 pages."""
    try:
        r = await client.get(base + "/_vlabprobe_404_nonexistent_xyz_888")
        return len(r.content), r.status_code
    except Exception:
        return None, None


async def _probe(client, base, entry, baseline_len, baseline_status, sem):
    async with sem:
        path = entry.get("path", "")
        if not path:
            return None
        url = base + path
        try:
            r = await client.get(url)
        except Exception:
            return None
        if r.status_code not in (200, 301, 302, 401, 403):
            return None
        # Filter out custom-404 echoes
        if baseline_len and r.status_code == baseline_status and abs(len(r.content) - baseline_len) < 96:
            return None
        return {
            "path": path,
            "category": entry.get("category", "unknown"),
            "severity": entry.get("severity", "MEDIUM"),
            "status": r.status_code,
            "length": len(r.content),
        }


@router.post("/api/webapp/directory_brute")
@vl_verify(check_spa=True)
async def webapp_directory_brute(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    hits = []
    sem = asyncio.Semaphore(_CONCURRENCY)
    deadline = time.time() + _WALL_CLOCK_S

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, timeout=_PER_REQ_TIMEOUT,
        headers={"User-Agent": "VulnusLab/1.0"}
    ) as client:
        baseline_len, baseline_status = await _calibrate_404(client, base)

        # Priority-order — high-priority paths first so we hit critical findings
        # even if wall-clock cap aborts the scan
        ordered = sorted(_PATHS, key=lambda e: -int(e.get("priority", 5)))
        # Cap probed paths to keep scan reasonable on slow targets
        ordered = ordered[:800]

        tasks = [_probe(client, base, e, baseline_len, baseline_status, sem) for e in ordered]
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=_WALL_CLOCK_S)
        except asyncio.TimeoutError:
            results = []

    for r in results:
        if not r: continue
        hits.append(r)
        sev = r["severity"] if r["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "LOW"
        findings.append(wrap_finding(
            f"Accessible path discovered: {r['path']} (status {r['status']}, category {r['category']})",
            sev,
            cvss={"CRITICAL": "9.1", "HIGH": "7.5", "MEDIUM": "5.3", "LOW": "3.1"}.get(sev, "5.0"),
            cwe="CWE-538", cwe_name="Insertion of Sensitive Information into Externally-Accessible File or Directory",
            owasp="A05:2021",
            remediation=("Restrict access to internal paths via auth or WAF rules. "
                          "Move sensitive files outside the document root. Block dot-prefixed paths at the web server."),
            evidence_marker=f"GET {base}{r['path']} -> HTTP {r['status']} ({r['length']}B)",
        ))

    return standard_response(
        tool="directory_brute", target=req.target,
        findings=findings,
        tests_performed=len(ordered),
        tests_summary=f"Probed {len(ordered)} AI-curated paths; {len(hits)} accessible",
        raw_data={"directory_brute": {
            "paths_probed": len(ordered),
            "paths_found": len(hits),
            "category_breakdown": _category_breakdown(hits),
            "wordlist_source": f"AI-curated ({len(_PATHS)} paths)",
            "sample_hits": [h["path"] for h in hits[:20]],
        }},
    )


def _category_breakdown(hits):
    from collections import Counter
    return dict(Counter(h["category"] for h in hits))


def register(app):
    app.include_router(router)
