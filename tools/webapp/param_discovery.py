"""Webapp parameter discovery — Arjun-style hidden-parameter probe.

Route: POST /api/webapp/param_discovery
Loads tools/_payloads/param_discovery_names.py (557 AI-curated parameter names).
Probes by adding each candidate as a query parameter and watching for response
size/status delta vs baseline. Reports params that change response behavior.
"""
import asyncio

import httpx

from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()

_FALLBACK_NAMES = [
    {"name": "debug",    "category": "debug",    "priority": 9},
    {"name": "test",     "category": "debug",    "priority": 8},
    {"name": "admin",    "category": "admin",    "priority": 9},
    {"name": "id",       "category": "user",     "priority": 9},
    {"name": "callback", "category": "callback", "priority": 7},
    {"name": "url",      "category": "path",     "priority": 8},
    {"name": "redirect", "category": "callback", "priority": 8},
]
try:
    from tools._payloads.param_discovery_names import PARAM_DISCOVERY_NAMES as _AI_NAMES
    _NAMES = list(_AI_NAMES) if isinstance(_AI_NAMES, list) and _AI_NAMES else _FALLBACK_NAMES
except Exception:
    _NAMES = _FALLBACK_NAMES

_CONCURRENCY = 25
_TIMEOUT = httpx.Timeout(connect=3.0, read=4.0, write=3.0, pool=5.0)
_WALL_CLOCK_S = 60.0
_SIZE_DELTA_THRESHOLD = 100


async def _probe(client, base, name, baseline_size, baseline_status, sem):
    async with sem:
        try:
            r = await client.get(f"{base}/?{name}=VLPROBE")
        except Exception:
            return None
        if r.status_code != baseline_status:
            return {"name": name, "delta_type": "status",
                    "baseline": baseline_status, "observed": r.status_code,
                    "length": len(r.content)}
        if abs(len(r.content) - baseline_size) >= _SIZE_DELTA_THRESHOLD:
            return {"name": name, "delta_type": "size",
                    "baseline": baseline_size, "observed": len(r.content),
                    "status": r.status_code,
                    "delta": abs(len(r.content) - baseline_size)}
        return None


@router.post("/api/webapp/param_discovery")
@vl_verify(check_spa=True)
async def webapp_param_discovery(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    hits = []
    sem = asyncio.Semaphore(_CONCURRENCY)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, timeout=_TIMEOUT,
        headers={"User-Agent": "VulnusLab/1.0"}
    ) as client:
        try:
            base_r = await client.get(base + "/")
        except Exception:
            return standard_response(tool="param_discovery", target=req.target,
                findings=[], tests_performed=0,
                skipped_reason="Could not connect to target for baseline")
        baseline_size = len(base_r.content)
        baseline_status = base_r.status_code

        ordered = sorted(_NAMES, key=lambda e: -int(e.get("priority", 5)))[:500]
        tasks = [_probe(client, base, e.get("name", ""), baseline_size, baseline_status, sem)
                 for e in ordered if e.get("name")]
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=_WALL_CLOCK_S)
        except asyncio.TimeoutError:
            results = []

    for r in results:
        if not r: continue
        hits.append(r)

    if len(hits) >= 3:
        size_hits = [h for h in hits if h["delta_type"] == "size"]
        status_hits = [h for h in hits if h["delta_type"] == "status"]
        if status_hits:
            findings.append(wrap_finding(
                f"Hidden parameters cause status-code change ({len(status_hits)} found)",
                "MEDIUM", cvss="5.3", cwe="CWE-200",
                cwe_name="Exposure of Sensitive Information",
                owasp="A05:2021",
                remediation=("Hidden parameters that change server behavior suggest dev/debug "
                              "surface or unused features still wired in. Audit each one; "
                              "remove if unused."),
                evidence_marker=f"Sample params: {', '.join(h['name'] for h in status_hits[:8])}",
            ))
        if size_hits:
            findings.append(wrap_finding(
                f"Hidden parameters cause response-size change ({len(size_hits)} found)",
                "LOW", cvss="3.7", cwe="CWE-200", owasp="A05:2021",
                remediation="Audit each — likely echo/reflection. Verify no sensitive data leaks.",
                evidence_marker=f"Sample params: {', '.join(h['name'] for h in size_hits[:8])}",
            ))

    return standard_response(
        tool="param_discovery", target=req.target,
        findings=findings,
        tests_performed=len(ordered),
        tests_summary=f"Probed {len(ordered)} AI-curated parameter names; {len(hits)} caused response delta",
        raw_data={"param_discovery": {
            "params_probed": len(ordered),
            "params_found": len(hits),
            "wordlist_source": f"AI-curated ({len(_NAMES)} names)",
            "sample_params": [h["name"] for h in hits[:30]],
        }},
    )


def register(app):
    app.include_router(router)
