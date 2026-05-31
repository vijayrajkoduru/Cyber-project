"""censys_hosts_search — Censys hosts API (free tier with key)."""
import asyncio, base64
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req):
    q = (req.target or "").strip()
    creds = (req.auth_bearer or "").strip()
    if ":" not in creds:
        return standard_response(tool="censys_hosts_search", target=req.target,
            findings=[wrap_finding(
                "Censys hosts search requires API_ID:API_SECRET",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Free 250 queries/mo at search.censys.io. Pass "
                            "auth_bearer='API_ID:API_SECRET'.",
                evidence_marker=f"query: {q}")],
            tests_performed=0, vulnerable=False, tests_summary="advisory")
    auth = base64.b64encode(creds.encode()).decode()
    r = safe_get(f"https://search.censys.io/api/v2/hosts/search?q={q}&per_page=25",
        req=req, timeout=10,
        headers={"Authorization": f"Basic {auth}",
                  "User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(tool="censys_hosts_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"Censys {r.status_code if r else 'no-conn'}")
    try: data = r.json()
    except Exception:
        return standard_response(tool="censys_hosts_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False, skipped_reason="non-JSON")
    hits = data.get("result", {}).get("hits", [])
    return standard_response(tool="censys_hosts_search", target=req.target,
        findings=[wrap_finding(
            f"Censys hosts: {len(hits)} hit(s) for '{q}'",
            severity="POSITIVE", cwe="CWE-200",
            remediation="Cross-reference with Shodan + FOFA + ZoomEye.",
            evidence_marker=f"hits={len(hits)}")],
        tests_performed=1, vulnerable=False,
        tests_summary=f"Censys: {len(hits)}",
        raw_data={"hits": len(hits)})


@router.post("/api/osint/censys_hosts_search")
async def scan_censys_hosts_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(tool="censys_hosts_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
