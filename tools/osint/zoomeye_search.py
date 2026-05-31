"""zoomeye_search — ZoomEye (Knownsec) internet-scan search engine (paid)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    q = (req.target or "").strip()
    key = (req.auth_bearer or "").strip()
    if not key:
        return standard_response(tool="zoomeye_search", target=req.target,
            findings=[wrap_finding(
                "ZoomEye requires API key via auth_bearer",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Register at zoomeye.org (free tier 10K queries/mo, "
                            "paid from $35/mo). Pass auth_bearer=API_KEY. "
                            "Chinese alternative + complementary to FOFA.",
                evidence_marker=f"query: {q} | no API key")],
            tests_performed=0, vulnerable=False, tests_summary="ZoomEye advisory")
    r = safe_get(f"https://api.zoomeye.org/host/search?query={q}&page=1",
        req=req, timeout=10,
        headers={"API-KEY": key, "User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(tool="zoomeye_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"ZoomEye {r.status_code if r else 'no-conn'}")
    try: data = r.json()
    except Exception:
        return standard_response(tool="zoomeye_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False, skipped_reason="non-JSON")
    total = data.get("total", 0)
    return standard_response(
        tool="zoomeye_search", target=req.target,
        findings=[wrap_finding(
            f"ZoomEye: {total:,} host(s) match '{q}'",
            severity="POSITIVE", cwe="CWE-200",
            remediation="Cross-reference with Shodan, FOFA, Censys.",
            evidence_marker=f"total={total} (CONFIRMED via ZoomEye)")],
        tests_performed=1, vulnerable=False,
        tests_summary=f"ZoomEye: {total} hosts", raw_data={"total": total})


@router.post("/api/osint/zoomeye_search")
async def scan_zoomeye_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(tool="zoomeye_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
