"""intelx_search — IntelligenceX paste/leak search (paid API)."""
import asyncio, json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_post, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 12


def _do_scan(req: ScanRequest) -> dict:
    q = (req.target or "").strip()
    key = (req.auth_bearer or "").strip()
    if not key:
        return standard_response(
            tool="intelx_search", target=req.target,
            findings=[wrap_finding(
                "IntelX search requires API key via auth_bearer",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Register at https://intelx.io. Free tier 50 "
                            "queries/mo, paid from $99/mo. Pass auth_bearer=API_KEY. "
                            "IntelX corpus includes pastes, leaks, dark-web archives.",
                evidence_marker=f"query: {q} | no API key")],
            tests_performed=0, vulnerable=False,
            tests_summary="IntelX advisory")
    r = safe_post("https://2.intelx.io/intelligent/search",
        req=req, timeout=10,
        headers={"x-key": key, "Content-Type": "application/json",
                  "User-Agent": "VulnusLab-OSINT/1.0"},
        data=json.dumps({"term": q, "maxresults": 50}))
    if r is None or r.status_code != 200:
        return standard_response(
            tool="intelx_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"IntelX status {r.status_code if r else 'no-conn'}")
    try: data = r.json()
    except Exception:
        return standard_response(tool="intelx_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False, skipped_reason="non-JSON")
    return standard_response(
        tool="intelx_search", target=req.target,
        findings=[wrap_finding(
            f"IntelX query accepted: id={data.get('id', '?')[:16]}",
            severity="INFO", cwe="CWE-200",
            remediation="Query ID can be retrieved via /intelligent/search/result?id=ID.",
            evidence_marker=f"IntelX search initiated (CONFIRMED)")],
        tests_performed=1, vulnerable=False,
        tests_summary="IntelX search initiated",
        raw_data=data if isinstance(data, dict) else {})


@router.post("/api/osint/intelx_search")
@vl_verify()
async def scan_intelx_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(tool="intelx_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
