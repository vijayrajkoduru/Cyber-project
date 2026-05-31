"""snusbase_search — Snusbase paste/breach search (paid API)."""
import asyncio, json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_post, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    q = (req.target or "").strip()
    key = (req.auth_bearer or "").strip()
    if not key:
        return standard_response(tool="snusbase_search", target=req.target,
            findings=[wrap_finding(
                "Snusbase requires API key via auth_bearer",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Subscribe at snusbase.com ($25/mo entry). Pass "
                            "auth_bearer=API_KEY. Snusbase has overlapping "
                            "corpus with DeHashed + IntelX; useful as triangulation.",
                evidence_marker=f"query: {q} | no API key")],
            tests_performed=0, vulnerable=False, tests_summary="Snusbase advisory")
    r = safe_post("https://api.snusbase.com/v3/search",
        req=req, timeout=10,
        headers={"Auth": key, "Content-Type": "application/json"},
        data=json.dumps({"terms": [q], "types": ["email", "username", "lastip"]}))
    if r is None or r.status_code != 200:
        return standard_response(tool="snusbase_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Snusbase {r.status_code if r else 'no-conn'}")
    try: data = r.json()
    except Exception:
        return standard_response(tool="snusbase_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False, skipped_reason="non-JSON")
    total = data.get("size", 0)
    return standard_response(
        tool="snusbase_search", target=req.target,
        findings=[wrap_finding(
            f"Snusbase: {total} record(s) for '{q}'",
            severity="HIGH" if total > 0 else "POSITIVE",
            cvss="7.5" if total > 0 else "0.0",
            cwe="CWE-359", owasp="A07:2021",
            remediation="If hits — force password rotation + audit recent logins.",
            evidence_marker=f"size={total} (CONFIRMED via Snusbase)")],
        tests_performed=1, vulnerable=bool(total),
        tests_summary=f"Snusbase: {total} records", raw_data={"total": total})


@router.post("/api/osint/snusbase_search")
async def scan_snusbase_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(tool="snusbase_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
