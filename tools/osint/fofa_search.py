"""fofa_search — FOFA Chinese internet-scan search engine (paid)."""
import asyncio, base64
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    q = (req.target or "").strip()
    creds = (req.auth_bearer or "").strip()
    if ":" not in creds:
        return standard_response(tool="fofa_search", target=req.target,
            findings=[wrap_finding(
                "FOFA requires email:api_key via auth_bearer",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Register at fofa.info (Chinese alternative to "
                            "Shodan). Pass auth_bearer as 'email@example.com:"
                            "FOFA_KEY'. Strong on .cn / APAC infrastructure.",
                evidence_marker=f"query: {q} | no API key")],
            tests_performed=0, vulnerable=False, tests_summary="FOFA advisory")
    email, key = creds.split(":", 1)
    qb64 = base64.b64encode(q.encode()).decode()
    r = safe_get(f"https://fofa.info/api/v1/search/all?email={email}&key={key}"
                  f"&qbase64={qb64}&size=20",
                  req=req, timeout=10,
                  headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(tool="fofa_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"FOFA {r.status_code if r else 'no-conn'}")
    try: data = r.json()
    except Exception:
        return standard_response(tool="fofa_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False, skipped_reason="non-JSON")
    if data.get("error"):
        return standard_response(tool="fofa_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"FOFA error: {data.get('errmsg','?')}")
    size = data.get("size", 0)
    return standard_response(
        tool="fofa_search", target=req.target,
        findings=[wrap_finding(
            f"FOFA: {size:,} host(s) match '{q}'",
            severity="POSITIVE", cwe="CWE-200",
            remediation="Cross-reference with Shodan + Censys for full picture.",
            evidence_marker=f"results={size} (CONFIRMED via FOFA)")],
        tests_performed=1, vulnerable=False,
        tests_summary=f"FOFA: {size} hosts", raw_data={"size": size})


@router.post("/api/osint/fofa_search")
async def scan_fofa_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(tool="fofa_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
