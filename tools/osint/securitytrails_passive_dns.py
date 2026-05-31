"""securitytrails_passive_dns — SecurityTrails passive-DNS + subdomain history (paid)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    domain = (req.target or "").strip().lstrip("@")
    key = (req.auth_bearer or "").strip()
    if not key:
        return standard_response(tool="securitytrails_passive_dns", target=req.target,
            findings=[wrap_finding(
                "SecurityTrails requires API key via auth_bearer",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Register at securitytrails.com (50/mo free, $50/mo "
                            "paid). Pass auth_bearer=API_KEY. Deeper subdomain + "
                            "passive-DNS history than crt.sh.",
                evidence_marker=f"domain: {domain} | no API key")],
            tests_performed=0, vulnerable=False, tests_summary="SecurityTrails advisory")
    r = safe_get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        req=req, timeout=8,
        headers={"APIKEY": key, "User-Agent": "VulnusLab-OSINT/1.0",
                  "Accept": "application/json"})
    if r is None or r.status_code != 200:
        return standard_response(tool="securitytrails_passive_dns", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"ST {r.status_code if r else 'no-conn'}")
    try: data = r.json()
    except Exception:
        return standard_response(tool="securitytrails_passive_dns", target=req.target,
            findings=[], tests_performed=1, vulnerable=False, skipped_reason="non-JSON")
    subs = data.get("subdomains", []) or []
    return standard_response(
        tool="securitytrails_passive_dns", target=req.target,
        findings=[wrap_finding(
            f"SecurityTrails: {len(subs)} subdomain(s) for {domain}",
            severity="POSITIVE", cwe="CWE-200",
            remediation="Cross-reference with crt.sh + Amass.",
            evidence_marker=f"sample: {', '.join(subs[:10])}")],
        tests_performed=1, vulnerable=False,
        tests_summary=f"ST: {len(subs)} subs",
        raw_data={"subdomain_count": len(subs), "sample": subs[:30]})


@router.post("/api/osint/securitytrails_passive_dns")
async def scan_securitytrails_passive_dns(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(tool="securitytrails_passive_dns", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
