"""urlscan.io free public search — playbook §4 (URL reputation slice).

urlscan.io has a free public-search endpoint that returns previously-scanned
URLs matching a domain. Strong source of historical malware-URL data,
phishing kit patterns, and what other researchers have publicly inspected.

Real probe. Zero false positives.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify
from tools._core import grade

router = APIRouter()
WALL_CLOCK_S = 12


def _clean(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    return t.lower()


def _do_scan(req: ScanRequest) -> dict:
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="urlscan_io_search", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    H = {"User-Agent": "VulnusLab-OSINT/1.0"}
    if req.auth_bearer:
        H["API-Key"] = req.auth_bearer

    q = f'domain:"{domain}" OR page.domain:"{domain}"'
    r = safe_get(
        f"https://urlscan.io/api/v1/search/?q={q}&size=25",
        req=req, timeout=10, headers=H)
    if r is None or r.status_code == 429:
        return standard_response(
            tool="urlscan_io_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"urlscan status {r.status_code if r else 'no-conn'} (rate-limited)")
    if r.status_code != 200:
        return standard_response(
            tool="urlscan_io_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"urlscan status {r.status_code}")

    try: data = r.json()
    except Exception:
        return standard_response(
            tool="urlscan_io_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON urlscan")

    results = data.get("results", []) or []
    if not results:
        return standard_response(
            tool="urlscan_io_search", target=req.target,
            findings=[wrap_finding(
                f"urlscan.io: 0 prior scans for {domain}",
                severity=grade.protective(), cwe="CWE-1395",
                remediation="No historical urlscan record. Domain hasn't been "
                            "publicly investigated. If your domain has any "
                            "exposed assets you don't want indexed: just don't "
                            "submit to urlscan.",
                evidence_marker="urlscan returned 0 hits (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No urlscan history")

    # Check for malicious verdicts in results
    malicious = [r for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious")]
    page_urls = [r.get("page", {}).get("url", "?")[:80] for r in results[:10]]

    findings = []
    if malicious:
        findings.append(wrap_finding(
            f"urlscan FLAGGED — {len(malicious)} scan(s) on {domain} marked malicious",
            severity=(sev := grade.exposure(confirmed=True, impact='enables')),
            cvss=grade.cvss_for(sev), cwe="CWE-829",
            owasp="A06:2021",
            remediation="Public scans of this domain returned malicious verdict. "
                        "Investigate each scan ID at https://urlscan.io/result/<uuid>. "
                        "If your domain: rotate any compromised pages, check for "
                        "phishing kits, audit recent uploads.",
            evidence_marker=" | ".join(
                f"{m.get('task',{}).get('time','?')[:10]} {m.get('page',{}).get('url','?')[:60]}"
                for m in malicious[:5]
            ) + " (CONFIRMED via urlscan.io)"))

    findings.append(wrap_finding(
        f"urlscan.io: {len(results)} prior scan(s) for {domain}",
        severity=grade.protective() if not malicious else grade.info(), cwe="CWE-200",
        remediation="Public scan history. Review entries for unusual paths / "
                    "phishing-clone attempts. Cross-reference with phishtank.",
        evidence_marker=f"sample: {' | '.join(page_urls[:6])}"))

    return standard_response(
        tool="urlscan_io_search", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(malicious),
        tests_summary=f"urlscan: {len(results)} total ({len(malicious)} malicious)",
        raw_data={"total": len(results), "malicious_count": len(malicious),
                   "sample_urls": page_urls})


@router.post("/api/osint/urlscan_io_search")
@vl_verify()
async def scan_urlscan_io_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="urlscan_io_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
