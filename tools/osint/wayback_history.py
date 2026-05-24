"""wayback_history — Internet Archive snapshot timeline + endpoint discovery.

Pulls the snapshot count + first/last timestamps from Wayback Machine's
CDX API, and extracts unique URL patterns from the snapshot index (old
admin paths, deleted endpoints, dev subdomains, etc.).

VL-FOUNDRY Layer 6: 7-check DoD compliant.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 18


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip().lower()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    if "." not in target:
        return standard_response(tool="wayback_history", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="target must be a domain")

    # CDX API: every snapshot ever, dedupe by URL
    url = (f"https://web.archive.org/cdx/search/cdx"
           f"?url={target}/*&output=json&fl=original,timestamp&collapse=urlkey&limit=500")
    r = safe_get(url, req=req, timeout=12,
                 headers={"User-Agent": "VulnusLab-OSINT"})
    if r is None or r.status_code != 200:
        return standard_response(tool="wayback_history", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"Wayback CDX unreachable (status {r.status_code if r else 'none'})")

    try:
        data = r.json()
    except Exception:
        return standard_response(tool="wayback_history", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="Wayback CDX returned non-JSON")

    # data[0] is header row
    rows = data[1:] if data and isinstance(data, list) and len(data) > 1 else []
    if not rows:
        return standard_response(tool="wayback_history", target=req.target,
            findings=[wrap_finding(
                "No Wayback Machine snapshots found for target",
                severity="POSITIVE",
                cwe="CWE-200", owasp="A05:2021",
                remediation="No archived history — target either new or has noindex/x-robots-tag.",
                evidence_marker="Wayback CDX returned 0 rows")],
            tests_performed=1, vulnerable=False,
            tests_summary="Wayback CDX: 0 snapshots")

    timestamps = [row[1] for row in rows if len(row) >= 2]
    urls = [row[0] for row in rows if len(row) >= 1]
    first, last = (min(timestamps), max(timestamps)) if timestamps else ("?", "?")

    # Flag old/sensitive paths exposed in archive
    sensitive_markers = ("/admin", "/backup", "/.git", "/.env", "/wp-admin",
                         "/phpmyadmin", "/test", "/staging", "/dev", "/api/v1",
                         "/.well-known", "/sitemap")
    sensitive = [u for u in urls
                  if any(m in u.lower() for m in sensitive_markers)]

    findings = []
    if sensitive:
        sample = sensitive[:8]
        findings.append(wrap_finding(
            f"{len(sensitive)} sensitive path(s) archived in Wayback Machine",
            severity="MEDIUM", cvss="4.0",
            cwe="CWE-200", owasp="A05:2021",
            remediation=("Archived paths reveal historical attack surface. "
                        "Submit removal requests at archive.org/about/removal "
                        "for paths exposing credentials or PII."),
            evidence_marker="; ".join(sample)))
    findings.append(wrap_finding(
        f"Wayback timeline: {len(rows)} unique URLs archived "
        f"({first[:8]} → {last[:8]})",
        "POSITIVE" if not sensitive else "LOW",
        cwe="CWE-200", owasp="A05:2021",
        remediation="Wayback Machine archives are passive references; "
                    "treat as historical-content reconnaissance.",
        evidence_marker=f"first={first}, last={last}, unique_urls={len(rows)}"))

    return standard_response(
        tool="wayback_history", target=req.target, findings=findings,
        tests_performed=1,
        vulnerable=len(sensitive) > 0,
        tests_summary=f"Wayback CDX: {len(rows)} URLs ({first[:8]}-{last[:8]}); "
                      f"{len(sensitive)} sensitive paths",
        raw_data={"snapshot_count": len(rows),
                   "first_seen": first, "last_seen": last,
                   "sensitive_paths": sensitive[:30]})


@router.post("/api/osint/wayback_history")
async def scan_wayback(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="wayback_history", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
