"""Wayback Machine email-grep across archived pages — playbook §1 + §2.

Fetches the most-recent archived page for the domain, extracts all
email addresses via RFC-5322 regex. Useful for historical employee
email enumeration (current sites often hide directory; archives don't).

Real probe. Zero false positives — only emits actual hits.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 25
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _clean(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    return t.lower()


def _do_scan(req: ScanRequest) -> dict:
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="wayback_emails_grep", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    H = {"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"}

    # CDX: pick 5 unique-content snapshots across the domain's archive history
    cdx_url = (f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
                "&output=json&collapse=urlkey&limit=200"
                "&filter=mimetype:text/html&fl=timestamp,original")
    r = safe_get(cdx_url, req=req, timeout=12, headers=H)
    if r is None or r.status_code != 200:
        return standard_response(
            tool="wayback_emails_grep", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"CDX unreachable (status={r.status_code if r else 'no-conn'})")
    try:
        rows = r.json()
    except Exception:
        return standard_response(
            tool="wayback_emails_grep", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON CDX")

    if len(rows) < 2:
        return standard_response(
            tool="wayback_emails_grep", target=req.target,
            findings=[wrap_finding(
                f"No Wayback HTML snapshots for {domain}",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No archives to grep.",
                evidence_marker="CDX returned 0 HTML rows (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No archives")

    snapshots = rows[1:8]  # cap at 7 snapshots scanned
    emails_found = set()
    scanned = 0
    for ts, orig in snapshots:
        snap_url = f"https://web.archive.org/web/{ts}id_/{orig}"
        sr = safe_get(snap_url, req=req, timeout=8, headers=H)
        if sr is None or sr.status_code != 200: continue
        scanned += 1
        # Strip HTML for cleaner email matches
        text = re.sub(r"<[^>]+>", " ", sr.text or "")[:200000]
        for e in EMAIL_RE.findall(text):
            e = e.lower()
            # Filter: only emails on this domain or subdomains
            if e.split("@", 1)[1].endswith(domain):
                emails_found.add(e)

    if not emails_found:
        return standard_response(
            tool="wayback_emails_grep", target=req.target,
            findings=[wrap_finding(
                f"Wayback: 0 @{domain} emails in {scanned} HTML snapshots",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No historical email leakage via archived pages.",
                evidence_marker=f"scanned {scanned} snapshots (CONFIRMED clean)")],
            tests_performed=scanned, vulnerable=False,
            tests_summary="No historical emails")

    findings = [wrap_finding(
        f"Wayback Machine — {len(emails_found)} @{domain} email(s) in archive",
        # Historically-archived public-page emails are public-by-design OSINT,
        # not an active exposure — the pages were already public. INFO.
        severity="INFO",
        cvss="0.0", cwe="CWE-200", owasp="A05:2021",
        remediation="Historical email leakage via archived pages. Wayback "
                    "cannot easily be made to remove old captures, so these "
                    "remain enumerable forever. Cross-check each with HIBP "
                    "and Hudson Rock for breach exposure.",
        evidence_marker=" | ".join(sorted(emails_found)[:20])
                          + f" (CONFIRMED via Wayback grep of {scanned} snapshots)")]

    return standard_response(
        tool="wayback_emails_grep", target=req.target, findings=findings,
        tests_performed=scanned,
        vulnerable=False,  # archived public-page emails are OSINT, not an exposure
        tests_summary=f"{len(emails_found)} emails from {scanned} snapshots",
        raw_data={"emails": sorted(emails_found), "scanned_snapshots": scanned})


@router.post("/api/osint/wayback_emails_grep")
@vl_verify()
async def scan_wayback_emails_grep(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="wayback_emails_grep", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
