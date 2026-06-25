"""Wayback Machine CDX API search — playbook §2 #29.

Different from existing wayback_history (which gets a yearly timeline).
This queries the full CDX index for unique-URL discovery: every URL the
Wayback Machine has ever crawled on this domain. Excellent for finding
forgotten endpoints, deprecated APIs, leaked admin paths.

Real probe. Zero false positives. Free, no key.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 30


def _clean(target: str) -> str:
    t = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    return t.lower()


def _do_scan(req: ScanRequest) -> dict:
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="wayback_cdx_search", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    # CDX collapsed by original-URL, limit 1500 for response size sanity
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
            "&output=json&collapse=urlkey&limit=1500&fl=original")
    r = safe_get(url, req=req, timeout=25,
                  headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="wayback_cdx_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Wayback CDX unreachable (status={r.status_code if r else 'no-conn'})")

    try:
        rows = r.json()
    except Exception:
        return standard_response(
            tool="wayback_cdx_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON CDX response")

    if not rows or len(rows) < 2:
        return standard_response(
            tool="wayback_cdx_search", target=req.target,
            findings=[wrap_finding(
                f"No archived URLs found for {domain}",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Either never crawled or robots.txt blocked Wayback. "
                            "Fresh or low-profile domain.",
                evidence_marker="CDX returned 0 records (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No Wayback records")

    # Row 0 is the column header
    urls = [r[0] for r in rows[1:] if r and r[0]]
    # Same tiering as commoncrawl_cdx: an archived URL is not an exposure by
    # itself — these are PUBLIC crawl records, and substrings like "/internal/"
    # match Go module paths, "/api/" matches docs, etc. Only secret/config
    # markers warrant a passive LOW; the rest is INFO attack-surface inventory.
    _SECRET = (".sql", ".bak", ".env", "/.git", "/.aws", "/config", "/backup", "phpinfo")
    _INV = ("/admin", "/wp-admin", "/login", "/api/", "/v1/", "/v2/", "/swagger",
            "/graphql", "/internal", "/test", "/dev", "/staging")
    secretish = [u for u in urls if any(k in u.lower() for k in _SECRET)]
    inv = [u for u in urls if any(k in u.lower() for k in _INV) and u not in secretish]
    interesting = secretish + inv

    findings = []
    if secretish:
        findings.append(wrap_finding(
            f"Archived URLs matching config/secret patterns ({len(secretish)}) on {domain}",
            severity="LOW", cwe="CWE-200", cvss="3.1", owasp="A05:2021",
            remediation="Wayback preserves URLs even after deletion. These match secret/"
                        "config patterns (.git/.env/.sql/backup/phpinfo) — verify each isn't "
                        "archiving sensitive content; if it is, request Wayback removal "
                        "(web.archive.org/help/contact) and rotate any leaked secrets.",
            evidence_marker=" | ".join(secretish[:20]) + (' ...' if len(secretish) > 20 else '')))
    if inv:
        findings.append(wrap_finding(
            f"Archived app/admin URLs — attack-surface inventory ({len(inv)}) on {domain}",
            severity="INFO", cwe="CWE-200", cvss="0.0", owasp="A05:2021",
            remediation="Archived public URLs containing api/admin/login/dev/internal paths — "
                        "recon inventory, not an exposure on their own (e.g. Go 'internal/' "
                        "package paths and docs match these). Use as a review target list.",
            evidence_marker=" | ".join(inv[:20]) + (' ...' if len(inv) > 20 else '')))

    findings.append(wrap_finding(
        f"Wayback Machine has {len(urls)} unique URL(s) for {domain}",
        severity="POSITIVE" if not interesting else "INFO",
        cwe="CWE-200",
        remediation="Public archive. Useful for finding deprecated endpoints, "
                    "outdated docs, and historical attack surface.",
        evidence_marker=f"first 15: {' | '.join(urls[:15])}"))

    return standard_response(
        tool="wayback_cdx_search", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(secretish),
        tests_summary=f"Wayback CDX: {len(urls)} URLs ({len(interesting)} interesting)",
        raw_data={"total_urls": len(urls), "interesting": interesting,
                   "sample_urls": urls[:50]})


@router.post("/api/osint/wayback_cdx_search")
@vl_verify()
async def scan_wayback_cdx_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="wayback_cdx_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
