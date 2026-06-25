"""Common Crawl CDX index search — playbook §2 #30.

Common Crawl is a massive (~300TB/month) public web crawl. CDX index
lets you query which URLs they've captured for any domain — across
hundreds of monthly indexes. Combined with Wayback CDX (which we already
have), gives near-complete passive URL discovery for free.

Real probe. Zero false positives. Free, no key. Slow due to CDX server load.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify
from tools._core import grade

router = APIRouter()
WALL_CLOCK_S = 40
# Use a recent monthly index — Common Crawl publishes one per month.
# 2024-30 is a stable known-good index; we list the latest known few and pick.
CDX_INDEX = "CC-MAIN-2024-46"


def _clean(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    return t.lower()


def _do_scan(req: ScanRequest) -> dict:
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="commoncrawl_cdx", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    url = (f"https://index.commoncrawl.org/{CDX_INDEX}-index"
            f"?url=*.{domain}/*&output=json&limit=400")
    r = safe_get(url, req=req, timeout=35,
                  headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="commoncrawl_cdx", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"CC CDX unreachable (status={r.status_code if r else 'no-conn'}) — "
                            f"CC servers are often overloaded; retry later")

    # Response is line-delimited JSON
    urls = set()
    statuses = []
    for line in (r.text or "").splitlines():
        line = line.strip()
        if not line: continue
        try:
            import json as _j
            d = _j.loads(line)
            u = d.get("url")
            if u: urls.add(u.split("?")[0].lower())
            statuses.append(d.get("status", "?"))
        except Exception:
            continue

    if not urls:
        return standard_response(
            tool="commoncrawl_cdx", target=req.target,
            findings=[wrap_finding(
                f"CC index {CDX_INDEX}: no captures for {domain}",
                severity=grade.protective(), cwe="CWE-200",
                remediation="Either domain not crawled in this index or genuinely "
                            "low-visibility. Try wayback_cdx_search for broader coverage.",
                evidence_marker=f"CC {CDX_INDEX} returned 0 records (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No CC captures")

    # A crawled URL is not an exposure by itself — these are PUBLIC crawl records.
    # Only secret/config markers warrant a (passive) LOW worth manual review;
    # api/admin/dev/test path substrings appear in countless benign public URLs,
    # so they are INFO attack-surface inventory, not a graded exposure.
    _SECRET = ("/.git", "/.env", "/config", "/backup", "phpinfo", ".sql", ".bak")
    _INV = ("/admin", "/api/", "/swagger", "/graphql", "/internal", "/staging",
            "/dev", "/test", "/v1/", "/v2/")
    secretish = sorted(u for u in urls if any(k in u for k in _SECRET))
    inv = sorted(u for u in urls if any(k in u for k in _INV) and u not in secretish)
    interesting = secretish + inv

    findings = []
    if secretish:
        findings.append(wrap_finding(
            f"Crawled URLs matching config/secret patterns ({len(secretish)})",
            severity=(sev := grade.hardening()), cwe="CWE-200",
            cvss=grade.cvss_for(sev), owasp="A05:2021",
            remediation="These public-crawl URLs match secret/config patterns (.git/.env/"
                        ".sql/backup/phpinfo). Passive evidence only — verify each isn't "
                        "actually serving sensitive content; if it is, remove it and rotate "
                        "any leaked secrets (crawl caches are hard to purge).",
            evidence_marker=" | ".join(secretish[:15]) + (' ...' if len(secretish) > 15 else '')))
    if inv:
        findings.append(wrap_finding(
            f"Crawled app/admin URLs — attack-surface inventory ({len(inv)})",
            severity=(sev := grade.inventory(len(inv))), cwe="CWE-200",
            cvss=grade.cvss_for(sev), owasp="A05:2021",
            remediation="Public URLs containing api/admin/dev/test paths — recon inventory, "
                        "not an exposure on their own. Use as a target list for deeper review.",
            evidence_marker=" | ".join(inv[:15]) + (' ...' if len(inv) > 15 else '')))

    findings.append(wrap_finding(
        f"Common Crawl {CDX_INDEX}: {len(urls)} unique URL(s) for {domain}",
        severity=grade.protective() if not interesting else grade.info(),
        cwe="CWE-200",
        remediation="Cross-reference with wayback_cdx_search for union coverage. "
                    "Each URL is a recon-target candidate.",
        evidence_marker=f"sample: {' | '.join(sorted(urls)[:10])}"))

    return standard_response(
        tool="commoncrawl_cdx", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(secretish),
        tests_summary=f"CC: {len(urls)} URLs ({len(interesting)} interesting)",
        raw_data={"url_count": len(urls), "interesting": interesting[:30],
                   "sample": sorted(urls)[:50], "index": CDX_INDEX})


@router.post("/api/osint/commoncrawl_cdx")
@vl_verify()
async def scan_commoncrawl_cdx(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="commoncrawl_cdx", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
