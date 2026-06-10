"""harvester_emails — passive email harvest from DuckDuckGo + Bing snippets.

Searches `"<target>" email` on DDG (no rate-limit) and Bing, regex-extracts
email addresses from result snippets. No keys, no accounts.

VL-FOUNDRY Layer 6: 7-check DoD compliant. Uses AI-curated EMAIL_REGEX
from tools._payloads.osint.email_patterns.
"""
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

try:
    from tools._payloads.osint.email_patterns import EMAIL_REGEX
except ImportError:
    EMAIL_REGEX = r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"

router = APIRouter()
WALL_CLOCK_S = 25

_SEARCH_ENGINES = [
    ("DuckDuckGo", "https://html.duckduckgo.com/html/?q={q}"),
    ("Bing",       "https://www.bing.com/search?q={q}"),
]


def _scrape_emails(url: str, target: str, req) -> tuple[set[str], str]:
    """Hit url, regex-extract emails matching target domain. Returns (emails, marker)."""
    r = safe_get(url, req=req, timeout=8,
                 headers={"User-Agent": "Mozilla/5.0 (VulnusLab OSINT)"})
    if r is None or r.status_code != 200:
        return set(), f"HTTP error from {url[:50]}"
    body = r.text or ""
    pattern = re.compile(EMAIL_REGEX)
    found = {m.lower() for m in pattern.findall(body)
             if target.lower() in m.lower()}
    return found, f"scraped {len(body)} bytes, {len(found)} target emails"


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip().lower()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    if "." not in target:
        return standard_response(tool="harvester_emails", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="target must be a domain")

    all_emails = set()
    markers = []
    queries = [f"\"{target}\" email", f"site:{target} contact"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = []
        for engine, tpl in _SEARCH_ENGINES:
            for q in queries:
                url = tpl.format(q=q.replace(' ', '+'))
                futs.append(pool.submit(_scrape_emails, url, target, req))
        for fut in futs:
            try:
                emails, marker = fut.result(timeout=10)
                all_emails.update(emails)
                markers.append(marker)
            except Exception:
                continue

    tests_performed = len(_SEARCH_ENGINES) * len(queries)
    findings = []
    if all_emails:
        sample = sorted(all_emails)[:20]
        sev = "MEDIUM" if len(all_emails) >= 5 else "LOW"
        findings.append(wrap_finding(
            f"{len(all_emails)} email(s) for {target} found in public search results",
            sev, cvss="4.0" if sev == "MEDIUM" else "2.5",
            cwe="CWE-200", owasp="A05:2021",
            remediation=("Replace high-traffic mailto: links with contact forms; "
                        "rotate any role-based email exposed (info@, admin@) that's "
                        "in a breach corpus."),
            evidence_marker=", ".join(sample)))
    else:
        findings.append(wrap_finding(
            "No org emails found via DDG/Bing snippets",
            severity="POSITIVE",
            cwe="CWE-200", owasp="A05:2021",
            remediation="Hygiene OK — no public email leakage via search snippets.",
            evidence_marker=f"{tests_performed} queries, 0 emails"))

    return standard_response(
        tool="harvester_emails", target=req.target, findings=findings,
        tests_performed=tests_performed,
        vulnerable=len(all_emails) > 0,
        tests_summary=f"DDG+Bing harvest: {tests_performed} queries, {len(all_emails)} unique emails",
        raw_data={"emails": sorted(all_emails)[:50]})


@router.post("/api/osint/harvester_emails")
@vl_verify()
async def scan_harvester(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="harvester_emails", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
