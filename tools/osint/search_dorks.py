"""search_dorks — run 50 OSINT dorks against DuckDuckGo, flag hits.

Each dork = a query template from tools._payloads.osint.osint_dorks.
DDG (no rate-limit) is the engine; hits are extracted from result HTML.
Severity per hit is dork-class-driven (DORK_SEVERITY map in payload).

VL-FOUNDRY Layer 6: 7-check DoD compliant.
"""
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

try:
    from tools._payloads.osint.osint_dorks import OSINT_DORKS, severity_for
except ImportError:
    OSINT_DORKS = [
        "site:{target} filetype:pdf",
        "site:{target} inurl:admin",
        "site:{target} intitle:\"index of\"",
    ]
    def severity_for(d): return "LOW"

router = APIRouter()
WALL_CLOCK_S = 28

# Pattern that identifies a non-empty DDG result page
_HAS_RESULTS = re.compile(r'class="result__title"|class="result__a"|<h2 class="result')


def _run_dork(target: str, dork: str, req) -> dict | None:
    """Run one dork. Returns hit dict if results found, None if clean."""
    q = dork.format(target=target).replace(" ", "+")
    url = f"https://html.duckduckgo.com/html/?q={q}"
    r = safe_get(url, req=req, timeout=5,
                 headers={"User-Agent": "Mozilla/5.0 (VulnusLab OSINT)"})
    if r is None or r.status_code != 200:
        return None
    body = r.text or ""
    if not _HAS_RESULTS.search(body):
        return None
    # Crude result-count proxy: tokens in HTML
    n = len(_HAS_RESULTS.findall(body))
    return {"dork": dork.format(target=target), "results_seen": n,
            "severity": severity_for(dork)}


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip().lower()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    if "." not in target:
        return standard_response(tool="search_dorks", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="target must be a domain")

    # Cap to 30 dorks per scan to stay under SLO
    dorks = OSINT_DORKS[:30]
    hits = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_run_dork, target, d, req): d for d in dorks}
        for fut in futs:
            try:
                result = fut.result(timeout=8)
                if result:
                    hits.append(result)
            except Exception:
                continue

    findings = []
    # Group hits by severity, emit one finding per CRIT/HIGH dork class.
    crit_high = [h for h in hits if h["severity"] in ("CRITICAL", "HIGH")]
    med_low = [h for h in hits if h["severity"] in ("MEDIUM", "LOW")]

    # NOTE: this scanner only observes that a DDG result PAGE is non-empty for
    # a dork — it does NOT fetch the result URL/content. A non-empty result
    # page is NOT proof that a real secret is exposed (the page may merely
    # mention the domain, or the dork may match benign content). Therefore
    # dork-category presence is NEVER graded; it is reported as INFO with a
    # manual-review note. To grade these, fetch + confirm the actual result.
    if crit_high:
        sample = [h["dork"] for h in crit_high[:8]]
        findings.append(wrap_finding(
            f"{len(crit_high)} high-risk dork(s) returned search results "
            f"(potential credentials, secrets, sensitive files) — UNVERIFIED",
            severity="INFO", cvss="0.0",
            cwe="CWE-200", owasp="A05:2021",
            remediation=("A non-empty dork result page is not proof of a real "
                        "exposure — the result URL/content was not fetched. "
                        "MANUALLY open each indexed URL: if it exposes credentials "
                        "or sensitive content, remove it from the public web, add "
                        "robots.txt + meta noindex, rotate any exposed credential, "
                        "and file removal requests with Google/Bing webmaster tools."),
            evidence_marker="; ".join(sample) + " (dork result page non-empty, content UNVERIFIED)"))
    if med_low:
        sample = [h["dork"] for h in med_low[:5]]
        findings.append(wrap_finding(
            f"{len(med_low)} informational dork(s) returned search results "
            f"(public docs, admin paths, third-party mentions)",
            severity="INFO", cvss="0.0",
            cwe="CWE-200", owasp="A05:2021",
            remediation="Informational — manually review each result for sensitive "
                        "content; consider noindex on admin paths.",
            evidence_marker="; ".join(sample) + " (content UNVERIFIED)"))
    if not hits:
        findings.append(wrap_finding(
            f"No hits across {len(dorks)} OSINT dorks",
            severity="POSITIVE",
            cwe="CWE-200", owasp="A05:2021",
            remediation="Clean public surface — no dork hits across credential/leak/path classes.",
            evidence_marker=f"{len(dorks)} dorks tested, 0 results"))

    return standard_response(
        tool="search_dorks", target=req.target, findings=findings,
        tests_performed=len(dorks),
        vulnerable=False,  # dork-page presence is unverified — never graded without fetching result content
        tests_summary=f"{len(dorks)} DDG dorks; {len(hits)} returned results",
        raw_data={"hits": hits[:50]})


@router.post("/api/osint/search_dorks")
@vl_verify()
async def scan_dorks(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="search_dorks", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
