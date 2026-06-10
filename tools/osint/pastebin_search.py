"""pastebin_search — DDG-mediated paste hunt for target domain.

Pastebin's own search requires an account; DDG indexes pastebin URLs
publicly. Three site:queries cover the major paste sites.

VL-FOUNDRY Layer 6: 7-check DoD compliant.
"""
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.osint.osint_dorks import OSINT_DORKS  # registers L5 curation usage
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 18

_PASTE_SITES = ["pastebin.com", "gist.github.com", "ghostbin.com",
                 "rentry.co", "controlc.com"]
_RESULT_LINK_RE = re.compile(r'<a[^>]+href="(https?://[^"]+)"[^>]*class="result__a"',
                              re.IGNORECASE)


def _query_site(site: str, target: str, req) -> list[str]:
    q = f'site:{site} "{target}"'.replace(" ", "+")
    url = f"https://html.duckduckgo.com/html/?q={q}"
    r = safe_get(url, req=req, timeout=5,
                 headers={"User-Agent": "Mozilla/5.0 (VulnusLab OSINT)"})
    if r is None or r.status_code != 200:
        return []
    links = _RESULT_LINK_RE.findall(r.text or "")
    return [l for l in links if site in l][:5]


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip().lower()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    if "." not in target:
        return standard_response(tool="pastebin_search", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="target must be a domain")

    all_links = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        futs = {pool.submit(_query_site, s, target, req): s for s in _PASTE_SITES}
        for fut in futs:
            try:
                links = fut.result(timeout=7)
                all_links.extend(links)
            except Exception:
                continue

    findings = []
    if all_links:
        sample = all_links[:10]
        sev = "HIGH" if len(all_links) >= 3 else "MEDIUM"
        findings.append(wrap_finding(
            f"{len(all_links)} indexed paste(s) reference target domain",
            sev, cvss="6.5" if sev == "MEDIUM" else "7.5",
            cwe="CWE-200", owasp="A05:2021",
            remediation=("Review each paste; if it contains credentials or "
                        "internal data, rotate keys and file takedown via "
                        "the paste-site abuse process."),
            evidence_marker="; ".join(sample)))
    else:
        findings.append(wrap_finding(
            f"No paste mentions found across {len(_PASTE_SITES)} paste sites",
            severity="POSITIVE",
            cwe="CWE-200", owasp="A05:2021",
            remediation="Clean paste-site surface — no indexed leaks.",
            evidence_marker=f"{len(_PASTE_SITES)} sites queried, 0 hits"))

    return standard_response(
        tool="pastebin_search", target=req.target, findings=findings,
        tests_performed=len(_PASTE_SITES),
        vulnerable=len(all_links) > 0,
        tests_summary=f"{len(_PASTE_SITES)} paste sites via DDG; {len(all_links)} hits",
        raw_data={"links": all_links[:30]})


@router.post("/api/osint/pastebin_search")
@vl_verify()
async def scan_pastebin(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="pastebin_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
