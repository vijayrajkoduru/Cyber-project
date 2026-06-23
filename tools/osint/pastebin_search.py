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

# Secret-like markers that, when present in a paste body ALONGSIDE the target
# domain, indicate an actually-attributable leak (not just a mention).
_SECRET_MARKERS = re.compile(
    r"(?i)\b(?:AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|ghp_[A-Za-z0-9]{36}|"
    r"AIza[0-9A-Za-z_-]{35}|xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"password\s*[:=]|passwd\s*[:=]|api[_-]?key\s*[:=]|secret\s*[:=]|"
    r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY)")


def _fetch_paste_body(url: str, req) -> str:
    """Fetch a raw-ish paste body for confirmation. Returns lowercased text."""
    raw = url
    # pastebin.com/<id> -> pastebin.com/raw/<id>; gist -> append /raw
    if "pastebin.com/" in url and "/raw/" not in url:
        raw = url.replace("pastebin.com/", "pastebin.com/raw/")
    elif "gist.github.com/" in url and not url.endswith("/raw"):
        raw = url.rstrip("/") + "/raw"
    r = safe_get(raw, req=req, timeout=5,
                 headers={"User-Agent": "Mozilla/5.0 (VulnusLab OSINT)"})
    if r is None or r.status_code != 200:
        # fall back to the original URL
        r = safe_get(url, req=req, timeout=5,
                     headers={"User-Agent": "Mozilla/5.0 (VulnusLab OSINT)"})
    if r is None or r.status_code != 200:
        return ""
    return (r.text or "")[:200000].lower()


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
    confirmed = []
    if all_links:
        sample = all_links[:10]
        # CONFIRMATION GATE: a search-engine hit alone is NOT a proven leak —
        # the page may merely mention the domain. Fetch each paste body and
        # only grade when it both references the target AND contains a
        # target-attributable secret marker. Unconfirmed hits stay INFO.
        with ThreadPoolExecutor(max_workers=5) as pool:
            body_futs = {pool.submit(_fetch_paste_body, l, req): l
                          for l in all_links[:10]}
            for fut in body_futs:
                link = body_futs[fut]
                try:
                    body = fut.result(timeout=7)
                except Exception:
                    continue
                if body and target in body and _SECRET_MARKERS.search(body):
                    confirmed.append(link)

        if confirmed:
            sev = "HIGH" if len(confirmed) >= 3 else "MEDIUM"
            findings.append(wrap_finding(
                f"{len(confirmed)} paste(s) contain target-attributable secrets",
                sev, cvss="6.5" if sev == "MEDIUM" else "7.5",
                cwe="CWE-200", owasp="A05:2021",
                remediation=("Each confirmed paste references the target AND "
                            "contains credential/secret markers. Review, rotate "
                            "exposed keys, and file takedown via the paste-site "
                            "abuse process."),
                evidence_marker="; ".join(confirmed[:10])
                                  + " (CONFIRMED — body contains target + secret marker)"))
        # All indexed hits (confirmed or not) reported as INFO for visibility.
        findings.append(wrap_finding(
            f"{len(all_links)} indexed paste(s) reference target domain",
            severity="INFO", cvss="0.0",
            cwe="CWE-200", owasp="A05:2021",
            remediation=("Search-engine indexing of a paste mentioning the "
                        "domain is not proof of a leak. Manually review each "
                        "paste body; only treat as an exposure if it contains "
                        "credentials or internal data."),
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
        vulnerable=len(confirmed) > 0,  # only a confirmed-body leak is graded
        tests_summary=(f"{len(_PASTE_SITES)} paste sites via DDG; {len(all_links)} hits; "
                       f"{len(confirmed)} body-confirmed"),
        raw_data={"links": all_links[:30], "confirmed": confirmed[:30]})


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
