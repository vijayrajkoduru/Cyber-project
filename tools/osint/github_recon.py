"""github_recon — GitHub public code search for target domain mentions.

Uses unauth GitHub Search API (10 req/min). Three queries:
  1. "<target>" in:file        — any committed mention
  2. "<target>" extension:env  — env-file leaks
  3. "<target>" extension:json — config-file leaks

VL-FOUNDRY Layer 6: 7-check DoD compliant.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.osint.osint_dorks import OSINT_DORKS  # registers L5 curation usage
from tools._vl_core.verify import vl_verify
from tools._core import grade

router = APIRouter()
WALL_CLOCK_S = 20

_QUERIES = [
    ('"{target}"',                  "LOW",      "any public mention"),
    ('"{target}" extension:env',    "HIGH",     ".env file mentioning target"),
    ('"{target}" extension:json',   "MEDIUM",   "JSON config mentioning target"),
    ('"{target}" "api_key"',        "HIGH",     "API key adjacent to target"),
    ('"{target}" "password"',       "HIGH",     "password adjacent to target"),
]


def _query(target: str, q_tpl: str, req) -> int | None:
    """Run one GitHub code search. Returns total_count or None on error."""
    q = q_tpl.format(target=target).replace(" ", "+")
    url = f"https://api.github.com/search/code?q={q}&per_page=1"
    r = safe_get(url, req=req, timeout=6,
                 headers={"Accept": "application/vnd.github+json",
                          "User-Agent": "VulnusLab-OSINT"})
    if r is None or r.status_code != 200:
        return None
    try:
        return int(r.json().get("total_count", 0))
    except Exception:
        return None


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip().lower()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    if "." not in target:
        return standard_response(tool="github_recon", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="target must be a domain")

    # Sequential to respect 10 req/min unauth limit
    hits = []
    for q_tpl, sev, label in _QUERIES:
        cnt = _query(target, q_tpl, req)
        if cnt is None:
            continue  # rate-limited or unreachable
        if cnt > 0:
            hits.append({"query": q_tpl.format(target=target),
                         "count": cnt, "severity": sev, "label": label})

    findings = []
    high_hits = [h for h in hits if h["severity"] == "HIGH"]
    if high_hits:
        sample = [f"{h['query']} ({h['count']} results)" for h in high_hits[:3]]
        findings.append(wrap_finding(
            f"GitHub code search returned {sum(h['count'] for h in high_hits)} "
            f"high-risk hits (env/json/credentials)",
            severity=(sev := grade.exposure(confirmed=True, impact="enables")),
            cvss=grade.cvss_for(sev),
            cwe="CWE-538", owasp="A05:2021",
            remediation=("Audit hits with: gh search code '\"{target}\" extension:env'. "
                        "Open file removal requests with GitHub Trust & Safety; rotate "
                        "any credential present."),
            evidence_marker="; ".join(sample)))
    low_hits = [h for h in hits if h["severity"] != "HIGH"]
    if low_hits:
        sample = [f"{h['query']} ({h['count']} results)" for h in low_hits[:3]]
        _ref_count = sum(h['count'] for h in low_hits)
        findings.append(wrap_finding(
            f"GitHub mentions: {_ref_count} public references",
            severity=(sev := grade.inventory(n=_ref_count, low_at=50)),
            cvss=grade.cvss_for(sev),
            cwe="CWE-200", owasp="A05:2021",
            remediation="Informational — review any non-employee commits referencing target.",
            evidence_marker="; ".join(sample)))
    if not hits:
        findings.append(wrap_finding(
            "No GitHub code hits for target",
            severity=grade.protective(),
            cwe="CWE-538", owasp="A05:2021",
            remediation="Clean GitHub surface — no env/config leakage detected.",
            evidence_marker=f"{len(_QUERIES)} queries, 0 hits"))

    return standard_response(
        tool="github_recon", target=req.target, findings=findings,
        tests_performed=len(_QUERIES),
        vulnerable=len(high_hits) > 0,
        tests_summary=f"GitHub code search: {len(_QUERIES)} queries; {len(hits)} returned hits",
        raw_data={"hits": hits})


@router.post("/api/osint/github_recon")
@vl_verify()
async def scan_github(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="github_recon", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
