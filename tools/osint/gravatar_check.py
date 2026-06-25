"""gravatar_check — check Gravatar profile existence for common org emails.

For target=acme.com, generates role-based emails (info@, admin@, contact@,
support@, hr@, security@) and probes gravatar.com via MD5(email).
A 200 response = profile exists = identity surface for that role mailbox.

Curated from tools._payloads.osint.email_patterns (role-based section).
VL-FOUNDRY Layer 6: 7-check DoD compliant.
"""
import asyncio
import hashlib
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify
from tools._core import grade

try:
    from tools._payloads.osint.email_patterns import EMAIL_PATTERNS
    _ROLE_PATTERNS = [p for p in EMAIL_PATTERNS
                       if "{first}" not in p and "{last}" not in p]
except ImportError:
    _ROLE_PATTERNS = [
        "info@{domain}", "admin@{domain}", "contact@{domain}",
        "support@{domain}", "hr@{domain}", "security@{domain}",
    ]

router = APIRouter()
WALL_CLOCK_S = 18


def _probe(email: str, req) -> dict | None:
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/{h}.json"
    r = safe_get(url, req=req, timeout=4,
                 headers={"User-Agent": "VulnusLab-OSINT"})
    if r is None or r.status_code != 200:
        return None
    try:
        data = r.json()
        entry = (data.get("entry") or [{}])[0]
        return {"email": email, "url": entry.get("profileUrl"),
                 "name": entry.get("displayName") or entry.get("preferredUsername")}
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
        return standard_response(tool="gravatar_check", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="target must be a domain")

    emails = [p.format(domain=target) for p in _ROLE_PATTERNS]

    hits = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_probe, e, req): e for e in emails}
        for fut in futs:
            try:
                r = fut.result(timeout=6)
                if r:
                    hits.append(r)
            except Exception:
                continue

    findings = []
    if hits:
        sample = [f"{h['email']} → {h.get('name', '?')}" for h in hits[:8]]
        findings.append(wrap_finding(
            f"{len(hits)} Gravatar profile(s) found for role-based emails",
            severity=(sev := grade.inventory(len(hits), low_at=1)), cvss=grade.cvss_for(sev),
            cwe="CWE-200", owasp="A05:2021",
            remediation=("Gravatar links email to a public photo/profile — "
                        "informational. If sensitive, employees can delete "
                        "Gravatar profiles or use role-mailbox-specific images."),
            evidence_marker="; ".join(sample)))
    else:
        findings.append(wrap_finding(
            f"No Gravatar profiles for {len(emails)} role emails",
            severity=grade.protective(),
            cwe="CWE-200", owasp="A05:2021",
            remediation="Clean — role mailboxes not linked to identity profiles.",
            evidence_marker=f"{len(emails)} role emails probed, 0 hits"))

    return standard_response(
        tool="gravatar_check", target=req.target, findings=findings,
        tests_performed=len(emails), vulnerable=False,
        tests_summary=f"Gravatar MD5 lookup × {len(emails)} role emails; {len(hits)} hits",
        raw_data={"hits": hits})


@router.post("/api/osint/gravatar_check")
@vl_verify()
async def scan_gravatar(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="gravatar_check", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
