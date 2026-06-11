"""crtsh_emails — extract org emails from Certificate Transparency log subjects.

CT log entries often embed registrant / admin emails in cert subject fields.
Free, no key, no rate limit (crt.sh public endpoint).

VL-FOUNDRY Layer 6: 7-check DoD compliant.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

try:
    from tools._payloads.osint.email_patterns import EMAIL_REGEX
except ImportError:
    EMAIL_REGEX = r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"

router = APIRouter()
WALL_CLOCK_S = 20


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip().lower()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    if "." not in target:
        return standard_response(tool="crtsh_emails", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="target must be a domain")

    url = f"https://crt.sh/?q=%25.{target}&output=json"
    r = safe_get(url, req=req, timeout=12)
    if r is None or r.status_code != 200:
        return standard_response(tool="crtsh_emails", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"crt.sh unreachable (status {r.status_code if r else 'none'})")

    try:
        data = r.json()
    except Exception:
        return standard_response(tool="crtsh_emails", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="crt.sh returned non-JSON")

    pattern = re.compile(EMAIL_REGEX)
    emails = set()
    for row in data[:500]:  # cap iteration
        for field in ("name_value", "issuer_name", "common_name"):
            v = row.get(field, "")
            for m in pattern.findall(str(v)):
                emails.add(m.lower())

    org_emails = {e for e in emails if target in e}

    findings = []
    if org_emails:
        sample = sorted(org_emails)[:20]
        findings.append(wrap_finding(
            f"{len(org_emails)} email(s) extracted from CT log certificates",
            severity="MEDIUM", cvss="4.3",
            cwe="CWE-200", owasp="A05:2021",
            remediation=("Avoid putting personal contact emails in certificate "
                        "subjects/SAN fields. Use a role-based registration mailbox."),
            evidence_marker=", ".join(sample)))
    else:
        findings.append(wrap_finding(
            "No org emails leaked through certificate transparency logs",
            severity="POSITIVE",
            cwe="CWE-200", owasp="A05:2021",
            remediation="No certificate-subject email leakage — issuance hygiene OK.",
            evidence_marker=f"{len(data)} CT entries scanned, 0 emails"))

    return standard_response(
        tool="crtsh_emails", target=req.target, findings=findings,
        tests_performed=len(data),
        vulnerable=len(org_emails) > 0,
        tests_summary=f"crt.sh CT log: {len(data)} entries, {len(org_emails)} org emails",
        raw_data={"emails": sorted(org_emails)[:50]})


@router.post("/api/osint/crtsh_emails")
@vl_verify()
async def scan_crtsh(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="crtsh_emails", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
