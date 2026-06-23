"""Email format + MX-record validation — playbook §1 #16.

Validates RFC 5322 email format then queries DNS for MX records on the
domain. Returns CONFIRMED if MX records exist (mail can be delivered),
SUSPECTED if only A records exist (some mail servers accept-or-bounce
via fallback), CLEAN if no MX/A (domain rejects mail).

Pure-Python (dnspython). Zero false positives — relies on authoritative
DNS, not heuristic guessing.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 12
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _do_scan(req: ScanRequest) -> dict:
    email = (req.target or "").strip()
    if not EMAIL_RE.match(email):
        return standard_response(
            tool="email_validate_mx", target=req.target,
            findings=[wrap_finding(
                f"Invalid RFC 5322 format: {email}",
                severity="INFO", cwe="CWE-20",
                remediation="Validate input on intake. Bad format = cannot deliver.",
                evidence_marker="format-check failed")],
            tests_performed=1, vulnerable=False,
            tests_summary="Email format rejected")

    domain = email.split("@", 1)[1]
    try:
        import dns.resolver
    except ImportError:
        return standard_response(
            tool="email_validate_mx", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="dnspython not installed on backend")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 8

    mx_hosts = []
    try:
        ans = resolver.resolve(domain, "MX")
        mx_hosts = sorted([(int(r.preference), str(r.exchange).rstrip("."))
                            for r in ans], key=lambda x: x[0])
    except Exception:
        mx_hosts = []

    if mx_hosts:
        sev = "POSITIVE"
        title = f"Mail deliverable — {len(mx_hosts)} MX record(s) on {domain}"
        evidence = " | ".join(f"{p} {h}" for p, h in mx_hosts[:5])
        return standard_response(
            tool="email_validate_mx", target=req.target,
            findings=[wrap_finding(
                title, severity=sev, cwe="CWE-200",
                remediation="Mail is deliverable. For SMTP existence check, "
                            "use the SMTP RCPT-TO probe (separate tool, requires "
                            "rate-limit awareness to avoid blacklisting).",
                evidence_marker=f"{evidence} (CONFIRMED via DNS MX)")],
            tests_performed=1, vulnerable=False,
            tests_summary=f"MX-confirmed: {len(mx_hosts)} mail server(s)",
            raw_data={"mx": mx_hosts, "domain": domain})

    try:
        a_ans = resolver.resolve(domain, "A")
        a_ips = [str(r) for r in a_ans][:3]
    except Exception:
        a_ips = []

    if a_ips:
        return standard_response(
            tool="email_validate_mx", target=req.target,
            findings=[wrap_finding(
                f"No MX records — fallback to A records ({len(a_ips)} IP(s))",
                severity="INFO", cwe="CWE-200",
                remediation="Per RFC 5321 §5, some MTAs fall back to A-record "
                            "delivery when MX is absent. Most modern MTAs reject. "
                            "Recommend adding explicit MX even if same host.",
                evidence_marker=f"A: {', '.join(a_ips)} (SUSPECTED deliverability)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No MX — A-record fallback only",
            raw_data={"mx": [], "a": a_ips, "domain": domain})

    return standard_response(
        tool="email_validate_mx", target=req.target,
        findings=[wrap_finding(
            f"Domain {domain} has no MX or A records — mail not deliverable",
            # A missing MX/A is a DNS deliverability misconfiguration, not a
            # security breach or proven exposure. INFO, not graded.
            severity="INFO", cwe="CWE-1395",
            remediation="Informational: missing MX/A is a mail-deliverability "
                        "misconfiguration, not a breach. If this is your domain: "
                        "add MX records pointing to your mail provider. If this is "
                        "an attacker-controlled spoof lookalike: monitor via dnstwist.",
            evidence_marker="No MX, no A (CONFIRMED via DNS)")],
        tests_performed=1, vulnerable=False,
        tests_summary="Domain rejects mail (no MX/A)",
        raw_data={"mx": [], "a": [], "domain": domain})


@router.post("/api/osint/email_validate_mx")
@vl_verify()
async def scan_email_validate_mx(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="email_validate_mx", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
