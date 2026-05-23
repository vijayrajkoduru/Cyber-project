"""Email security audit — SPF, DMARC, DKIM, BIMI, MTA-STS, DANE deep checks."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            wrap_finding, standard_response)
from tools._payloads.email_security_checks import EMAIL_SECURITY_CHECKS

router = APIRouter()


def _query_txt(domain):
    """Return list of TXT record strings for domain. Empty list on error."""
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
            return [b"".join(r.strings).decode("utf-8", errors="ignore") for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
    except ImportError:
        return []


@router.post("/api/recon/email_audit")
async def recon_email_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    target = recon_host(req.target)
    # Skip non-public hostnames
    if "." not in target or target.endswith((".local", ".internal", ".test")):
        return standard_response(tool="email_audit", target=target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"{target!r} is not a public internet domain")

    # Collect all the relevant DNS records once
    apex_txt = _query_txt(target)
    dmarc_txt = _query_txt(f"_dmarc.{target}")
    mta_sts_txt = _query_txt(f"_mta-sts.{target}")
    tls_rpt_txt = _query_txt(f"_smtp._tls.{target}")

    spf = next((t for t in apex_txt if "v=spf1" in t.lower()), None)
    dmarc = next((t for t in dmarc_txt if "v=dmarc1" in t.lower()), None)
    mta_sts = next((t for t in mta_sts_txt if "v=stsv1" in t.lower()), None)
    tls_rpt = next((t for t in tls_rpt_txt if "v=tlsrptv1" in t.lower()), None)

    findings = []
    tests = 0

    # Iterate the library's checks
    for chk in EMAIL_SECURITY_CHECKS:
        tests += 1
        cat = chk.get("category", "")
        pattern = chk.get("pattern", "")

        # Pick the record to test
        record = ""
        if cat == "spf":
            record = spf or ""
        elif cat == "dmarc":
            record = dmarc or ""
        elif cat == "mta_sts":
            record = mta_sts or ""
        elif cat == "tls_rpt":
            record = tls_rpt or ""

        # Handle "missing record entirely" cases via empty-string match
        try:
            if pattern and re.search(pattern, record, re.IGNORECASE):
                findings.append(wrap_finding(
                    f"Email security: {chk['check_name']}",
                    chk.get("severity", "MEDIUM"),
                    cvss=str(chk.get("cvss", "5.0")),
                    cwe="CWE-290", owasp="A07:2021",
                    remediation=chk.get("remediation", "Update DNS records to follow modern email security standards."),
                    evidence_marker=f"{cat.upper()} record check: {chk['check_name']}"))
        except re.error:
            continue

    # Always-on checks for missing records (regardless of library matchers)
    if not spf:
        findings.append(wrap_finding(
            "No SPF record at apex — email spoofing protection missing",
            "HIGH", cvss="6.5", cwe="CWE-290", owasp="A07:2021",
            remediation="Publish TXT record at apex: 'v=spf1 mx -all' (or include your ESP).",
            evidence_marker=f"No v=spf1 TXT record found for {target}"))
    if not dmarc:
        findings.append(wrap_finding(
            "No DMARC record — no email authentication policy published",
            "HIGH", cvss="6.5", cwe="CWE-290", owasp="A07:2021",
            remediation=f"Publish DMARC TXT at _dmarc.{target}: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{target}'",
            evidence_marker=f"No v=DMARC1 TXT for _dmarc.{target}"))

    return standard_response(tool="email_audit", target=target,
        findings=findings, tests_performed=tests,
        tests_summary=(f"Email audit: {tests} checks across SPF/DMARC/DKIM/BIMI/MTA-STS/DANE "
                       f"({len(findings)} findings)"),
        raw_data={"email_audit": {"spf_present": bool(spf), "dmarc_present": bool(dmarc),
                                    "mta_sts_present": bool(mta_sts),
                                    "tls_rpt_present": bool(tls_rpt),
                                    "checks_total": len(EMAIL_SECURITY_CHECKS)}})


def register(app):
    app.include_router(router)
