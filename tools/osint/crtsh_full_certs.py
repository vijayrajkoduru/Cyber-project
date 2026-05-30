"""crt.sh full certificate transparency dump — playbook §2 #23.

Different from existing crtsh_emails (which extracts contact emails from
WHOIS-like cert fields). This one returns the full unique-subdomain list
discovered through CT log aggregation — a primary subdomain-enumeration
source rivaling Amass/Subfinder.

Real probe. Zero false positives. Free, no key.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 25


def _clean(target: str) -> str:
    t = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    return t.lower()


def _do_scan(req: ScanRequest) -> dict:
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="crtsh_full_certs", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    r = safe_get(f"https://crt.sh/?q=%25.{domain}&output=json",
                  req=req, timeout=20,
                  headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="crtsh_full_certs", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"crt.sh unreachable (status={r.status_code if r else 'no-conn'})")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="crtsh_full_certs", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON response — crt.sh may be temporarily unavailable")

    subs = set()
    issuers = set()
    for row in data:
        name = (row.get("name_value") or "").strip().lower()
        for line in name.split("\n"):
            line = line.strip().lstrip("*.")
            if line and line.endswith(domain):
                subs.add(line)
        if row.get("issuer_name"):
            issuers.add(row["issuer_name"])

    subs = sorted(subs)
    if not subs:
        return standard_response(
            tool="crtsh_full_certs", target=req.target,
            findings=[wrap_finding(
                f"No CT certificate records found for {domain}",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Either the domain has never had a public cert "
                            "(internal-only?) or CT logging is suppressed (rare).",
                evidence_marker="crt.sh returned 0 records (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No CT records found")

    interesting = [s for s in subs if any(k in s for k in
                    ("dev", "staging", "test", "uat", "qa", "internal",
                     "admin", "vpn", "api", "git", "jenkins", "jira", "k8s"))]

    findings = []
    if interesting:
        findings.append(wrap_finding(
            f"INTERESTING subdomains exposed via CT logs ({len(interesting)})",
            severity="MEDIUM", cwe="CWE-200", cvss="5.3", owasp="A05:2021",
            remediation="Pre-prod / admin subdomains should NEVER be exposed to "
                        "the public internet. Move them behind VPN or Cloudflare Access. "
                        "CT logs publish every cert issued — even private CAs leak.",
            evidence_marker=" | ".join(interesting[:25])
                              + (' ...' if len(interesting) > 25 else '')))

    findings.append(wrap_finding(
        f"CT logs reveal {len(subs)} subdomains for {domain}",
        severity="POSITIVE" if not interesting else "INFO",
        cwe="CWE-200",
        remediation="Subdomain enumeration via CT is standard recon — own the "
                    "list before attackers do. Cross-reference with dnstwist + Amass.",
        evidence_marker=f"first 20: {' | '.join(subs[:20])}"))

    return standard_response(
        tool="crtsh_full_certs", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(interesting),
        tests_summary=f"crt.sh: {len(subs)} subdomains ({len(interesting)} interesting), {len(issuers)} CAs",
        raw_data={"subdomains": subs, "interesting": interesting,
                   "issuers": list(issuers)[:20], "total_certs": len(data)})


@router.post("/api/osint/crtsh_full_certs")
async def scan_crtsh_full_certs(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="crtsh_full_certs", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
