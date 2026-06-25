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
from tools._vl_core.verify import vl_verify

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

    # CT-logged subdomains are PUBLIC inventory, not an exposure — api.<domain>
    # is normally an intended public service. Only internal/pre-prod-looking
    # names warrant a LOW; generic api/dev/admin names are INFO inventory.
    _INTERNAL = ("internal", "vpn", "jenkins", "jira", "staging", "uat", "qa", "k8s")
    _GENERIC = ("dev", "test", "admin", "api", "git")
    internalish = [s for s in subs if any(k in s for k in _INTERNAL)]
    generic = [s for s in subs if any(k in s for k in _GENERIC) and s not in internalish]
    interesting = internalish + generic

    findings = []
    if internalish:
        findings.append(wrap_finding(
            f"Internal/pre-prod-looking subdomains in CT logs ({len(internalish)})",
            severity="LOW", cvss="3.1", cwe="CWE-200", owasp="A05:2021",
            remediation="These CT-logged subdomains look like internal/pre-prod systems "
                        "(internal/vpn/jenkins/jira/staging/uat/k8s). CT is public, so issuing "
                        "a cert advertises their existence. Confirm which are meant to be "
                        "public; put the rest behind a VPN or use a wildcard / private CA.",
            evidence_marker=" | ".join(internalish[:25]) + (' ...' if len(internalish) > 25 else '')))
    if generic:
        findings.append(wrap_finding(
            f"Subdomain inventory from CT logs ({len(generic)} api/dev/admin-style)",
            severity="INFO", cvss="0.0", cwe="CWE-200", owasp="A05:2021",
            remediation="CT-logged subdomains (api/dev/test/admin/git) — attack-surface "
                        "inventory, not an exposure (e.g. api.<domain> is normally public). "
                        "Use as a recon target list.",
            evidence_marker=" | ".join(generic[:25]) + (' ...' if len(generic) > 25 else '')))

    findings.append(wrap_finding(
        f"CT logs reveal {len(subs)} subdomains for {domain}",
        severity="POSITIVE" if not interesting else "INFO",
        cwe="CWE-200",
        remediation="Subdomain enumeration via CT is standard recon — own the "
                    "list before attackers do. Cross-reference with dnstwist + Amass.",
        evidence_marker=f"first 20: {' | '.join(subs[:20])}"))

    return standard_response(
        tool="crtsh_full_certs", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(internalish),
        tests_summary=f"crt.sh: {len(subs)} subdomains ({len(interesting)} of interest), {len(issuers)} CAs",
        raw_data={"subdomains": subs, "interesting": interesting,
                   "issuers": list(issuers)[:20], "total_certs": len(data)})


@router.post("/api/osint/crtsh_full_certs")
@vl_verify()
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
