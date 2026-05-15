"""WHOIS recon tool — domain registration intelligence.

Active verification: queries the live WHOIS registry and produces
confirmed findings on:
  - Expiration risk (CRITICAL <7d, HIGH <30d, MEDIUM <90d)
  - Privacy / proxy registration
  - Domain age (phishing indicator if very new)
  - DNSSEC status
  - Name-server count
"""
import datetime
from fastapi import APIRouter, Depends

import whois

from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host,
    wrap_finding, standard_response,
)

router = APIRouter()


def _as_date(v):
    """WHOIS libs return dates as list / datetime / str. Normalize."""
    if isinstance(v, list):
        v = v[0] if v else None
    if isinstance(v, datetime.datetime):
        return v
    if isinstance(v, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.datetime.strptime(v, fmt)
            except ValueError:
                continue
    return None


@router.post("/api/scan/whois")
async def scan_whois(req: ScanRequest, _=Depends(verify_scan_quota)):
    target = recon_host(req.target)
    findings = []
    tests = 0
    raw = {}

    try:
        w = whois.whois(target)
    except Exception as e:
        return standard_response(
            tool="whois", target=target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"WHOIS query failed: {e}",
        )

    # Test 1 — expiration risk
    tests += 1
    exp = _as_date(w.expiration_date)
    if exp:
        days_left = (exp - datetime.datetime.utcnow()).days
        raw["expiration_date"] = exp.isoformat() + "Z"
        raw["days_until_expiry"] = days_left
        if days_left < 0:
            findings.append(wrap_finding(
                f"Domain expired {abs(days_left)} days ago",
                "CRITICAL", cwe="CWE-298",
                evidence_marker=f"expiration_date={exp.isoformat()}",
                remediation="Renew the domain immediately to prevent loss of ownership.",
                tests_performed=1,
            ))
        elif days_left <= 7:
            findings.append(wrap_finding(
                f"Domain expires in {days_left} days",
                "CRITICAL", cwe="CWE-298",
                evidence_marker=f"expiration_date={exp.isoformat()}",
                remediation="Renew the domain immediately.",
                tests_performed=1,
            ))
        elif days_left <= 30:
            findings.append(wrap_finding(
                f"Domain expires in {days_left} days",
                "HIGH",
                evidence_marker=f"expiration_date={exp.isoformat()}",
                remediation="Renew the domain in the next two weeks.",
                tests_performed=1,
            ))
        elif days_left <= 90:
            findings.append(wrap_finding(
                f"Domain expires in {days_left} days",
                "MEDIUM",
                evidence_marker=f"expiration_date={exp.isoformat()}",
                remediation="Schedule the domain renewal.",
                tests_performed=1,
            ))

    # Test 2 — domain age (phishing indicator)
    tests += 1
    created = _as_date(w.creation_date)
    if created:
        age_days = (datetime.datetime.utcnow() - created).days
        raw["creation_date"] = created.isoformat() + "Z"
        raw["age_days"] = age_days
        if age_days < 30:
            findings.append(wrap_finding(
                f"Domain registered only {age_days} days ago — phishing/scam indicator",
                "MEDIUM", cwe="CWE-1021",
                evidence_marker=f"creation_date={created.isoformat()}",
                remediation="If unexpected, treat traffic to this domain with high scrutiny.",
                tests_performed=1,
            ))
        elif age_days < 90:
            findings.append(wrap_finding(
                f"Domain registered {age_days} days ago — newly registered",
                "LOW",
                evidence_marker=f"creation_date={created.isoformat()}",
                tests_performed=1,
            ))

    # Test 3 — privacy / proxy registration
    tests += 1
    registrant = (str(w.registrant_name or "") + " " + str(w.org or "")).lower()
    privacy_markers = ("privacy", "whoisguard", "redacted", "domains by proxy",
                       "private", "gdpr masked", "data redacted")
    if any(m in registrant for m in privacy_markers):
        findings.append(wrap_finding(
            "Privacy / proxy registration detected (registrant identity hidden)",
            "INFO",
            evidence_marker=f"registrant={registrant.strip()[:80]}",
            tests_performed=1,
        ))
        raw["privacy_protected"] = True

    # Test 4 — DNSSEC status
    tests += 1
    dnssec = str(w.dnssec or "").lower()
    raw["dnssec"] = dnssec or "unknown"
    if dnssec in ("unsigned", "no", "none"):
        findings.append(wrap_finding(
            "DNSSEC not enabled — DNS responses are not cryptographically signed",
            "LOW", cwe="CWE-345", owasp="A04:2021",
            evidence_marker=f"dnssec={dnssec}",
            remediation="Enable DNSSEC at the registrar to prevent DNS spoofing.",
            tests_performed=1,
        ))

    # Test 5 — name-server count
    tests += 1
    ns = w.name_servers or []
    if isinstance(ns, str):
        ns = [ns]
    ns_count = len({n.lower() for n in ns if n})
    raw["name_servers"] = list({n.lower() for n in ns if n})
    raw["name_server_count"] = ns_count
    if ns_count < 2:
        findings.append(wrap_finding(
            f"Only {ns_count} name server configured — DNS single point of failure",
            "HIGH", cwe="CWE-1188",
            evidence_marker=f"ns_count={ns_count}",
            remediation="Configure at least 2 geographically diverse name servers.",
            tests_performed=1,
        ))

    return standard_response(
        tool="whois", target=target, findings=findings,
        tests_performed=tests,
        tests_summary="5 WHOIS checks: expiry, age, privacy, DNSSEC, NS count",
        raw_data={"whois": raw},
    )


def register(app):
    app.include_router(router)
garbage SYNTAX ERROR garbage
