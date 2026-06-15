"""third_party_sdk_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("third_party_sdk_audit_total"):
        return None
    return {"name": "SDK audit: no third-party tracking SDKs detected",
            "severity": "POSITIVE",
            "evidence": "Package tree scanned — no known analytics/ad/tracking SDKs bundled",
            "remediation": "Minimal SDK footprint — good for user privacy + faster startup.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_high_risk_sdks(s):
    high = s.get("high_risk_sdks") or []
    if not high:
        return None
    return {"name": f"{len(high)} high-risk tracking SDK(s) bundled",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": "; ".join(f"{h['sdk']}: {h['description']}" for h in high[:5]),
            "remediation": "Audit user-consent flows for each SDK. Required for GDPR / CCPA compliance. Document data sharing in privacy policy."}


def rule_total_sdks(s):
    """Always emit a count finding when ANY SDKs are detected.
    Severity scales with count: 1-4 = INFO, 5-9 = MEDIUM, 10+ = HIGH.
    Without this, Section 18 (Third-Party SDK Audit) was empty when 1-4
    benign SDKs were present and rule_high_risk_sdks didn't fire."""
    total = s.get("third_party_sdk_audit_total", 0)
    if total <= 0:
        return None
    if total >= 10:
        sev, cvss = "HIGH", "6.5"
    elif total >= 5:
        sev, cvss = "MEDIUM", "5.0"
    else:
        sev, cvss = "INFO", "2.0"
    return {"name": f"{total} third-party SDK(s) detected - supply-chain attack surface",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-1357", "owasp": "M3:2023",
            "evidence": f"Total SDKs: {total}. Each adds CVE exposure + binary size + permissions.",
            "remediation": "Audit each SDK for necessity. Subscribe to CVE alerts per SDK. Consider replacing with first-party code."}


# ── Vulnerable-SDK cross-check (curated vulnerable_sdks.json) ─────────────────
# CONFIRMED: a precise bundled version (Maven pom.properties) fell inside a
# vulnerable_version_ranges entry AND the catalogue entry has a real CVE. These
# are version-PROVEN, so they are graded by severity and stamped
# verified_exploit=True (so the global advisory cap does NOT downgrade them).
# A small set of RCE-class CVEs are CRITICAL; the rest default to HIGH.
_CRITICAL_CVES = {
    "CVE-2021-44228",  # Log4Shell (JNDI RCE)
    "CVE-2022-42889",  # Text4Shell (StringSubstitutor RCE)
}


def rule_vulnerable_sdks_confirmed(s):
    """One finding PER version-confirmed vulnerable SDK. Never advisory: the
    bundled version was reliably extracted and proven to be in a vulnerable
    range, so this is a CONFIRMED known-vulnerable component."""
    confirmed = s.get("vulnerable_sdks_confirmed") or []
    if not confirmed:
        return None
    # Emit a single aggregate finding so the report has one clear entry, but
    # grade at the worst severity present and enumerate every component.
    sev, cvss = "HIGH", "7.5"
    if any((c.get("cve") or "").strip().upper() in _CRITICAL_CVES for c in confirmed):
        sev, cvss = "CRITICAL", "9.8"
    lines = []
    for c in confirmed:
        lines.append(
            f"{c.get('sdk')} {c.get('version')} ({c.get('package')}) — "
            f"{c.get('cve')}: in vulnerable range [{c.get('matched_range')}]. "
            f"{c.get('note')}".strip()
        )
    cves = ", ".join(sorted({(c.get("cve") or "").strip()
                             for c in confirmed if c.get("cve")}))
    return {
        "name": f"{len(confirmed)} bundled SDK(s) at a known-vulnerable version",
        "severity": sev, "cvss": cvss,
        "cve": cves or "N/A",
        "cwe": "CWE-1395", "cwe_name": "Dependency on Vulnerable Third-Party Component",
        "owasp": "M2:2023",
        "evidence": " | ".join(lines),
        "remediation": ("Upgrade each listed SDK to a fixed release outside the "
                        "vulnerable range. Versions were read from bundled Maven "
                        "metadata (pom.properties), so each match is confirmed."),
        # Version-proven against bundled metadata — opt out of the advisory cap.
        "verified_exploit": True,
    }


def rule_vulnerable_sdks_advisory(s):
    """ADVISORY only. The SDK is bundled and listed in the vulnerable-SDK
    catalogue, but the exact version could NOT be reliably proven in-range
    (no extractable version, non-numeric range bound, or placeholder CVE).
    Deliberately INFO + advisory wording so it never reads as a confirmed
    critical. (Severity also re-clamped by the global advisory cap.)"""
    adv = s.get("vulnerable_sdks_advisory") or []
    if not adv:
        return None
    lines = []
    for a in adv:
        ver = a.get("version") or "version unknown"
        lines.append(
            f"{a.get('sdk')} ({a.get('package')}, {ver}) — vulnerable in "
            f"[{a.get('matched_range')}] per {a.get('cve')}; "
            f"{a.get('reason')}".strip()
        )
    return {
        "name": f"{len(adv)} bundled SDK(s) potentially vulnerable — verify version",
        "severity": "INFO", "cvss": "0.0",
        "cwe": "CWE-1395", "cwe_name": "Dependency on Vulnerable Third-Party Component",
        "owasp": "M2:2023",
        "evidence": " | ".join(lines),
        "remediation": ("Advisory: these SDKs are present and are known-vulnerable "
                        "in the listed ranges, but the bundled version was not "
                        "reliably extractable. Manually verify each SDK's exact "
                        "version and upgrade if it falls inside the listed range."),
    }


THIRD_PARTY_SDK_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_high_risk_sdks,
    rule_total_sdks,
    rule_vulnerable_sdks_confirmed,
    rule_vulnerable_sdks_advisory,
]
