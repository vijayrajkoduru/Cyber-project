"""OSINT Harvesting — findings rules library."""
import re

_SENSITIVE_EMAIL_PATTERNS = [
    (r"admin@", "admin email"),
    (r"root@", "root email"),
    (r"webmaster@", "webmaster email"),
    (r"support@", "support email"),
    (r"sales@", "sales email"),
    (r"abuse@", "abuse contact"),
    (r"security@", "security contact"),
    (r"noc@", "NOC contact"),
]


def rule_emails_found(s):
    n = len(s.get("emails") or [])
    if n == 0: return None
    return {"name": f"{n} email address(es) discovered via OSINT",
            "severity": "INFO",
            "evidence": f"Found across search engines + public sources"}


def rule_hosts_found(s):
    n = len(s.get("hosts") or [])
    if n == 0: return None
    return {"name": f"{n} hostname(s) discovered via OSINT",
            "severity": "INFO",
            "evidence": "Cross-referenced with passive DNS sources"}


def rule_high_value_emails(s):
    emails = s.get("emails") or []
    high_value = []
    for email in emails:
        e = email.lower()
        for pat, role in _SENSITIVE_EMAIL_PATTERNS:
            if re.search(pat, e):
                high_value.append({"email": email, "role": role})
                break
    if not high_value: return None
    return {"name": f"High-value role-based emails exposed ({len(high_value)})",
            "severity": "MEDIUM",
            "cwe": "CWE-200",
            "evidence": "; ".join(f"{x['email']} ({x['role']})" for x in high_value[:5]),
            "remediation": "Role-based emails (admin@/security@) are prime phishing/spear-phishing targets. Either use unguessable names or accept this as a known surface + train staff for phishing."}


def rule_no_results(s):
    if (s.get("emails") or []) or (s.get("hosts") or []): return None
    return {"name": "OSINT returned no public emails/hosts",
            "severity": "POSITIVE",
            "evidence": "No emails leaked via public search engines or breach data"}


def rule_breach_data_found(s):
    if not s.get("breach_count"): return None
    return {"name": f"{s.get('breach_count')} email(s) in known data breaches",
            "severity": "HIGH",
            "cwe": "CWE-359",
            "evidence": "HIBP / breach databases show prior exposure",
            "remediation": "Force password reset for affected accounts. Enable MFA. Monitor for credential-stuffing on these emails."}


def rule_sources_summary(s):
    sb = s.get("sources_used_internal") or []
    if not sb: return None
    return {"name": f"OSINT data gathered from {len(sb)} source(s)",
            "severity": "INFO",
            "evidence": ", ".join(sb)}


HARVESTER_FINDING_RULES = [
    rule_emails_found, rule_hosts_found, rule_high_value_emails,
    rule_no_results, rule_breach_data_found, rule_sources_summary,
]
