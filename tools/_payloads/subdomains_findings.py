"""Subdomain Discovery — findings rules library.

State shape: subdomains (set), sources_breakdown (dict source->set),
high_risk (list), takeover_candidates (list), wildcard_detected (bool),
ipv6_subdomains (list), ai_wordlist_used (bool).
"""
import re

# Subdomain patterns that indicate elevated attack surface
_HIGH_RISK_PATTERNS = [
    (r"^(admin|administrator|manage|management|panel|portal|backend)\b", "Admin panel"),
    (r"^(staging|stage|stg|preprod|pre-prod|qa|uat|test|testing|dev|development|sandbox|demo)\b", "Pre-production env"),
    (r"^(internal|intranet|private|corp|corporate|inside|internal-api)\b", "Internal-only system"),
    (r"^(jenkins|jira|confluence|gitlab|github|bitbucket|sonar|gerrit)\b", "DevOps tooling"),
    (r"^(grafana|kibana|prometheus|datadog|splunk|elastic|elasticsearch)\b", "Monitoring tool"),
    (r"^(phpmyadmin|pma|adminer|mysql|postgres|mongo|redis|db)\b", "Database admin"),
    (r"^(vpn|ssh|rdp|remote|terminal)\b", "Remote access"),
    (r"^(api-internal|internal-api|api-dev|api-staging|api-beta)\b", "Internal API"),
    (r"^(vault|secrets|keyvault|hashicorp)\b", "Secret store"),
    (r"^(jenkins|argo|tekton|drone|circle|travis)\b", "CI/CD"),
    (r"^(backup|backups|bak|archive|archives|old|legacy)\b", "Stale/backup"),
    (r"^(_)", "Hidden / service-discovery"),
]


def rule_subs_found(s):
    n = len(s.get("subdomains") or [])
    if n == 0: return None
    return {"name": f"{n} subdomain(s) discovered",
            "severity": "INFO",
            "evidence": f"Total unique subdomains across all sources: {n}"}


def rule_no_subs(s):
    if (s.get("subdomains") or []):
        return None
    return {"name": "No subdomains discovered",
            "severity": "INFO",
            "evidence": "All probed sources returned empty results — domain may have minimal external footprint or use private DNS",
            "remediation": "If you expect subdomains, verify DNS configuration. For a public site, having NO subdomains discovered usually means strong DNS hygiene."}


def rule_high_risk_subs(s):
    hr = s.get("high_risk") or []
    if not hr: return None
    return {"name": f"High-risk subdomains exposed ({len(hr)})",
            "severity": "HIGH",
            "cwe": "CWE-200",
            "evidence": "Found: " + ", ".join(f"{name} ({reason})" for name, reason in hr[:5]),
            "remediation": "Audit each — staging/admin/internal subdomains should be IP-restricted, behind VPN, or removed if unused. Common breach vector."}


def rule_wildcard_pollution(s):
    if not s.get("wildcard_detected"): return None
    return {"name": "Wildcard DNS detected — discovery results may be polluted",
            "severity": "MEDIUM",
            "evidence": "Random subdomain probe returned a result, meaning *.target resolves. Many 'found' subdomains may be false positives.",
            "remediation": "Verify each discovered subdomain individually via direct DNS query. Consider removing the wildcard."}


def rule_takeover_candidates(s):
    tc = s.get("takeover_candidates") or []
    if not tc: return None
    return {"name": f"Subdomain takeover candidates ({len(tc)})",
            "severity": "CRITICAL",
            "cwe": "CWE-350",
            "evidence": "; ".join(f"{sub} -> {hint}" for sub, hint in tc[:3]),
            "remediation": "Each candidate points to a 3rd-party service (S3/Heroku/GitHub Pages/etc.) where the underlying resource may have been deleted. Reclaim the service or remove the CNAME."}


def rule_ipv6_subs(s):
    ipv6 = s.get("ipv6_subdomains") or []
    if not ipv6: return None
    return {"name": f"IPv6-enabled subdomains ({len(ipv6)})",
            "severity": "POSITIVE",
            "evidence": f"AAAA records present on: {', '.join(ipv6[:5])}"}


def rule_sources_diverse(s):
    sb = s.get("sources_breakdown") or {}
    active = sum(1 for v in sb.values() if v)
    if active < 3: return None
    return {"name": f"Multi-source discovery ({active} sources contributed)",
            "severity": "POSITIVE",
            "evidence": f"Active sources: {', '.join(k for k, v in sb.items() if v)}"}


def rule_unique_per_source(s):
    sb = s.get("sources_breakdown") or {}
    if not sb: return None
    parts = [f"{k}: {len(v)}" for k, v in sb.items() if v]
    if not parts: return None
    return {"name": "Subdomain source breakdown",
            "severity": "INFO",
            "evidence": "; ".join(parts)}


SUBDOMAINS_FINDING_RULES = [
    rule_subs_found,
    rule_no_subs,
    rule_high_risk_subs,
    rule_wildcard_pollution,
    rule_takeover_candidates,
    rule_ipv6_subs,
    rule_sources_diverse,
    rule_unique_per_source,
]


def classify_high_risk(subdomain: str) -> tuple | None:
    """Return (matched_pattern, reason) if subdomain matches a high-risk pattern."""
    name = subdomain.split(".")[0].lower()
    for pattern, reason in _HIGH_RISK_PATTERNS:
        if re.search(pattern, name):
            return (subdomain, reason)
    return None
