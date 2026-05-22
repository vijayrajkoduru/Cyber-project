"""Certificate Transparency — findings rules library.

Distinct from Subdomain Discovery (which uses crt.sh as ONE source among
many). Cert Transparency focuses on CERT-LEVEL intelligence:
  - Wildcard certs (security risk if compromised)
  - Internal hostnames leaked in SAN lists
  - Pre-production environments exposed in cert SANs
  - Recently revoked certs
  - Cert issuance frequency (rotation cadence)
  - CA diversity (single CA risk)
  - Cert age + soon-to-expire detection

State shape: certs (list of dicts with id/name_value/issuer/not_before/
not_after), unique_sans (set), wildcard_certs (list), revoked_certs
(list), internal_hostnames (list), staging_envs (list), recent_certs
(list within 30d), issuers (dict CA->count), oldest_cert_age_days.
"""
import re


_INTERNAL_HOSTNAME_PATTERNS = [
    r"\.internal\.",       r"\.intranet\.",      r"\.corp\.",
    r"\.local\.",          r"\.lan\.",            r"\.localdomain\.",
    r"\.private\.",        r"\.test\.",
]

_STAGING_ENV_PATTERNS = [
    r"^(staging|stage|stg|test|qa|uat|preprod|pre-prod|dev|development)\.",
    r"\.(staging|stage|stg|test|qa|uat|preprod|dev)\.",
    r"-(staging|stage|stg|test|qa|uat|preprod|dev)\.",
]


def rule_total_certs(s):
    n = len(s.get("certs") or [])
    if n == 0: return None
    return {"name": f"{n} certificate(s) in transparency logs",
            "severity": "INFO",
            "evidence": f"crt.sh + secondary CT sources returned {n} total cert records"}


def rule_no_certs(s):
    if (s.get("certs") or []): return None
    return {"name": "No certificates found in CT logs",
            "severity": "INFO",
            "evidence": "No public certs issued for this domain — uncommon for production HTTPS sites",
            "remediation": "If the site uses HTTPS, expect certs in CT logs within minutes of issuance. Absence may indicate self-signed certs (not browser-trusted) or very new domain."}


def rule_wildcard_certs(s):
    wc = s.get("wildcard_certs") or []
    if not wc: return None
    return {"name": f"Wildcard certificate(s) issued ({len(wc)})",
            "severity": "MEDIUM",
            "cwe": "CWE-295",
            "evidence": f"Wildcards found: {', '.join(wc[:3])}",
            "remediation": "Wildcards expand blast radius — a compromised wildcard key authenticates ALL subdomains. Prefer SAN-listed individual certs for sensitive domains."}


def rule_internal_hostnames_leaked(s):
    ih = s.get("internal_hostnames") or []
    if not ih: return None
    return {"name": f"Internal hostnames leaked in cert SANs ({len(ih)})",
            "severity": "HIGH",
            "cwe": "CWE-200",
            "evidence": f"Found in SAN: {', '.join(ih[:5])}",
            "remediation": "CT logs are public — internal hostnames in SANs leak network topology. Issue separate certs for internal vs external systems."}


def rule_staging_envs_exposed(s):
    se = s.get("staging_envs") or []
    if not se: return None
    return {"name": f"Pre-production environments exposed in CT ({len(se)})",
            "severity": "MEDIUM",
            "cwe": "CWE-200",
            "evidence": f"staging/dev/test SANs: {', '.join(se[:5])}",
            "remediation": "Staging URLs are recon gold for attackers — they often have weaker security than prod. Either remove from SANs, or IP-restrict the staging endpoints."}


def rule_recent_cert_burst(s):
    rc = s.get("recent_certs") or []
    if len(rc) < 5: return None
    return {"name": f"High recent cert issuance rate ({len(rc)} in 30 days)",
            "severity": "INFO",
            "evidence": f"{len(rc)} certs issued in last 30 days — may indicate auto-renewal churn or service expansion",
            "remediation": "If you didn't deploy that many new services, investigate — could indicate compromised issuance process."}


def rule_ca_diversity(s):
    issuers = s.get("issuers") or {}
    if not issuers: return None
    n = len(issuers)
    if n == 1:
        only_ca = next(iter(issuers.keys()))
        return {"name": f"Single CA dependency ({only_ca})",
                "severity": "LOW",
                "evidence": f"All {sum(issuers.values())} certs issued by one CA: {only_ca}",
                "remediation": "CA monoculture — if your CA has an outage or revokes mass certs, you're affected. Consider 2-CA strategy (e.g., Let's Encrypt primary + ZeroSSL backup)."}
    return {"name": f"Multi-CA strategy ({n} different CAs)",
            "severity": "POSITIVE",
            "evidence": "CAs used: " + ", ".join(f"{ca}({cnt})" for ca, cnt in list(issuers.items())[:5])}


def rule_unique_sans(s):
    sans = s.get("unique_sans") or set()
    n = len(sans) if isinstance(sans, (set, list)) else 0
    if n < 5: return None
    return {"name": f"{n} unique hostnames discovered via CT SANs",
            "severity": "INFO",
            "evidence": f"CT logs expose {n} unique hostnames across all certs — useful for subdomain enumeration"}


def rule_oldest_cert(s):
    age = s.get("oldest_cert_age_days")
    if age is None or age < 1825: return None  # 5 years
    return {"name": f"Mature CT footprint (oldest cert {age // 365}+ years old)",
            "severity": "POSITIVE",
            "evidence": f"Oldest cert in CT logs: {age} days old"}


CERTTRANS_FINDING_RULES = [
    rule_total_certs,
    rule_no_certs,
    rule_wildcard_certs,
    rule_internal_hostnames_leaked,
    rule_staging_envs_exposed,
    rule_recent_cert_burst,
    rule_ca_diversity,
    rule_unique_sans,
    rule_oldest_cert,
]


def classify_hostname(name: str) -> tuple[bool, bool]:
    """Returns (is_internal, is_staging) for a hostname."""
    name = name.lower().strip()
    is_internal = any(re.search(p, name) for p in _INTERNAL_HOSTNAME_PATTERNS)
    is_staging = any(re.search(p, name) for p in _STAGING_ENV_PATTERNS)
    return is_internal, is_staging
