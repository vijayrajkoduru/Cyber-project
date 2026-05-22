"""robots + sitemap — findings rules library."""
import re

_SENSITIVE_DISALLOW_PATTERNS = [
    (r"/admin", "admin path"),
    (r"/internal|/private", "internal area"),
    (r"/debug|/test|/staging|/dev", "non-prod path"),
    (r"/api/.*/(users|admin|config|secret)", "sensitive API"),
    (r"\.env|\.bak|\.sql|backup", "backup/config file"),
    (r"/auth|/login|/session", "auth endpoint"),
]


def rule_robots_present(s):
    if not s.get("robots_txt"): return None
    return {"name": "robots.txt present",
            "severity": "INFO",
            "evidence": f"{len(s.get('disallowed') or [])} Disallow rules"}


def rule_sitemap_present(s):
    n = len(s.get("sitemap_urls") or [])
    if n == 0: return None
    return {"name": f"sitemap.xml exposes {n} URLs",
            "severity": "INFO",
            "evidence": f"{n} unique URLs in sitemap.xml"}


def rule_sensitive_in_disallow(s):
    sd = s.get("sensitive_disallow") or []
    if not sd: return None
    return {"name": f"Sensitive paths revealed in robots.txt ({len(sd)})",
            "severity": "MEDIUM",
            "cwe": "CWE-200",
            "evidence": "; ".join(f"{x['path']} ({x['why']})" for x in sd[:5]),
            "remediation": "robots.txt is PUBLIC — listing /admin or /internal there TELLS attackers exactly where to look. Block via auth/firewall, then DON'T list in robots.txt."}


def rule_security_txt_present(s):
    if not s.get("security_txt"): return None
    return {"name": "security.txt published (RFC 9116)",
            "severity": "POSITIVE",
            "evidence": "Found at /.well-known/security.txt",
            "remediation": ""}


def rule_security_txt_missing(s):
    if s.get("security_txt"): return None
    if not s.get("base_reachable"): return None
    return {"name": "security.txt missing",
            "severity": "LOW",
            "evidence": "Not found at /.well-known/security.txt",
            "remediation": "Add a security.txt at /.well-known/security.txt declaring your responsible-disclosure contact. RFC 9116 standard."}


def rule_well_known_endpoints(s):
    we = s.get("well_known_found") or []
    if not we: return None
    return {"name": f"{len(we)} /.well-known/ endpoint(s) discovered",
            "severity": "INFO",
            "evidence": ", ".join(we[:5])}


ROBOTSMAP_FINDING_RULES = [
    rule_robots_present, rule_sitemap_present, rule_sensitive_in_disallow,
    rule_security_txt_present, rule_security_txt_missing,
    rule_well_known_endpoints,
]


def classify_disallow(path):
    for pat, why in _SENSITIVE_DISALLOW_PATTERNS:
        if re.search(pat, path, re.I):
            return why
    return None
