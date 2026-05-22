"""Wayback Machine — findings rules library."""
import re

_SENSITIVE_URL_PATTERNS = [
    (r"/admin", "admin URL"),
    (r"/internal", "internal URL"),
    (r"/debug", "debug URL"),
    (r"/staging|/dev/|/test/", "non-prod URL"),
    (r"\.env|\.bak|\.sql|\.zip", "backup/config file"),
    (r"/api/.*/(users|admin|secret)", "sensitive API"),
]

_SENSITIVE_PARAM_NAMES = [
    "token", "key", "secret", "password", "pwd", "passwd",
    "api_key", "access_token", "refresh_token", "session",
    "auth", "private", "credential",
]


def rule_total_snapshots(s):
    n = s.get("total_snapshots") or 0
    if n == 0: return None
    return {"name": f"{n} historical snapshot(s) in Wayback",
            "severity": "INFO",
            "evidence": f"archive.org has captured {n} URLs from this domain"}


def rule_no_snapshots(s):
    if (s.get("total_snapshots") or 0) > 0: return None
    return {"name": "No Wayback snapshots found",
            "severity": "INFO",
            "evidence": "Domain not in archive.org — either too new, or archive blocked"}


def rule_forgotten_admin(s):
    fa = s.get("forgotten_admin") or []
    if not fa: return None
    return {"name": f"Forgotten admin/internal URLs in Wayback ({len(fa)})",
            "severity": "HIGH",
            "cwe": "CWE-540",
            "evidence": ", ".join(f["url"] for f in fa[:3]),
            "remediation": "These URLs were once live + archived publicly. Verify each: still accessible? Auth-required? Remove from archive via Wayback's exclude form if no longer in use."}


def rule_sensitive_params_in_history(s):
    sp = s.get("sensitive_params_history") or []
    if not sp: return None
    return {"name": f"Sensitive parameters in historical URLs ({len(sp)})",
            "severity": "MEDIUM",
            "cwe": "CWE-598",
            "evidence": f"Found params: {', '.join(set(sp))}",
            "remediation": "Tokens/keys in URL query strings get logged everywhere (proxy logs, browser history, Wayback). Move to POST body or headers. If any of these were real tokens, ROTATE them."}


def rule_archive_age(s):
    age = s.get("oldest_snapshot_years")
    if age is None or age < 5: return None
    return {"name": f"Long archive history ({age}+ years)",
            "severity": "INFO",
            "evidence": f"Earliest Wayback snapshot is {age} years old"}


WAYBACK_FINDING_RULES = [
    rule_total_snapshots, rule_no_snapshots, rule_forgotten_admin,
    rule_sensitive_params_in_history, rule_archive_age,
]


def classify_url(url):
    for pat, why in _SENSITIVE_URL_PATTERNS:
        if re.search(pat, url, re.I):
            return why
    return None


def extract_sensitive_param_names(url):
    """Return list of sensitive param names found in URL query."""
    found = []
    for name in _SENSITIVE_PARAM_NAMES:
        if re.search(rf"[?&]{name}=", url, re.I):
            found.append(name)
    return found
