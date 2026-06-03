"""csp_trusted_types_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("csp_trusted_types_audit_total"):
        return None
    return {"name": "CSP + Trusted Types posture clean or N/A",
            "severity": "POSITIVE",
            "evidence": f"CSP files={len(s.get('html_files_with_csp') or [])} | Trusted Types={s.get('trusted_types_uses', 0)}",
            "remediation": "Continue shipping CSP meta + require-trusted-types-for in every WebView HTML.",
            "cwe": "CWE-79", "owasp": "M4:2023"}


def rule_no_csp(s):
    if s.get("html_files_with_csp"): return None
    if s.get("files_scanned", 0) <= 5: return None
    return {"name": "WebView HTML/JS bundle ships without CSP meta",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-79", "owasp": "M4:2023",
            "evidence": f"{s.get('files_scanned', 0)} html/js scanned; no <meta http-equiv=Content-Security-Policy>",
            "remediation": "Add <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; ...\"> to every loaded HTML."}


def rule_unsafe_csp(s):
    u = s.get("unsafe_csp_directives") or []
    if not u: return None
    return {"name": f"CSP carries 'unsafe-inline' / 'unsafe-eval' in {len(u)} bundle(s)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-79", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(u[:6]),
            "remediation": "Remove 'unsafe-inline' and 'unsafe-eval'; refactor inline scripts to external files with nonces / hashes."}


CSP_TRUSTED_TYPES_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_csp, rule_unsafe_csp]
