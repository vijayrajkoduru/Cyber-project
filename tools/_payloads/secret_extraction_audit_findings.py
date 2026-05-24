"""secret_extraction_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("secret_extraction_audit_total"):
        return None
    return {"name": "Secret extraction: no hardcoded credentials found",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} files scanned with 10 secret-pattern regexes — no matches",
            "remediation": "Continue using env vars / secrets manager. Re-scan every release.",
            "cwe": "CWE-798", "owasp": "M9:2023"}


def rule_critical_secrets(s):
    hits = s.get("secrets_found") or []
    critical = [h for h in hits if h["kind"] in
                ("AWS Access Key", "AWS Secret", "Stripe Live Key",
                 "GitHub Token", "RSA Private Key", "Slack Token")]
    if not critical:
        return None
    return {"name": f"{len(critical)} CRITICAL hardcoded secret(s) detected",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-798", "owasp": "M9:2023",
            "evidence": "; ".join(f"{h['kind']} in {h['file']}" for h in critical[:5]),
            "remediation": "ROTATE EACH KEY IMMEDIATELY. Remove from source. Use cloud secrets manager. Audit access logs for unauthorized use."}


def rule_high_secrets(s):
    hits = s.get("secrets_found") or []
    high = [h for h in hits if h["kind"] in
            ("Google API Key", "Firebase URL", "JWT", "Generic API Token")]
    if not high:
        return None
    return {"name": f"{len(high)} hardcoded API token(s) detected",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-798", "owasp": "M9:2023",
            "evidence": "; ".join(f"{h['kind']} in {h['file']}" for h in high[:5]),
            "remediation": "Restrict API keys by SHA-1 / package name in Google Cloud Console. Move tokens to backend proxy."}


SECRET_EXTRACTION_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_critical_secrets,
    rule_high_secrets,
]
