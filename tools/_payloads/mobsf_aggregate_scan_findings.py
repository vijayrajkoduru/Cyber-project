"""mobsf_aggregate_scan — findings rules."""


def rule_positive_emit(s):
    if s.get("mobsf_aggregate_scan_total") or s.get("mobsf_error"):
        return None
    # Always emit aggregate metadata regardless of MobSF presence
    sha = s.get("sha256", "?")
    size = s.get("file_size_mb", "?")
    return {"name": f"Binary aggregate: {size} MB, SHA-256: {(sha or '?')[:16]}...",
            "severity": "POSITIVE",
            "evidence": f"SHA-256: {sha}; size: {size} MB; DEX files: {s.get('dex_files', '?')}; native libs: {s.get('native_libs', '?')}",
            "remediation": "Submit SHA-256 to VirusTotal for community AV checks.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_mobsf_findings(s):
    if not s.get("mobsf_aggregate_scan_total"):
        return None
    return {"name": "MobSF aggregate scan completed",
            "severity": "INFO",
            "evidence": "MobSF returned structured findings (see raw output)",
            "remediation": "Review MobSF report. Map HIGH+ findings to OWASP MASVS controls.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_mobsf_unavailable(s):
    if not s.get("mobsf_error"):
        return None
    return {"name": "MobSF aggregate scan unavailable (fallback used)",
            "severity": "INFO",
            "evidence": s.get("mobsf_error", "MobSF not installed in container"),
            "remediation": "Install MobSF for richer static analysis. The other 11 scanners still ran.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


MOBSF_AGGREGATE_SCAN_FINDING_RULES = [
    rule_positive_emit,
    rule_mobsf_findings,
    rule_mobsf_unavailable,
]
