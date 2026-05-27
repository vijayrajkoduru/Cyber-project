"""file_provider_misconfig_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("file_provider_misconfig_audit_total"):
        return None
    return {"name": "FileProvider: no wildcard / exported misconfig detected",
            "severity": "POSITIVE",
            "evidence": "manifest + res/xml/ parsed cleanly — no risky FileProvider paths",
            "remediation": "Maintain current secure-defaults practice.",
            "cwe": "CWE-22", "owasp": "M3:2023"}


def rule_fp_exported(s):
    exp = s.get("fp_exported") or []
    if not exp:
        return None
    return {"name": f"FileProvider exported=true ({len(exp)} provider(s))",
            "severity": "CRITICAL", "cvss": "9.1",
            "cwe": "CWE-926", "owasp": "M3:2023",
            "evidence": "; ".join(exp[:5]),
            "remediation": "FileProvider must NEVER be exported. Set android:exported=\"false\" and use grantUriPermissions=\"true\" with explicit FLAG_GRANT_*_URI_PERMISSION flags per Intent."}


def rule_fp_wildcard_paths(s):
    wc = s.get("fp_wildcards") or []
    if not wc:
        return None
    critical = [w for w in wc if w["element"] == "root-path"]
    if critical:
        return {"name": f"FileProvider <root-path/> wildcard ({len(critical)} match)",
                "severity": "CRITICAL", "cvss": "9.6",
                "cwe": "CWE-22", "owasp": "M3:2023",
                "evidence": "; ".join(f"{w['file']}:<{w['element']} path={w['path']}>" for w in critical[:5]),
                "remediation": "<root-path/> grants whole-filesystem access. Replace with explicit sub-paths like <files-path name=\"shared\" path=\"shared/\"/>."}
    return {"name": f"FileProvider wildcard path ({len(wc)} match)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-22", "owasp": "M3:2023",
            "evidence": "; ".join(f"{w['file']}:<{w['element']} path={w['path']}>" for w in wc[:5]),
            "remediation": "Empty path attribute grants full directory access. Replace each empty path with a specific sub-folder under app's private storage."}


FILE_PROVIDER_MISCONFIG_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_fp_exported,
    rule_fp_wildcard_paths,
]
