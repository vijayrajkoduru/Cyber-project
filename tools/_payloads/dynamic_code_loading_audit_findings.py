"""dynamic_code_loading_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("dynamic_code_loading_audit_total"):
        return None
    return {"name": "No dynamic code loading detected",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} files scanned - no DexClassLoader / dlopen / dyld",
            "remediation": "Continue avoiding runtime code loading; ship all code in the signed bundle.",
            "cwe": "CWE-829", "owasp": "M3:2023"}


def rule_remote_payload(s):
    urls = s.get("remote_payload_urls") or []
    callers = (s.get("dex_callers") or []) + (s.get("dlopen_callers") or []) + (s.get("ios_callers") or [])
    if not (urls and callers):
        return None
    return {"name": f"Remote payload URLs ({len(urls)}) co-located with dynamic loader",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": f"URLs: {', '.join(urls[:4])} | Loaders in: {', '.join(callers[:4])}",
            "remediation": ("Block remote code loading. If you must, verify payload signature with a "
                            "vendor public key before passing to ClassLoader/dlopen.")}


def rule_dynamic_loading_present(s):
    if s.get("remote_payload_urls"):
        return None  # higher-severity already
    callers = (s.get("dex_callers") or []) + (s.get("dlopen_callers") or []) + (s.get("ios_callers") or [])
    if not callers:
        return None
    return {"name": f"Dynamic code-loading APIs called in {len(callers)} class(es)",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": f"Callers: {', '.join(callers[:6])}",
            "remediation": "Audit each call. Static code shipped in bundle is safest; flag any path that loads from disk paths the user can write."}


DYNAMIC_CODE_LOADING_AUDIT_FINDING_RULES = [rule_positive_emit, rule_remote_payload, rule_dynamic_loading_present]
