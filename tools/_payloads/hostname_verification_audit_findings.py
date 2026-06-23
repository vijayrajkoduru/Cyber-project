"""hostname_verification_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("hostname_verification_audit_total"):
        return None
    return {"name": "No TLS-bypass overrides detected in shipping code",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} files scanned - no ALLOW_ALL / empty TrustManager / disabled iOS trust on a live TLS path",
            "remediation": "Continue relying on system default TLS validation; never override HostnameVerifier.",
            "cwe": "CWE-295", "owasp": "M3:2023"}


def rule_test_only_bypass(s):
    # Bypass markers found only in test/mock/sample harness paths, or an
    # ALLOW_ALL constant not wired into any TLS path. presence != usage.
    if s.get("hostname_verification_audit_total"):
        return None
    t = s.get("test_only_bypass_hits") or []
    if not t:
        return None
    return {"name": f"TLS-bypass marker(s) in test/mock or unused context only ({len(t)} file(s))",
            "severity": "INFO",
            "cwe": "CWE-295", "owasp": "M3:2023",
            "evidence": ("Markers in: " + ", ".join(t[:6]) + ". These are in test/mock/sample paths or an "
                         "ALLOW_ALL constant not plumbed into a TLS socket factory - not a shipping bypass."),
            "remediation": ("Confirm these are excluded from release builds (debug-only source sets / ProGuard "
                            "stripping). No action needed for production TLS if so.")}


def rule_tls_bypass(s):
    allow_all = s.get("allow_all_users") or []
    empty_v = s.get("empty_verifiers") or []
    empty_t = s.get("empty_trust_managers") or []
    ios = s.get("ios_trust_disabled") or []
    total = len(allow_all) + len(empty_v) + len(empty_t) + len(ios)
    if total == 0:
        return None
    return {"name": f"TLS validation bypassed in {total} class(es)",
            "severity": "CRITICAL", "cvss": "9.0",
            "cwe": "CWE-295", "owasp": "M3:2023",
            "evidence": (f"ALLOW_ALL={len(allow_all)} | empty verifier={len(empty_v)} | "
                         f"empty TrustManager={len(empty_t)} | iOS trust disabled={len(ios)}. "
                         f"Sample: {', '.join((allow_all + empty_v + empty_t + ios)[:5])}"),
            "remediation": ("Remove every override. Use OkHttpClient default with system TrustManager + "
                            "default HostnameVerifier. On iOS, never set allowInvalidCertificates=true or "
                            "disable kCFStreamSSLValidatesCertificateChain. MITM attackers can read all "
                            "TLS traffic with this bypass.")}


HOSTNAME_VERIFICATION_AUDIT_FINDING_RULES = [rule_positive_emit, rule_tls_bypass, rule_test_only_bypass]
