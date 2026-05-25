"""tls_version_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("tls_version_audit_total"):
        return None
    return {"name": "TLS configuration: clean (no TLSv1.0/1.1, no NSC issues, no minSdk<21)",
            "severity": "POSITIVE",
            "evidence": f"manifest + {s.get('files_scanned', 0)} smali files scanned; minSdk={s.get('min_sdk', '?')}",
            "remediation": "Continue requiring TLS 1.2+. Pin certificates via OkHttp CertificatePinner OR native pinning.",
            "cwe": "CWE-326", "owasp": "M10:2023"}


def rule_min_sdk_too_low(s):
    msdk = s.get("min_sdk")
    if not (msdk and msdk.isdigit() and int(msdk) < 21):
        return None
    return {"name": f"minSdkVersion={msdk} - older devices force TLS 1.0 / 1.1",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-326", "owasp": "M10:2023",
            "evidence": f"AndroidManifest.xml uses-sdk minSdkVersion={msdk}",
            "remediation": "Raise minSdkVersion to >= 21 (Android 5.0+ defaults to TLS 1.2). Most active devices are 23+."}


def rule_tls_marker_hits(s):
    hits = s.get("tls_marker_hits") or {}
    if not hits:
        return None
    has_critical = any(k in hits for k in ("TLSv1.0", "TLSv1.1", "SSLv2/SSLv3",
                                              "Cipher.getInstance SSL only",
                                              "ALLOW_ALL_HOSTNAME_VERIFIER",
                                              "HostnameVerifier returns true"))
    sev = "HIGH" if has_critical else "MEDIUM"
    return {"name": f"{len(hits)} insecure TLS marker(s) in code",
            "severity": sev, "cvss": "7.0" if sev == "HIGH" else "5.5",
            "cwe": "CWE-326", "owasp": "M10:2023",
            "evidence": "; ".join(f"{k}: {len(v)} file(s)" for k, v in list(hits.items())[:5]),
            "remediation": "Remove TLSv1.0/1.1 literals. Use SSLContext.getInstance(\"TLSv1.2\") or \"TLSv1.3\". Drop ALLOW_ALL_HOSTNAME_VERIFIER and any HostnameVerifier that returns true."}


def rule_nsc_issues(s):
    issues = s.get("network_security_config_issues") or []
    if not issues:
        return None
    return {"name": f"network_security_config.xml issue(s): {len(issues)}",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-295", "owasp": "M10:2023",
            "evidence": "; ".join(issues[:5]),
            "remediation": "Remove trust-anchors src=\"user\" (allows MITM via user-installed CA on Android 7+). Set cleartextTrafficPermitted=\"false\"."}


TLS_VERSION_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_min_sdk_too_low,
    rule_tls_marker_hits,
    rule_nsc_issues,
]
