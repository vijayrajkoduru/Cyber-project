"""cert_validation_bypass_audit — findings rules.

Zero-FP: "presence != usage". A TrustAll/HostnameVerifier class that is merely
*defined* (or lives inside a bundled SDK / test code) is not an exploitable
MITM bug. We grade CRITICAL only when the bypass is in APP code AND the app
actually wires a custom SSLSocketFactory / HostnameVerifier into its network
stack. Otherwise the reference is reported at INFO.
"""


def rule_positive_emit(s):
    if s.get("cert_validation_bypass_audit_total"):
        return None
    return {"name": "Certificate validation: no bypass patterns",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned with 5 bypass-pattern rules",
            "remediation": "Continue using the default TrustManager + system CA store. For high-value flows add certificate pinning.",
            "cwe": "CWE-295", "owasp": "M10:2023"}


def rule_bypass_detected(s):
    app_hits = s.get("cert_validation_bypass_app_hits") or {}
    used = s.get("cert_validation_bypass_used")
    # Only a CONFIRMED, wired bypass in the app's own code is critical.
    if not app_hits or not used:
        return None
    return {"name": f"{len(app_hits)} cert-validation bypass pattern(s) wired into app network code",
            "severity": "CRITICAL", "cvss": "8.5",
            "cwe": "CWE-295", "owasp": "M10:2023",
            "evidence": "; ".join(f"{label}: {len(files)} file(s)" for label, files in list(app_hits.items())[:5]),
            "remediation": "Remove TrustAllX509TrustManager / empty checkServerTrusted / ALLOW_ALL_HOSTNAME_VERIFIER. These disable TLS entirely - attacker on the same Wi-Fi gets full MITM."}


def rule_bypass_present_unconfirmed(s):
    """Bypass pattern present in app code but NOT observed being wired into the
    network stack, OR present only in SDK/test paths. Reported, not graded."""
    all_hits = s.get("cert_validation_bypass_hits") or {}
    app_hits = s.get("cert_validation_bypass_app_hits") or {}
    used = s.get("cert_validation_bypass_used")
    if not all_hits:
        return None
    # Suppress if the CRITICAL rule already fired (app + wired).
    if app_hits and used:
        return None
    if app_hits and not used:
        detail = "in app code but no custom SSLSocketFactory/HostnameVerifier wiring observed"
        hits = app_hits
    else:
        detail = "only in bundled SDKs / test code"
        hits = all_hits
    return {"name": f"{len(hits)} cert-validation bypass pattern(s) present — {detail}",
            "severity": "INFO",
            "cwe": "CWE-295", "owasp": "M10:2023",
            "evidence": "; ".join(f"{label}: {len(files)} file(s)" for label, files in list(hits.items())[:5]),
            "remediation": "Confirm whether the bypass class is instantiated and installed on a live connection. Unused/SDK-internal TrustManagers are not an exploitable MITM. Remove dead bypass code regardless."}


CERT_VALIDATION_BYPASS_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_bypass_detected,
    rule_bypass_present_unconfirmed,
]
