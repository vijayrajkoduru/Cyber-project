"""ssl_pinning_detection — findings rules."""


def rule_positive_emit(s):
    if s.get("ssl_pinning_detection_total"):
        return None
    return {"name": "No SSL pinning library detected - traffic is interceptable with default Burp+CA",
            "severity": "MEDIUM", "cvss": "5.0",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned - no OkHttp CertificatePinner / TrustKit / Cronet / custom TrustManager markers",
            "remediation": "If the app handles money / PII / auth tokens, add SSL pinning. Recommended: OkHttp CertificatePinner with backup pin + 30-day rotation policy.",
            "cwe": "CWE-295", "owasp": "M3:2023"}


def rule_pinning_present(s):
    libs = s.get("pinning_libraries") or {}
    if not libs:
        return None
    pins = s.get("extracted_pins") or []
    library_list = ", ".join(libs.keys())
    return {"name": f"SSL pinning present: {len(libs)} library/pattern(s)",
            "severity": "POSITIVE",
            "cwe": "CWE-295", "owasp": "M3:2023",
            "evidence": f"Libraries: {library_list}; extracted pins: {len(pins)}",
            "remediation": "Pinning is present - manual verification still recommended (Frida CodeShare universal bypass + Objection both work against OkHttp default). Consider native pinning + Play Integrity attestation for high-value flows."}


def rule_weak_pinning_pattern(s):
    libs = s.get("pinning_libraries") or {}
    weak = [l for l in libs if l in ("Custom TrustManager subclass",)]
    if not weak:
        return None
    return {"name": f"Custom TrustManager subclass found - verify it actually validates",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-295", "owasp": "M3:2023",
            "evidence": "Files: " + ", ".join(libs.get("Custom TrustManager subclass", [])[:5]),
            "remediation": "Custom X509TrustManager.checkServerTrusted methods often DISABLE validation accidentally. Decompile each and confirm it throws CertificateException on untrusted cert."}


SSL_PINNING_DETECTION_FINDING_RULES = [
    rule_positive_emit,
    rule_pinning_present,
    rule_weak_pinning_pattern,
]
