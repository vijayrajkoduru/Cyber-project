"""sqlcipher_presence_check — findings rules."""


def rule_positive_emit(s):
    if not s.get("sqlcipher_presence_check_total"):
        return None
    markers = s.get("encryption_markers") or {}
    libs = s.get("sqlcipher_libs") or []
    return {"name": "Encrypted-at-rest DB: SQLCipher / Realm encryption present",
            "severity": "POSITIVE",
            "evidence": f"Markers: {', '.join(list(markers.keys())[:5])}; native libs: {len(libs)}",
            "remediation": "Continue rotating DB encryption keys with each major release. Store key in Android Keystore (StrongBox where available).",
            "cwe": "CWE-311", "owasp": "M9:2023"}


def rule_no_encryption(s):
    if s.get("sqlcipher_presence_check_total"):
        return None
    return {"name": "No encrypted-DB markers found",
            "severity": "INFO",
            "evidence": "Searched for SQLCipher, Realm encryption, Room SupportFactory - no hits",
            "remediation": "If the app stores ANY sensitive data, adopt SQLCipher or Realm encryption. Industry standard for fintech / health apps.",
            "cwe": "CWE-311", "owasp": "M9:2023"}


SQLCIPHER_PRESENCE_CHECK_FINDING_RULES = [
    rule_positive_emit,
    rule_no_encryption,
]
