"""weak_algo_audit — findings rules.

Zero-FP: "presence != usage". An algorithm name appearing in decompiled
bytecode may belong to a bundled SDK, not the app. The scanner provides
`weak_algos_app_code` (algos seen in app code, excluding library/test paths).
Only those are graded; algos referenced ONLY inside libraries -> INFO.
"""

HIGH_RISK = ("DES", "3DES", "RC4/RC2", "PBEWithMD5", "ECB-mode hint")
MEDIUM_RISK = ("Blowfish", "MD5", "SHA-1")


def rule_positive_emit(s):
    if s.get("weak_algo_audit_total"):
        return None
    return {"name": "No weak crypto algorithms detected",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned - no DES/3DES/RC4/MD5/SHA-1/ECB references",
            "remediation": "Continue using AES-GCM (auth-encrypt), SHA-256 / SHA-3, PBKDF2 / Argon2id.",
            "cwe": "CWE-327", "owasp": "M10:2023"}


def rule_high_risk_algos(s):
    app = s.get("weak_algos_app_code") or {}
    high_risk = {a: f for a, f in app.items() if a in HIGH_RISK}
    if not high_risk:
        return None
    return {"name": f"{len(high_risk)} HIGH-risk algorithm(s) referenced in app code",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-327", "owasp": "M10:2023",
            "evidence": "; ".join(f"{a}: {len(files)} file(s)" for a, files in high_risk.items()),
            "remediation": "Replace DES/3DES/RC4 with AES-GCM. Replace PBEWithMD5 with PBKDF2WithHmacSHA256. ECB-mode = visible plaintext patterns."}


def rule_medium_risk_algos(s):
    app = s.get("weak_algos_app_code") or {}
    medium = {a: f for a, f in app.items() if a in MEDIUM_RISK}
    if not medium:
        return None
    return {"name": f"{len(medium)} MEDIUM-risk algorithm(s) referenced in app code (collision-vulnerable hashes / aging cipher)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-328", "owasp": "M10:2023",
            "evidence": "; ".join(f"{a}: {len(files)} file(s)" for a, files in medium.items()),
            "remediation": "MD5/SHA-1 are broken for collision resistance — confirm they aren't on a security path (e.g. password/signature). MD5 used only as a cache/ETag key is acceptable. Replace Blowfish with AES."}


def rule_library_only_algos(s):
    """Weak algorithms referenced ONLY in bundled SDKs / test paths.
    Reported for awareness, not graded — the app does not control library internals."""
    found = s.get("weak_algos_found") or {}
    app = s.get("weak_algos_app_code") or {}
    lib_only = {a: f for a, f in found.items() if a not in app}
    if not lib_only:
        return None
    return {"name": f"{len(lib_only)} weak algorithm(s) referenced only by bundled libraries/test code",
            "severity": "INFO",
            "cwe": "CWE-327", "owasp": "M10:2023",
            "evidence": "; ".join(f"{a}: {len(files)} file(s)" for a, files in lib_only.items()),
            "remediation": "These references live in 3rd-party SDKs or test/mock code, not the app's own crypto path. No action unless the app explicitly drives the weak primitive through that SDK."}


WEAK_ALGO_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_high_risk_algos,
    rule_medium_risk_algos,
    rule_library_only_algos,
]
