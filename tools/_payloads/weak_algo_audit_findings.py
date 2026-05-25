"""weak_algo_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("weak_algo_audit_total"):
        return None
    return {"name": "No weak crypto algorithms detected",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned - no DES/3DES/RC4/MD5/SHA-1/ECB references",
            "remediation": "Continue using AES-GCM (auth-encrypt), SHA-256 / SHA-3, PBKDF2 / Argon2id.",
            "cwe": "CWE-327", "owasp": "M10:2023"}


def rule_high_risk_algos(s):
    found = s.get("weak_algos_found") or {}
    high_risk = {a: f for a, f in found.items() if a in ("DES", "3DES", "RC4/RC2", "PBEWithMD5", "ECB-mode hint")}
    if not high_risk:
        return None
    return {"name": f"{len(high_risk)} HIGH-risk algorithm(s) referenced",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-327", "owasp": "M10:2023",
            "evidence": "; ".join(f"{a}: {len(files)} file(s)" for a, files in high_risk.items()),
            "remediation": "Replace DES/3DES/RC4 with AES-GCM. Replace PBEWithMD5 with PBKDF2WithHmacSHA256. ECB-mode = visible plaintext patterns."}


def rule_medium_risk_algos(s):
    found = s.get("weak_algos_found") or {}
    medium = {a: f for a, f in found.items() if a in ("Blowfish", "MD5", "SHA-1")}
    if not medium:
        return None
    return {"name": f"{len(medium)} MEDIUM-risk algorithm(s) referenced (collision-vulnerable hashes / aging cipher)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-328", "owasp": "M10:2023",
            "evidence": "; ".join(f"{a}: {len(files)} file(s)" for a, files in medium.items()),
            "remediation": "MD5/SHA-1 are broken for collision resistance. Use SHA-256+ everywhere. Replace Blowfish with AES."}


WEAK_ALGO_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_high_risk_algos,
    rule_medium_risk_algos,
]
