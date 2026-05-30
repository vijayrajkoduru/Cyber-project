"""biometric_auth_audit — findings rules."""


def rule_positive_emit(s):
    mod = s.get("biometric_modern_found") or []
    dep = s.get("biometric_deprecated_found") or []
    if mod and not dep:
        return {"name": f"Modern biometric auth in use ({len(mod)} API(s))",
                "severity": "POSITIVE",
                "cwe": "CWE-287", "owasp": "M3:2023",
                "evidence": ", ".join(m["name"] for m in mod[:4]),
                "remediation": "Maintain. Add CryptoObject-bound biometric (so success "
                               "actually unlocks a Keystore key) rather than result-only "
                               "biometric (which is bypassable on rooted devices)."}
    return None


def rule_no_biometric_at_all(s):
    if (s.get("biometric_modern_found") or []) or (s.get("biometric_deprecated_found") or []):
        return None
    return {"name": "No biometric authentication detected",
            "severity": "LOW",
            "cwe": "CWE-287", "owasp": "M3:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files, no biometric APIs",
            "remediation": "Not always required (chat apps, weather, etc.). For apps "
                           "handling financial transactions / health data / encrypted "
                           "vaults: add BiometricPrompt (Android) / LocalAuthentication "
                           "(iOS) for re-auth before sensitive ops. PSD2 SCA / FFIEC "
                           "guidance recommend biometric as an inherence factor."}


def rule_deprecated_biometric(s):
    dep = s.get("biometric_deprecated_found") or []
    if not dep: return None
    return {"name": f"Deprecated biometric API in use ({len(dep)})",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-287", "owasp": "M3:2023",
            "evidence": ", ".join(d["name"] for d in dep),
            "remediation": "FingerprintManager was deprecated in API 28. Migrate to "
                           "AndroidX BiometricPrompt for face + fingerprint + class-3 "
                           "biometric strength selection + crypto-object binding. "
                           "Old API doesn't gate on biometric class strength → weak-class "
                           "biometric can unlock."}
