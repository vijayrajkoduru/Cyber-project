"""nfc_attack_surface — findings rules."""


def rule_positive_emit(s):
    if s.get("nfc_attack_surface_total"):
        return None
    return {"name": "No NFC attack surface",
            "severity": "POSITIVE",
            "evidence": f"manifest + {s.get('files_scanned', 0)} smali files scanned - no NFC permission / NfcAdapter / IsoDep markers",
            "remediation": "App does not use NFC. No NFC pentest tooling needed.",
            "cwe": "CWE-200", "owasp": "M3:2023"}


def rule_nfc_hce_service(s):
    if not s.get("nfc_hce_service_declared"):
        return None
    return {"name": "Host Card Emulation (HCE) service declared",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-300", "owasp": "M3:2023",
            "evidence": "Service with BIND_NFC_SERVICE permission found in manifest",
            "remediation": "HCE = the app emulates a contactless card (payment / transit / access). Verify backend validates every transaction independently (no client-only signing) + uses AID-based isolation. Test with Proxmark3 / Flipper Zero replay."}


def rule_nfc_general(s):
    perms = s.get("nfc_permissions") or []
    apis = s.get("nfc_api_hits") or {}
    if not (perms or apis) or s.get("nfc_hce_service_declared"):
        return None
    return {"name": "NFC tag-reading or P2P NFC usage detected",
            "severity": "INFO",
            "cwe": "CWE-300", "owasp": "M3:2023",
            "evidence": f"Permissions: {', '.join(p.split('.')[-1] for p in perms)}; APIs: {', '.join(list(apis.keys())[:5])}",
            "remediation": "Plan an NFC-specific pentest. Reading: clone tag with Proxmark3, verify server distinguishes original vs clone (UID-only auth = trivial bypass). P2P: replay captured exchange."}


NFC_ATTACK_SURFACE_FINDING_RULES = [
    rule_positive_emit,
    rule_nfc_hce_service,
    rule_nfc_general,
]
