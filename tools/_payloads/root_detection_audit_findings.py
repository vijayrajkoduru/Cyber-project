"""root_detection_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("root_detection_audit_total"):
        return None
    return {"name": "NO root-detection found - app runs identically on rooted devices",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned - no RootBeer, su path, Magisk, or test-keys markers",
            "remediation": "If the app handles money / PII / DRM, add root-detection (RootBeer is OK as a baseline but pair with server-side Play Integrity attestation - the bypass needs to FAIL silently or trigger account-lock)."}


def rule_root_detection_present(s):
    mechs = s.get("root_detection_mechanisms") or {}
    if not mechs:
        return None
    only_rootbeer = list(mechs.keys()) == ["RootBeer (com.scottyab.rootbeer)"]
    sev = "INFO" if not only_rootbeer else "LOW"
    return {"name": f"Root-detection: {len(mechs)} mechanism(s) found" + (" (RootBeer-only, trivially bypassable)" if only_rootbeer else ""),
            "severity": sev, "cvss": "3.0",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": "; ".join(f"{k}: {len(v)} file(s)" for k, v in list(mechs.items())[:5]),
            "remediation": "Layer defenses: RootBeer + server-side Play Integrity + custom checks (rare paths, /init.rc parsing, mount options). Single-layer RootBeer-only takes <5 min to bypass with Frida CodeShare."}


ROOT_DETECTION_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_root_detection_present,
]
