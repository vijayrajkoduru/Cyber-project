"""dex_protection_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("dex_protection_audit_total", 0)
    if n == 0:
        return {"name": "No commercial mobile-app shield detected",
                "severity": "LOW",
                "cwe": "CWE-693", "owasp": "M9:2023",
                "evidence": f"scanned {s.get('files_scanned', 0)} files, 0 known RASP/shields",
                "remediation": "R8 only? Fine for low-value apps. For finance / DRM / "
                               "competitive-IP apps, consider DexGuard / Promon SHIELD / "
                               "Appdome / zShield to add anti-debug, anti-Frida, "
                               "anti-tamper integrity, control-flow obfuscation, "
                               "and string encryption."}
    found = s.get("shields_found") or []
    return {"name": f"Commercial mobile-app shield active ({n})",
            "severity": "POSITIVE",
            "cwe": "CWE-693", "owasp": "M9:2023",
            "evidence": ", ".join(f["vendor"] for f in found[:5]),
            "remediation": "Strong resilience posture. Verify the shield config "
                           "includes: anti-debug, anti-Frida, root/jailbreak detect, "
                           "anti-emulator, string encryption, control-flow obfuscation, "
                           "RASP integrity check."}
