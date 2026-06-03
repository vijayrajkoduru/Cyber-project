"""hook_detection_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("hook_detection_audit_total"):
        return None
    return {"name": "Hook-detection signals present",
            "severity": "POSITIVE",
            "evidence": (f"Xposed checks={len(s.get('xposed_checks') or [])} "
                         f"Substrate/Cydia checks={len(s.get('substrate_cydia_checks') or [])} "
                         f"Stack inspections={s.get('stack_inspection', 0)} "
                         f"/proc/self/maps reads={s.get('proc_self_maps_inspection', 0)}"),
            "remediation": "Continue layering hook signal detection alongside Frida + integrity checks.",
            "cwe": "CWE-693", "owasp": "M8:2023"}


def rule_no_hook_detection(s):
    if s.get("xposed_checks") or s.get("substrate_cydia_checks") or s.get("stack_inspection"):
        return None
    return {"name": "App does not detect Xposed / Substrate / Cydia hooking",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": (f"No Xposed/Substrate class references or stack-trace inspection in "
                         f"{s.get('files_scanned', 0)} files. Attacker can hook business logic "
                         f"without triggering existing root/Frida checks."),
            "remediation": ("Inspect /proc/self/maps for libsubstrate.so / XposedBridge.jar at startup; "
                            "verify caller stack-trace doesn't contain de.robv.android.xposed; "
                            "exit on detection.")}


HOOK_DETECTION_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_hook_detection]
