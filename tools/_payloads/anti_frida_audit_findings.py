"""anti_frida_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("anti_frida_audit_total"):
        return None
    return {"name": "NO anti-Frida defenses - Frida hooks succeed instantly",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": f"{s.get('files_scanned', 0)} smali files + native libs scanned - no port 27042 / frida-server / re.frida.server markers",
            "remediation": "Add: port-27042 socket connect attempt, /proc/self/maps scan for frida-agent, named-pipe check for re.frida.server. Best in JNI_OnLoad so it runs before Java-level hooks attach."}


def rule_partial_defense(s):
    mechs = s.get("anti_frida_mechanisms") or {}
    if not mechs or len(mechs) >= 3:
        return None
    return {"name": f"Limited anti-Frida: only {len(mechs)} mechanism(s)",
            "severity": "LOW", "cvss": "3.5",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": "; ".join(mechs.keys()),
            "remediation": "Stack multiple checks - port scan + /proc/self/maps + pthread inspection + named pipe. Single-check defenses are bypassed with Frida's --no-pause + delayed hook."}


def rule_strong_defense(s):
    mechs = s.get("anti_frida_mechanisms") or {}
    native = s.get("native_anti_frida") or []
    if not (len(mechs) >= 3 or (mechs and native)):
        return None
    return {"name": f"Layered anti-Frida defense: {len(mechs)} Java + {len(native)} native lib(s)",
            "severity": "POSITIVE",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": "Java: " + ", ".join(list(mechs.keys())[:3]) + (f"; Native: {native[0]}" if native else ""),
            "remediation": "Solid foundation. Pair with Play Integrity attestation server-side so a successful client bypass still triggers account-side rejection."}


ANTI_FRIDA_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_strong_defense,
    rule_partial_defense,
]
