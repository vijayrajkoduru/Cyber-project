"""magisk_zygisk_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("magisk_zygisk_audit_total"):
        return None
    return {"name": "Magisk / Zygisk / Riru hide-tool checks present",
            "severity": "POSITIVE",
            "evidence": (f"Magisk={len(s.get('magisk_checks') or [])} "
                         f"Zygisk={len(s.get('zygisk_checks') or [])} "
                         f"Riru={len(s.get('riru_checks') or [])} "
                         f"magiskd socket={len(s.get('daemon_socket_checks') or [])}"),
            "remediation": "Continue checking /sbin/.magisk + Zygisk inject markers + magiskd socket.",
            "cwe": "CWE-693", "owasp": "M8:2023"}


def rule_no_modern_root_checks(s):
    if (s.get("magisk_checks") or s.get("zygisk_checks") or
        s.get("riru_checks") or s.get("daemon_socket_checks")):
        return None
    return {"name": "App does not detect Magisk Hide / Zygisk / Riru frameworks",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": (f"{s.get('files_scanned', 0)} files scanned; no /sbin/.magisk, /data/adb/magisk, "
                         "zygisk markers or magiskd-socket references"),
            "remediation": ("Existing su / busybox checks are bypassed by Magisk Hide. Add: "
                            "(1) stat() of /sbin/.magisk, /data/adb/magisk, /data/adb/modules. "
                            "(2) Look for libzygisk.so / riru.so in /proc/self/maps. "
                            "(3) Connect to @magisk daemon socket; presence = compromise.")}


MAGISK_ZYGISK_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_modern_root_checks]
