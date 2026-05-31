"""device_admin_perm_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("device_admin_perm_audit_total", 0) > 0: return None
    return {"name": "No Device Admin declaration",
            "severity": "POSITIVE",
            "cwe": "CWE-668", "owasp": "M8:2023",
            "evidence": "no BIND_DEVICE_ADMIN receivers",
            "remediation": "App doesn't request device-admin privileges."}


def rule_device_admin_present(s):
    recv = s.get("device_admin_receivers") or []
    if not recv: return None
    return {"name": f"Device Admin declared ({len(recv)} receiver(s)) — high-privilege",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-668", "owasp": "M8:2023",
            "evidence": " | ".join(r["name"] for r in recv),
            "remediation": "Device Admin lets the app lock screen + wipe + force-pwd-change + "
                           "disable camera. Legitimate use: MDM. ANY other use case is "
                           "suspicious and Google Play will likely reject. Note: legacy "
                           "Device Admin is being DEPRECATED in favor of Device Policy "
                           "Controller (DPC) + Work Profile for true MDM. Migrate."}


DEVICE_ADMIN_PERM_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_device_admin_present,
]
