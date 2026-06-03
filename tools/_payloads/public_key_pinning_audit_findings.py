"""public_key_pinning_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("public_key_pinning_audit_total"):
        return None
    return {"name": "Public-key pinning posture clean",
            "severity": "POSITIVE",
            "evidence": (f"NSC pinning files={len(s.get('nsc_pinning_files') or [])} "
                         f"backup-pin={s.get('nsc_has_backup_pin')} | "
                         f"iOS NSPinnedDomains={len(s.get('ios_pin_files') or [])}"),
            "remediation": "Continue pinning with at least one backup pin and rotate before expiry.",
            "cwe": "CWE-295", "owasp": "M3:2023"}


def rule_no_backup_pin(s):
    if not s.get("nsc_pinning_files") or s.get("nsc_has_backup_pin"):
        return None
    return {"name": "Android NSC pinning has no backup pin",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-295", "owasp": "M3:2023",
            "evidence": "Single <pin digest=\"SHA-256\"> entry detected - no second-pin failover",
            "remediation": ("Add a second <pin> entry for backup CA / future leaf cert so rotation "
                            "doesn't brick the app when the primary pin expires.")}


def rule_no_pinning(s):
    if s.get("nsc_pinning_files") or s.get("ios_pin_files"):
        return None
    if not s.get("has_network_security_config"):
        return None
    return {"name": "Network security config present but no public-key pinning",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-295", "owasp": "M3:2023",
            "evidence": "network_security_config.xml shipped but no <pin-set> entry",
            "remediation": ("Add <pin-set> with at least two SHA-256 pins (current + backup). "
                            "iOS: NSPinnedDomains with NSPinnedLeafIdentities or NSPinnedCAIdentities.")}


PUBLIC_KEY_PINNING_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_backup_pin, rule_no_pinning]
