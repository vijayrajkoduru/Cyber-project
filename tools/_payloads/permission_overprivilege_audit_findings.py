"""permission_overprivilege_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("permission_overprivilege_audit_total", 0)
    if n > 0: return None
    return {"name": "Permission profile: no dangerous / privileged perms requested",
            "severity": "POSITIVE",
            "cwe": "CWE-250", "owasp": "M8:2023",
            "evidence": f"manifest declared {s.get('permission_count', 0)} permissions, "
                        "none in dangerous-or-privileged set",
            "remediation": "Maintain least-privilege. Continue annual permission audit."}


def rule_privileged_perms(s):
    pp = s.get("privileged_permissions") or []
    if not pp: return None
    return {"name": "PRIVILEGED permission(s) requested — should be impossible for third-party apps",
            "severity": "CRITICAL", "cvss": "9.0",
            "cwe": "CWE-250", "owasp": "M8:2023",
            "evidence": " | ".join(pp),
            "remediation": "Privileged perms are only granted to apps signed by the OEM "
                           "system signature. If declared in a non-OEM app: either dead "
                           "leftover from copy-paste (remove), or attempt at silent install "
                           "/ log read / package manage. Audit each. NEVER ship to Play Store."}


def rule_dangerous_perms(s):
    dp = s.get("dangerous_permissions") or []
    if not dp: return None
    n = len(dp)
    sev = "HIGH" if n >= 8 else "MEDIUM" if n >= 4 else "LOW"
    cvss = "7.0" if n >= 8 else "5.0" if n >= 4 else "3.5"
    return {"name": f"{n} dangerous permission(s) requested",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-250", "owasp": "M8:2023",
            "evidence": " | ".join(dp[:10]),
            "remediation": "Each dangerous perm = runtime consent prompt. Audit "
                           "each: does the app's PUBLIC feature list justify it? "
                           "Common smells: requesting LOCATION when app has no map; "
                           "requesting SMS perms outside of identity-verify flows; "
                           "requesting CONTACTS when app has no contact-sharing. "
                           "Each unneeded perm = lower Play Store conversion (Play "
                           "shows the count to users) + bigger privacy attack surface."}


def rule_perm_explosion(s):
    n = s.get("permission_count", 0)
    if n < 30: return None
    return {"name": f"Permission explosion: {n} total uses-permission entries",
            "severity": "LOW",
            "cwe": "CWE-250", "owasp": "M8:2023",
            "evidence": f"manifest has {n} uses-permission tags (typical apps: 5-15)",
            "remediation": "Too many permissions = bundled SDK overreach. Audit "
                           "each SDK dependency — common cause: 3-4 analytics SDKs "
                           "each requesting LOCATION + PHONE_STATE + CONTACTS."}
