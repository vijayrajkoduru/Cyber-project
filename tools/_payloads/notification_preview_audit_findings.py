"""notification_preview_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("notification_preview_audit_total"):
        return None
    return {"name": "Notification preview hiding controls present",
            "severity": "POSITIVE",
            "evidence": (f"Android notif files={len(s.get('android_notif_files') or [])} "
                         f"hide-policy={s.get('android_hide_files', 0)} | "
                         f"iOS notif files={len(s.get('ios_notif_files') or [])} "
                         f"hide-policy={s.get('ios_hide_files', 0)}"),
            "remediation": "Continue using VISIBILITY_PRIVATE on Android channels and UNShowPreviews=.whenAuthenticated on iOS.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_android_no_hide(s):
    notif = s.get("android_notif_files") or []
    if not notif or (s.get("android_hide_files") or 0) > 0:
        return None
    return {"name": f"Android: {len(notif)} notification builder(s) without lockscreen-visibility policy",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": ("No setVisibility(VISIBILITY_PRIVATE) or VISIBILITY_SECRET found. "
                         f"Files: {', '.join(notif[:6])}"),
            "remediation": ("Set NotificationCompat.Builder.setVisibility(NotificationCompat.VISIBILITY_PRIVATE) and "
                            "per-channel setLockscreenVisibility on payment / transaction / OTP notifications.")}


def rule_ios_no_hide(s):
    notif = s.get("ios_notif_files") or []
    if not notif or (s.get("ios_hide_files") or 0) > 0:
        return None
    return {"name": f"iOS: {len(notif)} notification builder(s) without preview hiding",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": ("No UNShowPreviewsSetting or hideAlways policy found. "
                         f"Files: {', '.join(notif[:6])}"),
            "remediation": ("Configure UNUserNotificationCenter showsPreviewsOption = .whenAuthenticated on "
                            "sensitive UNNotificationContent; use NSE to redact content if device is locked.")}


NOTIFICATION_PREVIEW_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_android_no_hide,
    rule_ios_no_hide,
]
