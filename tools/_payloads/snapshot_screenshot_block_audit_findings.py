"""snapshot_screenshot_block_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("snapshot_screenshot_block_audit_total"):
        return None
    if not s.get("is_ios"):
        return {"name": "Not an iOS bundle - snapshot-block check N/A",
                "severity": "POSITIVE",
                "evidence": "No .swift/.m/.h files in unpacked archive",
                "remediation": "Run snapshot block audit only against iOS .ipa binaries.",
                "cwe": "CWE-200", "owasp": "M9:2023"}
    return {"name": "iOS app blanks UI on backgrounding for sensitive views",
            "severity": "POSITIVE",
            "evidence": f"BG hook={s.get('has_bg_hook')} blanking={s.get('has_blanking')} sensitive views={len(s.get('sensitive_views') or [])}",
            "remediation": "Keep blanking logic in applicationDidEnterBackground / sceneWillResignActive.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_no_blanking(s):
    if not s.get("is_ios"):
        return None
    sv = s.get("sensitive_views") or []
    if not sv:
        return None
    if s.get("has_bg_hook") and s.get("has_blanking"):
        return None
    return {"name": f"iOS app exposes {len(sv)} sensitive view(s) in app-switcher snapshot",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": f"Sensitive views: {', '.join(sv[:6])} | BG hook={s.get('has_bg_hook')} blanking={s.get('has_blanking')}",
            "remediation": ("Implement applicationDidEnterBackground / sceneWillResignActive; "
                            "hide UIWindow.rootViewController or overlay a UIBlurEffect view before backgrounding.")}


SNAPSHOT_SCREENSHOT_BLOCK_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_no_blanking,
]
