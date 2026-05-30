"""advertising_id_audit — findings rules."""


def rule_positive_emit(s):
    usage = s.get("ad_id_usage") or {}
    if any(usage.values()): return None
    return {"name": "No advertising-ID usage detected",
            "severity": "POSITIVE",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files, no IDFA/AAID markers",
            "remediation": "App doesn't read advertising identifiers — no IDFA/ATT "
                           "compliance burden. For Android: still declare AD_ID perm "
                           "as 'false' for clarity in API 33+ Play submission."}


def rule_ios_idfa_no_att(s):
    usage = s.get("ad_id_usage") or {}
    if usage.get("ios_idfa") and not usage.get("ios_att"):
        return {"name": "IDFA access WITHOUT AppTrackingTransparency request",
                "severity": "HIGH", "cvss": "7.0",
                "cwe": "CWE-359", "owasp": "M9:2023",
                "evidence": "ASIdentifierManager called, ATTrackingManager not detected",
                "remediation": "Since iOS 14.5, advertisingIdentifier returns all-zeros "
                                "UNLESS the user has granted ATT permission. Apps shipping "
                                "IDFA-reading code without ATT request will get all-zeros "
                                "(wasted code) AND face App Store rejection. Add: "
                                "ATTrackingManager.requestTrackingAuthorization(...)."}
    return None


def rule_ios_idfa_no_purpose_string(s):
    usage = s.get("ad_id_usage") or {}
    if usage.get("ios_idfa") and not s.get("ios_att_purpose_string"):
        return {"name": "IDFA access WITHOUT NSUserTrackingUsageDescription",
                "severity": "HIGH", "cvss": "7.5",
                "cwe": "CWE-359", "owasp": "M9:2023",
                "evidence": "IDFA used, Info.plist missing NSUserTrackingUsageDescription",
                "remediation": "App Store WILL REJECT. Add NSUserTrackingUsageDescription "
                                "to Info.plist with a SPECIFIC reason: 'Used to show ads "
                                "relevant to your interests' (not generic). User sees "
                                "this string in the ATT prompt."}
    return None


def rule_android_ad_id_missing_perm(s):
    usage = s.get("ad_id_usage") or {}
    if usage.get("google_ad_id") and not s.get("android_ad_id_perm"):
        return {"name": "AAID usage WITHOUT com.google.android.gms.permission.AD_ID",
                "severity": "MEDIUM", "cvss": "5.3",
                "cwe": "CWE-359", "owasp": "M9:2023",
                "evidence": "AdvertisingIdClient called, AD_ID perm not declared",
                "remediation": "API 33+ requires declaring AD_ID permission to read "
                                "AAID. Without it: AAID returns all-zeros. Add: "
                                "<uses-permission android:name='com.google.android.gms."
                                "permission.AD_ID' />."}
    return None


def rule_ad_id_inventory(s):
    usage = s.get("ad_id_usage") or {}
    found = [k for k, v in usage.items() if v]
    if not found: return None
    if s.get("compliance_issues", 0) > 0: return None  # higher-severity rule covered
    return {"name": f"Ad-ID usage detected ({len(found)} type(s))",
            "severity": "INFO",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": ", ".join(found),
            "remediation": "Declare in App Privacy Nutrition + Play Data Safety: "
                            "category = Identifiers, used-for = Advertising/marketing. "
                            "Honor user's tracking-permission choice in your analytics SDK."}
