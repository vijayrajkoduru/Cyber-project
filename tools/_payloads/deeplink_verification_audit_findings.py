"""deeplink_verification_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("deeplink_verification_audit_total", 0)
    if n > 0: return None
    deep = len(s.get("all_deeplinks") or [])
    return {"name": f"Deeplinks properly verified ({deep} HTTPS, all autoVerify)",
            "severity": "POSITIVE",
            "cwe": "CWE-940", "owasp": "M3:2023",
            "evidence": f"{deep} https deeplinks, 0 unverified, 0 custom-scheme",
            "remediation": "Maintain. Continue hosting /.well-known/assetlinks.json "
                           "on every deeplinked domain."}


def rule_unverified_https(s):
    unv = s.get("unverified_deeplinks") or []
    if not unv: return None
    n = len(unv)
    return {"name": f"{n} HTTPS deeplink(s) WITHOUT autoVerify",
            "severity": "HIGH", "cvss": "7.4",
            "cwe": "CWE-940", "owasp": "M3:2023",
            "evidence": " | ".join(f"{d['scheme']}://{d['host']}" for d in unv[:5]),
            "remediation": "Add android:autoVerify='true' to each intent-filter "
                           "AND host /.well-known/assetlinks.json on each domain. "
                           "Without verification, ANY app can hijack the deeplink "
                           "(showing a Chooser bottom-sheet at best, silent-intercept "
                           "at worst). Reference: developer.android.com/training/app-links."}


def rule_custom_scheme(s):
    cs = s.get("custom_scheme_deeplinks") or []
    if not cs: return None
    n = len(cs)
    return {"name": f"{n} custom-scheme deeplink(s) — inherently hijackable",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-940", "owasp": "M3:2023",
            "evidence": " | ".join(f"{d['scheme']}://{d.get('host','')}" for d in cs[:5]),
            "remediation": "Custom schemes ('myapp://...') CANNOT be verified — any "
                           "app can register the same scheme. For auth callbacks, "
                           "migrate to App Links (HTTPS + assetlinks.json). For "
                           "in-app navigation, use NavController instead of intents. "
                           "OAuth flows MUST use App Links since iOS 9 / Android 6+."}


DEEPLINK_VERIFICATION_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_unverified_https,
    rule_custom_scheme,
]
