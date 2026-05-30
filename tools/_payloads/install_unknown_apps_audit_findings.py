"""install_unknown_apps_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("install_unknown_apps_audit_total", 0) > 0: return None
    return {"name": "No sideload / install-packages perms requested",
            "severity": "POSITIVE",
            "cwe": "CWE-250", "owasp": "M8:2023",
            "evidence": "no REQUEST_INSTALL_PACKAGES / DELETE_PACKAGES",
            "remediation": "App can't sideload — minimal package-install attack surface."}


def rule_sideload_perms(s):
    perms = s.get("sideload_perms") or []
    if not perms: return None
    has_install = any("INSTALL" in p for p in perms)
    has_delete  = any("DELETE" in p for p in perms)
    sev = "HIGH" if has_install else "MEDIUM"
    cvss = "7.0" if has_install else "5.0"
    return {"name": f"App requests sideload perms ({len(perms)})",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-250", "owasp": "M8:2023",
            "evidence": " | ".join(perms),
            "remediation": "REQUEST_INSTALL_PACKAGES lets app prompt user to install "
                           "ANY APK from a downloaded file. Only legitimate use cases: "
                           "(a) you ARE an app store (Amazon Appstore, F-Droid, "
                           "Galaxy Store), (b) you do your own A/B updates (rare). "
                           "Google Play scrutinizes this perm heavily — declare exact "
                           "use case in your Play Store listing or face rejection."}
