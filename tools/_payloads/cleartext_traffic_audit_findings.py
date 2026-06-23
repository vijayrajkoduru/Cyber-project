"""cleartext_traffic_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("cleartext_traffic_audit_total"):
        return None
    # Don't claim "TLS-only enforced" when a permissive flag is set but
    # unused — that case emits its own INFO finding instead.
    if ((s.get("android_cleartext_allowed") and not s.get("android_cleartext_blocked"))
            or s.get("ios_ats_arbitrary_loads") or s.get("ios_ats_exception_domains")):
        return None
    return {"name": "TLS-only network policy enforced",
            "severity": "POSITIVE",
            "evidence": (f"Android cleartext blocked={s.get('android_cleartext_blocked')} | "
                         f"iOS ATS arbitrary loads={s.get('ios_ats_arbitrary_loads')}"),
            "remediation": "Continue with usesCleartextTraffic=\"false\" + NSAllowsArbitraryLoads=false.",
            "cwe": "CWE-319", "owasp": "M3:2023"}


def _http_evidence(s):
    return (s.get("http_url_evidence") or []) + (s.get("http_client_evidence") or [])


def rule_android_cleartext(s):
    if not s.get("android_cleartext_allowed") or s.get("android_cleartext_blocked"):
        return None
    # presence != usage: the flag alone is a permissive default (Android <28).
    # Only grade HIGH when cleartext HTTP use is actually observed in code.
    confirmed = s.get("cleartext_use_confirmed")
    ev = _http_evidence(s)
    if not confirmed:
        return {"name": "Android: usesCleartextTraffic=\"true\" flag set (no cleartext HTTP use observed)",
                "severity": "INFO",
                "cwe": "CWE-319", "owasp": "M3:2023",
                "evidence": ("AndroidManifest @usesCleartextTraffic=true (or NSC cleartextTrafficPermitted=true) "
                             "but no hardcoded http:// endpoint or HttpURLConnection plaintext call was found. "
                             "This is a permissive default, not confirmed cleartext traffic."),
                "remediation": ("Tighten anyway: set usesCleartextTraffic=\"false\" and add a "
                                "network_security_config.xml with <base-config cleartextTrafficPermitted=\"false\">.")}
    return {"name": "Android: usesCleartextTraffic=\"true\" with cleartext HTTP in use",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-319", "owasp": "M3:2023",
            "evidence": ("AndroidManifest @usesCleartextTraffic=true + observed plaintext HTTP. "
                         "Evidence: " + ", ".join(ev[:5])),
            "remediation": ("Set usesCleartextTraffic=\"false\" on <application>. Add a "
                            "network_security_config.xml with <base-config cleartextTrafficPermitted=\"false\"> "
                            "and migrate the listed endpoints to HTTPS.")}


def rule_ios_ats_open(s):
    if not s.get("ios_ats_arbitrary_loads"):
        return None
    confirmed = s.get("cleartext_use_confirmed")
    ev = _http_evidence(s)
    if not confirmed:
        return {"name": "iOS: NSAllowsArbitraryLoads=true flag set (no cleartext HTTP use observed)",
                "severity": "INFO",
                "cwe": "CWE-319", "owasp": "M3:2023",
                "evidence": ("Info.plist NSAppTransportSecurity.NSAllowsArbitraryLoads=true but no http:// "
                             "endpoint observed in code. Permissive ATS policy, not confirmed cleartext."),
                "remediation": ("Remove NSAllowsArbitraryLoads and scope any genuine HTTP need to "
                                "NSExceptionDomains with justification.")}
    return {"name": "iOS: NSAllowsArbitraryLoads=true with cleartext HTTP in use (ATS disabled)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-319", "owasp": "M3:2023",
            "evidence": "Info.plist NSAllowsArbitraryLoads=true + observed plaintext HTTP: " + ", ".join(ev[:5]),
            "remediation": ("Remove NSAllowsArbitraryLoads. If a single domain truly needs HTTP, "
                            "add it under NSExceptionDomains with NSExceptionAllowsInsecureHTTPLoads + justification.")}


def rule_ios_ats_exceptions(s):
    if s.get("ios_ats_arbitrary_loads"):
        return None
    ex = s.get("ios_ats_exception_domains") or []
    if not ex:
        return None
    confirmed = s.get("cleartext_use_confirmed")
    sev = "MEDIUM" if confirmed else "INFO"
    cvss = "5.0" if confirmed else None
    return {"name": f"iOS: NSExceptionDomains with insecure HTTP allowance ({len(ex)} domain(s))"
                    + ("" if confirmed else " — no cleartext use observed"),
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-319", "owasp": "M3:2023",
            "evidence": "Files: " + ", ".join(ex[:4])
                        + ("" if confirmed else " (declared exception; no http:// endpoint confirmed in code)"),
            "remediation": "Audit each exception. Migrate listed domains to HTTPS; remove exception once vendor ships TLS."}


CLEARTEXT_TRAFFIC_AUDIT_FINDING_RULES = [rule_positive_emit, rule_android_cleartext, rule_ios_ats_open, rule_ios_ats_exceptions]
