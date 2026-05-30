"""external_url_loading_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("external_url_loading_audit_total", 0)
    if n > 0: return None
    return {"name": f"No HTTP URLs in bundle ({s.get('https_url_count', 0)} HTTPS)",
            "severity": "POSITIVE",
            "cwe": "CWE-319", "owasp": "M5:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files",
            "remediation": "All URLs are HTTPS. Continue enforcing in Network "
                           "Security Config (cleartextTrafficPermitted='false')."}


def rule_http_urls_present(s):
    n = s.get("external_url_loading_audit_total", 0)
    if n == 0: return None
    sev = "HIGH" if n >= 5 else "MEDIUM"
    cvss = "7.5" if n >= 5 else "5.3"
    urls = s.get("http_urls_in_bundle") or []
    return {"name": f"INSECURE: {n} HTTP URL(s) hardcoded in bundle",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-319", "owasp": "M5:2023",
            "evidence": " | ".join(urls[:8]),
            "remediation": "HTTP URLs are MitM-readable + modifiable. Migrate ALL to "
                           "HTTPS. Enforce via Network Security Config: "
                           "<base-config cleartextTrafficPermitted='false'>. "
                           "iOS: set NSAllowsArbitraryLoads=false in Info.plist (ATS). "
                           "Each remaining HTTP URL needs explicit cleartextTrafficPermitted "
                           "domain exception with security justification."}


def rule_third_party_https_load(s):
    https = s.get("https_urls_in_bundle") or []
    if len(https) < 10: return None
    return {"name": f"{s.get('https_url_count',0)} HTTPS URLs in bundle — review for "
                    "third-party content",
            "severity": "INFO",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": "sample: " + " | ".join(https[:8]),
            "remediation": "WebView loading third-party HTTPS content can expose your app "
                           "context to remote XSS / phishing-clone risks. Verify each URL "
                           "is YOUR domain or a TRUSTED partner (CDN, payment processor)."}
