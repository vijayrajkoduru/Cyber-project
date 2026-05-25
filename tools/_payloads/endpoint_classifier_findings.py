"""endpoint_classifier — findings rules."""


def rule_positive_emit(s):
    if s.get("endpoint_classifier_total") or s.get("total_unique_urls", 0) == 0:
        if s.get("total_unique_urls", 0) == 0:
            return {"name": "No URL literals extracted from decompiled code",
                    "severity": "POSITIVE",
                    "evidence": f"{s.get('files_scanned', 0)} smali files scanned",
                    "remediation": "App likely fetches URLs from server config or uses non-standard transport. Manual Burp capture recommended.",
                    "cwe": "CWE-200", "owasp": "M3:2023"}
        return None
    classified = s.get("classified_endpoints") or {}
    cat_summary = ", ".join(f"{cat}: {len(hosts)}" for cat, hosts in classified.items())
    return {"name": f"Endpoint inventory: {s.get('total_unique_urls', 0)} unique URLs across {len(classified)} categories",
            "severity": "POSITIVE",
            "evidence": cat_summary,
            "remediation": "Focus Burp scanning on 'api' + 'auth' categories. Ignore analytics / ads / CDN traffic to reduce noise.",
            "cwe": "CWE-200", "owasp": "M3:2023"}


def rule_debug_endpoints(s):
    debug = s.get("debug_endpoints") or []
    if not debug:
        return None
    return {"name": f"{len(debug)} debug / staging URL(s) embedded in production binary",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-489", "owasp": "M3:2023",
            "evidence": "; ".join(debug[:5]),
            "remediation": "Strip debug endpoints from release builds via build-flavor switches (BuildConfig.DEBUG check). Production code should never reach localhost / 10.0.2.2 / dev. domains."}


ENDPOINT_CLASSIFIER_FINDING_RULES = [
    rule_positive_emit,
    rule_debug_endpoints,
]
