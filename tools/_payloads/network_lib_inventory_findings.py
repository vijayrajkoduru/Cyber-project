"""network_lib_inventory — findings rules."""


def rule_positive_emit(s):
    if s.get("network_lib_inventory_total"):
        return None
    return {"name": "No network/HTTP library detected",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned",
            "remediation": "App uses platform-default HttpURLConnection or no HTTP at all. Verify with manifest INTERNET permission check.",
            "cwe": "CWE-200", "owasp": "M3:2023"}


def rule_lib_inventory(s):
    libs = s.get("network_libraries") or {}
    versions = s.get("library_versions") or {}
    if not libs:
        return None
    summary = ", ".join(f"{lib}{' v'+versions[lib] if lib in versions else ''}" for lib in list(libs.keys())[:8])
    return {"name": f"Network libraries: {len(libs)} detected",
            "severity": "INFO",
            "cwe": "CWE-1395", "owasp": "M2:2023",
            "evidence": summary,
            "remediation": "Cross-reference each library version against NVD / GitHub Advisory DB. Common CVEs: OkHttp <4.9.2 (CVE-2021-0341 HTTP/2 stream cancel), Apache HttpClient <4.5.13 (CVE-2020-13956). Subscribe to dependabot alerts on these libs."}


NETWORK_LIB_INVENTORY_FINDING_RULES = [
    rule_positive_emit,
    rule_lib_inventory,
]
