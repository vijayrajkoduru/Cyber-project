"""content_provider_authority_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("content_provider_authority_audit_total"):
        return None
    return {"name": "No exported ContentProviders without permissions",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} manifest(s) scanned",
            "remediation": "Continue keeping exported=\"false\" or adding readPermission / writePermission.",
            "cwe": "CWE-926", "owasp": "M4:2023"}


def rule_exposed_provider(s):
    ex = s.get("exposed_providers") or []
    if not ex:
        return None
    sample = ", ".join(e["authority"] for e in ex[:4])
    return {"name": f"{len(ex)} exported ContentProvider(s) without permission gate",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-926", "owasp": "M4:2023",
            "evidence": f"Authorities: {sample}",
            "remediation": ("Set android:exported=\"false\" OR require android:readPermission and "
                            "android:writePermission with custom signature-level permissions. Add "
                            "<path-permission> to scope grants. Any installed app can query exposed providers.")}


CONTENT_PROVIDER_AUTHORITY_AUDIT_FINDING_RULES = [rule_positive_emit, rule_exposed_provider]
