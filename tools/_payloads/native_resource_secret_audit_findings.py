"""native_resource_secret_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("native_resource_secret_audit_total"):
        return None
    return {"name": "No vendor-keys / high-entropy tokens in native libs",
            "severity": "POSITIVE",
            "evidence": f"{s.get('libs_scanned', 0)} .so/.dylib files scanned",
            "remediation": "Continue hiding secrets server-side; never embed in NDK string tables.",
            "cwe": "CWE-798", "owasp": "M10:2023"}


def rule_pattern_hits(s):
    h = s.get("pattern_hits") or []
    if not h:
        return None
    sample = ", ".join(f"{e['lib']}:{e['match']}" for e in h[:4])
    return {"name": f"Vendor-shaped secret(s) in {len(set(e['lib'] for e in h))} native lib(s)",
            "severity": "CRITICAL", "cvss": "9.0",
            "cwe": "CWE-798", "owasp": "M10:2023",
            "evidence": f"Matches: {sample}",
            "remediation": ("Strip and rotate. AWS / OpenAI / GitHub / Google API keys recovered via "
                            "strings(1). Move credential exchange to a server-side proxy; never embed in "
                            "client binary.")}


def rule_entropy_hits(s):
    if s.get("pattern_hits"):
        return None
    h = s.get("high_entropy_hits") or []
    if not h:
        return None
    sample = ", ".join(f"{e['lib']}:{e['preview']}" for e in h[:4])
    return {"name": f"High-entropy tokens near api-key keywords in {len(set(e['lib'] for e in h))} lib(s)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-798", "owasp": "M10:2023",
            "evidence": f"Matches: {sample}",
            "remediation": "Manually audit each match. If real, move credential exchange to server-side proxy."}


NATIVE_RESOURCE_SECRET_AUDIT_FINDING_RULES = [rule_positive_emit, rule_pattern_hits, rule_entropy_hits]
