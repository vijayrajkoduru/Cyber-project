"""ios_purpose_string_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("ios_purpose_string_audit_total", 0)
    desc = s.get("usage_descriptions") or {}
    if not desc:
        return {"name": "No iOS NSXxxUsageDescription strings (not iOS / no sensitive perms)",
                "severity": "POSITIVE",
                "cwe": "CWE-359", "owasp": "M9:2023",
                "evidence": "0 usage descriptions detected",
                "remediation": "Either Android-only or iOS app with no sensitive perms — "
                               "no purpose-string review needed."}
    if n == 0:
        return {"name": f"All {len(desc)} iOS usage descriptions look adequate",
                "severity": "POSITIVE",
                "cwe": "CWE-359", "owasp": "M9:2023",
                "evidence": f"{len(desc)} descriptions, all >=30 chars + non-generic",
                "remediation": "Maintain. Review with each iOS App Privacy update."}
    return None


def rule_generic_descriptions(s):
    gen = s.get("generic_descriptions") or {}
    if not gen: return None
    return {"name": f"{len(gen)} GENERIC iOS usage description(s) — App Store rejection risk",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": " | ".join(f"{k}: '{v[:60]}'" for k, v in list(gen.items())[:5]),
            "remediation": "Apple App Review Guideline 5.1.1 requires SPECIFIC purpose "
                           "strings. 'We need this to function' = rejection. Write WHAT "
                           "feature uses the data + HOW: 'Used to scan QR codes for "
                           "two-factor enrolment in Settings → Security'. Be precise."}


def rule_short_descriptions(s):
    short = s.get("short_descriptions") or {}
    if not short: return None
    return {"name": f"{len(short)} SHORT iOS usage description(s) (<30 chars)",
            "severity": "LOW",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": " | ".join(f"{k}: '{v}'" for k, v in list(short.items())[:5]),
            "remediation": "Short purpose strings are technically valid but suboptimal "
                           "for user trust. Aim for 1-2 sentences explaining feature + "
                           "value."}
