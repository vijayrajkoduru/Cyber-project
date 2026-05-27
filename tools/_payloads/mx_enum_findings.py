"""mx_enum — findings rules."""
def rule_found(s):
    if s.get("mx_count", 0) == 0: return None
    return {"name":f"Mail servers identified ({s.get('mx_count',0)} MX records)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"Providers: {s.get('mx_providers','?')}. MX: {s.get('mx_list','')}",
            "remediation":"MX records expose mail-provider choice. Banner-grab leaks specific server software/version — disable SMTP banners or strip versions."}

def rule_banner_leak(s):
    b = s.get("smtp_sample_banner", "")
    if not b: return None
    if any(x in b.lower() for x in ["postfix", "exim", "sendmail", "exchange"]):
        return {"name":"SMTP banner reveals mail server software","severity":"LOW","cvss":"3.1",
                "cwe":"CWE-200","owasp":"M2:2023",
                "evidence":f"Banner: {b[:80]}",
                "remediation":"Strip software identification from SMTP greeting banner. Configure server to send generic banner."}
    return None

def rule_no_mx(s):
    if s.get("mx_count", 0) > 0: return None
    return {"name":"No MX records (domain cannot receive email)","severity":"INFO",
            "evidence":"DNS MX query returned empty",
            "remediation":"If email is intentional → add MX. If not → add `0 .` MX (RFC 7505) to formally reject mail.",
            "cwe":"CWE-200","owasp":"M2:2023"}

MX_ENUM_FINDING_RULES = [rule_found, rule_banner_leak, rule_no_mx]
