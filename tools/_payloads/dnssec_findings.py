"""dnssec — findings rules."""
def rule_enabled(s):
    if not s.get("dnssec_enabled"): return None
    return {"name":"DNSSEC enabled (signed delegation + signed records)","severity":"POSITIVE",
            "cwe":"CWE-345","owasp":"M5:2023",
            "evidence":f"DS={s.get('ds_count',0)} DNSKEY={s.get('dnskey_count',0)} AD-flag={s.get('ad_flag',False)}",
            "remediation":"Maintain — protects against DNS spoofing/cache poisoning."}

def rule_partial(s):
    if s.get("dnssec_enabled"): return None
    if s.get("ds_count", 0) > 0 or s.get("dnskey_count", 0) > 0:
        return {"name":"DNSSEC partially configured (chain broken)","severity":"MEDIUM","cvss":"4.3",
                "cwe":"CWE-345","owasp":"M5:2023",
                "evidence":f"DS={s.get('ds_count',0)} but DNSKEY={s.get('dnskey_count',0)} — chain incomplete",
                "remediation":"Complete DNSSEC config: ensure both registrar DS and zone DNSKEY align. Test with delv +rtrace."}
    return None

def rule_missing(s):
    if s.get("dnssec_enabled") or s.get("ds_count", 0) > 0 or s.get("dnskey_count", 0) > 0: return None
    return {"name":"DNSSEC not configured","severity":"LOW","cvss":"3.1",
            "cwe":"CWE-345","owasp":"M5:2023",
            "evidence":"No DS or DNSKEY records found",
            "remediation":"Enable DNSSEC at registrar + zone. Hardens against DNS spoofing. (Optional but recommended for sensitive domains.)"}

DNSSEC_FINDING_RULES = [rule_enabled, rule_partial, rule_missing]
