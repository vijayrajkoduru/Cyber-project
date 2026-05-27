"""origin_ip_bypass findings."""

def rule_f(s):
    c = s.get("bypass_count") or 0
    if c == 0: return None
    return {"name":f"Origin IP exposed via DNS history ({c} candidate IP(s))","severity":"HIGH","cvss":"6.5",
            "cwe":"CWE-200","owasp":"M5:2023",
            "evidence":s.get("bypass_ips",""),
            "remediation":"Origin reachable directly bypasses WAF/CDN. Configure origin to only accept connections from CDN edge IPs (or use mutual TLS)."}
def rule_n(s):
    if (s.get("bypass_count") or 0) > 0: return None
    return {"name":"No origin IP bypass possible","severity":"POSITIVE",
            "evidence":f"{s.get('candidates_count',0)} historical IPs tested, none accessible directly",
            "remediation":"Maintain — CDN/WAF protection effective.",
            "cwe":"CWE-200","owasp":"M5:2023"}
ORIGIN_IP_BYPASS_FINDING_RULES = [rule_f, rule_n]
