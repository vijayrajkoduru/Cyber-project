"""cache_snooping — findings rules."""
def rule_open_recursion(s):
    c = s.get("cs_open_recursive_count") or 0
    if c == 0: return None
    return {"name":f"Open recursive resolver detected ({c} NS)","severity":"HIGH","cvss":"6.5",
            "cwe":"CWE-441","owasp":"M5:2023",
            "evidence":f"NS allowing recursion: {', '.join(s.get('cs_open_recursive', []))}",
            "remediation":"Restrict recursion. In BIND: `allow-recursion { localnets; };`. Open recursors enable DNS amplification DDoS + cache poisoning."}

def rule_cache_leak(s):
    c = s.get("cs_cache_leaks") or 0
    if c == 0: return None
    return {"name":f"DNS cache snooping enabled ({c} cached domain hits)","severity":"MEDIUM","cvss":"4.3",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("cs_cache_sample",""),
            "remediation":"Attackers can profile which sites your users visit by probing cache. Disable cache snooping by restricting non-recursive queries to internal clients."}

def rule_secure(s):
    if (s.get("cs_open_recursive_count") or 0) > 0 or (s.get("cs_cache_leaks") or 0) > 0: return None
    if s.get("cs_ns_count", 0) == 0: return None
    return {"name":"DNS servers properly hardened (no recursion / no cache leak)","severity":"POSITIVE",
            "evidence":f"{s.get('cs_ns_count',0)} NS tested, no issues",
            "remediation":"Maintain — nameservers reject probing attempts.",
            "cwe":"CWE-200","owasp":"M2:2023"}

CACHE_SNOOPING_FINDING_RULES = [rule_open_recursion, rule_cache_leak, rule_secure,
]

def rule_positive_emit(s):
    """POSITIVE-emit when no risk indicators present (VL-FORGE pattern)."""
    if s.get("snooping_vulnerable") or s.get("cached_records"):
        return None
    return {
        "name": "DNS resolver not vulnerable to cache snooping",
        "severity": "POSITIVE",
        "evidence": "Resolver returned no leaked cached records",
        "remediation": "Maintain - resolver configured to prevent unauthorized cache reads.",
        "cwe": "CWE-200", "owasp": "N/A"
    }

CACHE_SNOOPING_FINDING_RULES.append(rule_positive_emit)
