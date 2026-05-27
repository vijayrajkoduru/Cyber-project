"""udp_port_scan findings."""

def rule_f(s):
    c = s.get("udp_count") or 0
    if c == 0: return None
    return {"name":f"{c} UDP port(s) responsive","severity":"INFO",
            "cwe":"CWE-200","owasp":"M5:2023",
            "evidence":", ".join(str(p) for p in s.get("udp_open",[])),
            "remediation":"DNS/NTP/SNMP commonly UDP. Restrict where not needed."}
def rule_n(s):
    if (s.get("udp_count") or 0) > 0: return None
    return {"name":"No UDP ports responsive","severity":"POSITIVE",
            "evidence":"13 probed UDP ports silent","remediation":"Maintain.",
            "cwe":"CWE-200","owasp":"M5:2023"}
UDP_PORT_SCAN_FINDING_RULES = [rule_f, rule_n]
