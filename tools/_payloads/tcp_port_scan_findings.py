"""tcp_port_scan findings."""

def rule_f(s):
    c = s.get("op_count") or 0
    if c == 0: return None
    sev = "HIGH" if c > 6 else "MEDIUM" if c > 3 else "LOW"
    return {"name":f"{c} TCP port(s) open","severity":sev,"cvss":"5.3" if sev=="HIGH" else "3.7",
            "cwe":"CWE-200","owasp":"M5:2023",
            "evidence":s.get("op_sample",""),
            "remediation":"Close ports not actively serving traffic. Use firewall + cloud security groups."}
def rule_n(s):
    if (s.get("op_count") or 0) > 0: return None
    return {"name":"No TCP ports open on 20 common ports","severity":"POSITIVE",
            "evidence":"All probed ports filtered/closed","remediation":"Maintain.",
            "cwe":"CWE-200","owasp":"M5:2023"}
TCP_PORT_SCAN_FINDING_RULES = [rule_f, rule_n]
