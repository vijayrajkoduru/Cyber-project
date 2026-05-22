"""Shodan Lookup — findings rules library."""


def rule_no_api_key(s):
    if s.get("api_key_configured"): return None
    return {"name": "Shodan API key not configured",
            "severity": "INFO",
            "evidence": "Set Shodan API key in Settings to enable this scan",
            "remediation": "Get a free Shodan API key at https://shodan.io/register — paid plans have higher rate limits."}


def rule_host_found(s):
    if not s.get("shodan_host_data"): return None
    return {"name": "Host indexed by Shodan",
            "severity": "INFO",
            "evidence": f"IP {s.get('ip')} has Shodan profile — visible to ALL Shodan users + crawlers"}


def rule_open_ports(s):
    ports = s.get("ports") or []
    if not ports: return None
    return {"name": f"{len(ports)} port(s) visible to Shodan",
            "severity": "INFO",
            "evidence": f"Open ports: {', '.join(str(p) for p in ports[:10])}",
            "remediation": "Shodan continuously scans IPv4. Any port visible there is visible to attackers. Verify each is intentional."}


def rule_known_cves(s):
    vulns = s.get("vulns") or []
    if not vulns: return None
    return {"name": f"{len(vulns)} CVE(s) flagged by Shodan",
            "severity": "HIGH",
            "cwe": "CWE-1104",
            "evidence": "CVEs: " + ", ".join(vulns[:5]),
            "remediation": "Patch immediately. CVE flags = automated exploitation tools already target this version."}


def rule_dangerous_services_shodan(s):
    ports = set(s.get("ports") or [])
    danger = {6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
              11211: "Memcached", 3306: "MySQL", 5432: "Postgres",
              2375: "Docker API", 6443: "K8s API"}
    found = [(p, danger[p]) for p in ports if p in danger]
    if not found: return None
    return {"name": f"Dangerous services exposed to Shodan ({len(found)})",
            "severity": "CRITICAL",
            "cwe": "CWE-668",
            "evidence": "Shodan sees: " + ", ".join(f"{p}/{svc}" for p, svc in found),
            "remediation": "These ports being visible to Shodan = visible to ALL attackers. Bind to localhost or VPN-only."}


def rule_host_org(s):
    org = s.get("shodan_org") or s.get("shodan_isp")
    if not org: return None
    return {"name": f"Host hosting org: {org}",
            "severity": "INFO",
            "evidence": f"ISP/Org per Shodan: {org}"}


SHODAN_FINDING_RULES = [
    rule_no_api_key, rule_host_found, rule_open_ports, rule_known_cves,
    rule_dangerous_services_shodan, rule_host_org,
]
