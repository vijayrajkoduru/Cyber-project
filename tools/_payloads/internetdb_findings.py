"""Free Shodan / InternetDB — findings rules library."""


def rule_indexed_by_internetdb(s):
    if not s.get("found"): return None
    return {"name": "Host indexed in Shodan InternetDB (free)",
            "severity": "INFO",
            "evidence": f"IP {s.get('ip')} appears in Shodan's free /internetdb dataset"}


def rule_not_indexed(s):
    if s.get("found"): return None
    if not s.get("ip"): return None
    return {"name": "Host not indexed in InternetDB",
            "severity": "POSITIVE",
            "evidence": f"IP {s.get('ip')} not found — minimal Shodan exposure"}


def rule_ports_known_to_shodan(s):
    ports = s.get("ports") or []
    if not ports: return None
    return {"name": f"{len(ports)} port(s) known to Shodan",
            "severity": "INFO",
            "evidence": f"Ports: {', '.join(str(p) for p in ports[:15])}",
            "remediation": "InternetDB is free + public — every script kiddie can see your open ports. Verify each is intentional."}


def rule_cves_shodan_free(s):
    cves = s.get("cves") or []
    if not cves: return None
    return {"name": f"{len(cves)} CVE(s) flagged by Shodan InternetDB",
            "severity": "HIGH",
            "cwe": "CWE-1104",
            "evidence": "CVEs: " + ", ".join(cves[:5]),
            "remediation": "Patch immediately. Shodan-flagged CVEs are weaponized + actively scanned for."}


def rule_hostnames_known(s):
    hosts = s.get("hostnames") or []
    if not hosts: return None
    return {"name": f"{len(hosts)} hostname(s) tied to this IP",
            "severity": "INFO",
            "evidence": ", ".join(hosts[:5]),
            "remediation": "If unexpected hostnames appear, investigate — could indicate shared hosting or stale DNS."}


def rule_tags(s):
    tags = s.get("tags") or []
    if not tags: return None
    risky = [t for t in tags if t in ("eol-os", "cdn", "cloud", "self-signed")]
    return {"name": f"Shodan tags: {', '.join(tags[:5])}",
            "severity": "MEDIUM" if risky else "INFO",
            "evidence": f"Tags: {', '.join(tags)}",
            "remediation": "Review risky tags — eol-os means end-of-life OS (urgent), self-signed cert (low trust)."}


INTERNETDB_FINDING_RULES = [
    rule_indexed_by_internetdb, rule_not_indexed, rule_ports_known_to_shodan,
    rule_cves_shodan_free, rule_hostnames_known, rule_tags,
]
