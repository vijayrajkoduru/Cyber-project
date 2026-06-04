"""dc_discovery - findings rules."""


def rule_positive(s):
    if s.get("dc_discovery_total", 0) == 0:
        return None
    return {"name": f"Domain Controllers enumerated via DNS SRV",
            "severity": "INFO",
            "evidence": (f"Domain: {s.get('dc_discovery_domain', '?')}; "
                         f"SRV records found: {s.get('dc_discovery_total', 0)}; "
                         f"Unique hosts resolved: {len(s.get('dc_discovery_resolved') or {})}"),
            "remediation": ("DNS SRV records leak DC topology — this is by design (AD requires it) "
                            "but use this map to verify all DCs are patched + monitored."),
            "cwe": "CWE-200", "owasp": "A01:2021"}


def rule_multi_forest_hint(s):
    rec = s.get("dc_discovery_records") or {}
    dc_hosts = rec.get("dc", [])
    if not dc_hosts:
        return None
    # Different parent domains in the same response = forest spanning multiple domains
    parents = set()
    for h in dc_hosts:
        parts = h.get("host", "").split(".", 1)
        if len(parts) > 1:
            parents.add(parts[1])
    if len(parents) > 1:
        return {"name": f"Multi-domain forest detected ({len(parents)} domains)",
                "severity": "INFO",
                "evidence": "Domains seen: " + ", ".join(sorted(parents)[:5]),
                "remediation": ("Map cross-domain trusts (use nltest /domain_trusts). "
                                "Trust paths are common privesc routes."),
                "cwe": "CWE-1188"}
    return None


def rule_kdc_exposed(s):
    rec = s.get("dc_discovery_records") or {}
    if rec.get("kdc"):
        return {"name": f"Kerberos KDC reachable for password spray / kerberoast",
                "severity": "MEDIUM",
                "evidence": f"{len(rec.get('kdc', []))} KDC SRV record(s) — attacker can target with kerbrute",
                "remediation": ("Monitor KDC for unusual TGT/TGS request patterns (event 4768/4769). "
                                "Implement account lockout policy + smart-card auth for privileged users."),
                "cwe": "CWE-307", "owasp": "A07:2021"}
    return None


DC_DISCOVERY_FINDING_RULES = [rule_positive, rule_multi_forest_hint, rule_kdc_exposed]
