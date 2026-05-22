"""DNS Zone Transfer — findings rules library."""


def rule_zone_transfer_allowed(s):
    transfers = s.get("transfers") or []
    if not transfers: return None
    return {"name": f"Zone transfer (AXFR) ALLOWED on {len(transfers)} nameserver(s)",
            "severity": "CRITICAL",
            "cwe": "CWE-200",
            "evidence": "Vulnerable NS: " + ", ".join(
                f"{t['ns']} ({t.get('record_count', '?')} records)"
                for t in transfers[:3]),
            "remediation": "Restrict AXFR to authorized secondaries only. Use TSIG (transaction signatures) or NS ACLs. Public AXFR leaks your entire DNS zone — subdomain map, internal hostnames, mail topology."}


def rule_zone_transfer_blocked(s):
    if s.get("transfers"): return None
    if (s.get("nameservers_tested") or 0) == 0: return None
    return {"name": "Zone transfer properly denied on all nameservers",
            "severity": "POSITIVE",
            "evidence": f"Tested {s.get('nameservers_tested', 0)} NS; AXFR refused on all"}


def rule_no_nameservers(s):
    if (s.get("nameservers_tested") or 0) > 0: return None
    return {"name": "Could not test — no nameservers found",
            "severity": "INFO",
            "evidence": "NS records not retrievable; cannot test AXFR"}


def rule_partial_transfer(s):
    partial = s.get("partial_transfers") or []
    if not partial: return None
    return {"name": f"Partial zone transfer on {len(partial)} NS",
            "severity": "HIGH",
            "cwe": "CWE-200",
            "evidence": "; ".join(p["ns"] for p in partial),
            "remediation": "Some records leaked even though full AXFR may have failed. Same fix as AXFR — restrict transfers via TSIG."}


def rule_nameservers_count(s):
    n = s.get("nameservers_tested") or 0
    if n == 0: return None
    return {"name": f"Tested AXFR against {n} authoritative nameserver(s)",
            "severity": "INFO",
            "evidence": f"NS list: {', '.join(s.get('nameservers') or [])}"}


ZONE_TRANSFER_FINDING_RULES = [
    rule_zone_transfer_allowed, rule_zone_transfer_blocked,
    rule_no_nameservers, rule_partial_transfer, rule_nameservers_count,
]
