"""Deep Subdomain (Amass) — findings rules library."""


def rule_total_subdomains(s):
    n = s.get("total_subdomains") or 0
    if n == 0: return None
    return {"name": f"{n} subdomain(s) via deep passive enumeration",
            "severity": "INFO",
            "evidence": f"Aggregated across {len(s.get('sources') or {})} passive sources"}


def rule_no_subdomains(s):
    if (s.get("total_subdomains") or 0) > 0: return None
    return {"name": "Amass deep enumeration found no subdomains",
            "severity": "INFO",
            "evidence": "Either minimal external footprint or all passive sources rate-limited"}


def rule_high_diversity(s):
    sources = s.get("sources") or {}
    active = sum(1 for v in sources.values() if v)
    if active < 3: return None
    return {"name": f"Deep enum covered {active} passive source(s)",
            "severity": "POSITIVE",
            "evidence": ", ".join(f"{k}({v})" for k, v in sources.items() if v)}


def rule_internal_subs_via_amass(s):
    subs = s.get("subdomains") or []
    risky = [sub for sub in subs if any(kw in sub for kw in
              ["staging", "dev", "internal", "test", "admin", "qa"])]
    if not risky: return None
    return {"name": f"Risky subdomain names in deep enum ({len(risky)})",
            "severity": "MEDIUM",
            "cwe": "CWE-200",
            "evidence": "Examples: " + ", ".join(risky[:5]),
            "remediation": "Subdomains revealing internal/staging/dev environments are leaked attack surface. Move pre-prod behind VPN or IP-allowlist + remove from public DNS."}


def rule_source_failures(s):
    failed = s.get("sources_failed") or {}
    if not failed: return None
    return {"name": f"{len(failed)} passive source(s) failed",
            "severity": "INFO",
            "evidence": "Failed: " + ", ".join(failed.keys()),
            "remediation": "Some passive sources may be rate-limited or unreachable. Results are subset of full coverage."}


AMASS_FINDING_RULES = [
    rule_total_subdomains, rule_no_subdomains, rule_high_diversity,
    rule_internal_subs_via_amass, rule_source_failures,
]
