"""ASN / IP Ownership — findings rules library."""


def rule_asn_identified(s):
    asn = s.get("asn")
    if not asn: return None
    return {"name": f"ASN identified: {asn}",
            "severity": "INFO",
            "evidence": f"Provider: {s.get('org', '?')}, Country: {s.get('country', '?')}"}


def rule_hosting_type(s):
    org = (s.get("org") or "").lower()
    if not org: return None
    cloud_keywords = ["amazon", "google", "microsoft", "cloudflare",
                       "digitalocean", "hetzner", "oracle", "linode",
                       "ovh", "vultr", "alibaba", "tencent"]
    for kw in cloud_keywords:
        if kw in org:
            return {"name": f"Hosted on major cloud ({kw.capitalize()})",
                    "severity": "INFO",
                    "evidence": f"ASN org: {s.get('org')}"}
    return None


def rule_multi_asn_anycast(s):
    asns = s.get("multiple_asns") or []
    if len(asns) < 2: return None
    return {"name": f"Multi-ASN announcement ({len(asns)} — likely Anycast/CDN)",
            "severity": "INFO",
            "evidence": f"ASNs: {', '.join(asns[:5])}",
            "remediation": "Multi-ASN is normal for CDN providers (Cloudflare, Fastly). If you don't use a CDN, investigate."}


def rule_country_unexpected(s):
    cc = s.get("country") or ""
    if not cc: return None
    # Flag suspicious country codes for typical western targets
    flagged = {"CN", "RU", "KP", "IR", "SY"}
    if cc.upper() in flagged:
        return {"name": f"Hosting in geopolitically-restricted country ({cc})",
                "severity": "MEDIUM",
                "evidence": f"IP geo: {cc}",
                "remediation": "Verify hosting choice — some compliance regimes (SOC2, FedRAMP, GDPR data-residency) restrict where data may live."}
    return None


def rule_ip_resolved(s):
    ip = s.get("ip")
    if not ip: return None
    return {"name": "IP address resolved",
            "severity": "INFO",
            "evidence": f"{s.get('host')} → {ip}"}


def rule_no_asn(s):
    if s.get("asn"): return None
    if not s.get("ip"): return None
    return {"name": "ASN lookup returned no data",
            "severity": "INFO",
            "evidence": f"IP {s.get('ip')} could not be resolved to an ASN",
            "remediation": "Could indicate Cloudflare/cloud-fronted target (real ASN obscured) or rate-limited lookup API."}


ASN_FINDING_RULES = [
    rule_asn_identified, rule_hosting_type, rule_multi_asn_anycast,
    rule_country_unexpected, rule_ip_resolved, rule_no_asn,
]
