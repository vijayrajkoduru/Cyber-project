"""CDN Origin Discovery — findings rules library."""


def rule_origin_candidates_found(s):
    candidates = s.get("origin_candidates") or []
    if not candidates: return None
    return {"name": f"Origin-IP candidate(s) found behind CDN ({len(candidates)})",
            "severity": "HIGH",
            "cwe": "CWE-200",
            "evidence": "Candidates: " + ", ".join(
                f"{c['ip']} via {c['method']}" for c in candidates[:3]),
            "remediation": "Origin IP leakage defeats your WAF/CDN. Common leak vectors: MX records, mail subdomains pointing to origin, old DNS records (Wayback), Censys/Shodan cert searches. Block direct access to origin via firewall rules: only allow CDN IP ranges."}


def rule_cdn_in_front(s):
    cdn = s.get("cdn_detected")
    if not cdn: return None
    return {"name": f"CDN in front: {cdn}",
            "severity": "POSITIVE",
            "evidence": f"Edge: {cdn}",
            "remediation": ""}


def rule_no_cdn(s):
    if s.get("cdn_detected"): return None
    return {"name": "No CDN/WAF detected — direct origin exposure",
            "severity": "MEDIUM",
            "cwe": "CWE-693",
            "evidence": "No Cloudflare/Akamai/Fastly headers detected",
            "remediation": "Without CDN/WAF, you're directly exposed to L7 attacks, DDoS, scrapers. Cloudflare free tier covers most small/medium sites."}


def rule_mx_origin_leak(s):
    if not s.get("mx_leak"): return None
    return {"name": "MX records leak origin IP",
            "severity": "HIGH",
            "cwe": "CWE-200",
            "evidence": f"MX target: {s.get('mx_leak')}",
            "remediation": "Mail servers often live on the origin host. Move mail to a separate IP/subdomain not in DNS, or use a third-party mail provider (Google Workspace, M365, Postmark) so MX doesn't point to your origin."}


def rule_subdomain_origin_leak(s):
    sl = s.get("subdomain_leaks") or []
    if not sl: return None
    return {"name": f"Subdomain(s) bypass CDN to origin ({len(sl)})",
            "severity": "HIGH",
            "cwe": "CWE-200",
            "evidence": "Direct-IP subdomains: " + ", ".join(
                f"{x['subdomain']} -> {x['ip']}" for x in sl[:3]),
            "remediation": "Subdomains like mail/ftp/cpanel often skip CDN. Either route them through the CDN too, or move to separate IPs not on the origin server."}


def rule_methods_attempted(s):
    methods = s.get("methods_tried") or []
    if not methods: return None
    return {"name": f"Origin-discovery methods attempted ({len(methods)})",
            "severity": "INFO",
            "evidence": "Tried: " + ", ".join(methods)}


CDN_ORIGIN_FINDING_RULES = [
    rule_origin_candidates_found, rule_cdn_in_front, rule_no_cdn,
    rule_mx_origin_leak, rule_subdomain_origin_leak, rule_methods_attempted,
]
