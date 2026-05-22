"""WAF/CDN Fingerprint — findings rules library.

State shape:
  vendors_detected (list of dicts: {vendor, category, source, evidence}),
  cdn_present (bool), waf_present (bool),
  ip_range_match (str | None),
  reverse_dns_hint (str | None),
  active_probe_blocked (bool),
  attack_categories_blocked (list — e.g., ["SQLi", "XSS"])
"""

def rule_no_waf_no_cdn(s):
    if s.get("vendors_detected"): return None
    return {"name": "No WAF or CDN detected — direct exposure to origin",
            "severity": "MEDIUM",
            "cwe": "CWE-693",
            "evidence": "No vendor signatures matched across header / cookie / body / IP-range checks",
            "remediation": "Consider Cloudflare (free) or AWS CloudFront. WAF blocks ~95% of automated attacks before they reach your origin."}


def rule_cdn_only(s):
    if not s.get("cdn_present"): return None
    if s.get("waf_present"): return None  # WAF+CDN — separate rule
    vendors = [v["vendor"] for v in (s.get("vendors_detected") or [])
                if v.get("category") == "CDN"]
    if not vendors: return None
    return {"name": f"CDN present without WAF ({', '.join(vendors[:2])})",
            "severity": "LOW",
            "evidence": "CDN reduces latency + DDoS surface but doesn't filter L7 attacks",
            "remediation": "Enable WAF on the same provider — Cloudflare WAF / CloudFront WAF / Fastly WAF are usually included in higher plans."}


def rule_waf_active(s):
    if not s.get("waf_present"): return None
    wafs = [v["vendor"] for v in (s.get("vendors_detected") or [])
             if v.get("category") in ("WAF", "CDN+WAF")]
    if not wafs: return None
    return {"name": f"WAF active ({', '.join(wafs[:2])})",
            "severity": "POSITIVE",
            "evidence": f"L7 filter detected: {', '.join(wafs[:3])}"}


def rule_waf_cdn_stack(s):
    if not (s.get("waf_present") and s.get("cdn_present")):
        return None
    vendors = [v["vendor"] for v in (s.get("vendors_detected") or [])]
    return {"name": f"Full WAF + CDN stack ({len(vendors)} vendor(s))",
            "severity": "POSITIVE",
            "evidence": f"Layered defense: {', '.join(vendors[:3])}"}


def rule_multi_waf(s):
    wafs = [v["vendor"] for v in (s.get("vendors_detected") or [])
             if v.get("category") in ("WAF", "CDN+WAF")]
    if len(wafs) < 2: return None
    return {"name": f"Multiple WAFs detected ({len(wafs)})",
            "severity": "INFO",
            "evidence": f"Defense-in-depth: {', '.join(wafs[:3])}",
            "remediation": "Multiple WAFs are usually intentional (e.g., Cloudflare + origin ModSecurity). Verify each layer is configured, not just present."}


def rule_ip_range_match(s):
    iprm = s.get("ip_range_match")
    if not iprm: return None
    return {"name": f"IP range matches {iprm} infrastructure",
            "severity": "INFO",
            "evidence": f"Resolved IP falls in {iprm} announced ranges — confirms vendor identification via separate signal"}


def rule_active_probe_blocked(s):
    if not s.get("active_probe_blocked"): return None
    blocked = s.get("attack_categories_blocked") or []
    return {"name": f"Active WAF probe confirmed ({len(blocked)} attack patterns blocked)",
            "severity": "POSITIVE",
            "evidence": f"Test payloads blocked: {', '.join(blocked)} — WAF actively filtering"}


def rule_active_probe_passthrough(s):
    if s.get("active_probe_blocked") is not False: return None  # only fires if explicitly False
    # WAF appears present but didn't block our probes
    if not s.get("waf_present"): return None
    return {"name": "WAF detected but did NOT block test attack payloads",
            "severity": "MEDIUM",
            "cwe": "CWE-693",
            "evidence": "Vendor signature present but SQLi/XSS test patterns passed through",
            "remediation": "WAF in monitor/log-only mode? Verify rules are in BLOCK mode, not just LEARNING. Cloudflare: Security Level should be Medium+; AWS WAF: action=BLOCK not COUNT."}


def rule_reverse_dns_hint(s):
    rdns = s.get("reverse_dns_hint")
    if not rdns: return None
    return {"name": f"Reverse DNS confirms vendor ({rdns})",
            "severity": "INFO",
            "evidence": f"PTR record points to {rdns}-managed hostname"}


def rule_vendor_count_summary(s):
    n = len(s.get("vendors_detected") or [])
    if n == 0: return None
    return {"name": f"Total infrastructure vendors detected: {n}",
            "severity": "INFO",
            "evidence": f"Across all sources ({n} unique vendors)"}


WAF_CDN_FINDING_RULES = [
    rule_no_waf_no_cdn,
    rule_cdn_only,
    rule_waf_active,
    rule_waf_cdn_stack,
    rule_multi_waf,
    rule_ip_range_match,
    rule_active_probe_blocked,
    rule_active_probe_passthrough,
    rule_reverse_dns_hint,
    rule_vendor_count_summary,
]
