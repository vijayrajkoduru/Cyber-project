"""WHOIS Intelligence — findings rules library.

Each rule is a function that takes a `state` dict (collected by the
recon/whois.py scanner) and returns either None (no finding) or a
finding dict {name, severity, evidence, cwe?, remediation?}.

The scanner's engine iterates this list and emits only the rules that
fire — so the output is a curated, named, actionable findings list
instead of 200 raw fields.

State dict shape (populated by scanner):
  domain, tld, raw_whois, raw_rdap, registrar, registrar_iana_id,
  registrar_url, abuse_email, abuse_phone, created (iso), updated (iso),
  expires (iso), domain_age_days, expires_in_days, status_codes (list),
  dnssec, name_servers (list), registrant_org, registrant_country,
  registrant_state, ips (list), ip_whois (list of dicts with asn/org/
  country), cdn_detected, cloud_provider, privacy_proxied (bool),
  is_idn (bool), crt_sh_subdomains (int).
"""
import re

# TLDs commonly abused by phishers (free / cheap / weak verification)
_RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "club",
               "site", "online", "buzz", "monster", "rest", "icu"}

# CDN nameserver patterns
_CDN_NS_PATTERNS = {
    "Cloudflare": [r"\.cloudflare\.com$", r"\.cloudflare\.net$"],
    "Akamai":     [r"\.akam\.net$", r"\.akamaiedge\.net$", r"\.akamai\.net$"],
    "AWS Route53": [r"awsdns-\d+\.(com|net|org|co\.uk)$"],
    "Google":     [r"\.googledomains\.com$", r"\.google\.com$"],
    "Fastly":     [r"\.fastly\.net$"],
    "Azure":      [r"\.azure-dns\.(com|net|org|info)$"],
    "DigitalOcean": [r"\.digitalocean\.com$"],
    "GoDaddy":    [r"\.domaincontrol\.com$"],
    "NS1":        [r"\.nsone\.net$"],
}

# Cloud-provider ASN keywords (appears in org name)
_CLOUD_ORG_PATTERNS = {
    "AWS":          [r"\bamazon\b", r"\baws\b"],
    "GCP":          [r"\bgoogle\b"],
    "Azure":        [r"\bmicrosoft\b", r"\bazure\b"],
    "Cloudflare":   [r"\bcloudflare\b"],
    "DigitalOcean": [r"\bdigitalocean\b"],
    "Hetzner":      [r"\bhetzner\b"],
    "Oracle":       [r"\boracle\b"],
    "Linode/Akamai": [r"\blinode\b"],
    "OVH":          [r"\bovh\b"],
    "Vultr":        [r"\bvultr\b"],
}


# ───────────────────────── RULES ─────────────────────────

def rule_young_domain(s):
    age = s.get("domain_age_days")
    if age is None or age >= 90: return None
    if age < 30:
        return {"name": "Domain registered less than 30 days ago",
                "severity": "HIGH",
                "cwe": "CWE-285",
                "evidence": f"Created {s.get('created')} ({age} days ago) — fresh domains are common in phishing / typosquat campaigns",
                "remediation": "If this is your domain, ignore. If investigating a target, treat fresh-registration as a phishing/scam risk indicator."}
    return {"name": "Domain registered less than 90 days ago",
            "severity": "MEDIUM",
            "evidence": f"Created {s.get('created')} ({age} days ago)",
            "remediation": "Newer domains lack reputation. Cross-check against threat-intel feeds before trusting."}


def rule_mature_domain(s):
    age = s.get("domain_age_days")
    if age is None or age < 3650: return None
    years = age // 365
    return {"name": "Mature domain (10+ years registered)",
            "severity": "POSITIVE",
            "evidence": f"Created {s.get('created')} (~{years} years ago) — established domain reputation"}


def rule_expiring_30(s):
    d = s.get("expires_in_days")
    if d is None or d > 30: return None
    return {"name": "Domain expires in less than 30 days",
            "severity": "HIGH",
            "evidence": f"Expires {s.get('expires')} ({d} days remaining)",
            "remediation": "Renew immediately. Expired domains drop services + can be sniped from the drop pool."}


def rule_expiring_90(s):
    d = s.get("expires_in_days")
    if d is None or d > 90 or d <= 30: return None
    return {"name": "Domain expires in less than 90 days",
            "severity": "MEDIUM",
            "evidence": f"Expires {s.get('expires')} ({d} days remaining)",
            "remediation": "Set up auto-renewal at your registrar before the 90-day window."}


def rule_expiring_365(s):
    d = s.get("expires_in_days")
    if d is None or d > 365 or d <= 90: return None
    return {"name": "Domain expires in less than 1 year",
            "severity": "LOW",
            "evidence": f"Expires {s.get('expires')} ({d} days remaining)",
            "remediation": "Consider multi-year renewal for better reputation + lock-in."}


def _has_status(s, code):
    return any(code.lower() in (c or "").lower() for c in (s.get("status_codes") or []))


def rule_pending_delete(s):
    if not _has_status(s, "pendingDelete"): return None
    return {"name": "Domain in pendingDelete status",
            "severity": "HIGH",
            "evidence": "Status: pendingDelete — domain is about to be released to the drop pool",
            "remediation": "If this is your domain, contact registrar IMMEDIATELY to restore."}


def rule_redemption(s):
    if not _has_status(s, "redemptionPeriod"): return None
    return {"name": "Domain in redemptionPeriod",
            "severity": "HIGH",
            "evidence": "Status: redemptionPeriod — domain expired, recoverable for ~30 more days at higher fee",
            "remediation": "Pay redemption fee at registrar before grace period ends."}


def rule_hold(s):
    for c in ("clientHold", "serverHold"):
        if _has_status(s, c):
            return {"name": f"Domain in {c} status (frozen)",
                    "severity": "HIGH",
                    "evidence": f"Status: {c} — domain is on hold, DNS resolution disabled",
                    "remediation": "Contact registrar/registry to resolve hold (often legal/abuse-related)."}
    return None


def rule_transfer_lock_ok(s):
    if not _has_status(s, "clientTransferProhibited"): return None
    return {"name": "Transfer lock properly enabled",
            "severity": "POSITIVE",
            "evidence": "Status: clientTransferProhibited — domain protected against unauthorized transfers"}


def rule_transfer_lock_missing(s):
    # Only flag for established domains — newly-registered domains often unlocked
    if (s.get("domain_age_days") or 0) < 7: return None
    if _has_status(s, "clientTransferProhibited"): return None
    return {"name": "Transfer lock NOT set (domain hijack risk)",
            "severity": "MEDIUM",
            "cwe": "CWE-284",
            "evidence": "Missing status: clientTransferProhibited",
            "remediation": "Enable Registrar Lock in your registrar control panel (one click, free)."}


def rule_update_lock_missing(s):
    if (s.get("domain_age_days") or 0) < 7: return None
    if _has_status(s, "clientUpdateProhibited"): return None
    return {"name": "Update lock NOT set",
            "severity": "LOW",
            "evidence": "Missing status: clientUpdateProhibited",
            "remediation": "Enable update lock for extra-sensitive domains (banking, root accounts)."}


def rule_delete_lock_missing(s):
    if (s.get("domain_age_days") or 0) < 7: return None
    if _has_status(s, "clientDeleteProhibited"): return None
    return {"name": "Delete lock NOT set",
            "severity": "LOW",
            "evidence": "Missing status: clientDeleteProhibited",
            "remediation": "Enable delete lock to prevent accidental drops."}


def rule_dnssec_disabled(s):
    d = (s.get("dnssec") or "").lower()
    if not d: return None
    if d in ("signed", "signeddelegation", "yes", "true", "active"): return None
    return {"name": "DNSSEC not enabled",
            "severity": "MEDIUM",
            "cwe": "CWE-345",
            "evidence": f"DNSSEC: {s.get('dnssec')} — DNS responses are NOT cryptographically signed",
            "remediation": "Enable DNSSEC at your registrar. Cloudflare/Route53/etc. offer one-click signing."}


def rule_dnssec_enabled(s):
    d = (s.get("dnssec") or "").lower()
    if d not in ("signed", "signeddelegation", "yes", "true", "active"): return None
    return {"name": "DNSSEC properly signed",
            "severity": "POSITIVE",
            "evidence": f"DNSSEC: {s.get('dnssec')} — DNS responses are cryptographically signed"}


def rule_single_nameserver(s):
    ns = s.get("name_servers") or []
    if len(ns) > 1: return None
    if len(ns) == 0: return None  # missing data, not a finding
    return {"name": "Single nameserver (no DNS redundancy)",
            "severity": "MEDIUM",
            "evidence": f"Only 1 nameserver: {ns[0]}",
            "remediation": "Add at least 2 (ideally 4) nameservers on different networks for resilience."}


def rule_ns_same_provider_spof(s):
    ns = s.get("name_servers") or []
    if len(ns) < 2: return None
    # All on same parent zone (e.g. both .cloudflare.com)
    suffixes = set()
    for n in ns:
        parts = n.lower().rstrip(".").split(".")
        if len(parts) >= 2:
            suffixes.add(".".join(parts[-2:]))
    if len(suffixes) > 1: return None
    cdn = s.get("cdn_detected")
    if cdn:
        return None  # CDN-on-purpose, not a SPOF concern
    return {"name": "All nameservers under same provider (single point of failure)",
            "severity": "LOW",
            "evidence": f"All {len(ns)} nameservers share suffix: {next(iter(suffixes))}",
            "remediation": "For high-availability domains, use secondary DNS on a different provider."}


def rule_cdn_detected(s):
    if not s.get("cdn_detected"): return None
    return {"name": f"Behind CDN ({s.get('cdn_detected')})",
            "severity": "INFO",
            "evidence": f"Nameservers + IP indicate {s.get('cdn_detected')} fronting traffic — origin server hidden"}


def rule_cloud_hosted(s):
    if not s.get("cloud_provider"): return None
    return {"name": f"Hosted on cloud ({s.get('cloud_provider')})",
            "severity": "INFO",
            "evidence": f"Resolved IPs map to {s.get('cloud_provider')} ASN"}


def rule_hosting_org(s):
    ipw = s.get("ip_whois") or []
    orgs = list({(w.get("org") or "").strip() for w in ipw if w.get("org")})
    if not orgs: return None
    if s.get("cdn_detected") or s.get("cloud_provider"): return None  # already covered
    return {"name": "Hosting provider identified",
            "severity": "INFO",
            "evidence": f"IP netblock owners: {', '.join(orgs[:3])}"}


def rule_redacted_registrant(s):
    org = (s.get("registrant_org") or "")
    if not org: return None
    if re.search(r"redacted|withheld|privacy|gdpr", org, re.I):
        return {"name": "Registrant fully GDPR-redacted",
                "severity": "INFO",
                "evidence": f"Registrant: {org} — personal info hidden per GDPR/privacy policy"}
    return None


def rule_privacy_proxy(s):
    if not s.get("privacy_proxied"): return None
    return {"name": "Privacy proxy service detected",
            "severity": "INFO",
            "evidence": "Registrant uses a privacy-proxy service (WhoisGuard/DomainsByProxy/etc.) — real owner hidden"}


def rule_idn_homograph(s):
    if not s.get("is_idn"): return None
    return {"name": "IDN/Punycode domain (homograph risk)",
            "severity": "MEDIUM",
            "evidence": f"Domain uses xn-- punycode encoding: {s.get('domain')}",
            "remediation": "Verify the visible characters match the actual domain — Cyrillic/Greek lookalikes are common phishing tactic."}


def rule_risky_tld(s):
    tld = (s.get("tld") or "").lower()
    if tld not in _RISKY_TLDS: return None
    return {"name": f"High-abuse TLD (.{tld})",
            "severity": "MEDIUM",
            "evidence": f"TLD .{tld} is frequently abused by phishers (free or near-free registration, weak verification)",
            "remediation": "If running services on this TLD, expect lower reputation. Consider migration."}


def rule_subdomains_via_crt(s):
    n = s.get("crt_sh_subdomains")
    if not n: return None
    return {"name": f"Subdomains discovered via Certificate Transparency",
            "severity": "INFO",
            "evidence": f"{n} unique subdomains found in cert-transparency logs (crt.sh) — visible to anyone, expands attack surface"}


def rule_country_mismatch(s):
    rc = (s.get("registrant_country") or "").upper()
    ipw = s.get("ip_whois") or []
    host_countries = list({(w.get("country") or "").upper() for w in ipw if w.get("country")})
    host_countries = [c for c in host_countries if c]
    if not rc or not host_countries: return None
    if rc in host_countries: return None
    return {"name": "Domain registered in different country than hosting",
            "severity": "INFO",
            "evidence": f"Registrant country: {rc}; Hosting country: {', '.join(host_countries)}"}


def rule_abuse_present(s):
    if not s.get("abuse_email"): return None
    return {"name": "Abuse contact email present",
            "severity": "POSITIVE",
            "evidence": f"Abuse contact: {s.get('abuse_email')}"}


def rule_abuse_missing(s):
    if s.get("abuse_email"): return None
    if not s.get("registrar"): return None  # no whois at all, don't double-warn
    return {"name": "Abuse contact missing in WHOIS",
            "severity": "LOW",
            "evidence": "No registrar abuse email field — harder to report abuse / takedown requests",
            "remediation": "Contact registrar to publish abuse contact in WHOIS."}


def rule_rdap_mismatch(s):
    if not s.get("raw_rdap"): return None
    rdap_registrar = s.get("rdap_registrar")
    cli_registrar = s.get("registrar")
    if not rdap_registrar or not cli_registrar: return None
    if rdap_registrar.split(",")[0].lower() in cli_registrar.lower(): return None
    if cli_registrar.split(",")[0].lower() in rdap_registrar.lower(): return None
    return {"name": "WHOIS vs RDAP registrar mismatch",
            "severity": "LOW",
            "evidence": f"CLI whois: '{cli_registrar}'; RDAP: '{rdap_registrar}'",
            "remediation": "Manually verify which is authoritative — may indicate stale registry data."}


def rule_no_ns(s):
    if s.get("name_servers"): return None
    if not s.get("registrar"): return None
    return {"name": "No nameservers found in WHOIS",
            "severity": "HIGH",
            "evidence": "Domain has no NS records published — DNS resolution will fail",
            "remediation": "Configure nameservers at your registrar immediately."}


# ───────────────────────── REGISTRY ─────────────────────────

WHOIS_FINDING_RULES = [
    rule_young_domain,
    rule_mature_domain,
    rule_expiring_30,
    rule_expiring_90,
    rule_expiring_365,
    rule_pending_delete,
    rule_redemption,
    rule_hold,
    rule_transfer_lock_ok,
    rule_transfer_lock_missing,
    rule_update_lock_missing,
    rule_delete_lock_missing,
    rule_dnssec_disabled,
    rule_dnssec_enabled,
    rule_single_nameserver,
    rule_ns_same_provider_spof,
    rule_cdn_detected,
    rule_cloud_hosted,
    rule_hosting_org,
    rule_redacted_registrant,
    rule_privacy_proxy,
    rule_idn_homograph,
    rule_risky_tld,
    rule_subdomains_via_crt,
    rule_country_mismatch,
    rule_abuse_present,
    rule_abuse_missing,
    rule_rdap_mismatch,
    rule_no_ns,
]


# ───────────────────────── DETECTORS ─────────────────────────
# Used by scanner pre-rule-evaluation to populate state.

def detect_cdn_from_nameservers(ns_list):
    """Return CDN name if any nameserver matches a known CDN pattern."""
    for ns in (ns_list or []):
        n = ns.lower().rstrip(".")
        for cdn, patterns in _CDN_NS_PATTERNS.items():
            for p in patterns:
                if re.search(p, n):
                    return cdn
    return None


def detect_cloud_from_org(org_name):
    """Return cloud-provider name if the netblock org matches."""
    if not org_name: return None
    org_lower = org_name.lower()
    for cloud, patterns in _CLOUD_ORG_PATTERNS.items():
        for p in patterns:
            if re.search(p, org_lower):
                return cloud
    return None
