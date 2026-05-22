"""DNS Recon intelligence — findings rules library.

Distinct from DNS Records (tools/recon/dns.py). DNS Records lists the
standard record types (A/AAAA/MX/NS/TXT/CNAME/SOA/CAA) and grades
email-auth posture (SPF/DMARC/DKIM/CAA).

DNS Recon focuses on RECONNAISSANCE operations a penetration tester
runs against a target's DNS infrastructure:

  - Reverse DNS / PTR lookups for resolved IPs
  - DNSSEC chain validation (DNSKEY + DS presence and signing)
  - Cross-resolver consistency (1.1.1.1 vs 8.8.8.8 vs 9.9.9.9)
    — detects DNS hijacking, regional manipulation, ISP poisoning
  - NSEC / NSEC3 zone-walking attempt (info disclosure)
  - SRV records for ancillary services (mail, CalDAV, SIP, etc.)
  - DNS over HTTPS / TLS availability

State dict shape (populated by recon/dnsrecon.py):
  host, ips (list of resolved A/AAAA),
  ptr_records (dict ip->[hostnames]),
  dnskey (list),  ds (list),  dnssec_chain_valid (bool|None),
  resolver_answers (dict resolver_name -> [ips]),
  resolver_consistent (bool),
  nsec_walk_possible (bool),  nsec_hop_sample (list),
  srv_found (dict service_name -> [records]),
  doh_supported (bool|None),  dot_supported (bool|None),
"""

# Service categories for SRV findings — different severity weights
_SRV_INFRA_HINTS = {
    "_caldav._tcp":       "CalDAV calendar service",
    "_carddav._tcp":      "CardDAV contact service",
    "_imap._tcp":         "IMAP email service",
    "_imaps._tcp":        "IMAPS (encrypted IMAP)",
    "_pop3._tcp":         "POP3 email service",
    "_pop3s._tcp":        "POP3S (encrypted POP3)",
    "_smtp._tcp":         "SMTP relay",
    "_submission._tcp":   "SMTP submission",
    "_sip._tcp":          "SIP / VoIP",
    "_sips._tcp":         "SIPS (encrypted SIP)",
    "_xmpp-client._tcp":  "XMPP chat",
    "_xmpp-server._tcp":  "XMPP federation",
    "_minecraft._tcp":    "Minecraft server",
    "_jmap._tcp":         "JMAP modern email",
    "_autodiscover._tcp": "Microsoft Exchange Autodiscover",
    "_h323cs._tcp":       "H.323 video conferencing",
}


# ───────────────────────── DNSSEC rules ─────────────────────────

def rule_dnssec_fully_signed(s):
    if s.get("dnssec_chain_valid") is not True: return None
    return {"name": "DNSSEC chain valid (DNSKEY + DS both present)",
            "severity": "POSITIVE",
            "evidence": f"DNSKEY: {len(s.get('dnskey') or [])} record(s); "
                        f"DS: {len(s.get('ds') or [])} record(s)"}


def rule_dnssec_partial(s):
    has_dnskey = bool(s.get("dnskey"))
    has_ds = bool(s.get("ds"))
    if has_dnskey and has_ds: return None  # fully signed — different rule
    if not has_dnskey and not has_ds: return None  # not signed at all — different rule
    return {"name": "DNSSEC partially configured (broken chain)",
            "severity": "MEDIUM",
            "cwe": "CWE-345",
            "evidence": f"DNSKEY present: {has_dnskey}; DS present: {has_ds} — chain is broken; resolvers will treat as bogus",
            "remediation": "Either publish the missing record (DS at the parent zone, or DNSKEY at the apex), or remove the existing one to revert to unsigned cleanly."}


def rule_dnssec_unsigned(s):
    if s.get("dnskey") or s.get("ds"): return None
    if not s.get("ips"): return None  # don't fire on non-resolving domains
    return {"name": "DNSSEC not signed (no DNSKEY, no DS)",
            "severity": "MEDIUM",
            "cwe": "CWE-345",
            "evidence": "No DNSKEY at apex and no DS at parent — domain is unsigned",
            "remediation": "Enable DNSSEC at your registrar. Cloudflare / Route53 / Google Cloud DNS offer one-click signing."}


# ───────────────────────── Cross-resolver rules ─────────────────────────

def rule_resolver_mismatch(s):
    if s.get("resolver_consistent") is not False: return None
    answers = s.get("resolver_answers") or {}
    summary = "; ".join(f"{r}: {', '.join((a[:1] if a else ['(empty)']))}"
                          for r, a in answers.items())
    return {"name": "Cross-resolver mismatch — potential DNS hijacking",
            "severity": "HIGH",
            "cwe": "CWE-345",
            "evidence": f"Different public resolvers returned different IPs. {summary}",
            "remediation": "Verify from a different network. If the mismatch persists, investigate ISP DNS manipulation, hijacked nameserver, or regional split-horizon misconfiguration."}


def rule_resolver_consistent(s):
    if s.get("resolver_consistent") is not True: return None
    n = len(s.get("resolver_answers") or {})
    if n < 2: return None
    return {"name": f"DNS answers consistent across {n} public resolvers",
            "severity": "POSITIVE",
            "evidence": f"Queried 1.1.1.1, 8.8.8.8, 9.9.9.9 — all returned matching A records"}


# ───────────────────────── PTR / reverse DNS rules ─────────────────────────

def rule_ptr_all_configured(s):
    ips = s.get("ips") or []
    ptr = s.get("ptr_records") or {}
    if not ips: return None
    have_ptr = sum(1 for ip in ips if ptr.get(ip))
    if have_ptr != len(ips): return None
    return {"name": "Reverse DNS (PTR) configured for all resolved IPs",
            "severity": "POSITIVE",
            "evidence": f"All {len(ips)} IP(s) have PTR records"}


def rule_ptr_missing(s):
    ips = s.get("ips") or []
    ptr = s.get("ptr_records") or {}
    if not ips: return None
    missing = [ip for ip in ips if not ptr.get(ip)]
    if not missing: return None
    if len(missing) == len(ips):
        sev = "LOW"
        name = "No reverse DNS (PTR) for resolved IPs"
    else:
        sev = "INFO"
        name = f"Partial reverse DNS — {len(missing)}/{len(ips)} IPs lack PTR"
    return {"name": name,
            "severity": sev,
            "evidence": f"Missing PTR for: {', '.join(missing[:3])}",
            "remediation": "Reverse DNS is required for SMTP delivery (most mail receivers reject mail from PTR-less IPs) and improves logging clarity."}


def rule_ptr_mismatch(s):
    ips = s.get("ips") or []
    ptr = s.get("ptr_records") or {}
    host = s.get("host") or ""
    if not ips or not host: return None
    mismatches = []
    for ip in ips:
        ptr_names = ptr.get(ip) or []
        if not ptr_names: continue
        # PTR should resolve back to the domain (or a subdomain of it)
        if not any(host in n or n in host for n in ptr_names):
            mismatches.append((ip, ptr_names[0]))
    if not mismatches: return None
    return {"name": "PTR records point to different hostnames (forward/reverse mismatch)",
            "severity": "INFO",
            "evidence": f"E.g. {mismatches[0][0]} -> {mismatches[0][1]} (expected something matching {host})",
            "remediation": "Common for cloud/CDN hosting where IPs are shared. Not a defect — just a recon signal that origin is on shared infrastructure."}


# ───────────────────────── NSEC zone-walking ─────────────────────────

def rule_nsec_walk_possible(s):
    if not s.get("nsec_walk_possible"): return None
    hops = s.get("nsec_hop_sample") or []
    return {"name": "NSEC zone walking possible — full subdomain list leakable",
            "severity": "MEDIUM",
            "cwe": "CWE-200",
            "evidence": f"NSEC traversal succeeded. Sample hops: {', '.join(hops[:5])}",
            "remediation": "Switch from NSEC to NSEC3 (opt-out) at your DNS provider. NSEC3 hashes record names so they cannot be walked sequentially."}


def rule_nsec3_configured(s):
    if s.get("nsec_walk_possible") is False and s.get("dnskey"):
        return {"name": "NSEC3 properly configured (zone-walking prevented)",
                "severity": "POSITIVE",
                "evidence": "DNSSEC enabled and NSEC traversal returns hashed names (NSEC3)"}
    return None


# ───────────────────────── SRV records ─────────────────────────

def rule_srv_services_discovered(s):
    srv = s.get("srv_found") or {}
    if not srv: return None
    services = []
    for svc, recs in srv.items():
        if recs:
            label = _SRV_INFRA_HINTS.get(svc, svc)
            services.append(f"{label} ({len(recs)} record)")
    if not services: return None
    return {"name": f"SRV records discovered ({len(services)} service(s))",
            "severity": "INFO",
            "evidence": f"Services: {'; '.join(services[:5])}",
            "remediation": "SRV records expose ancillary services. Audit each — outdated SRV pointers (e.g. for retired CalDAV servers) are common attack surface."}


# ───────────────────────── DoH / DoT rules ─────────────────────────

def rule_doh_supported(s):
    if not s.get("doh_supported"): return None
    return {"name": "DNS over HTTPS (DoH) available on authoritative server",
            "severity": "POSITIVE",
            "evidence": "Authoritative NS responds to /dns-query (RFC 8484)"}


def rule_dot_supported(s):
    if not s.get("dot_supported"): return None
    return {"name": "DNS over TLS (DoT) available on authoritative server",
            "severity": "POSITIVE",
            "evidence": "Authoritative NS responds on TCP/853 (RFC 7858)"}


# ───────────────────────── REGISTRY ─────────────────────────

DNSRECON_FINDING_RULES = [
    rule_dnssec_fully_signed,
    rule_dnssec_partial,
    rule_dnssec_unsigned,
    rule_resolver_mismatch,
    rule_resolver_consistent,
    rule_ptr_all_configured,
    rule_ptr_missing,
    rule_ptr_mismatch,
    rule_nsec_walk_possible,
    rule_nsec3_configured,
    rule_srv_services_discovered,
    rule_doh_supported,
    rule_dot_supported,
]
