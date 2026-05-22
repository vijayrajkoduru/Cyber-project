"""DNS Records intelligence — findings rules library.

Each rule takes a state dict (populated by recon/dns.py) and returns
either None (no finding) or a finding dict {name, severity, evidence,
cwe?, remediation?}.

State dict shape (populated by scanner):
  host, A (list), AAAA (list), MX (list), NS (list), TXT (list),
  CNAME (list), SOA (list), CAA (list), records (combined list),
  spf (str or None), dmarc (str or None), dkim_found (bool),
  dkim_selectors_found (list), mail_provider (str or None),
  cdn_provider (str or None), cloud_provider (str or None),
  wildcard_detected (bool), verification_count (int),
  resolver_consistency (bool), ns_providers (set).
"""
import re

# Mail-provider MX patterns (case-insensitive match against MX values)
_MAIL_PROVIDERS = {
    "Google Workspace":  [r"aspmx\.l\.google\.com", r"googlemail\.com"],
    "Microsoft 365":     [r"mail\.protection\.outlook\.com",
                          r"\.outlook\.com$"],
    "Zoho Mail":         [r"\.zoho\.com$", r"mx\.zoho"],
    "Yahoo":             [r"\.yahoodns\.net$"],
    "ProtonMail":        [r"\.protonmail\.ch$", r"\.proton\.me$"],
    "Fastmail":          [r"\.messagingengine\.com$"],
    "Amazon SES":        [r"amazonses\.com"],
    "Mailgun":           [r"mailgun\.org"],
    "Postmark":          [r"postmarkapp\.com"],
    "SendGrid":          [r"sendgrid\.net"],
    "Hostinger":         [r"\.hostinger\.com$"],
}

# CDN A-record patterns (IP ranges + reverse-DNS hints)
_CDN_IP_RANGES = {
    "Cloudflare":  [r"^104\.(1[6-9]|2[0-9]|3[01])\.", r"^172\.(6[4-9]|7[0-9])\.",
                    r"^173\.245\.4[8-9]\.", r"^141\.101\."],
    "Akamai":      [r"^23\.(3[2-9]|[4-9][0-9])\.", r"^2\.(1[6-9]|2[0-9])\.",
                    r"^104\.96\.", r"^184\.[2-3]\d\."],
    "Fastly":      [r"^151\.101\.", r"^199\.(232|27|29)\."],
    "CloudFront":  [r"^13\.(2[2-3][0-9]|2[4-9][0-9])\.",
                    r"^54\.[1-2][0-9][0-9]\.", r"^99\.8[4-7]\."],
    "Sucuri":      [r"^192\.124\.249\."],
    "Imperva":     [r"^45\.60\."],
}


# Common DKIM selectors to probe — covers ~95% of real-world setups.
COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2",
                           "mail", "k1", "dkim", "s1", "s2"]


# ───────────────────────── SPF rules ─────────────────────────

def rule_spf_missing(s):
    if s.get("spf"): return None
    if not s.get("TXT"): return None  # if no TXT at all, separate concern
    return {"name": "SPF record missing",
            "severity": "MEDIUM",
            "cwe": "CWE-290",
            "evidence": f"{len(s.get('TXT') or [])} TXT records present, none contain v=spf1",
            "remediation": "Publish a TXT record like 'v=spf1 mx -all' at the apex domain to prevent email spoofing."}


def rule_spf_too_permissive(s):
    spf = (s.get("spf") or "").lower()
    if not spf: return None
    if "+all" in spf:
        return {"name": "SPF policy is +all (anyone can send as this domain)",
                "severity": "HIGH",
                "cwe": "CWE-290",
                "evidence": f"spf record: {spf[:140]}",
                "remediation": "Change +all to -all (hard fail) or ~all (soft fail). +all permits ANY sender to spoof your domain."}
    return None


def rule_spf_weak_policy(s):
    spf = (s.get("spf") or "").lower()
    if not spf: return None
    if "+all" in spf: return None  # covered by separate rule
    if "-all" in spf or "~all" in spf: return None  # acceptable
    return {"name": "SPF record has no terminating qualifier (no -all or ~all)",
            "severity": "LOW",
            "cwe": "CWE-290",
            "evidence": f"spf record: {(s.get('spf') or '')[:140]}",
            "remediation": "Add a terminating qualifier. '-all' = strict fail, '~all' = soft fail. Required for downstream receivers to enforce the policy."}


def rule_spf_strict_policy(s):
    spf = (s.get("spf") or "").lower()
    if not spf: return None
    if "-all" not in spf: return None
    return {"name": "SPF policy properly enforced with -all",
            "severity": "POSITIVE",
            "evidence": "SPF terminates with -all (hard fail) — receivers must reject unauthorized senders."}


def rule_spf_too_many_lookups(s):
    spf = (s.get("spf") or "").lower()
    if not spf: return None
    # Count include: + redirect: + a + mx + exists + ptr — SPF spec limits to 10
    lookups = (len(re.findall(r"\binclude:", spf)) +
                len(re.findall(r"\bredirect=", spf)) +
                len(re.findall(r"\ba\s", " " + spf + " ")) +
                len(re.findall(r"\bmx\s", " " + spf + " ")) +
                len(re.findall(r"\bexists:", spf)) +
                len(re.findall(r"\bptr\s", " " + spf + " ")))
    if lookups <= 10: return None
    return {"name": f"SPF record exceeds 10 DNS lookups ({lookups} found) — RFC violation",
            "severity": "MEDIUM",
            "cwe": "CWE-754",
            "evidence": f"Counted {lookups} mechanisms requiring DNS lookups; spec max is 10",
            "remediation": "Consolidate include: chains, or use SPF flattening (third-party services automate this)."}


# ───────────────────────── DMARC rules ─────────────────────────

def rule_dmarc_missing(s):
    if s.get("dmarc"): return None
    if not s.get("A"): return None  # don't fire on non-resolvable domain
    return {"name": "DMARC record missing",
            "severity": "MEDIUM",
            "cwe": "CWE-290",
            "evidence": f"_dmarc.{s.get('host')} has no v=DMARC1 TXT record",
            "remediation": "Publish DMARC at _dmarc.<domain>: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>'. Start with p=none for monitoring, then tighten."}


def rule_dmarc_p_none(s):
    dmarc = (s.get("dmarc") or "").lower()
    if not dmarc: return None
    if "p=none" not in dmarc: return None
    return {"name": "DMARC policy is p=none (monitoring only, not enforced)",
            "severity": "LOW",
            "cwe": "CWE-290",
            "evidence": f"dmarc: {dmarc[:160]}",
            "remediation": "After verifying legitimate mail flow via DMARC reports (rua), tighten to p=quarantine or p=reject."}


def rule_dmarc_quarantine(s):
    dmarc = (s.get("dmarc") or "").lower()
    if not dmarc or "p=quarantine" not in dmarc: return None
    return {"name": "DMARC policy is p=quarantine (failing mail sent to spam)",
            "severity": "POSITIVE",
            "evidence": f"dmarc: {dmarc[:160]}"}


def rule_dmarc_reject(s):
    dmarc = (s.get("dmarc") or "").lower()
    if not dmarc or "p=reject" not in dmarc: return None
    return {"name": "DMARC policy is p=reject (strongest enforcement)",
            "severity": "POSITIVE",
            "evidence": f"dmarc: {dmarc[:160]}"}


# ───────────────────────── DKIM rules ─────────────────────────

def rule_dkim_found(s):
    found = s.get("dkim_selectors_found") or []
    if not found: return None
    return {"name": f"DKIM signing keys published ({len(found)} selector(s))",
            "severity": "POSITIVE",
            "evidence": f"DKIM TXT found at: {', '.join(found[:3])}"}


def rule_dkim_missing(s):
    if s.get("dkim_selectors_found"): return None
    if not s.get("MX"): return None  # only flag for domains that actually receive mail
    return {"name": "No DKIM keys found at common selectors",
            "severity": "LOW",
            "cwe": "CWE-290",
            "evidence": f"Probed: {', '.join(COMMON_DKIM_SELECTORS)} — none returned a v=DKIM1 TXT",
            "remediation": "If sending mail, configure DKIM at your mail provider. Without DKIM, DMARC alignment is weaker."}


# ───────────────────────── CAA rules ─────────────────────────

def rule_caa_missing(s):
    if s.get("CAA"): return None
    if not s.get("A"): return None
    return {"name": "CAA records missing — any CA can issue TLS certs",
            "severity": "LOW",
            "cwe": "CWE-295",
            "evidence": "No CAA records published at apex",
            "remediation": "Restrict cert issuance via CAA: '0 issue \"letsencrypt.org\"'. Prevents rogue CAs from issuing mis-issued certs."}


def rule_caa_present(s):
    caa = s.get("CAA") or []
    if not caa: return None
    return {"name": f"CAA records restrict CA issuance ({len(caa)} record(s))",
            "severity": "POSITIVE",
            "evidence": f"CAA: {', '.join((str(c) for c in caa[:3]))}"}


# ───────────────────────── NS / hygiene rules ─────────────────────────

def rule_no_a_records(s):
    if s.get("A") or s.get("AAAA"): return None
    return {"name": "Domain does not resolve (no A or AAAA records)",
            "severity": "HIGH",
            "evidence": "DNS lookups returned 0 A/AAAA records",
            "remediation": "Configure A or AAAA records pointing to your server."}


def rule_ipv6_missing(s):
    if s.get("AAAA"): return None
    if not s.get("A"): return None
    return {"name": "No IPv6 (AAAA) records — IPv4-only",
            "severity": "INFO",
            "evidence": "A records present but AAAA absent",
            "remediation": "Optional: add AAAA records for IPv6 reachability. Modern CDNs (Cloudflare, Fastly) provide IPv6 free."}


def rule_ipv6_present(s):
    if not s.get("AAAA"): return None
    return {"name": "IPv6 (AAAA) records published",
            "severity": "POSITIVE",
            "evidence": f"{len(s.get('AAAA') or [])} AAAA record(s)"}


def rule_single_nameserver(s):
    ns = s.get("NS") or []
    if len(ns) != 1: return None
    return {"name": "Single nameserver (no DNS redundancy)",
            "severity": "MEDIUM",
            "evidence": f"Only NS: {ns[0]}",
            "remediation": "Configure at least 2 nameservers (ideally on different networks)."}


def rule_wildcard_dns(s):
    if not s.get("wildcard_detected"): return None
    return {"name": "Wildcard DNS detected — random subdomains resolve",
            "severity": "MEDIUM",
            "cwe": "CWE-264",
            "evidence": s.get("wildcard_evidence") or "random.<domain> resolved to an IP",
            "remediation": "Remove wildcard A/AAAA, or scope tightly. Wildcards mask subdomain-takeover attack surface."}


def rule_cname_at_apex(s):
    cname = s.get("CNAME") or []
    if not cname: return None
    # CNAME at apex is technically invalid per RFC 1912
    return {"name": "CNAME record at apex domain (RFC 1912 violation)",
            "severity": "MEDIUM",
            "evidence": f"CNAME at apex: {cname[0]}",
            "remediation": "Apex domains should not have CNAME records. Use ALIAS/ANAME (if provider supports it) or flatten to A/AAAA."}


# ───────────────────────── tech detection rules ─────────────────────────

def _detect_mail_provider(mx_list):
    if not mx_list: return None
    txt = " ".join(str(m).lower() for m in mx_list)
    for provider, patterns in _MAIL_PROVIDERS.items():
        for p in patterns:
            if re.search(p, txt):
                return provider
    return None


def rule_mail_provider(s):
    provider = _detect_mail_provider(s.get("MX"))
    if not provider: return None
    return {"name": f"Mail provider identified: {provider}",
            "severity": "INFO",
            "evidence": f"MX records match {provider} signature"}


def _detect_cdn_from_ips(a_list):
    if not a_list: return None
    for cdn, patterns in _CDN_IP_RANGES.items():
        for ip in a_list:
            for p in patterns:
                if re.match(p, str(ip)):
                    return cdn
    return None


def rule_cdn_via_a_records(s):
    cdn = _detect_cdn_from_ips(s.get("A"))
    if not cdn: return None
    return {"name": f"CDN detected via A records ({cdn})",
            "severity": "INFO",
            "evidence": f"Resolved A IPs match {cdn} ranges"}


# ───────────────────────── verification debt ─────────────────────────

def rule_high_verification_debt(s):
    n = s.get("verification_count", 0)
    if n < 5: return None
    return {"name": f"High domain verification debt ({n} TXT verification records)",
            "severity": "INFO",
            "evidence": f"{n} third-party verification tokens in TXT records",
            "remediation": "Periodically prune unused verification tokens (Google site verify, Atlassian, Slack, etc.) — old ones leak which third-party services you tried."}


# ───────────────────────── REGISTRY ─────────────────────────

DNS_FINDING_RULES = [
    # SPF
    rule_spf_missing,
    rule_spf_too_permissive,
    rule_spf_weak_policy,
    rule_spf_strict_policy,
    rule_spf_too_many_lookups,
    # DMARC
    rule_dmarc_missing,
    rule_dmarc_p_none,
    rule_dmarc_quarantine,
    rule_dmarc_reject,
    # DKIM
    rule_dkim_found,
    rule_dkim_missing,
    # CAA
    rule_caa_missing,
    rule_caa_present,
    # Hygiene
    rule_no_a_records,
    rule_ipv6_missing,
    rule_ipv6_present,
    rule_single_nameserver,
    rule_wildcard_dns,
    rule_cname_at_apex,
    # Tech detection
    rule_mail_provider,
    rule_cdn_via_a_records,
    # Verification
    rule_high_verification_debt,
]
