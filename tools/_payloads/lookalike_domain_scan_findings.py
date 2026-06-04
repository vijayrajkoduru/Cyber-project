"""lookalike_domain_scan - findings rules.

Severity model (every registered lookalike domain is a usable
phishing-impersonation surface — the attacker has the DNS + likely
TLS + landing page ready to weaponize):

  HIGH    - any registered variant
  INFO    - dnspython missing / bad target / fan-out error
  POSITIVE - 0 registered variants among the probed set
"""

_CWE_SPOOF = "CWE-290"     # Authentication Bypass by Spoofing
_CWE_VERIFY = "CWE-345"    # Insufficient Verification of Data Authenticity
_NIST = "NIST 800-53 SC-8 (Transmission Confidentiality and Integrity)"


def rule_dnspython_missing(s):
    err = s.get("lookalike_error") or ""
    if "dnspython" not in err.lower():
        return None
    return {
        "name": "Lookalike domain probe skipped - dnspython not installed",
        "severity": "INFO",
        "evidence": err,
        "remediation": "Install dnspython on the scanner host: pip install dnspython.",
        "cwe": "CWE-1006",
    }


def rule_bad_target(s):
    err = s.get("lookalike_error") or ""
    if "registrable domain" not in err.lower():
        return None
    return {
        "name": "Lookalike probe skipped - target must be a registrable domain",
        "severity": "INFO",
        "evidence": err,
        "remediation": (
            "Re-run with target set to the bare registrable domain "
            "(e.g. `acme.com`, not `https://www.acme.com/login`)."
        ),
        "cwe": "CWE-1006",
    }


def rule_registered_variants(s):
    reg = s.get("lookalike_registered") or []
    if not reg:
        return None
    by_class = s.get("lookalike_by_class") or {}
    # Highlight the top 10 variants in evidence (PDF readability)
    examples = []
    for r in reg[:10]:
        d = r.get("domain", "?")
        ips = ", ".join(r.get("ips") or [])
        klass = r.get("class", "?")
        examples.append(f"{d} ({klass})" + (f" -> {ips}" if ips else ""))
    extra = f" + {len(reg) - 10} more" if len(reg) > 10 else ""
    breakdown = ", ".join(f"{k}={v}" for k, v in sorted(by_class.items()))
    return {
        "name": (f"{len(reg)} lookalike domain(s) registered against "
                 f"{s.get('lookalike_target_domain', 'target')}"),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": _CWE_SPOOF,
        "cwe_name": "Authentication Bypass by Spoofing",
        "owasp": "A07:2021",
        "evidence": (
            f"Out of {s.get('lookalike_variants_generated', 0)} probed "
            f"typosquat / homoglyph / TLD-swap variants, {len(reg)} "
            f"have public A-records. Class breakdown: {breakdown}. "
            f"Examples: " + "; ".join(examples) + extra + "."
        ),
        "remediation": (
            "1. Inventory each registered variant via WHOIS and decide "
            "per-domain action: (a) defensively register the variant "
            "yourself if cheap, (b) file a UDRP/URS complaint at "
            "ICANN if the registration is clearly bad-faith abuse, "
            "(c) submit to your brand-protection vendor for takedown. "
            "2. Subscribe to a real-time newly-registered-domain feed "
            "filtered to your brand keywords (e.g. WhoisXML APIs, "
            "DomainTools Iris, internal dnstwist cron). "
            "3. Add the lookalikes to your email gateway block-list "
            "and to your endpoint URL-filter so internal phishing "
            "clicks from compromised users are dropped at egress. "
            f"4. Train staff to verify the exact spelling of any URL "
            f"in a password-reset email. Compliance: {_NIST}, "
            f"MITRE ATT&CK T1583.001 (Acquire Infrastructure: Domains)."
        ),
    }


def rule_fanout_error(s):
    err = s.get("lookalike_error") or ""
    if "fan-out" not in err.lower():
        return None
    return {
        "name": "Lookalike probe partially failed - DNS fan-out raised an exception",
        "severity": "INFO",
        "evidence": err,
        "remediation": (
            "Confirm the scanner host has outbound UDP/53 + TCP/53 to "
            "the configured resolvers and retry. If problems persist, "
            "switch /etc/resolv.conf to 1.1.1.1 or 8.8.8.8."
        ),
        "cwe": "CWE-1006",
    }


def rule_positive_no_lookalikes(s):
    if s.get("lookalike_registered_total"):
        return None
    if not s.get("lookalike_variants_generated"):
        return None
    if s.get("lookalike_error"):
        return None
    return {
        "name": "No lookalike domains registered in the probed set",
        "severity": "POSITIVE",
        "evidence": (
            f"All {s.get('lookalike_variants_generated', 0)} probed "
            "typosquat / homoglyph / TLD-swap variants returned NXDOMAIN "
            "or had no A-record. Your brand surface is clean against "
            "the high-impact confusables this probe enumerates."
        ),
        "remediation": (
            "Maintain monitoring — newly-registered confusables appear "
            "weekly. Re-run this probe on a 30-day cadence (or wire "
            "into your SIEM via WhoisXML / Domaintools API)."
        ),
        "cwe": _CWE_VERIFY,
        "owasp": "A07:2021",
    }


LOOKALIKE_DOMAIN_SCAN_FINDING_RULES = [
    rule_dnspython_missing,
    rule_bad_target,
    rule_registered_variants,
    rule_fanout_error,
    rule_positive_no_lookalikes,
]
