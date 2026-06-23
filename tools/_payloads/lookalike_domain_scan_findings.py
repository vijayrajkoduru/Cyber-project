"""lookalike_domain_scan - findings rules.

ZERO-FP severity model (a registered/resolving lookalike domain is NOT
proof of an active phishing attack — it is impersonation *surface*, graded
by the strength of the evidence actually observed):

  MEDIUM   - one or more variants RESOLVE to a public A-record (the attacker
             has DNS + live hosting able to serve a brand-impersonating page)
  LOW      - variants exist but have NO A-record (NoAnswer / parked / MX-only)
             — registered but not yet hosting a landing page
  INFO     - dnspython missing / bad target / fan-out error
  POSITIVE - 0 registered variants among the probed set

A lookalike that merely resolves is impersonation *capability*, not a
confirmed hosted phishing IP — so this caps at MEDIUM and never claims a
verified exploit.
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


def _fmt_examples(items):
    examples = []
    for r in items[:10]:
        d = r.get("domain", "?")
        ips = ", ".join(r.get("ips") or [])
        klass = r.get("class", "?")
        examples.append(f"{d} ({klass})" + (f" -> {ips}" if ips else ""))
    extra = f" + {len(items) - 10} more" if len(items) > 10 else ""
    return "; ".join(examples) + extra


def rule_resolving_variants(s):
    """Variants with a live public A-record — graded MEDIUM (hosting-capable
    impersonation surface). A resolving lookalike is NOT a confirmed hosted
    phishing page, so this caps at MEDIUM and is not a verified exploit."""
    reg = s.get("lookalike_registered") or []
    resolving = [r for r in reg if r.get("ips")]
    if not resolving:
        return None
    by_class: dict = {}
    for r in resolving:
        k = r.get("class", "?")
        by_class[k] = by_class.get(k, 0) + 1
    breakdown = ", ".join(f"{k}={v}" for k, v in sorted(by_class.items()))
    return {
        "name": (f"{len(resolving)} lookalike domain(s) resolving to a public IP "
                 f"against {s.get('lookalike_target_domain', 'target')}"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": _CWE_SPOOF,
        "cwe_name": "Authentication Bypass by Spoofing",
        "owasp": "A07:2021",
        "evidence": (
            f"Out of {s.get('lookalike_variants_generated', 0)} probed "
            f"typosquat / homoglyph / TLD-swap variants, {len(resolving)} "
            f"resolve to a public A-record (DNS + live hosting present). This "
            "is impersonation CAPABILITY, not a confirmed hosted phishing "
            "page — triage each before takedown (may be a partner/reseller/"
            f"parked page). Class breakdown: {breakdown}. "
            f"Examples: " + _fmt_examples(resolving) + "."
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


def rule_existing_no_a_record(s):
    """Variants that exist in DNS but have NO A-record (NoAnswer / parked /
    MX-only). Registered but not yet hosting a landing page — this is LOW,
    distinctly weaker than a confirmed hosted phishing IP."""
    reg = s.get("lookalike_registered") or []
    no_a = [r for r in reg if not r.get("ips")]
    if not no_a:
        return None
    by_class: dict = {}
    for r in no_a:
        k = r.get("class", "?")
        by_class[k] = by_class.get(k, 0) + 1
    breakdown = ", ".join(f"{k}={v}" for k, v in sorted(by_class.items()))
    return {
        "name": (f"{len(no_a)} lookalike domain(s) exist in DNS without an "
                 f"A-record against {s.get('lookalike_target_domain', 'target')}"),
        "severity": "LOW",
        "cvss": "2.0",
        "cwe": _CWE_VERIFY,
        "cwe_name": "Insufficient Verification of Data Authenticity",
        "owasp": "A07:2021",
        "evidence": (
            f"{len(no_a)} probed variant(s) resolve in DNS but return NoAnswer "
            "for the A query (parked, MX-only, or not yet pointed at a host). "
            "These are registered impersonation candidates but are NOT hosting "
            "a phishing page at scan time — not the same as a confirmed hosted "
            f"phishing IP. Class breakdown: {breakdown}. "
            f"Examples: " + _fmt_examples(no_a) + "."
        ),
        "remediation": (
            "Monitor these registered-but-dormant variants — an attacker can "
            "point an A-record at a phishing host at any time. Add them to your "
            "brand-protection watchlist and email/URL block-lists pre-emptively, "
            f"and re-run this probe on a 7-30 day cadence. Compliance: {_NIST}."
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
    rule_resolving_variants,
    rule_existing_no_a_record,
    rule_fanout_error,
    rule_positive_no_lookalikes,
]
