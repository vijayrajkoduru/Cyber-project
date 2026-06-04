"""spf_dkim_dmarc_audit - findings rules.

Severity model (the trio is the email-spoofing fence — when any panel
is broken, sender-impersonation phishing lands successfully):

  CRITICAL - no DMARC record at all (recipient MTAs have no policy to
             apply, spoofed mail is delivered unflagged)
  HIGH     - SPF +all (any IP can send as the domain)
  HIGH     - DMARC p=none (policy is monitor-only)
  HIGH     - SPF ~all/?all WITH DMARC missing or p=none (soft-fail +
             no policy = spoofed mail still delivered)
  MEDIUM   - SPF missing entirely (no SPF check possible)
  MEDIUM   - no DKIM selector found for any common name
  MEDIUM   - DMARC pct < 100 (partial enforcement)
  INFO     - dnspython missing / domain not resolvable
  POSITIVE - DMARC p=reject + SPF -all + at least one DKIM selector
"""

# Common CWE / control mapping — every email-spoofing finding shares
# the same root: insufficient verification of message origin.
_CWE = "CWE-345"          # Insufficient Verification of Data Authenticity
_CWE_AUTHBYPASS = "CWE-290"  # Authentication Bypass by Spoofing
_NIST = "NIST 800-53 SC-8 (Transmission Confidentiality and Integrity)"


def rule_dnspython_missing(s):
    err = s.get("spf_dkim_dmarc_error") or ""
    if "dnspython" not in err.lower():
        return None
    return {
        "name": "SPF/DKIM/DMARC probe skipped - dnspython not installed",
        "severity": "INFO",
        "evidence": err,
        "remediation": (
            "Install dnspython on the scanner host: pip install dnspython. "
            "Then re-run this scan."
        ),
        "cwe": "CWE-1006",
    }


def rule_no_dmarc(s):
    if s.get("dmarc_present"):
        return None
    if not s.get("spf_target_domain"):
        return None
    return {
        "name": (f"No DMARC record on _dmarc.{s.get('spf_target_domain')}"
                 " - any spoofed mail delivers unflagged"),
        "severity": "CRITICAL",
        "cvss": "8.1",
        "cwe": _CWE_AUTHBYPASS,
        "cwe_name": "Authentication Bypass by Spoofing",
        "owasp": "A07:2021",
        "evidence": (
            f"TXT lookup for _dmarc.{s.get('spf_target_domain')} returned "
            "no record matching `v=DMARC1; ...`. Recipient mail servers "
            "have no published policy to apply when SPF / DKIM checks "
            "fail, so phishing email forged-as-your-domain is delivered "
            "to the user's inbox without any tag, quarantine, or reject."
        ),
        "remediation": (
            "Publish a DMARC TXT record at _dmarc.<domain>. Start with: "
            "`v=DMARC1; p=none; rua=mailto:dmarc@<domain>; fo=1; "
            "adkim=s; aspf=s`. Observe `rua` reports for 4–6 weeks, fix "
            "any aligned-but-failing mail flows, then ratchet `p=` to "
            "`quarantine` (50% pct) and finally `reject` (100% pct). "
            f"Compliance ref: {_NIST}; M3AAWG Email Authentication BCP "
            "(https://www.m3aawg.org/EmailAuthenticationRecommendedBestPractices)."
        ),
    }


def rule_spf_plus_all(s):
    if s.get("spf_all_qualifier") != "+":
        return None
    return {
        "name": "SPF record ends with `+all` - any IP can send as the domain",
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": _CWE_AUTHBYPASS,
        "owasp": "A07:2021",
        "evidence": (
            f"The SPF record for {s.get('spf_target_domain')} ends with "
            "the `+all` mechanism (or has `all` with no qualifier, which "
            "defaults to `+`). The `+` qualifier means PASS — every "
            "source IP on the public internet is authorized to send "
            "mail as your domain, defeating the entire SPF mechanism."
        ),
        "remediation": (
            "Change the SPF record's trailing mechanism from `+all` to "
            "`-all` (hard fail) or at minimum `~all` (soft fail) and "
            "ensure all legitimate sender IPs / includes are listed "
            "explicitly. Test the new record via `dig TXT <domain>` "
            "and a tool like MXToolbox SPF Surveyor before deploying. "
            f"Compliance: {_NIST}."
        ),
    }


def rule_dmarc_p_none(s):
    if (s.get("dmarc_p") or "").lower() != "none":
        return None
    return {
        "name": "DMARC policy is `p=none` - monitor-only mode, spoofs still deliver",
        "severity": "HIGH",
        "cvss": "6.5",
        "cwe": _CWE_AUTHBYPASS,
        "owasp": "A07:2021",
        "evidence": (
            f"DMARC record for _dmarc.{s.get('spf_target_domain')} has "
            "policy `p=none`. Mail that fails SPF/DKIM alignment is "
            "STILL delivered to the recipient's inbox; only an aggregate "
            "report is sent. From a phishing attacker's POV the domain "
            "is effectively unprotected."
        ),
        "remediation": (
            "Once the rua/ruf reports show all aligned flows are passing "
            "(2–4 weeks observation), update DMARC `p=quarantine` and "
            "`pct=50` for a phased rollout, then `p=reject` `pct=100`. "
            "Reject is the only setting that materially blocks "
            "impersonation phishing. "
            f"Compliance: {_NIST}, BIMI prerequisite (p=quarantine or stricter)."
        ),
    }


def rule_spf_softfail_dmarc_weak(s):
    """SPF ~all/?all combined with no DMARC or p=none = partial fence."""
    q = s.get("spf_all_qualifier")
    d = (s.get("dmarc_p") or "").lower()
    weak_spf = q in ("~", "?")
    weak_d = (not s.get("dmarc_present")) or d == "none"
    if not (weak_spf and weak_d):
        return None
    return {
        "name": (
            f"SPF qualifier `{q}all` combined with weak/missing DMARC "
            "- soft-fail mail still delivers"
        ),
        "severity": "HIGH",
        "cvss": "6.5",
        "cwe": _CWE_AUTHBYPASS,
        "owasp": "A07:2021",
        "evidence": (
            f"SPF for {s.get('spf_target_domain')} ends in `{q}all` "
            "(soft-fail or neutral) and DMARC is "
            f"{'absent' if not s.get('dmarc_present') else 'p=none'}. "
            "Mail that fails SPF is not hard-rejected and DMARC adds no "
            "enforcement on top — phishing email survives both layers."
        ),
        "remediation": (
            "Tighten SPF to `-all` once all legitimate senders are listed "
            "in include: mechanisms, AND publish a DMARC record with at "
            "least `p=quarantine`. Both must be enforced for the fence "
            f"to hold. {_NIST}."
        ),
    }


def rule_spf_missing(s):
    if s.get("spf_present"):
        return None
    if not s.get("spf_target_domain"):
        return None
    return {
        "name": "No SPF record on the target domain",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": _CWE_AUTHBYPASS,
        "owasp": "A07:2021",
        "evidence": (
            f"TXT lookup for {s.get('spf_target_domain')} returned no "
            "record matching `v=spf1 ...`. Receiving mail servers cannot "
            "validate whether a given source IP is authorized to send as "
            "your domain — DMARC alignment will also fail for SPF since "
            "there is no SPF result to align."
        ),
        "remediation": (
            "Publish an SPF TXT record listing your legitimate senders: "
            "`v=spf1 include:_spf.google.com include:spf.protection.outlook.com "
            "-all` (adjust includes for your mail providers). Hard-fail "
            "(`-all`) is the recommended trailing mechanism. "
            f"{_NIST}."
        ),
    }


def rule_dkim_missing(s):
    if s.get("dkim_present"):
        return None
    if not s.get("dkim_selectors_tried"):
        return None
    return {
        "name": "No DKIM selector found for any well-known name",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": _CWE,
        "owasp": "A07:2021",
        "evidence": (
            f"Probed {len(s.get('dkim_selectors_tried') or [])} common "
            "DKIM selectors (default, google, selector1, selector2, k1, "
            "etc.) under <selector>._domainkey."
            f"{s.get('spf_target_domain')}; none returned a DKIM TXT "
            "record. Outbound mail may not be DKIM-signed, which means "
            "DMARC will only have SPF alignment to rely on."
        ),
        "remediation": (
            "Confirm your mail provider has DKIM enabled and the public "
            "key is published as a TXT record at "
            "<selector>._domainkey.<domain>. For Google Workspace use "
            "the `google` selector; for Microsoft 365 use selector1 + "
            "selector2 (key-rotation pair). If you use a custom selector "
            "name, re-run this scan with options.dkim_selectors set to "
            "that name. "
            f"Compliance: {_NIST}, RFC 6376."
        ),
    }


def rule_dmarc_pct_partial(s):
    pct = s.get("dmarc_pct")
    if not pct:
        return None
    try:
        pct_int = int(str(pct).strip())
    except (TypeError, ValueError):
        return None
    if pct_int >= 100 or pct_int <= 0:
        return None
    return {
        "name": f"DMARC `pct={pct_int}` - policy applied to only "
                f"{pct_int}% of failing mail",
        "severity": "MEDIUM",
        "cvss": "4.3",
        "cwe": _CWE_AUTHBYPASS,
        "owasp": "A07:2021",
        "evidence": (
            f"DMARC `pct=` is set to {pct_int}, meaning the policy "
            "(quarantine/reject) is enforced on a sampled portion of "
            "failing mail only. Attackers can re-send the same phishing "
            "lure several times to land in the unsampled bucket."
        ),
        "remediation": (
            "Once your rua reports confirm legitimate mail flows are "
            "aligned, raise `pct=100` so DMARC policy applies to every "
            "failing message. Until then, plan a 25 -> 50 -> 100 ramp."
        ),
    }


def rule_positive_full_stack(s):
    """All three controls present + DMARC reject = best practice."""
    if not s.get("spf_present"):
        return None
    if not s.get("dmarc_present"):
        return None
    if not s.get("dkim_present"):
        return None
    if (s.get("dmarc_p") or "").lower() != "reject":
        return None
    if s.get("spf_all_qualifier") not in ("-", "~"):
        return None
    return {
        "name": "Email auth fence is fully deployed (SPF + DKIM + DMARC reject)",
        "severity": "POSITIVE",
        "evidence": (
            f"{s.get('spf_target_domain')} publishes a complete SPF "
            f"({s.get('spf_all_qualifier')}all) + at least one DKIM "
            f"selector + DMARC p=reject. Receiving MTAs will reject "
            "spoofed mail at the gateway."
        ),
        "remediation": (
            "Maintain quarterly DMARC report review to catch new "
            "shadow-IT mail senders that may break alignment. Consider "
            "adding BIMI for inbox logo proof of authentication."
        ),
        "cwe": _CWE_AUTHBYPASS,
        "owasp": "A07:2021",
    }


SPF_DKIM_DMARC_AUDIT_FINDING_RULES = [
    rule_dnspython_missing,
    rule_no_dmarc,
    rule_spf_plus_all,
    rule_dmarc_p_none,
    rule_spf_softfail_dmarc_weak,
    rule_spf_missing,
    rule_dkim_missing,
    rule_dmarc_pct_partial,
    rule_positive_full_stack,
]
