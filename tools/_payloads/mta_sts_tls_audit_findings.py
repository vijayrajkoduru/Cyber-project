"""mta_sts_tls_audit - findings rules.

The mail-transport TLS fence (MTA-STS + DANE + TLS-RPT) backs up the
sender-auth fence (SPF/DKIM/DMARC). Without it, an active on-path
attacker can strip STARTTLS and read or rewrite inbound mail — including
password-reset and MFA links — even when DMARC is at p=reject.

ZERO-FALSE-POSITIVE rule: a graded (MEDIUM/LOW) severity fires ONLY when
the domain demonstrably receives mail (an MX exists) AND the relevant
public record was queried and found absent or in a non-enforcing mode.
No MX, or a probe that could not run, is INFO only.

Severity model:
  MEDIUM   - MX exists but NO MTA-STS policy at all (TXT + well-known both
             missing) — STARTTLS-stripping downgrade is undefended
  LOW      - MTA-STS published but mode=testing/none (not enforcing)
  LOW      - MX exists but TLS-RPT record absent (no failure visibility)
  INFO     - MTA-STS enforce present, DANE TLSA absent (either is fine)
  INFO     - dnspython/httpx missing, or no MX (mail-transport N/A)
  POSITIVE - MTA-STS mode=enforce fully deployed (TXT + valid well-known)
"""

_CWE_DOWNGRADE = "CWE-757"   # Selection of Less-Secure Algorithm During Negotiation
_CWE_CLEARTEXT = "CWE-319"   # Cleartext Transmission of Sensitive Information
_NIST = "NIST 800-53 SC-8 (Transmission Confidentiality and Integrity)"


def rule_dep_missing(s):
    err = s.get("mta_sts_error") or ""
    if "dnspython" not in err.lower():
        return None
    return {
        "name": "MTA-STS/TLS-RPT probe skipped - dnspython not installed",
        "severity": "INFO",
        "evidence": err,
        "remediation": (
            "Install dnspython on the scanner host: pip install dnspython. "
            "Then re-run this scan."
        ),
        "cwe": "CWE-1006",
    }


def rule_no_mx(s):
    # Only emit when the probe ran (domain set) but no MX exists.
    if not s.get("mta_sts_target_domain"):
        return None
    if s.get("mta_sts_has_mx"):
        return None
    if s.get("mta_sts_error"):
        return None
    return {
        "name": (f"No MX record on {s.get('mta_sts_target_domain')} "
                 "- mail-transport TLS posture not applicable"),
        "severity": "INFO",
        "evidence": (
            f"An MX lookup for {s.get('mta_sts_target_domain')} returned no "
            "records, so this domain does not receive SMTP mail directly. "
            "MTA-STS / DANE / TLS-RPT only apply to mail-receiving domains, "
            "so no graded transport finding is raised. (If this domain DOES "
            "receive mail via a parent zone, audit the parent instead.)"
        ),
        "remediation": (
            "If this is intentional (parked / send-only domain), publish a "
            "null-MX record (`. 0`) and `v=spf1 -all` to make the no-mail "
            "intent explicit and block spoofing. RFC 7505."
        ),
        "cwe": "CWE-1006",
    }


def rule_mta_sts_absent(s):
    # MEDIUM only when the domain actually receives mail AND no policy
    # exists in either form. This is a DETECTED condition, not advisory.
    if not s.get("mta_sts_has_mx"):
        return None
    if s.get("mta_sts_txt_present"):
        return None
    if (s.get("mta_sts_policy") or None):
        return None
    return {
        "name": (f"No MTA-STS policy on {s.get('mta_sts_target_domain')} "
                 "- inbound STARTTLS can be stripped by an on-path attacker"),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": _CWE_DOWNGRADE,
        "cwe_name": "Selection of Less-Secure Algorithm During Negotiation",
        "owasp": "A02:2021",
        "evidence": (
            f"Neither `_mta-sts.{s.get('mta_sts_target_domain')}` (TXT "
            "signpost) nor "
            f"`https://mta-sts.{s.get('mta_sts_target_domain')}/.well-known/"
            "mta-sts.txt` (policy) returned a valid STSv1 record, yet the "
            f"domain publishes MX `{s.get('mta_sts_mx_host')}`. STARTTLS on "
            "inbound SMTP is therefore opportunistic only: an active network "
            "attacker between a sending MTA and your server can delete the "
            "`250-STARTTLS` line from the EHLO response, forcing the message "
            "(and any password-reset / MFA links inside it) into cleartext."
        ),
        "remediation": (
            "Deploy MTA-STS in enforce mode: (1) publish TXT "
            "`_mta-sts.<domain>` = `v=STSv1; id=<timestamp>`; (2) host "
            "`https://mta-sts.<domain>/.well-known/mta-sts.txt` with "
            "`version: STSv1`, `mode: enforce`, one `mx:` line per receiving "
            "host, and `max_age: 604800`. Roll out `mode: testing` first, "
            "watch TLS-RPT reports, then switch to `enforce`. "
            f"Compliance: {_NIST}, RFC 8461."
        ),
    }


def rule_mta_sts_not_enforcing(s):
    # LOW: a policy IS published but its mode does not enforce.
    if not s.get("mta_sts_has_mx"):
        return None
    mode = (s.get("mta_sts_policy_mode") or "").lower()
    if mode not in ("testing", "none"):
        return None
    return {
        "name": (f"MTA-STS policy is mode={mode} (not enforcing) on "
                 f"{s.get('mta_sts_target_domain')}"),
        "severity": "LOW",
        "cvss": "3.7",
        "cwe": _CWE_DOWNGRADE,
        "owasp": "A02:2021",
        "evidence": (
            f"The published MTA-STS policy for "
            f"{s.get('mta_sts_target_domain')} sets `mode: {mode}`. In "
            "`testing` mode a sender that detects a TLS failure still "
            "delivers the message (it only emits a TLS-RPT report); in "
            "`none` mode the policy is effectively withdrawn. A STARTTLS "
            "downgrade therefore still succeeds against your inbound mail."
        ),
        "remediation": (
            "Once TLS-RPT reports confirm all sending MTAs negotiate TLS "
            "cleanly against the listed `mx:` hosts, change the policy file "
            "to `mode: enforce`. Keep `max_age` >= 604800 so caches honor "
            "the policy for a week. RFC 8461 §5."
        ),
    }


def rule_tlsrpt_absent(s):
    # LOW: domain receives mail but has no TLS-RPT visibility.
    if not s.get("mta_sts_has_mx"):
        return None
    if s.get("tlsrpt_present"):
        return None
    return {
        "name": (f"No TLS-RPT record on {s.get('mta_sts_target_domain')} "
                 "- TLS delivery failures are invisible"),
        "severity": "LOW",
        "cvss": "2.6",
        "cwe": _CWE_CLEARTEXT,
        "owasp": "A09:2021",
        "evidence": (
            f"TXT lookup for `_smtp._tls.{s.get('mta_sts_target_domain')}` "
            "returned no `v=TLSRPTv1` record. Sending MTAs have nowhere to "
            "report STARTTLS / MTA-STS failures, so a downgrade attack (or a "
            "broken cert on your receiver) produces no signal you can see."
        ),
        "remediation": (
            "Publish TXT `_smtp._tls.<domain>` = "
            "`v=TLSRPTv1; rua=mailto:tlsrpt@<domain>` (or an https reporting "
            "endpoint). Review the daily aggregate reports — they are how you "
            "safely ratchet MTA-STS from testing to enforce. RFC 8460."
        ),
    }


def rule_dane_absent_info(s):
    # INFO ONLY — DANE and MTA-STS are alternatives; absence of DANE when
    # MTA-STS enforces is NOT a vulnerability. Advisory.
    if not s.get("mta_sts_has_mx"):
        return None
    if (s.get("mta_sts_policy_mode") or "").lower() != "enforce":
        return None
    if s.get("dane_tlsa_present"):
        return None
    return {
        "name": (f"DANE TLSA not published for {s.get('mta_sts_mx_host')} "
                 "(MTA-STS enforce already covers downgrade) [ADVISORY]"),
        "severity": "INFO",
        "evidence": (
            f"No TLSA record at `_25._tcp.{s.get('mta_sts_mx_host')}`. This "
            "is informational only: MTA-STS in enforce mode already prevents "
            "STARTTLS stripping, and DANE additionally requires a "
            "DNSSEC-signed zone. Either mechanism is sufficient."
        ),
        "remediation": (
            "Optional hardening: if your DNS zone is DNSSEC-signed, also "
            "publish a DANE TLSA record (`3 1 1 <cert-hash>`) at "
            "`_25._tcp.<mxhost>` for defence-in-depth alongside MTA-STS. "
            "RFC 7672. Not required where MTA-STS enforce is deployed."
        ),
        "cwe": _CWE_DOWNGRADE,
    }


def rule_positive(s):
    if not s.get("mta_sts_has_mx"):
        return None
    if (s.get("mta_sts_policy_mode") or "").lower() != "enforce":
        return None
    if not s.get("mta_sts_deployed"):
        return None
    return {
        "name": ("MTA-STS deployed in enforce mode "
                 f"on {s.get('mta_sts_target_domain')}"),
        "severity": "POSITIVE",
        "evidence": (
            f"Both the `_mta-sts.{s.get('mta_sts_target_domain')}` TXT "
            "signpost and a valid `mode: enforce` policy file are published. "
            "Sending MTAs will refuse to deliver over a downgraded/cleartext "
            "channel — STARTTLS stripping against your inbound mail fails."
        ),
        "remediation": (
            "Maintain: keep the well-known policy reachable over a valid TLS "
            "cert, rotate the `id=` in the TXT record whenever the policy "
            "changes, and review TLS-RPT reports for new shadow-IT senders."
        ),
        "cwe": _CWE_DOWNGRADE,
        "owasp": "A02:2021",
    }


MTA_STS_TLS_AUDIT_FINDING_RULES = [
    rule_dep_missing,
    rule_no_mx,
    rule_mta_sts_absent,
    rule_mta_sts_not_enforcing,
    rule_tlsrpt_absent,
    rule_dane_absent_info,
    rule_positive,
]
