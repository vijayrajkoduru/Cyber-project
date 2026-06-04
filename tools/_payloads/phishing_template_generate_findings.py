"""phishing_template_generate - findings rules.

This probe doesn't TEST a customer system — it generates an artifact
the customer's red team / awareness program will use. Findings are
INFO-only, with the rendered template embedded as evidence so the
PDF reader can copy/paste it into their simulation tooling.

Severity model:
  INFO  - template rendered successfully (here is the artifact)
  INFO  - unknown template_type supplied (we fell back to default)
"""

_CWE_VERIFY = "CWE-345"   # Insufficient Verification of Data Authenticity
_CWE_SPOOF  = "CWE-290"   # Authentication Bypass by Spoofing
_NIST = "NIST 800-53 SC-8 (Transmission Confidentiality and Integrity)"


def rule_unknown_template(s):
    bad = s.get("template_unknown")
    if not bad:
        return None
    return {
        "name": f"Unknown template_type `{bad}` - fell back to default",
        "severity": "INFO",
        "evidence": (
            f"options.template_type={bad!r} is not in the supported "
            f"catalogue. Supported templates: "
            f"{', '.join(s.get('template_supported') or [])}. The probe "
            "rendered `password_expiry` as a fallback."
        ),
        "remediation": (
            "Re-run with one of the supported template_type values "
            "listed above. Custom templates can be added by extending "
            "tools/phishing/tier2_simulation/phishing_template_generate.py."
        ),
        "cwe": "CWE-1006",
    }


def rule_artifact(s):
    rendered = s.get("template_rendered") or {}
    if not rendered:
        return None
    subj = rendered.get("subject") or ""
    html = rendered.get("html") or ""
    tpl_id = s.get("template_id", "?")
    domain = s.get("template_target_domain", "?")
    sender = s.get("template_sender_domain", "?")
    cb = s.get("template_callback_url", "?")
    # Trim HTML preview to keep PDF readable; full HTML lives in intel.
    preview = html[:600] + ("..." if len(html) > 600 else "")
    return {
        "name": (f"Phishing template `{tpl_id}` rendered for "
                 f"{domain} (artifact - no send)"),
        "severity": "INFO",
        "cwe": _CWE_SPOOF,
        "owasp": "A07:2021",
        "evidence": (
            f"Template: {tpl_id}. Spoof sender domain: {sender}. "
            f"Callback URL placeholder: {cb}. "
            f"Subject (rendered): {subj!r}. "
            f"HTML preview ({len(html)}B total): {preview}"
        ),
        "remediation": (
            "1. Import the rendered subject + HTML into your authorized "
            "phishing-simulation platform (GoPhish, King-Phisher, "
            "KnowBe4, Cofense). VulnusLab does NOT send the message - "
            "you remain in full control of who receives it. "
            "2. Register the sender_domain you splice into the From: "
            "header BEFORE sending; otherwise SPF / DMARC will reject "
            "it (which is good for production, but breaks your "
            "simulation). "
            "3. Run the campaign on a 6-8 week cadence, rotating "
            "template_type each round. Industry baselines (Verizon "
            "DBIR 2024) show single-template programs train to one "
            "lure - rotate so users don't pattern-match. "
            "4. Track click + reporter rates and feed any clicker "
            "into a just-in-time micro-training module rather than "
            "punitive action. "
            f"Compliance: {_NIST}, NIST SP 800-50r1 (Building a "
            "Cybersecurity and Privacy Workforce). MITRE ATT&CK T1566."
        ),
    }


PHISHING_TEMPLATE_GENERATE_FINDING_RULES = [
    rule_unknown_template,
    rule_artifact,
]
