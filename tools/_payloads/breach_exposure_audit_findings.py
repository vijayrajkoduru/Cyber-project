"""breach_exposure_audit - finding rules (VL-METHOD aware).

Reads state populated by BreachExposureAudit:
  - methodology_findings : list of breach observations
  - target_domain        : the domain queried
  - hibp_breaches        : list of breach names returned by HIBP (public API)
  - hibp_queried         : bool - did we actually reach the HIBP API?
  - hibp_error           : optional error string (network / rate-limit / key)

ZERO-FALSE-POSITIVE CONTRACT
----------------------------
A graded breach finding is emitted ONLY when the public Have I Been Pwned
breach API returned one or more breaches that name this domain. That is a
documented, third-party-verified fact (a real, disclosed breach), not a
recommendation — so it stamps verified_exploit=True.

If HIBP could not be reached (no network, rate limited, or the breach-by-
domain endpoint requires a key in this deployment), the result is an honest
INFO advisory, NOT a clean POSITIVE and NEVER a graded finding.
"""


INTEL_FIELDS = [
    ("Target domain",   "target_domain"),
    ("HIBP queried",    "hibp_queried"),
    ("Breaches found",  "hibp_breaches"),
    ("HIBP error",      "hibp_error"),
    ("Stage timings (ms)", "stage_timings"),
    ("Stage errors",    "stage_errors"),
]


def _breach_findings(s):
    return [f for f in (s.get("methodology_findings") or []) if f.get("kind") == "domain_breach"]


def rule_input_missing(s):
    sr = s.get("skipped_reason") or ""
    if "no target" not in sr:
        return None
    return {
        "name": "No target supplied - breach exposure audit skipped",
        "severity": "INFO",
        "evidence": sr,
        "remediation": "Supply a domain (or URL) so the breach exposure can be checked.",
        "cwe": "CWE-1006",
    }


def rule_domain_breaches(s):
    hits = _breach_findings(s)
    if not hits:
        return None
    names = []
    for h in hits:
        n = h.get("breach_name")
        if n and n not in names:
            names.append(n)
    count = len(names)
    sev = "HIGH" if count > 3 else "MEDIUM" if count > 1 else "LOW"
    cvss = "7.5" if sev == "HIGH" else "5.3" if sev == "MEDIUM" else "3.7"
    sample = ", ".join(names[:8]) + ("..." if count > 8 else "")
    return {
        "name": f"Domain appears in {count} known data breach(es)",
        "severity": sev, "cvss": cvss,
        "cwe": "CWE-200", "owasp": "A07:2021",
        "verified_exploit": True,  # third-party-confirmed disclosed breach(es)
        "evidence": ("The public Have I Been Pwned breach database lists this "
                     f"domain in {count} disclosed breach(es): {sample}. Credentials "
                     "from these breaches are circulated in combo lists and fuel "
                     "credential-stuffing and password-spray campaigns against the "
                     "organisation's accounts."),
        "remediation": ("Force a password reset for affected accounts and require "
                        "phishing-resistant MFA (passkeys / FIDO2). Reject known-"
                        "breached passwords at set-time (Pwned Passwords k-anonymity "
                        "API, NIST SP 800-63B). Subscribe to HIBP domain monitoring "
                        "for proactive alerts on new breaches."),
    }


def rule_no_breaches(s):
    # Honest POSITIVE only when we ACTUALLY queried HIBP successfully.
    if not s.get("hibp_queried"):
        return None
    if _breach_findings(s):
        return None
    if s.get("hibp_error"):
        return None
    return {
        "name": "No known breaches found for this domain",
        "severity": "POSITIVE",
        "evidence": ("The public Have I Been Pwned breach database returned no "
                     "disclosed breaches naming this domain at scan time."),
        "remediation": ("Maintain — enable HIBP domain monitoring so newly "
                        "disclosed breaches involving this domain trigger an alert, "
                        "and keep MFA + breached-password rejection in place."),
        "cwe": "CWE-200",
        "owasp": "A07:2021",
    }


def rule_hibp_unavailable(s):
    err = s.get("hibp_error")
    if not err:
        return None
    if s.get("hibp_queried") and not err:
        return None
    return {
        "name": "[ADVISORY-BY-DESIGN] Breach exposure could not be confirmed via HIBP",
        "severity": "INFO",
        "evidence": ("The Have I Been Pwned breach-by-domain lookup could not be "
                     f"completed: {err}. The breach-by-domain endpoint requires an "
                     "API key / domain verification, or the request was rate-limited "
                     "or blocked by the network egress policy. No conclusion about "
                     "breach exposure should be drawn from this run."),
        "remediation": ("Provision an HIBP API key (and verify domain ownership in "
                        "the HIBP dashboard) to enable authoritative breach-by-domain "
                        "lookups, or check the domain manually at "
                        "https://haveibeenpwned.com. Either way, enforce MFA and "
                        "breached-password rejection regardless of breach status."),
        "cwe": "CWE-200",
        "owasp": "A07:2021",
    }


BREACH_EXPOSURE_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_domain_breaches,
    rule_no_breaches,
    rule_hibp_unavailable,
]
