"""m365_security_score - findings rules (CISA M365 / CSA SaaS baselines).

Mapping:
  CWE-1392 / CWE-1188      = misconfigured / weak default security posture
  CWE-308                  = single-factor auth (weak MFA enforcement)
  CWE-307                  = insufficient brute-force protection
  ISO 27001 A.5.17 / A.5.18 = access control + privileged access
  ISO 27001 A.8.5          = secure authentication
  ISO 27001 A.5.23         = cloud-services security

Severity model (graded ONLY from the explicit numeric maxScore Graph reports
for each control id — never from a substring of the control NAME):
  CRITICAL — (none here; we never auto-fail on a posture readout)
  MEDIUM   — Not-Implemented control with explicit maxScore >= 5
  LOW      — Not-Implemented control with explicit maxScore in [1,5)
           — OR total secure score < 70% of max
  INFO     — Not-Implemented control whose maxScore is NOT known (unverifiable)
           — OR credentials missing | Graph auth failed | Graph API error
  POSITIVE — score >= 90% of max
"""


def rule_creds_missing(s):
    if not s.get("m365_secure_score_creds_missing"):
        return None
    return {
        "name": "M365 Secure Score audit skipped — credentials required",
        "severity": "INFO",
        "evidence": ("This probe needs options.tenant_id + options.client_id + "
                     "options.client_secret for an Entra app-registration with "
                     "the SecureScores.Read.All (application) Graph permission."),
        "remediation": ("In the Entra admin centre create an App Registration, "
                        "grant 'SecureScores.Read.All' as an Application "
                        "permission (admin-consent), and resubmit the scan with "
                        "options.tenant_id / .client_id / .client_secret. The "
                        "secret is used once per scan and never persisted."),
        "cwe": "CWE-1006",
        "iso27001": "A.5.23",
    }


def rule_auth_failed(s):
    if not s.get("m365_secure_score_auth_error"):
        return None
    return {
        "name": "Microsoft Graph authentication failed",
        "severity": "INFO",
        "evidence": f"MSAL error: {s.get('m365_secure_score_auth_error')}",
        "remediation": ("Verify the tenant_id/client_id/client_secret are "
                        "correct, the secret is not expired, and the app "
                        "registration has been granted admin consent for the "
                        "SecureScores.Read.All Graph permission."),
        "cwe": "CWE-287",
        "iso27001": "A.5.17",
    }


def rule_api_error(s):
    if not s.get("m365_secure_score_api_error"):
        return None
    return {
        "name": "Microsoft Graph API error during secure-score read",
        "severity": "INFO",
        "evidence": str(s.get("m365_secure_score_api_error")),
        "remediation": ("Most common cause is missing 'SecureScores.Read.All' "
                        "Application permission. Re-grant admin consent in the "
                        "Entra admin centre and retry. If the error is HTTP 429, "
                        "back off — Graph rate-limits per-tenant."),
        "cwe": "CWE-863",
        "iso27001": "A.5.18",
    }


def rule_no_data(s):
    if not s.get("m365_secure_score_no_data"):
        return None
    return {
        "name": "Secure Score data not yet populated for this tenant",
        "severity": "INFO",
        "evidence": ("Graph returned an empty secureScores collection — the "
                     "tenant may be new, the licence may not include Secure "
                     "Score, or the daily snapshot hasn't been generated yet."),
        "remediation": ("Wait 24-48h after tenant creation for the first "
                        "Secure Score snapshot. Confirm the tenant has at "
                        "least one M365 E3/E5 or Business Premium licence."),
        "cwe": "CWE-1392",
        "iso27001": "A.5.23",
    }


def rule_low_score(s):
    score = s.get("m365_score_pct") or 0
    if not s.get("m365_score_max"):
        return None
    if score >= 70:
        return None
    return {
        "name": f"Microsoft 365 Secure Score below industry baseline "
                f"({score}% of max)",
        "severity": "LOW",
        "evidence": (f"Current secure score is {s.get('m365_score_current')} / "
                     f"{s.get('m365_score_max')} ({score}%). Microsoft's "
                     "internal benchmark for healthy production tenants is "
                     ">=70%; market-leading tenants exceed 85%."),
        "remediation": ("Open the 365 Defender portal -> Secure Score and "
                        "work the top-3 highest-impact controls each sprint. "
                        "Target +5 points per month until score >=85%."),
        "cwe": "CWE-1392",
        "iso27001": "A.5.23",
    }


def rule_not_implemented_controls(s):
    controls = s.get("m365_not_implemented_controls") or []
    if not controls:
        return None
    out = []
    seen_highs = 0
    seen_meds = 0
    for c in controls[:25]:
        # ZERO-FP: default to INFO when severity wasn't explicitly graded from
        # a numeric maxScore (never silently promote an ungraded control).
        sev = c.get("severity") or "INFO"
        title = c.get("title") or c.get("name") or "(unknown control)"
        category = c.get("category") or c.get("service") or ""
        max_pts = c.get("max") or 0
        out.append({
            "name": f"M365 control unimplemented: {title}"
                    + (f" [{category}]" if category else ""),
            "severity": sev,
            "evidence": ((c.get("description") or "")[:240]
                         + (f"  Max impact: {max_pts} pts." if max_pts else "")),
            "remediation": (c.get("remediation")
                            or "Open 365 Defender -> Secure Score -> this "
                               "control and follow Microsoft's recommended "
                               "configuration. Validate via secureScores Graph "
                               "API delta after rollout."),
            "cwe": ("CWE-308" if sev == "HIGH" else "CWE-1392"),
            "owasp": "A07:2021" if sev == "HIGH" else "N/A",
            "iso27001": ("A.8.5" if sev == "HIGH" else "A.5.23"),
        })
        if sev == "HIGH": seen_highs += 1
        elif sev == "MEDIUM": seen_meds += 1
    # Append a roll-up if there are more we truncated
    if len(controls) > 25:
        out.append({
            "name": f"+{len(controls) - 25} additional unimplemented M365 controls",
            "severity": "INFO",
            "evidence": (f"Showing the 25 highest-impact controls. Full list of "
                         f"{len(controls)} entries available via the Graph API."),
            "remediation": "Triage by maxScore descending in 365 Defender.",
            "cwe": "CWE-1392",
            "iso27001": "A.5.23",
        })
    return out


def rule_positive(s):
    if s.get("m365_secure_score_creds_missing"): return None
    if s.get("m365_secure_score_auth_error"):    return None
    if s.get("m365_secure_score_api_error"):     return None
    if not s.get("m365_score_max"):              return None
    score_pct = s.get("m365_score_pct") or 0
    not_impl = s.get("m365_not_implemented_controls") or []
    high = [c for c in not_impl if (c.get("severity") == "HIGH")]
    if score_pct < 90:
        return None
    if high:
        return None
    return {
        "name": (f"M365 secure posture is industry-leading "
                 f"({score_pct}% of max, no MFA/CA/legacy-auth gaps)"),
        "severity": "POSITIVE",
        "evidence": (f"Secure score {s.get('m365_score_current')}/"
                     f"{s.get('m365_score_max')} ({score_pct}%); zero "
                     "high-risk controls unimplemented."),
        "remediation": ("Keep enforcing the current baseline. Re-audit quarterly "
                        "as Microsoft adds new controls (Secure Score is "
                        "additive — new controls drop the percentage even if "
                        "you change nothing)."),
        "cwe": "N/A",
        "iso27001": "A.5.23",
    }


M365_SECURITY_SCORE_FINDING_RULES = [
    rule_creds_missing,
    rule_auth_failed,
    rule_api_error,
    rule_no_data,
    rule_low_score,
    rule_not_implemented_controls,
    rule_positive,
]
