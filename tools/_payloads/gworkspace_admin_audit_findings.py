"""gworkspace_admin_audit - findings rules (CISA ScubaGoggles baseline).

Mapping:
  CWE-308   = single-factor authentication
  CWE-307   = insufficient protection against brute-force
  CWE-1391  = use of weak credentials (no hardware token)
  CWE-672   = use of expired/dormant resource (dormant admin)
  CWE-1390  = weak authentication
  ISO 27001 A.5.17 = access management
  ISO 27001 A.5.18 = privileged access rights
  ISO 27001 A.8.5  = secure authentication

Severity model:
  HIGH    — admin without 2SV, super-admin dormant >180 days
  MEDIUM  — admin enrolled in 2SV but no hardware key, suspended-still-admin,
             super-admin dormant 90-180 days
  LOW     — N/A here (we don't drop low for posture readouts)
  INFO    — credentials missing / API error / parse error
  POSITIVE — 100% admin 2SV + 0 dormant super-admins
"""


def rule_creds_missing(s):
    if not s.get("gworkspace_admin_audit_creds_missing"):
        return None
    return {
        "name": "Google Workspace admin audit skipped — credentials required",
        "severity": "INFO",
        "evidence": ("This probe needs options.gcp_service_account_json (raw "
                     "or base64-encoded SA JSON key) + options.delegated_admin "
                     "(super-admin email the SA will impersonate via DWD)."),
        "remediation": ("In Google Cloud Console create a service account, "
                        "enable domain-wide delegation, and authorise its "
                        "client ID for scopes "
                        "admin.directory.user.readonly + "
                        "admin.directory.user.security in the Workspace admin "
                        "console (Security > Access and data control > API "
                        "controls > Domain-wide delegation). Re-run with "
                        "options.gcp_service_account_json + .delegated_admin."),
        "cwe": "CWE-1006",
        "iso27001": "A.5.23",
    }


def rule_creds_error(s):
    if not s.get("gworkspace_admin_audit_creds_error"):
        return None
    return {
        "name": "Google service-account JSON could not be parsed",
        "severity": "INFO",
        "evidence": str(s.get("gworkspace_admin_audit_creds_error")),
        "remediation": ("Provide options.gcp_service_account_json as either "
                        "the raw JSON file content OR the base64 of that file. "
                        "It must be a Google IAM service-account key with "
                        "'type': 'service_account'."),
        "cwe": "CWE-1006",
        "iso27001": "A.5.23",
    }


def rule_auth_error(s):
    if not s.get("gworkspace_admin_audit_auth_error"):
        return None
    return {
        "name": "Google Admin SDK authentication failed",
        "severity": "INFO",
        "evidence": str(s.get("gworkspace_admin_audit_auth_error"))[:600],
        "remediation": ("Most common cause: domain-wide delegation not "
                        "authorised for the service-account client ID. In the "
                        "Workspace admin console go to Security > API controls "
                        "> Domain-wide delegation and add the SA client ID with "
                        "the two admin.directory scopes. Also confirm "
                        "options.delegated_admin is a SUPER ADMIN email in this "
                        "tenant."),
        "cwe": "CWE-287",
        "iso27001": "A.5.17",
    }


def rule_api_error(s):
    if not s.get("gworkspace_admin_audit_api_error"):
        return None
    return {
        "name": "Google Admin Directory API call failed",
        "severity": "INFO",
        "evidence": str(s.get("gworkspace_admin_audit_api_error"))[:600],
        "remediation": ("Confirm the Admin SDK API is enabled in the GCP "
                        "project the SA lives in, and that the delegated admin "
                        "has the 'Users > Read' privilege. HTTP 429 = back off."),
        "cwe": "CWE-863",
        "iso27001": "A.5.18",
    }


def rule_admins_no_2sv(s):
    rows = s.get("gworkspace_admins_no_2sv") or []
    if not rows:
        return None
    sample = ", ".join(r.get("email", "?") for r in rows[:5])
    extra = f" (+{len(rows)-5} more)" if len(rows) > 5 else ""
    return {
        "name": f"{len(rows)} Workspace admin(s) without 2-Step Verification",
        "severity": "HIGH",
        "cvss": "8.1",
        "evidence": (f"Admins missing 2SV: {sample}{extra}. Single-factor "
                     "auth on a privileged account is the #1 SaaS compromise "
                     "vector."),
        "remediation": ("In the Workspace admin console enforce 2SV for the "
                        "admin org-unit immediately (Security > 2-Step "
                        "Verification > Allow / Enforce). For super-admins "
                        "require a hardware security key, not SMS."),
        "cwe": "CWE-308",
        "owasp": "A07:2021",
        "iso27001": "A.8.5",
    }


def rule_admins_no_hwkey(s):
    rows = s.get("gworkspace_admins_no_hwkey") or []
    if not rows:
        return None
    sample = ", ".join(r.get("email", "?") for r in rows[:5])
    extra = f" (+{len(rows)-5} more)" if len(rows) > 5 else ""
    return {
        "name": (f"{len(rows)} admin(s) on 2SV but NOT enrolled "
                 "in a hardware security key"),
        "severity": "MEDIUM",
        "cvss": "5.4",
        "evidence": (f"2SV-enrolled but no security key: {sample}{extra}. "
                     "Phishable 2SV factors (SMS, push) bypassable via AiTM "
                     "kits (EvilProxy, NakedPages)."),
        "remediation": ("Enrol every super-admin in Advanced Protection "
                        "Program with a FIDO2 security key. Make hardware key "
                        "the ONLY accepted second factor for admin accounts."),
        "cwe": "CWE-1391",
        "iso27001": "A.8.5",
    }


def rule_hwkey_field_unavailable(s):
    rows = s.get("gworkspace_admins_hwkey_field_unavailable") or []
    if not rows:
        return None
    sample = ", ".join(r.get("email", "?") for r in rows[:5])
    extra = f" (+{len(rows)-5} more)" if len(rows) > 5 else ""
    return {
        "name": (f"Hardware security-key status not available for {len(rows)} "
                 "admin(s) on this Workspace edition"),
        "severity": "INFO",
        "evidence": (f"The Directory API did not populate the "
                     "securityKeyAuthenticatorEnrolled field for these "
                     f"admin(s): {sample}{extra}. This field is exposed on "
                     "Enterprise editions; its absence is NOT evidence of a "
                     "missing key, so no posture grade is assigned."),
        "remediation": ("To grade hardware-key coverage, run this audit on a "
                        "Workspace Enterprise edition (or via Advanced "
                        "Protection enrolment reporting). FIDO2 keys remain "
                        "the recommended second factor for all admins."),
        "cwe": "CWE-1391",
        "iso27001": "A.8.5",
    }


def rule_admins_dormant(s):
    rows = s.get("gworkspace_admins_dormant") or []
    if not rows:
        return None
    # split 90-180 (MEDIUM) vs 180+ (HIGH)
    high = [r for r in rows if (r.get("last_login_days") or 0) >= 180]
    med = [r for r in rows if 90 <= (r.get("last_login_days") or 0) < 180]
    out = []
    if high:
        sample = ", ".join(f"{r.get('email','?')} (~{r.get('last_login_days')}d)" for r in high[:5])
        out.append({
            "name": f"{len(high)} super-admin(s) dormant 180+ days",
            "severity": "HIGH",
            "cvss": "7.2",
            "evidence": f"Dormant super-admins: {sample}",
            "remediation": ("Revoke admin role from any account that has not "
                            "actively administered the tenant in 6+ months. "
                            "Convert to a regular user or suspend if departed."),
            "cwe": "CWE-672",
            "iso27001": "A.5.18",
        })
    if med:
        sample = ", ".join(f"{r.get('email','?')} (~{r.get('last_login_days')}d)" for r in med[:5])
        out.append({
            "name": f"{len(med)} super-admin(s) dormant 90-180 days",
            "severity": "MEDIUM",
            "cvss": "5.3",
            "evidence": f"Dormant super-admins: {sample}",
            "remediation": ("Review with the account owner. If the role is no "
                            "longer required, downgrade now — every dormant "
                            "super-admin is a higher-value phish target."),
            "cwe": "CWE-672",
            "iso27001": "A.5.18",
        })
    return out or None


def rule_suspended_admins(s):
    rows = s.get("gworkspace_suspended_admins") or []
    if not rows:
        return None
    sample = ", ".join(r.get("email", "?") for r in rows[:5])
    return {
        "name": (f"{len(rows)} SUSPENDED account(s) still hold admin role"),
        "severity": "MEDIUM",
        "cvss": "5.0",
        "evidence": (f"Accounts suspended but still admin: {sample}. If "
                     "suspension is lifted (or the account is restored from "
                     "backup) the role returns automatically."),
        "remediation": ("Suspend != revoke. For departed admins remove the "
                        "admin role first, THEN suspend. Re-audit quarterly."),
        "cwe": "CWE-672",
        "iso27001": "A.5.17",
    }


def rule_positive(s):
    if s.get("gworkspace_admin_audit_creds_missing"): return None
    if s.get("gworkspace_admin_audit_auth_error"):    return None
    if s.get("gworkspace_admin_audit_api_error"):     return None
    if (s.get("gworkspace_admin_audit_total") or 0) > 0: return None
    if not s.get("gworkspace_total_admins"):          return None
    hwkey_na = s.get("gworkspace_admins_hwkey_field_unavailable") or []
    hwkey_note = ("hardware-key coverage on every admin, "
                  if not hwkey_na else
                  "no hardware-key gaps among admins where the field is "
                  "reported, ")
    return {
        "name": "Workspace admin posture meets CISA ScubaGoggles baseline",
        "severity": "POSITIVE",
        "evidence": (f"Audited {s.get('gworkspace_total_admins', 0)} admin(s) "
                     f"of {s.get('gworkspace_total_users', 0)} user(s). 100% "
                     f"2SV enrolment, {hwkey_note}"
                     "no dormant super-admins, no suspended-still-admin."),
        "remediation": ("Re-audit monthly — admin set drifts as roles are "
                        "added. Schedule via /api/sspm/run_all on cron."),
        "cwe": "N/A",
        "iso27001": "A.5.17",
    }


GWORKSPACE_ADMIN_AUDIT_FINDING_RULES = [
    rule_creds_missing,
    rule_creds_error,
    rule_auth_error,
    rule_api_error,
    rule_admins_no_2sv,
    rule_admins_no_hwkey,
    rule_hwkey_field_unavailable,
    rule_admins_dormant,
    rule_suspended_admins,
    rule_positive,
]
