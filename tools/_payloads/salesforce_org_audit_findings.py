"""salesforce_org_audit - findings rules.

Mapping:
  CWE-269  = improper privilege management
  CWE-732  = incorrect permission assignment for critical resource
  CWE-863  = incorrect authorization
  CWE-1390 = weak authentication
  ISO 27001 A.5.15 = access control
  ISO 27001 A.5.18 = privileged access rights
  ISO 27001 A.8.3  = information access restriction

Severity model:
  HIGH    — non-SysAdmin profile/permset with ModifyAllData (god-mode)
  HIGH    — no login IP-range restrictions configured org-wide
  MEDIUM  — non-SysAdmin profile with API+ModifyMetadata
  MEDIUM  — non-SysAdmin profile with ViewAllData
  INFO    — credentials missing / domain invalid / API error
  POSITIVE — all checks clean
"""


def rule_creds_missing(s):
    if not s.get("salesforce_org_audit_creds_missing"):
        return None
    return {
        "name": "Salesforce org audit skipped — credentials required",
        "severity": "INFO",
        "evidence": ("This probe needs options.sf_domain (e.g. "
                     "https://acme.my.salesforce.com) and options.sf_access_token "
                     "(OAuth bearer with 'api' scope)."),
        "remediation": ("Create a Connected App in Setup > App Manager, grant "
                        "the OAuth scopes 'Manage user data via APIs (api)' + "
                        "'Perform requests at any time (refresh_token)'. Use "
                        "JWT bearer flow or User-Password OAuth to mint a "
                        "session token, then resubmit the scan with "
                        "options.sf_domain + .sf_access_token."),
        "cwe": "CWE-1006",
        "iso27001": "A.5.23",
    }


def rule_domain_invalid(s):
    if not s.get("salesforce_org_audit_domain_invalid"):
        return None
    return {
        "name": "options.sf_domain rejected — not a *.salesforce.com URL",
        "severity": "INFO",
        "evidence": ("Probe refuses to call non-Salesforce hosts. Provide the "
                     "tenant's My Domain URL (e.g. acme.my.salesforce.com or "
                     "acme.lightning.force.com) — never login.salesforce.com."),
        "remediation": ("In Setup > My Domain copy the current domain URL and "
                        "use it as options.sf_domain. The probe accepts "
                        "https://*.salesforce.com and https://*.force.com only."),
        "cwe": "CWE-1390",
        "iso27001": "A.5.23",
    }


def rule_api_error(s):
    if not s.get("salesforce_org_audit_api_error"):
        return None
    return {
        "name": "Salesforce REST API error during org audit",
        "severity": "INFO",
        "evidence": str(s.get("salesforce_org_audit_api_error"))[:600],
        "remediation": ("Most common cause: bearer token expired / session "
                        "killed by an IP restriction / connected app rejected "
                        "the OAuth scope. Mint a new token and retry. HTTP 401 "
                        "= bad token; HTTP 403 = scope insufficient."),
        "cwe": "CWE-863",
        "iso27001": "A.5.18",
    }


def rule_god_mode_profiles(s):
    rows = s.get("salesforce_god_mode_profiles") or []
    if not rows:
        return None
    sample = ", ".join(r.get("name", "?") for r in rows[:6])
    extra = f" (+{len(rows)-6} more)" if len(rows) > 6 else ""
    return {
        "name": (f"{len(rows)} non-SysAdmin profile(s) grant "
                 "ModifyAllData (org-wide god-mode)"),
        "severity": "HIGH",
        "cvss": "8.4",
        "evidence": (f"Profiles: {sample}{extra}. ModifyAllData lets the user "
                     "edit any record in any object, ignoring sharing rules. "
                     "Only the 'System Administrator' profile should hold it."),
        "remediation": ("Strip 'Modify All Data' from non-admin profiles. If a "
                        "use-case needs scoped power, switch to record-type "
                        "specific permission sets with 'Modify All' on the "
                        "specific objects only."),
        "cwe": "CWE-269",
        "owasp": "A01:2021",
        "iso27001": "A.5.18",
    }


def rule_api_modify_meta_profiles(s):
    rows = s.get("salesforce_api_modify_meta_profiles") or []
    if not rows:
        return None
    sample = ", ".join(r.get("name", "?") for r in rows[:6])
    extra = f" (+{len(rows)-6} more)" if len(rows) > 6 else ""
    return {
        "name": (f"{len(rows)} non-SysAdmin profile(s) grant "
                 "API Enabled + Modify Metadata"),
        "severity": "MEDIUM",
        "cvss": "6.7",
        "evidence": (f"Profiles: {sample}{extra}. The combination lets a user "
                     "deploy Apex / Flow / custom objects via the Metadata "
                     "API — equivalent to silent code-deploy on a production "
                     "org."),
        "remediation": ("Remove either 'API Enabled' or 'Modify Metadata' "
                        "from these profiles. Keep both only on dedicated CI "
                        "deploy users gated by IP-range restrictions."),
        "cwe": "CWE-732",
        "owasp": "A05:2021",
        "iso27001": "A.5.18",
    }


def rule_view_all_profiles(s):
    rows = s.get("salesforce_view_all_profiles") or []
    if not rows:
        return None
    sample = ", ".join(r.get("name", "?") for r in rows[:6])
    extra = f" (+{len(rows)-6} more)" if len(rows) > 6 else ""
    return {
        "name": (f"{len(rows)} non-SysAdmin profile(s) grant "
                 "ViewAllData (read every record)"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "evidence": (f"Profiles: {sample}{extra}. ViewAllData bypasses "
                     "sharing rules — a user can read records they aren't "
                     "the owner / shared with."),
        "remediation": ("Replace blanket ViewAllData with object-specific "
                        "'View All' on the permission set tied to the role. "
                        "For analytics use Analytics-Snowflake reader perms, "
                        "not org-wide view."),
        "cwe": "CWE-863",
        "iso27001": "A.8.3",
    }


def rule_permset_overpriv(s):
    rows = s.get("salesforce_permset_overpriv") or []
    if not rows:
        return None
    sample = ", ".join((r.get("label") or r.get("name") or "?")
                       for r in rows[:6])
    extra = f" (+{len(rows)-6} more)" if len(rows) > 6 else ""
    return {
        "name": (f"{len(rows)} custom permission set(s) grant ModifyAllData"),
        "severity": "HIGH",
        "cvss": "8.0",
        "evidence": (f"Permission sets: {sample}{extra}. Permission sets are "
                     "easy to assign and forget — silent privilege escalation "
                     "path."),
        "remediation": ("Audit who has each of these permission sets assigned "
                        "(SetupAuditTrail + PermissionSetAssignment). Remove "
                        "the privilege from the permset (downgrade to object-"
                        "specific 'Modify All') and reassign with care."),
        "cwe": "CWE-269",
        "owasp": "A01:2021",
        "iso27001": "A.5.18",
    }


def rule_no_ip_restrictions(s):
    if s.get("salesforce_org_audit_creds_missing"):
        return None
    # We only know this if the query succeeded
    if "salesforce_login_ip_ranges" not in s:
        return None
    if (s.get("salesforce_login_ip_ranges") or 0) > 0:
        return None
    return {
        "name": "Salesforce org has NO login IP-range restrictions",
        "severity": "HIGH",
        "cvss": "7.5",
        "evidence": ("Query against LoginIp returned 0 ranges. Any user with "
                     "valid credentials + 2FA can log in from anywhere — no "
                     "corporate-network gate."),
        "remediation": ("In Setup > Network Access add the corporate egress "
                        "ranges. Then on each Profile set 'Login IP Ranges' "
                        "to the same. For SaaS-only orgs use Login Flows + "
                        "device trust instead. Re-audit after rollout."),
        "cwe": "CWE-1390",
        "owasp": "A07:2021",
        "iso27001": "A.8.5",
    }


def rule_positive(s):
    if s.get("salesforce_org_audit_creds_missing"): return None
    if s.get("salesforce_org_audit_domain_invalid"): return None
    if s.get("salesforce_org_audit_api_error"):     return None
    if (s.get("salesforce_org_audit_total") or 0) > 0: return None
    if not s.get("salesforce_total_profiles"):      return None
    return {
        "name": "Salesforce org posture clean across audited surface",
        "severity": "POSITIVE",
        "evidence": (f"{s.get('salesforce_total_profiles', 0)} profile(s), "
                     f"{s.get('salesforce_total_permsets', 0)} custom permset(s), "
                     f"{s.get('salesforce_login_ip_ranges', 0)} login-IP "
                     "range(s) — no over-privilege, IP gating in place."),
        "remediation": ("Re-audit before every production release. Add "
                        "session-policy enforcement + IP allow-list on the "
                        "Connected App used by this scanner itself."),
        "cwe": "N/A",
        "iso27001": "A.5.18",
    }


SALESFORCE_ORG_AUDIT_FINDING_RULES = [
    rule_creds_missing,
    rule_domain_invalid,
    rule_api_error,
    rule_god_mode_profiles,
    rule_api_modify_meta_profiles,
    rule_view_all_profiles,
    rule_permset_overpriv,
    rule_no_ip_restrictions,
    rule_positive,
]
