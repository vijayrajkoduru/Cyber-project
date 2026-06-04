"""github_org_audit - findings rules (CIS GitHub + SLSA + CSA SaaS).

Mapping:
  CWE-308   = single-factor authentication
  CWE-1390  = weak authentication
  CWE-672   = use of expired / dormant resource (dormant admin)
  CWE-269   = improper privilege management
  CWE-732   = incorrect permission assignment (unprotected default branch)
  CWE-693   = protection mechanism failure (SSO not enforced)
  ISO 27001 A.5.17 = identity management
  ISO 27001 A.5.18 = privileged access rights
  ISO 27001 A.8.5  = secure authentication
  ISO 27001 A.8.32 = change management (branch protection)
"""


def rule_creds_missing(s):
    if not s.get("github_org_audit_creds_missing"):
        return None
    return {
        "name": "GitHub org audit skipped — credentials required",
        "severity": "INFO",
        "evidence": ("This probe needs options.github_token (classic ghp_ or "
                     "fine-grained github_pat_) AND options.github_org "
                     "(org login). Classic PAT scopes: read:org + admin:org "
                     "+ repo. Fine-grained: Org Members:read, Administration:"
                     "read; Repo Administration:read, Contents:read."),
        "remediation": ("In GitHub Settings -> Developer settings -> Personal "
                        "access tokens, mint a token scoped to the audited "
                        "org. Re-run with options.github_token + .github_org."),
        "cwe": "CWE-1006",
        "iso27001": "A.5.23",
    }


def rule_auth_error(s):
    if not s.get("github_org_audit_auth_error"):
        return None
    return {
        "name": "GitHub REST API rejected the PAT",
        "severity": "INFO",
        "evidence": str(s.get("github_org_audit_auth_error")),
        "remediation": ("Confirm PAT not expired + scopes include read:org + "
                        "admin:org. For SSO-enforced orgs you must Authorize "
                        "the PAT for SSO at github.com/settings/tokens."),
        "cwe": "CWE-287",
        "iso27001": "A.5.17",
    }


def rule_not_found(s):
    if not s.get("github_org_audit_not_found"):
        return None
    return {
        "name": "GitHub organisation not found or token has no access",
        "severity": "INFO",
        "evidence": "GET /orgs/{org} returned 404.",
        "remediation": ("Verify options.github_org is the correct login (case "
                        "insensitive). Confirm the PAT owner is a member of "
                        "the org and has authorized the token for SSO if "
                        "enforced."),
        "cwe": "CWE-1006",
        "iso27001": "A.5.17",
    }


def rule_api_error(s):
    if not s.get("github_org_audit_api_error"):
        return None
    return {
        "name": "GitHub REST API error during org audit",
        "severity": "INFO",
        "evidence": str(s.get("github_org_audit_api_error"))[:600],
        "remediation": ("Likely rate-limit (5000 req/h per user). Wait an "
                        "hour and retry, or upgrade the PAT to a "
                        "GitHub App installation token (15000 req/h)."),
        "cwe": "CWE-755",
        "iso27001": "A.5.23",
    }


def rule_org_no_2fa_required(s):
    if s.get("github_org_audit_creds_missing"): return None
    if s.get("github_org_audit_not_found"):     return None
    if s.get("github_org_audit_auth_error"):    return None
    if "github_org_two_factor_required" not in s: return None
    if s.get("github_org_two_factor_required"):  return None
    return {
        "name": "GitHub organisation does NOT enforce 2FA on members",
        "severity": "HIGH",
        "cvss": "8.1",
        "evidence": (f"Org '{s.get('github_org_login','?')}' "
                     "two_factor_requirement_enabled = false. Any member can "
                     "log in with password alone — account takeover via "
                     "credential stuffing immediately escalates to "
                     "source-code access."),
        "remediation": ("In Organisation settings -> Authentication "
                        "security -> 'Require two-factor authentication for "
                        "everyone in this organization'. Members without 2FA "
                        "are auto-removed; communicate the deadline "
                        "7+ days in advance."),
        "cwe": "CWE-308",
        "owasp": "A07:2021",
        "iso27001": "A.8.5",
    }


def rule_members_no_2fa(s):
    rows = s.get("github_org_members_no_2fa") or []
    if not rows:
        return None
    sample = ", ".join((r.get("login") or "?") for r in rows[:8])
    extra = f" (+{len(rows)-8} more)" if len(rows) > 8 else ""
    return {
        "name": f"{len(rows)} org member(s) without 2FA enabled",
        "severity": "HIGH",
        "cvss": "7.5",
        "evidence": f"Members missing 2FA: {sample}{extra}",
        "remediation": ("Enforce org-wide 2FA (see previous finding) — these "
                        "accounts will be removed until 2FA is added. As a "
                        "lighter touch, email each user with a 14-day "
                        "deadline and the GitHub TOTP / WebAuthn setup link."),
        "cwe": "CWE-308",
        "owasp": "A07:2021",
        "iso27001": "A.8.5",
    }


def rule_public_no_protection(s):
    rows = s.get("github_org_public_no_protection") or []
    if not rows:
        return None
    sample = ", ".join((r.get("repo") or "?") for r in rows[:6])
    extra = f" (+{len(rows)-6} more)" if len(rows) > 6 else ""
    return {
        "name": (f"{len(rows)} public repo(s) without branch protection on "
                 "default branch"),
        "severity": "HIGH",
        "cvss": "7.2",
        "evidence": (f"Public repos missing protection: {sample}{extra}. "
                     "Anyone with write access can force-push, delete, or "
                     "merge without review — supply-chain attack path."),
        "remediation": ("For each repo enable rules: required reviews >= 1, "
                        "required status checks (CI green), block force-push, "
                        "block branch delete, require signed commits. Apply "
                        "via Organisation -> Rulesets so new repos inherit."),
        "cwe": "CWE-732",
        "owasp": "A05:2021",
        "iso27001": "A.8.32",
    }


def rule_admins_dormant(s):
    rows = s.get("github_org_admins_dormant") or []
    if not rows:
        return None
    sample = ", ".join(f"{r.get('login','?')} "
                       f"(last: {(r.get('last_activity') or 'never')[:10]})"
                       for r in rows[:6])
    extra = f" (+{len(rows)-6} more)" if len(rows) > 6 else ""
    return {
        "name": f"{len(rows)} org admin(s) dormant 180+ days",
        "severity": "MEDIUM",
        "cvss": "6.0",
        "evidence": f"Dormant admins: {sample}{extra}",
        "remediation": ("Audit with each admin's manager. If admin rights are "
                        "no longer required, downgrade to Member or remove. "
                        "Every dormant admin is a higher-value compromise "
                        "target with no detection signal."),
        "cwe": "CWE-672",
        "iso27001": "A.5.18",
    }


def rule_sso_not_enforced(s):
    if not s.get("github_org_sso_available"):
        return None
    if not s.get("github_org_sso_unknown_enforcement"):
        return None
    return {
        "name": "GitHub SAML SSO present — enforcement could not be verified via REST",
        "severity": "MEDIUM",
        "cvss": "5.0",
        "evidence": ("REST exposes SSO presence but not the enforced-flag. "
                     "If SSO is configured but not enforced, members can "
                     "still log in with username+password+2FA, bypassing IdP "
                     "conditional access policies."),
        "remediation": ("In Organisation -> Authentication security -> SAML "
                        "single sign-on, toggle 'Require SAML SSO "
                        "authentication for all members'. Re-issue PATs and "
                        "SSH keys so they require SSO authorisation."),
        "cwe": "CWE-693",
        "iso27001": "A.8.5",
    }


def rule_positive(s):
    if s.get("github_org_audit_creds_missing"): return None
    if s.get("github_org_audit_auth_error"):    return None
    if s.get("github_org_audit_not_found"):     return None
    if (s.get("github_org_audit_total") or 0) > 0: return None
    if not s.get("github_org_repos_scanned"):   return None
    return {
        "name": "GitHub organisation posture clean across audited surface",
        "severity": "POSITIVE",
        "evidence": (f"Org '{s.get('github_org_login','?')}' — "
                     f"{s.get('github_org_repos_scanned', 0)} repo(s), "
                     f"{s.get('github_org_admins_total', 0)} admin(s); 2FA "
                     "required org-wide, every public repo branch-protected, "
                     "no dormant admins."),
        "remediation": ("Re-audit monthly + before every major release. "
                        "Schedule via /api/sspm/run_all on cron."),
        "cwe": "N/A",
        "iso27001": "A.5.17",
    }


GITHUB_ORG_AUDIT_FINDING_RULES = [
    rule_creds_missing,
    rule_auth_error,
    rule_not_found,
    rule_api_error,
    rule_org_no_2fa_required,
    rule_members_no_2fa,
    rule_public_no_protection,
    rule_admins_dormant,
    rule_sso_not_enforced,
    rule_positive,
]
