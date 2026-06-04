"""slack_workspace_audit - findings rules (CSA SaaS + Slack Enterprise hardening).

Mapping:
  CWE-308   = single-factor authentication
  CWE-269   = improper privilege management (OAuth app over-scope)
  CWE-200   = exposure to unauthorized actor (external channel sharing)
  CWE-1392  = use of default credentials/config (default retention = DLP gap)
  ISO 27001 A.5.15 = access control
  ISO 27001 A.5.17 = identity management
  ISO 27001 A.5.34 = privacy + PII protection
  ISO 27001 A.8.5  = secure authentication
"""


def rule_creds_missing(s):
    if not s.get("slack_workspace_audit_creds_missing"):
        return None
    return {
        "name": "Slack workspace audit skipped — credentials required",
        "severity": "INFO",
        "evidence": ("This probe needs options.slack_bot_token (xoxb-...). "
                     "Required scopes: users:read, channels:read, groups:read, "
                     "team:read. For full coverage also grant admin.users:read, "
                     "admin.conversations:read, admin.teams:read (Enterprise "
                     "Grid only)."),
        "remediation": ("Create a Slack app, install to the workspace, copy "
                        "the Bot User OAuth Token (xoxb-...) and submit as "
                        "options.slack_bot_token. Use admin scopes only on "
                        "the dedicated audit app — keep production apps "
                        "least-priv."),
        "cwe": "CWE-1006",
        "iso27001": "A.5.23",
    }


def rule_token_invalid(s):
    if not s.get("slack_workspace_audit_token_invalid"):
        return None
    return {
        "name": "options.slack_bot_token format invalid (not xoxb-...)",
        "severity": "INFO",
        "evidence": ("Probe expects a Slack OAuth token starting with xox[abprs]-. "
                     "User OAuth (xoxp) and app-level (xapp) tokens are also "
                     "accepted; legacy xoxs / xoxt strings are not."),
        "remediation": ("Re-issue the token from the Slack app's 'OAuth & "
                        "Permissions' page. Copy the Bot User OAuth Token "
                        "value verbatim."),
        "cwe": "CWE-1390",
        "iso27001": "A.5.23",
    }


def rule_auth_error(s):
    if not s.get("slack_workspace_audit_auth_error"):
        return None
    return {
        "name": "Slack auth.test rejected the bot token",
        "severity": "INFO",
        "evidence": str(s.get("slack_workspace_audit_auth_error")),
        "remediation": ("Common errors: invalid_auth (token revoked), "
                        "account_inactive (workspace owner disabled the app), "
                        "missing_scope (re-install with required scopes), "
                        "token_revoked (rotate)."),
        "cwe": "CWE-287",
        "iso27001": "A.5.17",
    }


def rule_users_no_2fa(s):
    rows = s.get("slack_users_no_2fa") or []
    if not rows:
        return None
    admins_no_2fa = [r for r in rows if r.get("is_admin") or r.get("is_owner")]
    sample = ", ".join((r.get("name") or r.get("id") or "?") for r in rows[:6])
    out = [{
        "name": f"{len(rows)} Slack member(s) without 2FA enabled",
        "severity": "HIGH" if admins_no_2fa else "MEDIUM",
        "cvss": "7.5" if admins_no_2fa else "5.4",
        "evidence": (f"Members missing 2FA: {sample}"
                     + (f" (+{len(rows)-6} more)" if len(rows) > 6 else "")
                     + (f". {len(admins_no_2fa)} of these are admins/owners — "
                        "this is a workspace-takeover path."
                        if admins_no_2fa else "")),
        "remediation": ("In Settings & Administration -> Workspace settings "
                        "-> Authentication, set 'Two-factor authentication' "
                        "to 'Required for all members'. Communicate the "
                        "deadline 7 days in advance to avoid lockouts."),
        "cwe": "CWE-308",
        "owasp": "A07:2021",
        "iso27001": "A.8.5",
    }]
    return out


def rule_public_external_channels(s):
    rows = s.get("slack_public_external_channels") or []
    if not rows:
        return None
    sample = ", ".join((r.get("name") or r.get("id") or "?") for r in rows[:6])
    return {
        "name": (f"{len(rows)} channel(s) shared with EXTERNAL workspaces"),
        "severity": "MEDIUM",
        "cvss": "6.5",
        "evidence": (f"Externally-shared channels: {sample}"
                     + (f" (+{len(rows)-6} more)" if len(rows) > 6 else "")
                     + ". Members of partner workspaces can read messages "
                       "and download files."),
        "remediation": ("In Settings & Administration -> Manage Slack "
                        "Connect, review each externally-shared channel. "
                        "Disable file-sharing on external channels, restrict "
                        "membership to a named DL, and enable DLP policies "
                        "for outbound files."),
        "cwe": "CWE-200",
        "owasp": "A01:2021",
        "iso27001": "A.5.34",
    }


def rule_risky_oauth_apps(s):
    rows = s.get("slack_risky_oauth_apps") or []
    if not rows:
        return None
    sample = ", ".join(f"{r.get('name','?')} ({','.join(r.get('risky_scopes',[])[:2])})"
                       for r in rows[:5])
    extra = f" (+{len(rows)-5} more)" if len(rows) > 5 else ""
    return {
        "name": (f"{len(rows)} OAuth app(s) installed with elevated scopes"),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "evidence": (f"Apps with risky scopes: {sample}{extra}. "
                     "Elevated scopes (admin.*, *:write, files:write) make "
                     "the app a high-value compromise target."),
        "remediation": ("Audit each app's necessity in Settings & "
                        "Administration -> Manage apps -> 'Approved apps'. "
                        "Revoke unused. For required apps, restrict to a "
                        "single channel + rotate their tokens quarterly. "
                        "Watch for DUCKTAIL-style malicious consent grants."),
        "cwe": "CWE-269",
        "owasp": "A01:2021",
        "iso27001": "A.5.15",
    }


def rule_channels_default_retention(s):
    rows = s.get("slack_channels_default_retention") or []
    if not rows:
        return None
    sample = ", ".join((r.get("name") or r.get("id") or "?") for r in rows[:6])
    return {
        "name": (f"{len(rows)} channel(s) on default (unlimited) file retention"),
        "severity": "LOW",
        "cvss": "4.0",
        "evidence": (f"Channels: {sample}"
                     + (f" (+{len(rows)-6} more)" if len(rows) > 6 else "")
                     + ". Unlimited retention = larger blast radius if a "
                       "single user account is compromised."),
        "remediation": ("Set workspace-default file retention to 90 days "
                        "(or your DLP policy). Override per-channel for "
                        "compliance-archived rooms only. Enable Slack "
                        "Discovery API export for the regulated channels."),
        "cwe": "CWE-1392",
        "iso27001": "A.5.34",
    }


def rule_positive(s):
    if s.get("slack_workspace_audit_creds_missing"): return None
    if s.get("slack_workspace_audit_auth_error"):    return None
    if (s.get("slack_workspace_audit_total") or 0) > 0: return None
    if not s.get("slack_total_users"):               return None
    return {
        "name": "Slack workspace posture clean across audited surface",
        "severity": "POSITIVE",
        "evidence": (f"Workspace '{s.get('slack_team_name','?')}' — "
                     f"{s.get('slack_total_users', 0)} member(s), "
                     f"{s.get('slack_total_channels', 0)} channel(s), "
                     f"{s.get('slack_total_apps', 0)} OAuth app(s). 100% "
                     "2FA, no external shares, no risky scopes, no default-"
                     "retention DLP gaps."),
        "remediation": ("Re-audit monthly — OAuth apps + external channels "
                        "drift quickly. Schedule via /api/sspm/run_all on "
                        "cron."),
        "cwe": "N/A",
        "iso27001": "A.5.17",
    }


SLACK_WORKSPACE_AUDIT_FINDING_RULES = [
    rule_creds_missing,
    rule_token_invalid,
    rule_auth_error,
    rule_users_no_2fa,
    rule_public_external_channels,
    rule_risky_oauth_apps,
    rule_channels_default_retention,
    rule_positive,
]
