"""§29 SaaS Security Posture Management — 77 endpoints per 29_sspm.md."""
from tools._pack_common import make_advisory_router

T = [
    # §1 M365 Posture (15)
    ("m365_secure_score_audit", "M365 Secure Score audit.", "MEDIUM", "5.5"),
    ("m365_exchange_transport_rules", "Exchange transport rules audit.", "MEDIUM", "5.5"),
    ("m365_exchange_mailbox_forward", "Exchange mailbox auto-forward audit.", "HIGH", "7.5"),
    ("m365_sharepoint_external_share", "SharePoint external sharing audit.", "HIGH", "7.5"),
    ("m365_teams_external_audit", "Teams external access audit.", "HIGH", "7.5"),
    ("m365_dlp_audit", "DLP policy audit.", "MEDIUM", "5.5"),
    ("m365_atp_safe_links_audit", "ATP Safe Links audit.", "MEDIUM", "5.5"),
    ("m365_atp_safe_attachments_audit", "ATP Safe Attachments audit.", "MEDIUM", "5.5"),
    ("m365_audit_log_enabled", "Audit log enabled check.", "MEDIUM", "5.5"),
    ("m365_unified_audit_search", "Unified audit search.", "INFO", "0.0"),
    ("m365_inbox_rule_audit", "Inbox rule audit.", "MEDIUM", "5.5"),
    ("m365_oauth_consent_admin_only", "Admin-only OAuth consent.", "MEDIUM", "5.5"),
    ("m365_basic_auth_legacy", "Basic auth legacy.", "HIGH", "8.0"),
    ("m365_modern_auth_only", "Modern auth-only audit.", "MEDIUM", "5.5"),
    ("manual_m365_review", "Manual M365 review.", "INFO", "0.0"),
    # §2 Google Workspace (13)
    ("gws_2sv_enforcement", "2SV enforcement audit.", "HIGH", "7.5"),
    ("gws_advanced_protection", "Advanced Protection audit.", "MEDIUM", "5.5"),
    ("gws_external_sharing_drive", "Drive external sharing.", "HIGH", "7.5"),
    ("gws_gmail_forwarding_audit", "Gmail forwarding audit.", "HIGH", "7.5"),
    ("gws_app_access_audit", "App access audit.", "MEDIUM", "5.5"),
    ("gws_oauth_scope_audit", "OAuth scope audit.", "HIGH", "7.5"),
    ("gws_data_classification", "Data classification audit.", "MEDIUM", "5.5"),
    ("gws_password_policy", "Password policy audit.", "MEDIUM", "5.5"),
    ("gws_session_length", "Session length audit.", "MEDIUM", "5.5"),
    ("gws_third_party_app_audit", "3rd-party app audit.", "MEDIUM", "5.5"),
    ("gws_admin_log_audit", "Admin log audit.", "MEDIUM", "5.5"),
    ("gws_alert_center_audit", "Alert Center audit.", "MEDIUM", "5.5"),
    ("manual_gws_review", "Manual GWS review.", "INFO", "0.0"),
    # §3 Salesforce (9)
    ("sf_health_check_audit", "Salesforce Health Check.", "MEDIUM", "5.5"),
    ("sf_session_settings", "Session settings audit.", "MEDIUM", "5.5"),
    ("sf_login_history", "Login history audit.", "INFO", "0.0"),
    ("sf_permission_set_audit", "Permission set audit.", "MEDIUM", "5.5"),
    ("sf_profile_audit", "Profile audit.", "MEDIUM", "5.5"),
    ("sf_field_level_security", "Field-level security audit.", "MEDIUM", "5.5"),
    ("sf_org_wide_default_audit", "Org-wide default audit.", "MEDIUM", "5.5"),
    ("sf_api_access_audit", "API access audit.", "MEDIUM", "5.5"),
    ("manual_sf_review", "Manual SF review.", "INFO", "0.0"),
    # §4 Slack/Teams/Discord (9)
    ("slack_workspace_admin_audit", "Slack workspace admin audit.", "MEDIUM", "5.5"),
    ("slack_app_integration_audit", "Slack app integration audit.", "MEDIUM", "5.5"),
    ("slack_external_share_audit", "Slack external share audit.", "MEDIUM", "5.5"),
    ("teams_admin_audit", "Teams admin audit.", "MEDIUM", "5.5"),
    ("teams_app_policy_audit", "Teams app policy audit.", "MEDIUM", "5.5"),
    ("teams_external_access", "Teams external access.", "MEDIUM", "5.5"),
    ("discord_server_audit", "Discord server audit.", "MEDIUM", "5.5"),
    ("discord_bot_token_audit", "Discord bot token audit.", "HIGH", "7.5"),
    ("manual_chat_review", "Manual chat platform review.", "INFO", "0.0"),
    # §5 Atlassian (7)
    ("jira_user_perm_audit", "Jira user permission audit.", "MEDIUM", "5.5"),
    ("jira_project_role_audit", "Jira project role audit.", "MEDIUM", "5.5"),
    ("confluence_external_audit", "Confluence external sharing audit.", "MEDIUM", "5.5"),
    ("confluence_anonymous_access", "Confluence anonymous access.", "HIGH", "7.5"),
    ("atlassian_org_admin_audit", "Atlassian org admin audit.", "MEDIUM", "5.5"),
    ("atlassian_app_integration", "Atlassian app integration audit.", "MEDIUM", "5.5"),
    ("manual_atlassian_review", "Manual Atlassian review.", "INFO", "0.0"),
    # §6 GitHub/GitLab Org Settings (9)
    ("gh_org_2fa_enforce", "GitHub org 2FA enforce.", "HIGH", "7.5"),
    ("gh_org_member_visibility", "GitHub org member visibility.", "MEDIUM", "5.5"),
    ("gh_org_default_branch_protection", "Default branch protection.", "MEDIUM", "5.5"),
    ("gh_org_ip_allowlist", "Org IP allowlist audit.", "MEDIUM", "5.5"),
    ("gh_org_oauth_app_audit", "Org OAuth app audit.", "MEDIUM", "5.5"),
    ("gh_org_outside_collab", "Outside collaborator audit.", "MEDIUM", "5.5"),
    ("gh_org_secret_scanning", "Secret scanning enabled.", "MEDIUM", "5.5"),
    ("gh_org_dependabot_audit", "Dependabot audit.", "MEDIUM", "5.5"),
    ("manual_gh_org_review", "Manual GitHub org review.", "INFO", "0.0"),
    # §7 OAuth Connected Apps (8) ⭐
    ("oauth_app_inventory", "⭐ OAuth app inventory.", "MEDIUM", "5.5"),
    ("oauth_app_high_risk_scope", "⭐ High-risk scope audit.", "HIGH", "7.5"),
    ("oauth_app_inactive", "⭐ Inactive OAuth app.", "MEDIUM", "5.5"),
    ("oauth_app_unverified_publisher", "⭐ Unverified publisher.", "HIGH", "7.5"),
    ("oauth_app_consent_phish_block", "⭐ Consent phish block.", "MEDIUM", "5.5"),
    ("oauth_app_cross_saas_dataflow", "⭐ Cross-SaaS dataflow audit.", "MEDIUM", "5.5"),
    ("manual_oauth_app_review", "Manual OAuth app review.", "INFO", "0.0"),
    ("manual_oauth_app_chain", "Manual OAuth app chain.", "INFO", "0.0"),
    # §8 Cross-SaaS DLP (7) ⭐
    ("dlp_data_residency_audit", "⭐ Data residency audit.", "MEDIUM", "5.5"),
    ("dlp_export_audit", "⭐ Export audit.", "MEDIUM", "5.5"),
    ("dlp_share_link_audit", "⭐ Share link audit.", "MEDIUM", "5.5"),
    ("dlp_data_classification_consistency", "⭐ Classification consistency.", "MEDIUM", "5.5"),
    ("dlp_cross_app_signal_correlate", "⭐ Cross-app signal correlate.", "MEDIUM", "5.5"),
    ("manual_dlp_review", "Manual DLP review.", "INFO", "0.0"),
    ("manual_dlp_chain", "Manual DLP chain.", "INFO", "0.0"),
]

router = make_advisory_router("sspm", T,
    playbook_ref="See module_playbooks/29_sspm.md.")


def register(app):
    app.include_router(router)
