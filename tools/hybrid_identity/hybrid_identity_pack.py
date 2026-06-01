"""§28 Hybrid Identity (Entra ID / Azure AD) — 74 endpoints per 28_hybrid_identity.md.

VL-FORGE 2026-05-30: 3 live probes for unauthenticated Entra ID
reconnaissance via Microsoft's public endpoints (tenant ID lookup,
domain validation/federation, OpenID config discovery).
"""
import urllib.request, urllib.error, json
from tools._pack_common import make_advisory_router, _adv_response
from tools._shared import wrap_finding


def _host(t):
    return t.split("://", 1)[-1].split("/")[0].split(":")[0].strip().lower() or t

def _http_get(url, timeout=4):
    try:
        r = urllib.request.Request(url, headers={"User-Agent":"VulnusLab/2.0"})
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(4096).decode("utf-8", errors="ignore")
        except Exception: return e.code, ""
    except Exception:
        return 0, ""

def _build(tool, target, findings, tested, summary, raw=None):
    sev_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0,"POSITIVE":0}
    top = "INFO"
    for f in findings:
        if sev_order.get(f.get("severity","INFO"),0) > sev_order.get(top,0):
            top = f.get("severity","INFO")
    return {"tool":tool,"target":target,"scan_time":0,
            "vulnerable": top in ("CRITICAL","HIGH","MEDIUM"),
            "severity": top, "findings": findings,
            "tests_performed": tested, "tests_summary": summary, "raw_data": raw or {}}


def _probe_tenant_id_lookup(target, req):
    """Resolve tenant ID via Microsoft OpenID config endpoint (unauthenticated)."""
    domain = _host(target)
    url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
    code, body = _http_get(url, timeout=5)
    findings = []; raw = {}
    if code == 200 and body.strip().startswith("{"):
        try:
            cfg = json.loads(body)
            raw = cfg
            issuer = cfg.get("issuer", "")
            tenant_id = issuer.split("/")[3] if issuer.count("/") >= 3 else "unknown"
            findings.append(wrap_finding(
                f"Entra ID tenant exists — tenant ID: {tenant_id}",
                "INFO", cvss="0.0", cwe="CWE-200",
                remediation="Tenant ID is public by design; ensure user enum is restricted.",
                evidence_marker=f"Issuer: {issuer}"))
        except Exception:
            findings.append(wrap_finding(
                "OpenID config returned but failed to parse",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Manual review.", evidence_marker=body[:120]))
    elif code == 400:
        findings.append(wrap_finding(
            f"No Entra ID tenant for domain '{domain}' (Microsoft returned 400)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify domain ownership.",
            evidence_marker=f"GET {url} → 400"))
    else:
        findings.append(wrap_finding(
            f"Entra ID lookup inconclusive (status {code})",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry.",
            evidence_marker=f"GET {url} → {code}"))
    return _build("entra_tenant_id_lookup", target, findings, 1,
                   "Entra ID tenant discovery via OpenID config", raw)


def _probe_domain_validation(target, req):
    """Federation type lookup via getuserrealm endpoint (unauthenticated)."""
    domain = _host(target)
    url = f"https://login.microsoftonline.com/getuserrealm.srf?login=admin@{domain}&xml=1"
    code, body = _http_get(url, timeout=5)
    findings = []
    if code == 200 and "<NameSpaceType>" in body:
        ns_type = body.split("<NameSpaceType>", 1)[1].split("</")[0]
        sev = "INFO"; cvss = "0.0"
        if ns_type == "Federated":
            findings.append(wrap_finding(
                f"Domain '{domain}' is FEDERATED (likely ADFS/PingFederate/Okta) — federation cert theft risk",
                "MEDIUM", cvss="5.0", cwe="CWE-287",
                remediation="Audit federation provider security; consider migrating to cloud auth.",
                evidence_marker=f"NameSpaceType: {ns_type}"))
        elif ns_type == "Managed":
            findings.append(wrap_finding(
                f"Domain '{domain}' is MANAGED (cloud auth) — good posture",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue managed posture; enable security defaults + Conditional Access.",
                evidence_marker=f"NameSpaceType: {ns_type}"))
        else:
            findings.append(wrap_finding(
                f"Domain namespace type: {ns_type}",
                sev, cvss=cvss, cwe="CWE-200",
                remediation="Review namespace configuration.",
                evidence_marker=f"NameSpaceType: {ns_type}"))
    else:
        findings.append(wrap_finding(
            f"Domain '{domain}' not registered with Entra ID",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify domain in tenant config.",
            evidence_marker=f"getuserrealm status: {code}"))
    return _build("entra_domain_validation", target, findings, 1,
                   "Entra ID federation type lookup via getuserrealm")


def _probe_app_registration_enum(target, req):
    """Check for app registration metadata leakage via well-known paths."""
    host = _host(target)
    paths = [
        f"https://{host}/.well-known/microsoft-identity-association.json",
        f"https://{host}/.well-known/openid-configuration",
    ]
    findings = []
    for url in paths:
        code, body = _http_get(url, timeout=3)
        if code == 200 and body.strip().startswith("{"):
            findings.append(wrap_finding(
                f"Identity association metadata exposed at {url}",
                "INFO", cvss="0.0", cwe="CWE-200",
                remediation="App association files are typically public by design; verify content.",
                evidence_marker=f"GET {url} → 200; {len(body)} bytes"))
    if not findings:
        findings.append(wrap_finding(
            "No identity association metadata at standard paths",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue.",
            evidence_marker=f"Tested {len(paths)} paths"))
    return _build("entra_app_registration_enum", target, findings, len(paths),
                   "Entra ID app registration metadata leak check")


PROBES = {
    "entra_tenant_id_lookup":      _probe_tenant_id_lookup,
    "entra_domain_validation":     _probe_domain_validation,
    "entra_app_registration_enum": _probe_app_registration_enum,
}

T = [
    # §1 Entra ID Recon (13)
    ("entra_user_enum_aadinternals", "AADInternals user enum.", "MEDIUM", "5.5"),
    ("entra_group_enum_msgraph", "MS Graph group enum.", "INFO", "0.0"),
    ("entra_app_registration_enum", "App registration enum.", "MEDIUM", "5.5"),
    ("entra_sp_enum", "Service principal enum.", "INFO", "0.0"),
    ("entra_tenant_id_lookup", "Tenant ID lookup.", "INFO", "0.0"),
    ("entra_domain_validation", "Domain validation check.", "INFO", "0.0"),
    ("entra_role_member_enum", "Role member enum.", "MEDIUM", "5.5"),
    ("entra_application_consent_audit", "Application consent audit.", "MEDIUM", "5.5"),
    ("entra_admin_unit_audit", "Administrative unit audit.", "MEDIUM", "5.5"),
    ("entra_b2b_guest_audit", "B2B guest audit.", "MEDIUM", "5.5"),
    ("entra_b2c_tenant_audit", "B2C tenant audit.", "MEDIUM", "5.5"),
    ("entra_dynamic_group_audit", "Dynamic group audit.", "MEDIUM", "5.5"),
    ("manual_entra_recon", "Manual Entra recon.", "INFO", "0.0"),
    # §2 Hybrid AD Connect Attacks (10)
    ("aadconnect_msoldap_password_recover", "AADConnect MSOL password recover.", "CRITICAL", "9.0"),
    ("aadconnect_pta_agent_abuse", "PTA agent abuse.", "HIGH", "8.0"),
    ("aadconnect_seamless_sso_abuse", "Seamless SSO abuse.", "HIGH", "8.0"),
    ("aadconnect_pwh_sync_audit", "Password hash sync audit.", "HIGH", "8.0"),
    ("aadconnect_federation_audit", "Federation audit.", "HIGH", "7.5"),
    ("aadconnect_writeback_audit", "Writeback audit.", "HIGH", "7.5"),
    ("aadconnect_provisioning_log_audit", "Provisioning log audit.", "MEDIUM", "5.5"),
    ("hybrid_join_audit", "Hybrid AD join audit.", "MEDIUM", "5.5"),
    ("psh_hybrid_admin_audit", "Hybrid admin audit.", "HIGH", "7.5"),
    ("manual_aadconnect_review", "Manual AADConnect review.", "INFO", "0.0"),
    # §3 Conditional Access Bypass (7)
    ("ca_legacy_protocol_bypass", "CA legacy protocol bypass.", "HIGH", "8.0"),
    ("ca_named_location_bypass", "CA named location bypass.", "HIGH", "7.5"),
    ("ca_device_compliance_bypass", "CA device compliance bypass.", "HIGH", "7.5"),
    ("ca_trusted_named_ip", "CA trusted IP misconfig.", "HIGH", "7.5"),
    ("ca_mfa_token_replay", "CA MFA token replay.", "HIGH", "8.0"),
    ("ca_app_password_audit", "App password audit.", "HIGH", "7.5"),
    ("manual_ca_review", "Manual CA review.", "INFO", "0.0"),
    # §4 Token Theft / Replay (8)
    ("token_refresh_steal_audit", "Refresh token steal audit.", "HIGH", "8.0"),
    ("token_pra_audit", "PRA (Persistent Refresh Auth) audit.", "HIGH", "7.5"),
    ("token_clipboard_steal", "Token clipboard steal.", "HIGH", "7.5"),
    ("token_aitm_steal", "Token AiTM steal.", "CRITICAL", "9.0"),
    ("token_dump_via_token_finder", "Token dump (TokenFinder).", "HIGH", "7.5"),
    ("token_replay_cross_tenant", "Cross-tenant token replay.", "HIGH", "8.0"),
    ("token_ipchange_audit", "Token IP-change audit.", "MEDIUM", "5.5"),
    ("manual_token_chain", "Manual token chain.", "INFO", "0.0"),
    # §5 Service Principal / App Reg (11)
    ("sp_credential_dump", "SP credential dump.", "HIGH", "8.0"),
    ("sp_secret_in_keyvault_audit", "SP secret in KeyVault audit.", "MEDIUM", "5.5"),
    ("sp_owner_audit", "SP owner audit.", "MEDIUM", "5.5"),
    ("sp_app_role_assignment", "App role assignment audit.", "HIGH", "7.0"),
    ("sp_overpermissive_app_perm", "Overpermissive app permissions.", "HIGH", "8.0"),
    ("sp_consent_grant_audit", "Consent grant audit.", "HIGH", "7.5"),
    ("sp_implicit_grant_audit", "Implicit grant audit.", "HIGH", "7.5"),
    ("sp_redirect_uri_audit", "SP redirect URI audit.", "HIGH", "7.5"),
    ("sp_certificate_audit", "SP certificate audit.", "MEDIUM", "5.5"),
    ("sp_managed_identity_audit", "Managed identity audit.", "MEDIUM", "5.5"),
    ("manual_sp_review", "Manual SP review.", "INFO", "0.0"),
    # §6 Cross-Tenant Attacks (7)
    ("ct_b2b_guest_abuse", "Cross-tenant B2B guest abuse.", "HIGH", "8.0"),
    ("ct_cross_tenant_access_settings", "Cross-tenant access settings audit.", "HIGH", "7.5"),
    ("ct_sync_attack", "Cross-tenant sync attack.", "HIGH", "8.0"),
    ("ct_msdt_phishing", "MSDT consent phishing.", "HIGH", "8.0"),
    ("ct_admin_consent_workflow", "Admin consent workflow audit.", "MEDIUM", "5.5"),
    ("ct_external_collab_audit", "External collab audit.", "MEDIUM", "5.5"),
    ("manual_cross_tenant_chain", "Manual cross-tenant chain.", "INFO", "0.0"),
    # §7 M365 Privesc (10)
    ("m365_eligible_role_activation", "Eligible role activation audit.", "MEDIUM", "5.5"),
    ("m365_global_admin_creep", "Global Admin role creep.", "HIGH", "8.0"),
    ("m365_partner_relationship_audit", "Partner relationship audit.", "MEDIUM", "5.5"),
    ("m365_exchange_admin_creep", "Exchange Admin creep.", "MEDIUM", "5.5"),
    ("m365_sharepoint_admin_creep", "SharePoint Admin creep.", "MEDIUM", "5.5"),
    ("m365_teams_admin_creep", "Teams Admin creep.", "MEDIUM", "5.5"),
    ("m365_directory_writer_audit", "Directory Writer audit.", "HIGH", "8.0"),
    ("m365_application_admin", "Application Admin audit.", "HIGH", "8.0"),
    ("m365_cloud_app_admin", "Cloud App Admin audit.", "HIGH", "8.0"),
    ("manual_m365_review", "Manual M365 review.", "INFO", "0.0"),
    # §8 Modern CVE / TTPs (8)
    ("entra_cve_token_signing", "Entra token signing CVE audit.", "HIGH", "8.0"),
    ("entra_cve_seamless_sso_2024", "Seamless SSO 2024 CVE.", "HIGH", "7.5"),
    ("entra_storm_0558_audit", "Storm-0558 token signing audit.", "HIGH", "8.0"),
    ("entra_msa_audit", "MSA consumer key audit.", "HIGH", "7.5"),
    ("entra_signin_log_anomaly", "Sign-in log anomaly detection.", "MEDIUM", "5.5"),
    ("entra_authentication_methods_v2", "Authentication Methods V2 audit.", "MEDIUM", "5.5"),
    ("entra_ngc_key_audit", "NGC key audit.", "MEDIUM", "5.5"),
    ("manual_modern_entra_chain", "Manual modern Entra chain.", "INFO", "0.0"),
]

router = make_advisory_router("hybrid_identity", T,
    playbook_ref="See module_playbooks/28_hybrid_identity.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
