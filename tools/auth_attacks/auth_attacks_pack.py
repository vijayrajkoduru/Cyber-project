"""§17 Auth Attacks — 74 endpoints under /api/auth_attacks/<tool>.

MITRE ATT&CK TA0006 Credential Access. Mix of detectable patterns + advisories.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding

router = APIRouter()


def _adv(tool, target, title, *, sev="MEDIUM", cvss="5.0", cwe="CWE-287",
         remediation="See module_playbooks/17_auth_attacks.md.",
         evidence="Advisory — detect against IdP/SIEM logs."):
    return {"tool":tool,"target":target,"scan_time":0,
            "vulnerable": sev in ("CRITICAL","HIGH","MEDIUM"),
            "severity": sev,
            "findings":[wrap_finding(title, sev, cvss=cvss, cwe=cwe, owasp="A07:2021",
                remediation=remediation, evidence_marker=evidence)],
            "tests_performed":1, "tests_summary":title[:80], "raw_data":{}}


TECHNIQUES = [
    # §1 Pass-the-Hash / Pass-the-Ticket (10)
    ("pth_impacket", "PtH via impacket -hashes.", "HIGH", "7.5"),
    ("pth_crackmapexec", "PtH via crackmapexec/NetExec.", "HIGH", "7.5"),
    ("pth_evil_winrm", "PtH via evil-winrm.", "HIGH", "7.5"),
    ("ptt_rubeus_ptt", "Pass-the-Ticket via Rubeus ptt.", "HIGH", "8.0"),
    ("ptt_mimikatz", "Pass-the-Ticket via mimikatz.", "HIGH", "8.0"),
    ("overpass_the_hash_rubeus", "Overpass-the-Hash (Rubeus asktgt + ptt).", "HIGH", "8.0"),
    ("pass_the_cert", "⭐ Pass-the-Cert (cert-based auth).", "HIGH", "8.0"),
    ("pass_the_cookie", "⭐ Pass-the-Cookie (browser session).", "HIGH", "8.0"),
    ("pass_the_token_oidc", "⭐ Pass-the-Token (cloud OIDC).", "HIGH", "8.0"),
    ("manual_ptx_chain", "Manual creative PtX chain (analyst).", "INFO", "0.0"),

    # §2 MFA Bypass (12)
    ("evilginx2_aitm", "⭐ EvilGinx2 AiTM phishing (session steal).", "CRITICAL", "9.0"),
    ("modlishka_aitm", "⭐ Modlishka reverse-proxy phishing.", "CRITICAL", "9.0"),
    ("bitb_browser_in_browser", "⭐ Browser-in-the-Browser (BitB).", "HIGH", "8.0"),
    ("mfa_fatigue_push_bomb", "⭐ MFA fatigue / push bombing (manual).", "MEDIUM", "5.5"),
    ("sms_otp_sim_swap_manual", "SMS-OTP SIM swap (manual).", "INFO", "0.0"),
    ("sms_otp_intercept_read_sms", "SMS-OTP intercept via READ_SMS perm.", "HIGH", "7.5"),
    ("push_notification_spam", "Push notification spam.", "MEDIUM", "5.0"),
    ("oauth_device_code_phish", "⭐ OAuth device-code phishing.", "HIGH", "8.0"),
    ("recovery_flow_weakness", "⭐ Recovery flow weakness.", "HIGH", "7.5"),
    ("backup_code_abuse", "Backup-code abuse.", "MEDIUM", "5.5"),
    ("manual_mfa_bypass_chain", "Manual MFA-bypass chain.", "INFO", "0.0"),
    ("aitm_cookie_steal", "⭐ Adversary-in-the-Middle cookie steal.", "CRITICAL", "9.0"),

    # §3 OAuth / OIDC Attacks (14)
    ("oauth_redirect_uri_hijack", "OAuth redirect_uri hijack.", "HIGH", "7.5"),
    ("oauth_state_csrf", "OAuth state CSRF.", "HIGH", "7.0"),
    ("oauth_pkce_missing", "⭐ OAuth PKCE missing (RFC 7636).", "MEDIUM", "5.5"),
    ("implicit_flow_abuse", "Implicit flow abuse (deprecated).", "MEDIUM", "5.5"),
    ("client_secret_leakage", "client_secret leakage.", "HIGH", "7.5"),
    ("refresh_token_rotation_absent", "Refresh token rotation absence.", "MEDIUM", "5.5"),
    ("oidc_nonce_missing", "⭐ OIDC nonce validation missing.", "MEDIUM", "5.5"),
    ("oidc_userinfo_abuse", "⭐ OIDC userinfo abuse.", "HIGH", "7.0"),
    ("ms_graph_consent_phishing", "OAuth consent phishing (Microsoft Graph).", "HIGH", "7.5"),
    ("oauth_device_code_phish_2", "⭐ OAuth device-code phishing (dup of §2#8).", "HIGH", "7.5"),
    ("apple_google_one_tap_csrf", "⭐ Apple Sign In / Google One Tap CSRF.", "MEDIUM", "5.5"),
    ("oauth_introspection_abuse", "⭐ OAuth introspection endpoint abuse.", "MEDIUM", "5.5"),
    ("manual_oauth_audit", "Manual OAuth flow audit (analyst).", "INFO", "0.0"),
    ("manual_creative_oauth_chain", "Manual creative OAuth chain.", "INFO", "0.0"),

    # §4 SAML / Federation Attacks (8)
    ("saml_xsw", "SAML XML Signature Wrapping (XSW).", "HIGH", "8.0"),
    ("samlraider_auto_tests", "SAMLRaider automated tests.", "HIGH", "7.5"),
    ("saml_golden_ticket_adfs", "SAML Golden Ticket (ADFS cert theft).", "CRITICAL", "9.5"),
    ("saml_response_replay", "SAML response replay.", "HIGH", "7.5"),
    ("saml_jwt_bridge_confusion", "⭐ SAML 2.0 + JWT bridge confusion.", "HIGH", "7.5"),
    ("saml_assertion_tamper", "SAML assertion tamper.", "HIGH", "7.5"),
    ("samlter_burp_editor", "SAMLter / Burp SAML editor.", "MEDIUM", "5.5"),
    ("manual_saml_chain", "Manual creative SAML chain.", "INFO", "0.0"),

    # §5 JWT Attacks (10)
    ("jwt_alg_none", "JWT alg=none confusion.", "CRITICAL", "9.0"),
    ("jwt_hs256_weak_crack", "JWT HS256 weak-secret crack.", "HIGH", "8.0"),
    ("jwt_signature_strip", "JWT signature stripping.", "CRITICAL", "9.0"),
    ("jwt_jku_x5u_ssrf", "⭐ JWT JKU / X5U SSRF.", "HIGH", "8.0"),
    ("jwt_kid_path_traversal", "⭐ JWT kid path traversal.", "HIGH", "8.0"),
    ("jwt_kid_sqli", "⭐ JWT kid SQL injection.", "HIGH", "8.0"),
    ("jwt_alg_confusion_hs_vs_rs", "JWT cross-algorithm confusion (HS256 vs RS256).", "HIGH", "8.0"),
    ("jwt_expired_replay", "JWT expired token replay.", "MEDIUM", "5.5"),
    ("jwt_key_confusion_pub_to_sym", "JWT key confusion (public→symmetric).", "HIGH", "8.0"),
    ("jwt_tool_comprehensive", "jwt_tool comprehensive scan.", "MEDIUM", "5.5"),

    # §6 Kerberos Attacks on-prem AD (10)
    ("kerberoasting", "Kerberoasting (GetUserSPNs).", "HIGH", "7.5"),
    ("asrep_roasting", "AS-REP Roasting (GetNPUsers).", "HIGH", "7.5"),
    ("unconstrained_delegation_tgt", "Unconstrained delegation TGT capture.", "HIGH", "8.0"),
    ("constrained_delegation_s4u", "Constrained delegation S4U.", "HIGH", "7.5"),
    ("rbcd_shadow_credentials", "RBCD via Shadow Credentials.", "HIGH", "8.0"),
    ("diamond_sapphire_ticket", "⭐ Diamond/Sapphire ticket (modify PAC).", "HIGH", "8.0"),
    ("golden_ticket_krbtgt", "Golden ticket (krbtgt forgery).", "CRITICAL", "9.5"),
    ("silver_ticket_service", "Silver ticket (service-specific).", "HIGH", "8.0"),
    ("targeted_kerberoast_one_user", "⭐ Targeted Kerberoast.", "HIGH", "7.5"),
    ("manual_kerberos_chain", "Manual creative Kerberos chain.", "INFO", "0.0"),

    # §7 Modern Passwordless (Passkey / WebAuthn) (10) ⭐
    ("webauthn_fido2_misconfig", "⭐ WebAuthn / FIDO2 misconfig audit.", "MEDIUM", "5.5"),
    ("passkey_enum", "⭐ Passkey enumeration.", "MEDIUM", "5.5"),
    ("passkey_cross_device_sync_abuse", "⭐ Passkey cross-device sync abuse (manual).", "INFO", "0.0"),
    ("passkey_downgrade_attack", "⭐ Passkey downgrade attack (manual).", "INFO", "0.0"),
    ("magic_link_entropy_replay", "⭐ Magic-link entropy / replay.", "HIGH", "7.0"),
    ("passwordless_flow_audit", "⭐ Passwordless flow audit (Stytch, Auth0).", "MEDIUM", "5.5"),
    ("account_recovery_flow_weakness", "⭐ Account-recovery flow weakness.", "HIGH", "7.0"),
    ("totp_secret_leak", "⭐ TOTP secret leak (if stored).", "HIGH", "8.0"),
    ("manual_passkey_phishing", "⭐ Manual Passkey phishing.", "INFO", "0.0"),
    ("manual_passwordless_chain", "⭐ Manual creative passwordless chain.", "INFO", "0.0"),
]


def _make_handler(slug, title, sev, cvss):
    def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
        return _adv(slug, req.target, title, sev=sev, cvss=cvss)
    _h.__name__ = slug
    return _h


for slug, title, sev, cvss in TECHNIQUES:
    router.add_api_route(f"/api/auth_attacks/{slug}", _make_handler(slug, title, sev, cvss),
                          methods=["POST"])


def register(app):
    app.include_router(router)
