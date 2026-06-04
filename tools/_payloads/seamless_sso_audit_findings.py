"""seamless_sso_audit - finding rules.

CWE-294 Authentication Bypass by Capture-replay
MITRE ATT&CK T1606.001 Forge Web Credentials: Web Cookies
Microsoft MSAPPS17 Seamless SSO silver-ticket attack class.
"""


def rule_sso_enabled(s):
    if s.get("seamless_sso_desktop_sso_enabled") is not True:
        return None
    return {
        "name": ("Seamless SSO enabled — MSAPPS17 silver-ticket attack surface "
                  "(AZUREADSSO computer account)"),
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-294", "owasp": "A07:2021",
        "mitre": "T1606.001",
        "evidence": (
            f"GetUserRealm.srf for tenant {s.get('seamless_sso_tenant') or '?'} "
            "returned DesktopSsoEnabled=true. The on-prem AZUREADSSO computer "
            "account in your domain holds the Kerberos key used to issue "
            "tickets for HTTP/aadg.windows.net.nsatc.net. If an attacker "
            "reaches DCSync on the DC and extracts the AZUREADSSO NT hash, "
            "they can forge silver tickets accepted by Entra ID for ANY user "
            "in the tenant (MSAPPS17 attack). The AZUREADSSO account is "
            "typically never rotated by default."),
        "remediation": (
            "1. Rotate the AZUREADSSO account password every 30 days via "
            "Update-AzureADSSOForcedPasswordChange (Microsoft documented "
            "procedure) — this kills any extracted hash. "
            "2. Move to Microsoft Entra Cloud Sync (replaces Seamless SSO + "
            "PHS with a cloud-only sync model). "
            "3. Disable Seamless SSO if Hybrid Join + Windows Hello for "
            "Business meets your SSO requirement. "
            "4. Deploy Defender for Identity sensor on every DC — it alerts "
            "on AZUREADSSO ticket forgery attempts (Alert ID 2019). "
            "5. Enforce Conditional Access requiring compliant device + MFA — "
            "silver tickets without device claims will fail CA. "
            "Reference: dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/"),
    }


def rule_federated_tenant(s):
    ns = (s.get("seamless_sso_namespace") or "").lower()
    if ns != "federated":
        return None
    authurl = s.get("seamless_sso_authurl") or "<unknown>"
    return {
        "name": "Federated tenant — ADFS/3rd-party IDP issues identity tokens",
        "severity": "INFO",
        "cwe": "CWE-287",
        "evidence": (f"NameSpaceType=Federated. Federation AuthURL: {authurl}. "
                     "The federated IDP is the keystore of the kingdom — "
                     "Solorigate / Storm-0558 classes target signing keys here."),
        "remediation": (
            "1. Run adfs_extract_audit against the federation AuthURL. "
            "2. Enable Microsoft Entra Connect Health for ADFS monitoring. "
            "3. Rotate the ADFS token-signing certificate quarterly + "
            "monitor for unscheduled cert pulls via 4662 + 4624 audit logs."),
    }


def rule_managed_no_sso(s):
    if s.get("seamless_sso_desktop_sso_enabled") is not False:
        return None
    if (s.get("seamless_sso_namespace") or "").lower() == "federated":
        return None
    return {
        "name": "Cloud-managed tenant (no Seamless SSO) — modern hybrid posture",
        "severity": "POSITIVE",
        "cwe": "N/A",
        "evidence": ("GetUserRealm returned DesktopSsoEnabled=false. Tenant is "
                     "not exposed to the MSAPPS17 AZUREADSSO silver-ticket class."),
        "remediation": ("Keep Cloud Sync / Hybrid Join + WHFB as the SSO "
                        "strategy. If you re-enable Seamless SSO, schedule "
                        "AZUREADSSO password rotation."),
    }


def rule_autodiscover_open(s):
    a = s.get("seamless_sso_autodiscover") or {}
    if not a.get("autodiscover_reachable"):
        return None
    return {
        "name": "M365 autodiscover endpoint reachable — hybrid mail flow confirmed",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": (f"autodiscover-s.outlook.com responded HTTP "
                     f"{a.get('autodiscover_status')}. Tenant uses Exchange "
                     "Online or hybrid Exchange. Combine with PRT-theft / "
                     "EvilGinx phishlets to chain into mailbox compromise."),
        "remediation": ("Disable autodiscover v1 endpoints where possible. "
                        "Force Modern Authentication (Conditional Access "
                        "block 'Other clients') to suppress legacy IMAP/POP."),
    }


def rule_tenant_missing(s):
    if not s.get("seamless_sso_tenant_missing"):
        return None
    return {
        "name": f"Tenant {s.get('seamless_sso_tenant') or '?'} not found in Entra ID",
        "severity": "INFO",
        "cwe": "N/A",
        "evidence": ("Both .well-known/openid-configuration and GetUserRealm "
                     "returned unresolvable for this target. Either the "
                     "tenant name is wrong or the target is not an Entra ID "
                     "customer."),
        "remediation": ("Re-run with the customer's primary tenant domain "
                        "(usually <tenant>.onmicrosoft.com) or vanity domain."),
    }


def rule_httpx_missing(s):
    err = s.get("seamless_sso_error") or ""
    if "httpx not installed" not in err:
        return None
    return {
        "name": "httpx not installed on scanner host",
        "severity": "INFO", "evidence": err,
        "remediation": "pip install httpx>=0.27",
        "cwe": "N/A",
    }


SEAMLESS_SSO_AUDIT_FINDING_RULES = [
    rule_sso_enabled,
    rule_federated_tenant,
    rule_managed_no_sso,
    rule_autodiscover_open,
    rule_tenant_missing,
    rule_httpx_missing,
]
