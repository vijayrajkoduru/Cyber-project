"""oauth_tenant_exposure - findings rules.

OAuth illicit-consent-grant and device-code phishing target the identity
provider's PUBLIC OAuth surface. This scanner reads that public metadata so
the customer sees what an attacker can enumerate about their tenant before
crafting a lure.

CRITICAL DESIGN NOTE (the zero-FP rule this module exists to enforce): no
finding here ever claims a consent grant, token theft, or successful
device-code phish occurred. Those require sending a lure to a victim and
observing them click Accept - which is out of SaaS scope and would be a
fabricated CRITICAL. Every finding below is either a DETECTED metadata fact
(graded at most LOW) or an honest advisory INFO.

Severity model:
  LOW      - federated tenant AND device-code flow endpoint exposed
             (device-code phishing path is reachable; narrow real exposure)
  INFO     - tenant discovered: situational awareness + advisory that the
             consent-grant / device-code LURE itself is advisory-by-design
  INFO     - not an Entra ID tenant / endpoint unreachable / httpx missing
"""

_CWE_TOKEN = "CWE-522"   # Insufficiently Protected Credentials
_CWE_DESIGN = "CWE-1395" # advisory-by-design marker (consistent w/ pack_common)
_NIST = "NIST 800-53 IA-2 / AC-2 (Identification, Authentication, Account Mgmt)"


def rule_dep_or_error(s):
    err = s.get("oauth_error") or ""
    if not err:
        return None
    if "not installed" in err.lower():
        return {
            "name": "OAuth tenant probe skipped - httpx not installed",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Install httpx on the scanner host: pip install httpx.",
            "cwe": "CWE-1006",
        }
    return {
        "name": "OAuth tenant probe could not run",
        "severity": "INFO",
        "evidence": err,
        "remediation": (
            "Microsoft's login.microsoftonline.com may have rate-limited the "
            "scanner egress IP. Re-run later."
        ),
        "cwe": "CWE-1006",
    }


def rule_not_a_tenant(s):
    if s.get("oauth_error"):
        return None
    if s.get("oauth_is_entra_tenant"):
        return None
    if not s.get("oauth_target_domain"):
        return None
    if s.get("oauth_is_entra_tenant") is None:
        return None
    return {
        "name": (f"{s.get('oauth_target_domain')} is not a Microsoft Entra ID "
                 "(Azure AD) tenant"),
        "severity": "INFO",
        "evidence": (
            f"GET login.microsoftonline.com/{s.get('oauth_target_domain')}"
            "/.well-known/openid-configuration returned HTTP "
            f"{s.get('oauth_oidc_status', '?')} (no federated tenant). The "
            "Microsoft 365 OAuth consent / device-code phishing vectors in "
            "playbook §5 do not apply to this domain. If you use Google "
            "Workspace, the equivalent OAuth-consent abuse should be reviewed "
            "in the Google Admin console (app access control / OAuth app "
            "allowlisting)."
        ),
        "remediation": (
            "No action for the M365 OAuth surface. If your identity provider "
            "is Google Workspace or Okta, enforce OAuth app allowlisting / "
            "admin consent there instead."
        ),
        "cwe": "CWE-1006",
    }


def rule_device_code_exposed(s):
    # LOW: a federated tenant with the device-code flow endpoint exposed.
    if not s.get("oauth_is_entra_tenant"):
        return None
    if not s.get("oauth_device_flow_exposed"):
        return None
    return {
        "name": ("Entra ID device-code authorization endpoint is exposed for "
                 f"{s.get('oauth_target_domain')} - device-code phishing path "
                 "is reachable"),
        "severity": "LOW",
        "cvss": "3.5",
        "cwe": _CWE_TOKEN,
        "cwe_name": "Insufficiently Protected Credentials",
        "owasp": "A07:2021",
        "evidence": (
            f"The tenant's published OAuth metadata advertises "
            f"`device_authorization_endpoint` "
            f"({s.get('oauth_device_endpoint')}), and the realm is "
            f"{s.get('oauth_realm_type') or 'managed/federated'}. The "
            "device-code flow is a top 2024-2026 phishing vector: an attacker "
            "starts a device-code request, sends the victim the legitimate "
            "`microsoft.com/devicelogin` URL + the attacker's user_code, and "
            "the victim's sign-in mints tokens for the attacker. This is a "
            "REACHABILITY observation read from public metadata - no token "
            "was requested and no phish was sent."
        ),
        "remediation": (
            "Block or scope the device-code flow with Conditional Access: in "
            "Entra ID, create a CA policy targeting the "
            "'Authentication flows' condition -> 'Device code flow' -> Block, "
            "scoped to all users except the few break-glass / kiosk accounts "
            "that genuinely need it. Also require phishing-resistant MFA "
            "(FIDO2) and a compliant device. Train users that a legitimate "
            "app will never ask them to enter a code they received by email. "
            f"Compliance: {_NIST}, MITRE ATT&CK T1528."
        ),
    }


def rule_tenant_discovered_advisory(s):
    # INFO situational-awareness + the consent-grant advisory-by-design note.
    if not s.get("oauth_is_entra_tenant"):
        return None
    return {
        "name": ("[ADVISORY-BY-DESIGN] Entra ID tenant enumerated for "
                 f"{s.get('oauth_target_domain')} - OAuth consent-grant lure "
                 "delivery is out of SaaS scope"),
        "severity": "INFO",
        "evidence": (
            f"Public OAuth metadata confirms {s.get('oauth_target_domain')} "
            f"is Entra ID tenant `{s.get('oauth_tenant_id') or '(GUID not in issuer)'}` "
            f"(issuer {s.get('oauth_issuer') or 'n/a'}, realm "
            f"{s.get('oauth_realm_type') or 'n/a'}). An attacker can "
            "enumerate this much without authentication. Actually executing "
            "illicit-consent-grant or device-code phishing (playbook §5 "
            "#43/#46/#47/#48) requires registering a malicious multi-tenant "
            "app and delivering a consent lure to a victim - VulnusLab does "
            "NOT send lures or create app registrations, so the attack itself "
            "is advisory-by-design here, not a live probe."
        ),
        "remediation": (
            "Harden the consent surface so the lure cannot succeed even if "
            "delivered: (1) Entra ID > Enterprise applications > Consent and "
            "permissions -> set user consent to 'Do not allow user consent', "
            "route all third-party app access through admin consent + an "
            "admin-consent workflow. (2) Restrict who can register apps "
            "(Users can register applications = No). (3) Review existing "
            "OAuth grants for over-privileged / unknown apps "
            "(Get-MgServicePrincipal / the 'Risky OAuth apps' report) and "
            "revoke stale ones. (4) Enable Conditional Access + "
            "phishing-resistant MFA. "
            f"Compliance: {_NIST}, Microsoft 'Detect and remediate illicit "
            "consent grants'."
        ),
        "cwe": _CWE_DESIGN,
    }


OAUTH_TENANT_EXPOSURE_FINDING_RULES = [
    rule_dep_or_error,
    rule_not_a_tenant,
    rule_device_code_exposed,
    rule_tenant_discovered_advisory,
]
