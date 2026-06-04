"""adfs_extract_audit - finding rules.

CWE-287 Improper Authentication
CWE-295 Improper Certificate Validation
CWE-668 Exposure of Resource to Wrong Sphere
CVE-2017-11774 Microsoft Outlook Forms RCE (via ADFS bypass chain)
MITRE T1606.002 Forge Web Credentials: SAML Tokens (Golden SAML)
MITRE T1190 Exploit Public-Facing Application
"""


def rule_legacy_adfs(s):
    """ADFS 2.0/2.1/3 lack anti-relay + modern WS-Trust hardening."""
    if not s.get("adfs_audit_is_legacy"):
        return None
    label = s.get("adfs_audit_version_label") or "<unknown>"
    build = s.get("adfs_audit_build") or "?"
    return {
        "name": f"Legacy ADFS detected: {label} (build {build}) — Golden SAML risk",
        "severity": "CRITICAL", "cvss": "9.1",
        "cwe": "CWE-287", "owasp": "A07:2021",
        "mitre": "T1606.002",
        "evidence": (
            f"ADFS at {s.get('adfs_audit_target_url') or '?'} identifies as {label}. "
            "Pre-ADFS 4 (Win Srv 2019) versions lack anti-relay protection "
            "on the WS-Trust mixed endpoints AND ship Outlook Forms RCE "
            "chain (CVE-2017-11774) via the ADFS proxy. Combined with token-"
            "signing-certificate extraction (Golden SAML / Solorigate-class), "
            "an attacker who compromises this ADFS server can forge SAML "
            "tokens for ANY user in the federated tenant — undetectable by "
            "Entra ID and indistinguishable from real logins."),
        "remediation": (
            "1. Upgrade to ADFS 5 (Windows Server 2022) or migrate the "
            "federation entirely to Microsoft Entra ID (no on-prem ADFS). "
            "2. Microsoft's recommended path is Entra ID + Conditional Access "
            "replacing ADFS Claims Rules — full ADFS retirement. "
            "3. While ADFS lives, rotate token-signing certificate quarterly "
            "(Set-AdfsCertificate -CertificateType Token-Signing -Thumbprint) "
            "AND log every rotation in Sentinel. "
            "4. Apply MS17-014 + every subsequent ADFS hotfix. "
            "5. Deploy Microsoft Entra Connect Health for ADFS — alerts on "
            "configuration drift + cert pulls."),
    }


def rule_unknown_adfs_version(s):
    if s.get("adfs_audit_is_legacy"):
        return None
    if s.get("adfs_audit_version_label"):
        return None
    if not s.get("adfs_audit_mex_reachable"):
        return None
    return {
        "name": "ADFS detected but version not disclosed",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": ("Mex/SAML metadata accessible but no build/version "
                     "string returned in any probe response. Either the "
                     "admin removed product banners (good) or version is "
                     "embedded only in authenticated responses."),
        "remediation": ("Confirm ADFS is fully patched via Get-HotFix on "
                        "the ADFS server. Apply latest cumulative update."),
    }


def rule_wia_bypass(s):
    if not s.get("adfs_audit_wia_bypass_surface"):
        return None
    return {
        "name": ("CVE-2017-11774 surface — ADFS WIA endpoint responds without "
                  "auth challenge"),
        "severity": "HIGH", "cvss": "7.8",
        "cwe": "CWE-287", "owasp": "A07:2021",
        "mitre": "T1190",
        "evidence": (f"POST {s.get('adfs_audit_target_url')}/adfs/ls/wia "
                     f"returned HTTP {s.get('adfs_audit_wia_status')} instead "
                     "of 401 challenge. The WIA endpoint is the precondition "
                     "for CVE-2017-11774 (Outlook home-page RCE chain that "
                     "abuses an ADFS auth-bypass)."),
        "remediation": (
            "1. Apply MS17-014 / KB4022715 (Outlook security update) — "
            "addresses the Outlook side of the chain. "
            "2. Patch ADFS to latest cumulative update. "
            "3. Restrict WIA endpoint to internal IP ranges only (Web "
            "Application Proxy ingress rule). "
            "4. Disable WIA on the ADFS proxy if external clients only need "
            "form-based auth."),
    }


def rule_policy_store_anon(s):
    if not s.get("adfs_audit_policystore_anonymous_reachable"):
        return None
    return {
        "name": "ADFS Policy Store endpoint reachable anonymously",
        "severity": "HIGH", "cvss": "7.5",
        "cwe": "CWE-668", "owasp": "A05:2021",
        "mitre": "T1606.002",
        "evidence": (f"{s.get('adfs_audit_target_url')}/adfs/services/"
                     "policystoreswstrust/policyStore returned HTTP 200 "
                     "without authentication. AADInternals "
                     "Get-AADIntADFSPolicyStoreToken expects this endpoint "
                     "behind auth — anonymous access exposes claim rules + "
                     "issuance authorization policy."),
        "remediation": ("Restrict /adfs/services/policystoreswstrust/* to "
                        "Windows Integrated Auth only at the ADFS proxy / "
                        "Web Application Proxy. Audit who has pulled the "
                        "policy store via Event ID 510 + 514."),
    }


def rule_idpinit_enabled(s):
    if not s.get("adfs_audit_idpinit_enabled"):
        return None
    return {
        "name": ("idpinitiatedsignon.aspx ENABLED — phishing landing page "
                  "surface"),
        "severity": "MEDIUM", "cvss": "5.0",
        "cwe": "CWE-1021", "owasp": "A05:2021",
        "evidence": (f"{s.get('adfs_audit_target_url')}/adfs/ls/"
                     "idpinitiatedsignon.aspx returned 200 with sign-in UI. "
                     "Microsoft has recommended disabling this page since "
                     "2019 (Set-AdfsProperties -EnableIdpInitiatedSignonPage "
                     "$false). The page is a phishing-clone target — "
                     "attackers spin up look-alike domains pointing at the "
                     "real ADFS form to lift creds."),
        "remediation": (
            "PowerShell on ADFS server:\n"
            "Set-AdfsProperties -EnableIdpInitiatedSignonPage $false\n\n"
            "Then restart ADFS (iisreset on ADFS server or Restart-Service "
            "adfssrv). Verify by re-running this probe."),
    }


def rule_saml_metadata_exposed(s):
    if not s.get("adfs_audit_saml_metadata_reachable"):
        return None
    if s.get("adfs_audit_is_legacy"):
        # already covered by CRITICAL
        return None
    return {
        "name": "SAML federation metadata + token-signing certificate exposed",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": (f"{s.get('adfs_audit_target_url')}"
                     "/federationmetadata/2007-06/federationmetadata.xml "
                     "returns the public token-signing certificate + issuer "
                     f"URI ({s.get('adfs_audit_issuer') or '?'}). This is "
                     "standard SAML behavior (required for federation "
                     "partners) but it does fingerprint your ADFS for "
                     "targeting."),
        "remediation": ("This endpoint MUST be public by SAML spec. "
                        "Monitor for unusual pull volume in IIS logs as a "
                        "weak reconnaissance signal."),
    }


def rule_no_adfs(s):
    if s.get("adfs_audit_no_url") or s.get("adfs_audit_error"):
        return None
    if s.get("adfs_audit_mex_reachable") or s.get("adfs_audit_saml_metadata_reachable"):
        return None
    return {
        "name": "Target does not appear to be ADFS",
        "severity": "INFO",
        "cwe": "N/A",
        "evidence": (f"Neither {s.get('adfs_audit_target_url') or '?'}/adfs/services/"
                     "trust/mex nor the SAML metadata endpoint returned valid "
                     "ADFS markers. If this customer is federated, they may "
                     "use a non-ADFS IDP (Okta / Ping / Azure AD Federation)."),
        "remediation": ("Confirm the federation IDP brand via "
                        "seamless_sso_audit's GetUserRealm output, then "
                        "apply IDP-specific hardening."),
    }


def rule_missing_url(s):
    if not s.get("adfs_audit_no_url"):
        return None
    return {
        "name": "adfs_extract_audit skipped — no adfs_server_url supplied",
        "severity": "INFO",
        "evidence": ("This probe requires options.adfs_server_url. ADFS host "
                     "URL (e.g. https://sts.contoso.com) is auto-discoverable "
                     "via seamless_sso_audit's GetUserRealm AuthURL field for "
                     "federated tenants."),
        "remediation": ("Re-run with options.adfs_server_url=<ADFS host URL>."),
        "cwe": "N/A",
    }


def rule_httpx_missing(s):
    err = s.get("adfs_audit_error") or ""
    if "httpx not installed" not in err:
        return None
    return {
        "name": "httpx not installed on scanner host",
        "severity": "INFO", "evidence": err,
        "remediation": "pip install httpx>=0.27",
        "cwe": "N/A",
    }


ADFS_EXTRACT_AUDIT_FINDING_RULES = [
    rule_legacy_adfs,
    rule_unknown_adfs_version,
    rule_wia_bypass,
    rule_policy_store_anon,
    rule_idpinit_enabled,
    rule_saml_metadata_exposed,
    rule_no_adfs,
    rule_missing_url,
    rule_httpx_missing,
]
