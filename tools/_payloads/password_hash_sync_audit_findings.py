"""password_hash_sync_audit - finding rules.

CWE-522 Insufficiently Protected Credentials
CWE-798 Use of Hard-coded Credentials (NTLM hash storage)
MITRE T1003.006 OS Credential Dumping: DCSync
MITRE T1556.007 Modify Authentication Process: Hybrid Identity
OWASP A07:2021 Identification and Authentication Failures
"""


def rule_phs_enabled(s):
    if s.get("phs_audit_phs_enabled") is not True:
        return None
    hosts = s.get("phs_audit_adconnect_hosts") or []
    host_str = ", ".join(hosts[:3]) if hosts else "<not disclosed>"
    msol = s.get("phs_audit_msol_accounts") or []
    msol_str = ", ".join(m["upn"] for m in msol[:3]) if msol else "<none enumerated>"
    return {
        "name": ("Password Hash Sync (PHS) ENABLED — on-prem AD hash "
                  "extraction path is live"),
        "severity": "HIGH", "cvss": "8.1",
        "cwe": "CWE-522", "owasp": "A07:2021",
        "mitre": "T1003.006",
        "evidence": (
            f"Microsoft Graph reports passwordHashSyncEnabled=true for tenant "
            f"{s.get('phs_audit_tenant_id') or '?'}. Last on-prem sync: "
            f"{s.get('phs_audit_last_sync') or '<unknown>'}. ADConnect host(s): "
            f"{host_str}. MSOL_ service accounts: {msol_str}. "
            "PHS extracts the on-prem NTLM hash of every synced user, hashes it "
            "with SHA256, and uploads to Entra ID. If an attacker compromises "
            "the ADConnect server (DA-equivalent target — see ADSyncDecrypt / "
            "AADInternals Get-AADIntSyncCredentials), they extract the "
            "encryption keys and replay password hashes against any synced "
            "cloud account."),
        "remediation": (
            "1. Treat every ADConnect / Entra Connect server as a Tier 0 asset "
            "(DA-equivalent, no internet, dedicated PAW). "
            "2. Rotate the MSOL_ service account password monthly (it's the "
            "AD-side write target for sync). "
            "3. Enable Microsoft Defender for Identity on the ADConnect server "
            "— it alerts on ADSyncDecrypt-style reads. "
            "4. Enable Conditional Access requiring compliant device + MFA for "
            "all synced user accounts — DCSync-replayed hashes alone won't pass. "
            "5. Migrate to Microsoft Entra Cloud Sync (Cloud Sync agent runs in "
            "the cloud, smaller blast radius than full ADConnect). "
            "6. Audit Synchronization Service Manager (miisclient.exe) console "
            "access — only 1-2 trusted hybrid admins should have it."),
    }


def rule_phs_inconclusive(s):
    if not s.get("phs_audit_phs_inconclusive"):
        return None
    return {
        "name": "Password Hash Sync state inconclusive (feature flag not readable)",
        "severity": "INFO",
        "cwe": "N/A",
        "mitre": "T1556.007",
        "evidence": (
            f"For tenant {s.get('phs_audit_tenant_id') or '?'}: "
            + str(s.get("phs_audit_phs_inconclusive_reason")
                  or "passwordHashSyncEnabled could not be read explicitly.")),
        "remediation": (
            "Grant the app registration Synchronization.Read.All (application) "
            "+ admin-consent so the onPremisesSynchronization feature flags "
            "are readable, then re-run. PHS state is not graded until the "
            "explicit feature flag is observed."),
    }


def rule_on_prem_sync_only(s):
    if s.get("phs_audit_on_prem_sync_enabled") is not True:
        return None
    if s.get("phs_audit_phs_enabled") is True:
        # already covered by PHS rule
        return None
    if s.get("phs_audit_phs_inconclusive"):
        # covered by the dedicated inconclusive INFO rule
        return None
    return {
        "name": "Hybrid identity sync ENABLED (likely PTA or federated, not PHS)",
        "severity": "MEDIUM", "cvss": "5.0",
        "cwe": "CWE-287",
        "mitre": "T1556.007",
        "evidence": ("Organization.onPremisesSyncEnabled=true but PHS feature "
                     "flag not detected. This usually means PTA (Pass-Through "
                     "Auth) or federated ADFS. Run pta_agent_audit + "
                     "adfs_extract_audit to cover the auth-method-specific "
                     "attack paths."),
        "remediation": ("Apply Tier 0 protections to whichever sync mode is in "
                        "use. PTA = harden PTA agent servers. Federated = "
                        "harden ADFS + rotate token-signing cert."),
    }


def rule_no_sync(s):
    if s.get("phs_audit_on_prem_sync_enabled") is False:
        return {
            "name": "Cloud-only tenant — no on-prem sync, no PHS exposure",
            "severity": "POSITIVE",
            "cwe": "N/A",
            "evidence": ("Organization.onPremisesSyncEnabled=false. Tenant is "
                         "Entra ID-only. No hybrid-sync hash-extraction path "
                         "exists."),
            "remediation": ("Maintain cloud-only posture. If you must add "
                             "hybrid later, prefer Entra Cloud Sync over "
                             "classic Entra Connect."),
        }
    return None


def rule_msol_enumerated(s):
    msol = s.get("phs_audit_msol_accounts") or []
    if not msol:
        return None
    return {
        "name": f"{len(msol)} MSOL_ service account(s) enumerated",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": (f"MSOL_<random> accounts: " +
                     ", ".join(m["upn"] or "?" for m in msol[:5])),
        "remediation": ("MSOL_ accounts are the on-prem write-back identities "
                        "used by Entra Connect. Audit their last sign-in via "
                        "Get-MgAuditLogSignIn. Suspicious cloud sign-ins from "
                        "MSOL_ accounts (other than 'Microsoft Azure Active "
                        "Directory Connect Sync' application) = compromise "
                        "indicator."),
    }


def rule_missing_creds(s):
    if not s.get("phs_audit_missing_creds"):
        return None
    return {
        "name": "password_hash_sync_audit skipped — Graph credentials not supplied",
        "severity": "INFO",
        "evidence": ("This probe requires options.tenant_id + client_id + "
                     "client_secret on the request. The app registration must "
                     "have Directory.Read.All + Synchronization.Read.All "
                     "(application permissions, admin-consented)."),
        "remediation": ("Re-run with the customer's app-registration "
                        "credentials. Create a dedicated service principal in "
                        "Entra ID portal -> App registrations -> New -> "
                        "Certificates & secrets -> New client secret -> grant "
                        "Directory.Read.All + Synchronization.Read.All and "
                        "admin-consent."),
        "cwe": "N/A",
    }


def rule_auth_error(s):
    err = s.get("phs_audit_auth_error") or ""
    if not err:
        return None
    return {
        "name": "Microsoft Graph authentication failed",
        "severity": "INFO",
        "evidence": f"Token acquisition error: {err}",
        "remediation": ("Verify tenant_id / client_id / client_secret are "
                        "correct, the secret has not expired, and the "
                        "Directory.Read.All + Synchronization.Read.All app "
                        "permissions have been admin-consented."),
        "cwe": "N/A",
    }


PASSWORD_HASH_SYNC_AUDIT_FINDING_RULES = [
    rule_phs_enabled,
    rule_phs_inconclusive,
    rule_on_prem_sync_only,
    rule_no_sync,
    rule_msol_enumerated,
    rule_missing_creds,
    rule_auth_error,
]
