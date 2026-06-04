"""pta_agent_audit - finding rules.

CWE-522 Insufficiently Protected Credentials
MITRE T1556.007 Modify Authentication Process: Hybrid Identity
MITRE T1003 OS Credential Dumping (on the PTA agent host)
OWASP A07:2021 Identification and Authentication Failures
"""


def rule_pta_agent_per_host(s):
    """One HIGH per PTA agent host — each agent server == Tier 0 target."""
    agents = s.get("pta_audit_pta_only_agents") or []
    if not agents:
        return None
    # Emit ONE finding listing all PTA agents (rule funcs return one finding
    # — the rule engine doesn't currently support fan-out from a single rule.
    # We list every agent inside the evidence so the PDF shows each hostname.)
    host_list = ", ".join(f"{a.get('machine_name')}@{a.get('external_ip') or '?'}"
                          for a in agents[:10])
    return {
        "name": (f"Pass-Through Authentication active — {len(agents)} on-prem "
                  "PTA agent(s) capture cleartext cloud login passwords"),
        "severity": "HIGH", "cvss": "8.2",
        "cwe": "CWE-522", "owasp": "A07:2021",
        "mitre": "T1556.007",
        "evidence": (
            f"Microsoft Graph reports {len(agents)} PTA agent(s) in tenant "
            f"{s.get('pta_audit_tenant_id') or '?'}. Hosts: {host_list}. "
            "Every cloud sign-in is forwarded back to one of these on-prem "
            "Windows servers. The PTA agent process sees the cleartext "
            "password on every login before validating against on-prem AD. "
            "Compromise of any PTA agent host = credential capture for the "
            "entire tenant (see pta-mim Mimikatz module / SpecterOps "
            "PassTheGod / Adam Chester research)."),
        "remediation": (
            "1. Treat every PTA agent host as a Tier 0 asset (DA-equivalent). "
            "Dedicated PAW access only, no internet egress, no email/Office. "
            "2. Run >=3 PTA agents for HA — but keep them ALL Tier 0. "
            "3. Restrict local admin on PTA agent hosts to a 2-person break-"
            "glass group. Audit Event ID 4672 (special privileges) on agent "
            "hosts. "
            "4. Enable Microsoft Defender for Endpoint on every PTA agent + "
            "alert on Mimikatz-class process injection / pta-mim signatures. "
            "5. Migrate to Microsoft Entra Cloud Sync where possible — Cloud "
            "Sync removes the on-prem sign-in path entirely. "
            "6. Audit recent PTA sign-ins for unusual source IPs / impossible "
            "travel via Sentinel / Entra Identity Protection."),
    }


def rule_no_pta_agents(s):
    if s.get("pta_audit_missing_creds") or s.get("pta_audit_auth_error"):
        return None
    if not s.get("pta_audit_authenticated"):
        return None
    if (s.get("pta_audit_pta_only_count") or 0) > 0:
        return None
    return {
        "name": "No PTA agents detected — tenant uses PHS or federated auth",
        "severity": "POSITIVE",
        "cwe": "N/A",
        "evidence": ("Graph enumerated 0 PTA-only agents in the tenant's "
                     "onPremisesPublishingProfiles. Authentication mode is "
                     "likely PHS, federated, or cloud-only."),
        "remediation": ("Run password_hash_sync_audit + adfs_extract_audit to "
                        "cover the active auth mode's attack surface."),
    }


def rule_appproxy_only(s):
    """If publishing agents exist but none are PTA-only, they're App Proxy."""
    total = s.get("pta_audit_agent_count") or 0
    pta = s.get("pta_audit_pta_only_count") or 0
    if total <= 0 or pta > 0:
        return None
    return {
        "name": f"{total} Entra Application Proxy connector(s) detected (no PTA)",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": (f"{total} onPremisesPublishingProfile agent(s) registered, "
                     "but supportedPublishingTypes does not include "
                     "'authentication'. These are Application Proxy connectors "
                     "(publishing internal apps to the internet) — they don't "
                     "see cleartext passwords like PTA does, but a compromised "
                     "Application Proxy connector is a perimeter beachhead."),
        "remediation": ("Apply Tier 1 hardening to Application Proxy connector "
                        "hosts. Audit which on-prem apps they publish — they "
                        "are the customer's reverse-proxy from the internet."),
    }


def rule_recent_signins(s):
    n = s.get("pta_audit_recent_signins_count") or 0
    if n <= 0:
        return None
    return {
        "name": f"Recent PTA sign-in activity ({n} in last query window)",
        "severity": "INFO",
        "cwe": "N/A",
        "evidence": (f"Last {n} PTA sign-in(s) returned by Graph audit. "
                     "Provides forensic baseline for what 'normal' PTA volume "
                     "looks like; PTA agent compromise typically shows as "
                     "unusual source-IP geolocation for these sign-ins."),
        "remediation": ("Stream auditLogs/signIns filtered to "
                        "authenticationProtocol='passthroughAuthentication' "
                        "into Sentinel + alert on geo-anomalies."),
    }


def rule_missing_creds(s):
    if not s.get("pta_audit_missing_creds"):
        return None
    return {
        "name": "pta_agent_audit skipped — Graph credentials not supplied",
        "severity": "INFO",
        "evidence": ("This probe requires options.tenant_id + client_id + "
                     "client_secret. The app registration must have "
                     "Policy.Read.All + OnPremisesPublishingProfiles.Read.All "
                     "(application permissions, admin-consented)."),
        "remediation": ("Re-run with the customer's app-registration "
                        "credentials. Create the service principal with the "
                        "two required Graph permissions and admin-consent."),
        "cwe": "N/A",
    }


def rule_auth_error(s):
    err = s.get("pta_audit_auth_error") or ""
    if not err:
        return None
    return {
        "name": "Microsoft Graph authentication failed",
        "severity": "INFO",
        "evidence": f"Token acquisition error: {err}",
        "remediation": ("Verify tenant_id / client_id / client_secret and "
                        "admin-consent for the Graph permissions."),
        "cwe": "N/A",
    }


PTA_AGENT_AUDIT_FINDING_RULES = [
    rule_pta_agent_per_host,
    rule_no_pta_agents,
    rule_appproxy_only,
    rule_recent_signins,
    rule_missing_creds,
    rule_auth_error,
]
