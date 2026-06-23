"""hybrid_identity_advisory_pack - honest advisory-by-design coverage.

One scanner that enumerates every hybrid_identity playbook technique
(module_playbooks/28_hybrid_identity.md) which CANNOT be safely detected
from an external SaaS scanner, each as an [ADVISORY-BY-DESIGN] INFO finding
(vulnerable:false). This guarantees the report reflects the full 90-technique
catalogue without ever passing a playbook's PLANNED severity through as a
real finding severity (the exact bug that shipped fake CRITICALs in the
pivot module).

What IS actively probed elsewhere in this module (so NOT repeated here):
  §1: entra_user_enum_unauth, seamless_sso_audit, openid_tenant_recon,
      tenant_domain_enum
  §2: password_hash_sync_audit, pta_agent_audit (Graph-authenticated)
  §2/§8: adfs_extract_audit
  §3: legacy_wstrust_surface_audit

Everything below needs cloud/host credentials, on-host or LAN execution, a
post-compromise foothold, active exploitation, social engineering, or DoS —
so it is advisory-by-design INFO. This scanner performs NO network I/O and
NEVER chains into another scanner.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()


class HybridIdentityAdvisoryPackRequest(ScanRequest):
    options: Optional[dict] = None


# (key, section, title, why-not-SaaS-probeable, cwe)
_ADVISORY_TECHNIQUES = [
    # --- §1 Entra ID Recon / Enumeration (credential / tool-execution items) ---
    ("roadrecon_full_dump", "§1",
     "ROADrecon (ROADtools) full tenant dump",
     "Requires authenticated tenant credentials (delegated or app) to dump the directory; "
     "a read-only-with-auth operation, not an unauthenticated external probe.",
     "CWE-200"),
    ("azurehound_ingest", "§1",
     "azurehound BloodHound-Azure graph ingest",
     "Requires authenticated Graph access to enumerate the tenant graph for BloodHound.",
     "CWE-200"),
    ("stormspotter_graph", "§1",
     "StormSpotter Azure graph traversal",
     "Requires Azure Reader credentials to traverse ARM + AAD resources.",
     "CWE-200"),
    ("msolspray_spray", "§1",
     "MSOLSpray password spray against the tenant",
     "Submitting candidate passwords to login.microsoftonline.com is an active credential "
     "attack (and can trigger Smart Lockout) — VulnusLab does not spray live accounts.",
     "CWE-307"),
    ("mfasweep_enum", "§1",
     "MFASweep per-protocol MFA enumeration",
     "Requires a valid credential to walk each Microsoft auth surface and observe MFA gaps.",
     "CWE-287"),
    ("skyark_shadow_admin", "§1",
     "SkyArk Azure shadow-admin discovery",
     "Requires authenticated Reader access to compute shadow-admin privilege paths.",
     "CWE-269"),
    ("manual_azuread_ps", "§1",
     "Manual Entra ID PowerShell / Graph exploration (AzureAD module)",
     "An interactive authenticated analyst task, not an automated external probe.",
     "CWE-200"),
    ("scubagear_baseline", "§1",
     "ScubaGear M365 secure-baseline assessment",
     "A defender-side, authenticated CISA baseline scan run from inside the tenant.",
     "CWE-1188"),
    # --- §2 Hybrid AD Connect Attacks (on-prem / post-compromise) ---
    ("adsync_server_compromise", "§2",
     "ADSync server compromise -> Domain Admin",
     "Requires code execution on the on-prem Entra Connect (ADSync) server to extract the "
     "sync credentials — a post-compromise, on-host action.",
     "CWE-522"),
    ("msol_account_abuse", "§2",
     "MSOL_xxxxx service-account credential abuse / DCSync",
     "Requires the extracted MSOL_ account hash and LAN reachability to a Domain Controller "
     "to perform DCSync replication.",
     "CWE-522"),
    ("seamless_sso_silver_ticket", "§2",
     "Seamless SSO AZUREADSSO silver-ticket forge (MSAPPS17)",
     "Requires the AZUREADSSO computer-account hash extracted from a DC, then forging "
     "Kerberos tickets — post-compromise on-prem. (Exposure of Seamless SSO is detected "
     "remotely by seamless_sso_audit.)",
     "CWE-294"),
    ("phs_hash_extraction", "§2",
     "Password Hash Sync (PHS) hash extraction / replay",
     "Requires extracting the sync key from the ADSync DB on the on-prem server; replay "
     "needs that key — on-host post-compromise. (PHS config is detected with credentials by "
     "password_hash_sync_audit.)",
     "CWE-522"),
    ("pta_agent_compromise", "§2",
     "PTA agent host compromise (pta-mim cleartext capture)",
     "Requires code execution on the on-prem PTA agent host to hook plaintext passwords. "
     "(PTA agent inventory is detected with credentials by pta_agent_audit.)",
     "CWE-522"),
    ("adfs_golden_saml", "§2",
     "ADFS Golden SAML (token-signing private-key theft + forge)",
     "Requires extracting the ADFS token-signing private key from the IdP host (DKM master "
     "key) — post-compromise. (ADFS surface is detected by adfs_extract_audit.)",
     "CWE-347"),
    ("aad_connect_sync_api", "§2",
     "AAD Connect Sync API abuse (Set-AADIntUserPassword class)",
     "Requires the extracted sync credentials and an authenticated Sync API session.",
     "CWE-522"),
    ("manual_hybrid_bridge_audit", "§2",
     "Manual hybrid bridge / Cloud-Sync-vs-AAD-Connect audit",
     "An authenticated configuration review of on-prem connectors and sync scope.",
     "CWE-1188"),
    ("permanent_hybrid_admin", "§2",
     "Permanent Hybrid Identity Administrator role abuse",
     "Requires authenticated directory read to enumerate standing role assignments.",
     "CWE-269"),
    ("adfs_proxy_attack", "§2",
     "ADFS Web Application Proxy (WAP) attack surface",
     "The reachable ADFS/WAP surface is fingerprinted by adfs_extract_audit; weaponizing it "
     "is active exploitation and out of scope for VA.",
     "CWE-668"),
    # --- §3 Conditional Access Bypass (config-read / human / device) ---
    ("device_compliance_bypass", "§3",
     "Device-compliance / Intune CA bypass",
     "Requires a compliant or spoofed device context to evade a CA policy — needs an "
     "enrolled device and authenticated session.",
     "CWE-287"),
    ("cae_audit", "§3",
     "Continuous Access Evaluation (CAE) configuration audit",
     "Requires authenticated Policy.Read.All to read CAE configuration.",
     "CWE-1188"),
    ("risk_policy_bypass", "§3",
     "Risk-based Conditional Access policy bypass",
     "Requires an authenticated session and the ability to manipulate sign-in risk signals.",
     "CWE-287"),
    ("named_location_bypass", "§3",
     "Named-locations CA bypass (trusted-IP / VPN egress)",
     "Requires egress from a trusted IP and a valid credential — an authenticated bypass, "
     "not an external probe.",
     "CWE-287"),
    ("ca_policy_enum", "§3",
     "Conditional Access policy enumeration (read-only)",
     "Requires authenticated Policy.Read.All to read the tenant CA policy set.",
     "CWE-1188"),
    ("manual_ca_gap_analysis", "§3",
     "Manual CA policy-gap analysis + creative bypass chains",
     "An authenticated analyst review of the full policy matrix.",
     "CWE-1188"),
    ("mfa_fatigue_phish", "§3",
     "Phishing -> MFA fatigue / push-bombing chain",
     "Generating real push prompts to a live user is harassment / DoS of the account owner — "
     "VulnusLab never floods real users.",
     "CWE-307"),
    # --- §4 Token Theft / Replay (endpoint / post-compromise / phishing) ---
    ("prt_theft", "§4",
     "Primary Refresh Token (PRT) theft (Mimikatz / ROADtoken)",
     "Requires code execution on a victim's Entra-joined device to extract the PRT.",
     "CWE-522"),
    ("tokentactics_replay", "§4",
     "TokenTactics / TokenTactics V2 refresh-token abuse",
     "Requires a refresh token already exfiltrated from a victim; replay is out-of-band.",
     "CWE-539"),
    ("browser_cookie_theft", "§4",
     "Browser cookie theft -> Microsoft session replay",
     "Requires post-compromise extraction of session cookies from a victim's browser.",
     "CWE-539"),
    ("office_client_token_theft", "§4",
     "Office / Teams / OneDrive desktop client token theft (.aad.* files)",
     "Requires filesystem access to the victim's endpoint to read cached token blobs.",
     "CWE-522"),
    ("evilginx_m365_phishlet", "§4",
     "EvilGinx2 AiTM with an M365 phishlet",
     "Requires standing up a reverse-proxy phishing site and a human clicking it — social "
     "engineering, not a target-side probe.",
     "CWE-1021"),
    ("aitm_ropc_replay", "§4",
     "AiTM cookie replay through the ROPC flow",
     "Requires a captured session and active credential replay against the tenant.",
     "CWE-294"),
    ("refresh_token_longlived", "§4",
     "Long-lived refresh-token abuse",
     "Requires an already-issued refresh token from a compromised session.",
     "CWE-613"),
    # --- §5 Service Principal / App Registration Abuse (authenticated Graph) ---
    ("app_permission_audit", "§5",
     "Application permission audit (over-privileged Graph grants)",
     "Requires authenticated Directory.Read.All to enumerate app role assignments and "
     "consent grants.",
     "CWE-269"),
    ("app_secret_leak_scan", "§5",
     "Application secret leak hunting (gitleaks across customer repos)",
     "Requires access to the customer's source repositories / CI to scan for leaked client "
     "secrets — out of scope for an external tenant probe.",
     "CWE-798"),
    ("app_cert_theft", "§5",
     "Application certificate theft + reuse",
     "Requires post-compromise extraction of an app's auth certificate private key.",
     "CWE-522"),
    ("owner_add_credentials", "§5",
     "App/SP owner role abuse (add credentials to escalate)",
     "Requires an authenticated owner/privileged session to mint new app credentials.",
     "CWE-269"),
    ("delegated_vs_app_perms", "§5",
     "Delegated-vs-Application permission abuse + group-claims abuse",
     "Requires authenticated directory read to map effective permissions and claim mappings.",
     "CWE-269"),
    ("federated_identity_creds", "§5",
     "Federated identity credentials (workload identity federation) abuse",
     "Requires authenticated read of the app's federatedIdentityCredentials and the external "
     "OIDC issuer trust — a credentialed configuration review.",
     "CWE-287"),
    ("app_roles_claim_tamper", "§5",
     "App Roles / group-claims tampering",
     "Requires an authenticated token-issuance context to manipulate role/group claims.",
     "CWE-290"),
    # --- §6 Cross-Tenant Attacks (authenticated / multi-tenant config) ---
    ("guest_user_abuse", "§6",
     "Cross-tenant guest (B2B) user abuse",
     "Requires an authenticated guest principal in the target tenant to enumerate access.",
     "CWE-284"),
    ("b2b_direct_connect_audit", "§6",
     "B2B Direct Connect / Cross-Tenant Access settings audit",
     "Requires authenticated Policy.Read.All to read cross-tenant access policy.",
     "CWE-1188"),
    ("cross_tenant_sync_audit", "§6",
     "Cross-Tenant Synchronization configuration audit",
     "Requires authenticated read of the cross-tenant sync job configuration.",
     "CWE-1188"),
    ("multitenant_consent_abuse", "§6",
     "Multi-tenant app + admin-consent abuse",
     "Requires luring a tenant admin to consent to a malicious multi-tenant app — social "
     "engineering / authenticated consent action.",
     "CWE-862"),
    ("cross_tenant_ca_skew", "§6",
     "Cross-tenant Conditional Access skew analysis",
     "Requires authenticated read of both tenants' CA policies to compare.",
     "CWE-1188"),
    ("cross_cloud_oidc_trust", "§6",
     "Cross-cloud OIDC trust map (AWS/GCP <-> Entra workload federation)",
     "Requires authenticated read of workload-identity-federation trust in each cloud.",
     "CWE-287"),
    # --- §7 Microsoft 365 Privesc (authenticated role/PIM) ---
    ("global_admin_enum", "§7",
     "Global Administrator role enumeration",
     "Requires authenticated RoleManagement.Read.Directory to enumerate role members.",
     "CWE-269"),
    ("pim_abuse", "§7",
     "Privileged Identity Management (PIM) eligible-role abuse / activation race",
     "Requires an authenticated eligible-role principal to activate roles.",
     "CWE-269"),
    ("sharepoint_admin_takeover", "§7",
     "SharePoint admin -> tenant compromise",
     "Requires an authenticated SharePoint admin role and active exploitation.",
     "CWE-269"),
    ("exchange_admin_mailbox_read", "§7",
     "Exchange admin -> read any mailbox",
     "Requires an authenticated Exchange admin role and active mailbox access.",
     "CWE-269"),
    ("teams_defender_compliance_admin", "§7",
     "Teams / Defender / Compliance admin role abuse (bot impersonation, audit disable, DLP bypass)",
     "Requires the corresponding authenticated admin role and active configuration change.",
     "CWE-269"),
    ("outlook_exfil_rules", "§7",
     "Outlook custom rules + mail exfiltration",
     "Requires an authenticated mailbox session to plant forwarding/exfil rules.",
     "CWE-269"),
    ("manual_m365_role_analysis", "§7",
     "Manual M365 admin-role / least-privilege analysis",
     "An authenticated analyst review of the role assignment matrix.",
     "CWE-1188"),
    # --- §8 Modern Entra ID CVE / TTPs (post-compromise / threat-actor emulation) ---
    ("noauth_cve", "§8",
     "nOAuth (email-claim spoofing account takeover)",
     "Requires testing a downstream application's handling of a spoofed email claim — an "
     "authenticated app-level test against the relying party, not the tenant.",
     "CWE-290"),
    ("ducktail_consent_abuse", "§8",
     "DUCKTAIL malware-style OAuth consent abuse",
     "Requires luring a victim to consent to a malicious app — social engineering.",
     "CWE-862"),
    ("storm0558_token_forge", "§8",
     "Storm-0558 token-forging class (stolen signing key)",
     "Requires a stolen Microsoft/IdP signing key — post-compromise of the key material.",
     "CWE-347"),
    ("nationstate_ttp_emulation", "§8",
     "Volt Typhoon / Midnight Blizzard / Solorigate TTP emulation",
     "Requires authenticated, foothold-based threat-actor emulation across the tenant.",
     "CWE-1188"),
    ("defender_sentinel_evasion", "§8",
     "Defender for Identity bypass / Sentinel UEBA evasion",
     "Requires an authenticated foothold and active evasion against the customer's detections.",
     "CWE-778"),
]


async def gather(ctx: ScanContext):
    # Pure advisory enumeration — no network, no chaining.
    ctx.state["advisory_count"] = len(_ADVISORY_TECHNIQUES)
    ctx.state["advisory_techniques"] = [t[0] for t in _ADVISORY_TECHNIQUES]
    ctx.state["advisory_sections"] = sorted({t[1] for t in _ADVISORY_TECHNIQUES})
    ctx.source("hybrid_identity advisory-by-design enumeration")


def _make_advisory_rule(key, section, title, reason, cwe):
    def _rule(s):
        return {
            "name": f"[ADVISORY-BY-DESIGN] {section} {title}",
            "severity": "INFO",
            "cvss": "0.0",
            "cwe": cwe,
            # No blanket OWASP tag: these advisories span auth, consent, crypto,
            # authz, etc. — a single A07 label was inaccurate. The per-technique
            # CWE already carries the correct categorisation.
            "owasp": "N/A",
            "evidence": (
                f"This technique cannot be safely detected from an external SaaS scanner. "
                f"{reason} It is reported as advisory-by-design (NOT a forge gap and NOT a "
                "confirmed vulnerability on this target)."
            ),
            "remediation": (
                "Validate this control via an authenticated tenant assessment / red-team "
                "engagement per module_playbooks/28_hybrid_identity.md. Detection-only SaaS "
                "scanning intentionally does not execute it."
            ),
        }
    return _rule


HYBRID_IDENTITY_ADVISORY_PACK_FINDING_RULES = [
    _make_advisory_rule(k, sec, t, r, c)
    for (k, sec, t, r, c) in _ADVISORY_TECHNIQUES
]


INTEL_FIELDS = [
    ("Advisory sections",   "advisory_sections"),
    ("Advisory techniques", "advisory_techniques"),
    ("Advisory count",      "advisory_count"),
]


@router.post("/api/hybrid_identity/hybrid_identity_advisory_pack")
async def hybrid_identity_advisory_pack(req: HybridIdentityAdvisoryPackRequest,
                                        _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="hybrid_identity_advisory_pack",
        gather_func=_gather,
        finding_rules=HYBRID_IDENTITY_ADVISORY_PACK_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
