"""hybrid_identity module - Entra ID + on-prem AD bridge attacks
(per module_playbooks/28_hybrid_identity.md).

8 sections, 90 techniques. Starter set covers §1 Entra ID Recon +
§2 Hybrid AD Connect Attacks + §8 Modern Entra ID CVE/TTPs via real
msal / azure-identity / httpx probes against login.microsoftonline.com,
graph.microsoft.com, and customer-provided ADFS endpoints.

Customer-supplied options on the ScanRequest:
  - target              : Entra ID tenant name (e.g. "contoso.onmicrosoft.com")
                          OR on-prem DC IP / ADFS host
  - options.username_list   : newline-separated UPNs for entra_user_enum_unauth
  - options.tenant_id       : Azure AD tenant GUID (Graph-authenticated probes)
  - options.client_id       : App registration client ID
  - options.client_secret   : App registration secret
  - options.adfs_server_url : ADFS host URL (e.g. "https://sts.contoso.com")

Some probes (entra_user_enum_unauth, seamless_sso_audit, adfs_extract_audit)
run UNAUTHENTICATED. Graph-authenticated probes (password_hash_sync_audit,
pta_agent_audit) require options.tenant_id/client_id/client_secret.
"""
