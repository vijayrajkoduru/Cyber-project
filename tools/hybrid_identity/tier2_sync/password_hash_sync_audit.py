"""password_hash_sync_audit - Password Hash Sync (PHS) configuration
audit via Microsoft Graph (playbook §2 #18 PHS extraction + #21 AAD
Connect Sync API abuse).

PHS is the hybrid auth mode where Microsoft Entra Connect extracts the
NTLM hash of every on-prem AD user, hashes it again (SHA256 of the
unicodePwd hash), and uploads it to Microsoft. From the attacker's POV
this means: if the on-prem ADConnect server is compromised, you can
extract Recovery Key + Sync Key and replay hashes for cloud accounts via
the AADInternals Set-AADIntUserPassword endpoint OR pull all on-prem
hashes via the MSOL_ service account.

This probe authenticates to Microsoft Graph via the customer's app
registration (client credentials flow) and queries:

  GET /v1.0/directory/onPremisesSynchronization
       — synchronization configuration objects
  GET /v1.0/organization
       — onPremisesSyncEnabled flag + sync interval

If onPremisesSyncEnabled is true AND PHS feature flag is enabled in
synchronization configuration, emit HIGH (extracted hashes are the
DCSync-from-cloud path). Plus details on the ADConnect server hostname
which becomes the highest-value target in the customer environment.

Customer input via ScanRequest.options:
  - options.tenant_id     = Azure AD tenant GUID (required)
  - options.client_id     = App registration client ID (required)
  - options.client_secret = App registration client secret (required)

The app registration must have at minimum:
  - Directory.Read.All       (read directory sync state)
  - Synchronization.Read.All (read sync rules / config)

CWE-522 Insufficiently Protected Credentials
MITRE T1003.006 OS Credential Dumping: DCSync /
       T1606.002 Forge Web Credentials: SAML Tokens
"""
from __future__ import annotations
import asyncio
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.password_hash_sync_audit_findings import (
    PASSWORD_HASH_SYNC_AUDIT_FINDING_RULES,
)

router = APIRouter()

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class PhsAuditRequest(ScanRequest):
    options: Optional[dict] = None


async def _get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> tuple[Optional[str], Optional[str]]:
    """Client-credentials flow via msal. Returns (token, error)."""
    try:
        import msal
    except ImportError:
        return None, "msal library not installed (pip install msal)"
    try:
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority,
        )
        # acquire_token_for_client is sync; run in executor to keep us async
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, lambda: app.acquire_token_for_client(scopes=[GRAPH_SCOPE]))
        if "access_token" in result:
            return result["access_token"], None
        err = result.get("error_description") or result.get("error") or "unknown msal error"
        return None, f"msal: {str(err)[:200]}"
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:120]}"


async def _graph_get(client, token: str, url: str) -> tuple[dict, int, Optional[str]]:
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/json",
               "ConsistencyLevel": "eventual"}
    try:
        r = await client.get(url, headers=headers)
    except Exception as e:
        return {}, 0, f"{type(e).__name__}: {str(e)[:80]}"
    try:
        data = r.json()
    except Exception:
        data = {"_raw": (r.text or "")[:500]}
    return data, r.status_code, None


async def _run(req: PhsAuditRequest, ctx: ScanContext):
    try:
        import httpx
    except ImportError:
        ctx.state["phs_audit_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    opts = req.options or {}
    tenant_id = (opts.get("tenant_id") or "").strip()
    client_id = (opts.get("client_id") or "").strip()
    client_secret = (opts.get("client_secret") or "").strip()
    if not tenant_id or not client_id or not client_secret:
        ctx.state["phs_audit_missing_creds"] = True
        ctx.source("missing tenant_id/client_id/client_secret in options")
        return

    token, terr = await _get_graph_token(tenant_id, client_id, client_secret)
    if not token:
        ctx.state["phs_audit_auth_error"] = terr or "no token"
        ctx.source(f"Graph auth failed: {terr}")
        return

    ctx.state["phs_audit_tenant_id"] = tenant_id
    ctx.state["phs_audit_authenticated"] = True

    async with httpx.AsyncClient(timeout=15.0, verify=True) as client:
        # 1. Organization sync flag
        org_data, org_status, org_err = await _graph_get(
            client, token, f"{GRAPH_BASE}/organization")
        on_prem_sync_enabled = None
        last_sync_dt = None
        on_prem_password_sync_enabled = None
        org_id = None
        if org_status == 200:
            orgs = (org_data.get("value") or [])
            if orgs:
                org = orgs[0]
                org_id = org.get("id")
                on_prem_sync_enabled = org.get("onPremisesSyncEnabled")
                last_sync_dt = org.get("onPremisesLastSyncDateTime")
                # passwordHashSyncEnabled is in beta; try v1.0 first
                on_prem_password_sync_enabled = org.get("onPremisesLastPasswordSyncDateTime") is not None
        else:
            ctx.state["phs_audit_org_error"] = f"GET /organization rc={org_status}"

        ctx.state["phs_audit_on_prem_sync_enabled"] = on_prem_sync_enabled
        ctx.state["phs_audit_last_sync"] = last_sync_dt
        ctx.state["phs_audit_org_id"] = org_id

        # 2. Sync configuration objects via beta endpoint
        sync_config_data, sync_status, _ = await _graph_get(
            client, token, f"{GRAPH_BETA}/directory/onPremisesSynchronization")
        phs_enabled = None
        sync_features: dict = {}
        adconnect_hosts: list[str] = []
        if sync_status == 200:
            for cfg in (sync_config_data.get("value") or []):
                feat = cfg.get("features") or {}
                sync_features.update({k: v for k, v in feat.items()
                                       if isinstance(v, bool)})
                if feat.get("passwordHashSyncEnabled") is True:
                    phs_enabled = True
                elif feat.get("passwordHashSyncEnabled") is False and phs_enabled is None:
                    phs_enabled = False
                # adcs / hostname clues in 'configuration'
                conf = cfg.get("configuration") or {}
                synchost = (conf.get("synchronizationServer") or
                            conf.get("computerAccount") or "")
                if synchost:
                    adconnect_hosts.append(str(synchost))
        else:
            ctx.state["phs_audit_sync_config_status"] = sync_status

        # Fallback: if v1.0 had onPremisesLastPasswordSyncDateTime set, PHS is enabled
        if phs_enabled is None and on_prem_password_sync_enabled:
            phs_enabled = True

        ctx.state["phs_audit_phs_enabled"] = phs_enabled
        ctx.state["phs_audit_sync_features"] = sync_features
        ctx.state["phs_audit_adconnect_hosts"] = adconnect_hosts

        # 3. List MSOL_ service-account-like users via directory query
        # MSOL_ accounts are the synced AD Connect service accounts
        msol_data, _, _ = await _graph_get(
            client, token,
            f"{GRAPH_BASE}/users?$filter=startswith(userPrincipalName,'msol_')"
            "&$select=userPrincipalName,id,onPremisesSyncEnabled"
            "&$top=10")
        msol_accounts = []
        for u in (msol_data.get("value") or []):
            msol_accounts.append({
                "upn": u.get("userPrincipalName"),
                "id": u.get("id"),
                "synced": u.get("onPremisesSyncEnabled"),
            })
        ctx.state["phs_audit_msol_accounts"] = msol_accounts

    ctx.source(f"Graph audit: on_prem_sync={on_prem_sync_enabled} "
               f"PHS={phs_enabled} ADConnect hosts={len(adconnect_hosts)} "
               f"MSOL accounts={len(msol_accounts)}")


INTEL_FIELDS = [
    ("Tenant ID",                "phs_audit_tenant_id"),
    ("Authenticated to Graph?",  "phs_audit_authenticated"),
    ("Organization ID",          "phs_audit_org_id"),
    ("On-prem sync enabled?",    "phs_audit_on_prem_sync_enabled"),
    ("Last on-prem sync",        "phs_audit_last_sync"),
    ("Password Hash Sync?",      "phs_audit_phs_enabled"),
    ("Sync features",            "phs_audit_sync_features"),
    ("AD Connect host(s)",       "phs_audit_adconnect_hosts"),
    ("MSOL_ service accounts",   "phs_audit_msol_accounts"),
]


@router.post("/api/hybrid_identity/password_hash_sync_audit")
async def hybrid_identity_password_hash_sync_audit(req: PhsAuditRequest,
                                                     _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        await _run(req, ctx)
    return await run_scanner(
        host=req.target, tool="password_hash_sync_audit",
        gather_func=_gather,
        finding_rules=PASSWORD_HASH_SYNC_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
