"""pta_agent_audit - Pass-Through Authentication (PTA) agent audit
(playbook §2 #19 PTA agent abuse).

PTA is one of three hybrid-identity auth modes (the others being PHS and
ADFS). When PTA is active, every cloud sign-in is forwarded back to one
of the customer-installed PTA agents (running on on-prem Windows hosts),
which then validates the credential against on-prem AD. The PTA agent
sees the cleartext password on every login.

If an attacker compromises a PTA agent (Mimikatz module pta-mim by
Adam Chester / SpecterOps), they capture every cloud sign-in's plaintext
password. Each PTA agent server is therefore a Tier 0 asset.

This probe authenticates to Microsoft Graph (client credentials) and
queries the Authentication Methods Policy + the
onPremisesPassThroughAuthentication agent collection. For each PTA
agent discovered, we report:
  - Agent ID
  - Agent display name (on-prem hostname)
  - Activation status
  - Last sign-in via the agent

Customer input via ScanRequest.options:
  - options.tenant_id     = Azure AD tenant GUID (required)
  - options.client_id     = App registration client ID (required)
  - options.client_secret = App registration client secret (required)

Required Graph permissions (application):
  - Policy.Read.All
  - OnPremisesPublishingProfiles.Read.All (for the agent collection)

CWE-522 Insufficiently Protected Credentials
MITRE T1556.007 Modify Authentication Process: Hybrid Identity
"""
from __future__ import annotations
import asyncio
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.pta_agent_audit_findings import (
    PTA_AGENT_AUDIT_FINDING_RULES,
)

router = APIRouter()

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class PtaAuditRequest(ScanRequest):
    options: Optional[dict] = None


async def _get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> tuple[Optional[str], Optional[str]]:
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
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, lambda: app.acquire_token_for_client(scopes=[GRAPH_SCOPE]))
        if "access_token" in result:
            return result["access_token"], None
        err = result.get("error_description") or result.get("error") or "unknown msal error"
        return None, f"msal: {str(err)[:200]}"
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:120]}"


async def _graph_get(client, token: str, url: str) -> tuple[dict, int]:
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/json"}
    try:
        r = await client.get(url, headers=headers)
    except Exception as e:
        return {"_transport_error": f"{type(e).__name__}: {str(e)[:80]}"}, 0
    try:
        data = r.json()
    except Exception:
        data = {"_raw": (r.text or "")[:500]}
    return data, r.status_code


async def _run(req: PtaAuditRequest, ctx: ScanContext):
    try:
        import httpx
    except ImportError:
        ctx.state["pta_audit_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    opts = req.options or {}
    tenant_id = (opts.get("tenant_id") or "").strip()
    client_id = (opts.get("client_id") or "").strip()
    client_secret = (opts.get("client_secret") or "").strip()
    if not tenant_id or not client_id or not client_secret:
        ctx.state["pta_audit_missing_creds"] = True
        ctx.source("missing tenant_id/client_id/client_secret in options")
        return

    token, terr = await _get_graph_token(tenant_id, client_id, client_secret)
    if not token:
        ctx.state["pta_audit_auth_error"] = terr or "no token"
        ctx.source(f"Graph auth failed: {terr}")
        return

    ctx.state["pta_audit_tenant_id"] = tenant_id
    ctx.state["pta_audit_authenticated"] = True

    async with httpx.AsyncClient(timeout=15.0, verify=True) as client:
        # 1. onPremisesPublishingProfiles -> 'authentication' agent collection
        # This is the Graph endpoint that lists Application Proxy + PTA agents.
        agents_url = (f"{GRAPH_BETA}/onPremisesPublishingProfiles/authentication"
                       "/agentGroups?$expand=agents")
        agents_data, agents_status = await _graph_get(client, token, agents_url)

        # ZERO-FP: a non-200 status, a transport error, or a response with no
        # 'value' array means the agent collection was NOT readable — this is
        # INCONCLUSIVE, not "0 PTA agents". Asserting a clean POSITIVE off a
        # failed read is a false negative.
        agents_read_ok = (agents_status == 200
                          and "_transport_error" not in agents_data
                          and isinstance(agents_data.get("value"), list))
        ctx.state["pta_audit_agents_read_ok"] = agents_read_ok
        if not agents_read_ok:
            ctx.state["pta_audit_inconclusive"] = True
            err = agents_data.get("_transport_error")
            if not err:
                graph_err = agents_data.get("error")
                if isinstance(graph_err, dict):
                    err = graph_err.get("message")
                else:
                    err = graph_err
            ctx.state["pta_audit_inconclusive_reason"] = (
                f"agentGroups read returned HTTP {agents_status}"
                + (f": {str(err)[:160]}" if err else "")
                + ". OnPremisesPublishingProfiles.Read.All may be missing.")

        pta_agents: list[dict] = []
        agent_groups: list[dict] = []
        for group in (agents_data.get("value") or []):
            group_id = group.get("id")
            group_name = group.get("displayName")
            group_default = group.get("isDefault")
            agent_groups.append({
                "id": group_id, "name": group_name,
                "is_default": group_default,
            })
            for agent in (group.get("agents") or []):
                pta_agents.append({
                    "agent_id": agent.get("id"),
                    "machine_name": (agent.get("machineName") or
                                      agent.get("displayName") or "<unknown>"),
                    "external_ip": agent.get("externalIp"),
                    "status": agent.get("status"),
                    "supported_publishing_types":
                        agent.get("supportedPublishingTypes") or [],
                    "group_name": group_name,
                })

        ctx.state["pta_audit_agent_groups"] = agent_groups
        ctx.state["pta_audit_agents"] = pta_agents
        ctx.state["pta_audit_agent_count"] = len(pta_agents)
        ctx.state["pta_audit_agents_status"] = agents_status

        # 2. Application Proxy connectors live under same publishing tree;
        # filter PTA-only agents by supportedPublishingTypes
        pta_only = [a for a in pta_agents
                     if "authentication" in (a.get("supported_publishing_types") or [])]
        ctx.state["pta_audit_pta_only_agents"] = pta_only
        ctx.state["pta_audit_pta_only_count"] = len(pta_only)

        # 3. Audit log query — recent PTA agent activity (best effort)
        # Sign-ins through PTA show in directory audits: filter past 24h.
        signin_url = (f"{GRAPH_BASE}/auditLogs/signIns?$top=10"
                       "&$filter=authenticationProtocol eq 'passthroughAuthentication'")
        signin_data, signin_status = await _graph_get(client, token, signin_url)
        pta_signins: list[dict] = []
        for s_ in (signin_data.get("value") or [])[:10]:
            pta_signins.append({
                "user_upn": s_.get("userPrincipalName"),
                "ip": s_.get("ipAddress"),
                "app": (s_.get("appDisplayName") or "?"),
                "time": s_.get("createdDateTime"),
                "status": (s_.get("status") or {}).get("errorCode"),
            })
        ctx.state["pta_audit_recent_signins"] = pta_signins
        ctx.state["pta_audit_recent_signins_count"] = len(pta_signins)

    ctx.source(f"Graph audit: {len(pta_agents)} PTA agent(s) discovered; "
               f"{len(pta_only)} PTA-only; "
               f"{len(pta_signins)} recent PTA sign-in(s)")


INTEL_FIELDS = [
    ("Tenant ID",                   "pta_audit_tenant_id"),
    ("Authenticated to Graph?",     "pta_audit_authenticated"),
    ("Agent collection readable?",  "pta_audit_agents_read_ok"),
    ("PTA agent groups",            "pta_audit_agent_groups"),
    ("Total connector agents",      "pta_audit_agent_count"),
    ("PTA-only agents",             "pta_audit_pta_only_count"),
    ("PTA agent details",           "pta_audit_pta_only_agents"),
    ("All publishing agents",       "pta_audit_agents"),
    ("Recent PTA sign-ins",         "pta_audit_recent_signins"),
]


@router.post("/api/hybrid_identity/pta_agent_audit")
async def hybrid_identity_pta_agent_audit(req: PtaAuditRequest,
                                            _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        await _run(req, ctx)
    return await run_scanner(
        host=req.target, tool="pta_agent_audit",
        gather_func=_gather,
        finding_rules=PTA_AGENT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
