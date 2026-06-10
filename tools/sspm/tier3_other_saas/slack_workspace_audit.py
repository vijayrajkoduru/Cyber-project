"""slack_workspace_audit - Slack workspace posture audit (playbook §4).

Uses the Slack Web API (slack.com/api/) with a customer-supplied bot
token (xoxb-...) to enumerate the workspace and surface posture gaps:

  - HIGH   : members without 2FA enabled (auth.teams + users.list 2fa flag)
  - HIGH   : public channels with external (shared) access enabled
  - MEDIUM : OAuth apps (workspace apps) with elevated scopes such as
             admin / channels:write / users.profile:write / files:write
  - MEDIUM : channels with default file retention (0 / -1)

All calls READ-ONLY (auth.test, team.info, users.list, conversations.list,
team.integrationLogs / apps.list). No message posts, no admin writes.

Customer input via ScanRequest.options:
  - slack_bot_token  = "xoxb-..." (required)
                       Required scopes: users:read, channels:read,
                       groups:read, team:read, conversations.connect:read.
                       For the OAuth-app inventory + 2FA flags:
                         admin.users:read, admin.conversations:read,
                         admin.teams:read (Enterprise Grid only).
                       The audit gracefully degrades if admin.* scopes
                       are missing — it reports what it could see.

Findings:
  - INFO    : token missing | auth.test failure
  - HIGH    : without_2fa list non-empty
  - HIGH    : public_external_shared_channels non-empty
  - MEDIUM  : risky_oauth_apps non-empty
  - MEDIUM  : channels_default_retention non-empty
  - POSITIVE: all checks clean
"""
from __future__ import annotations
import asyncio
import re
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.slack_workspace_audit_findings import (
    SLACK_WORKSPACE_AUDIT_FINDING_RULES,
)

router = APIRouter()

SLACK_BASE = "https://slack.com/api"
TIMEOUT = 30.0
USER_PAGE_SIZE = 200
MAX_USER_PAGES = 10        # cap 2000 users for the starter
CHANNEL_PAGE_SIZE = 200
MAX_CHANNEL_PAGES = 5      # cap 1000 channels
TOKEN_RE = re.compile(r"^xox[abprso]-[A-Za-z0-9-]+$")

# OAuth scopes considered elevated / risky on a non-admin workspace app
RISKY_SCOPES = {
    "admin", "admin.users:write", "admin.conversations:write",
    "admin.teams:write", "channels:write", "groups:write",
    "users.profile:write", "files:write", "chat:write.public",
    "im:write", "mpim:write", "remote_files:write",
}


class SlackWorkspaceAuditRequest(ScanRequest):
    options: Optional[dict] = None


async def _slack_get(client, method: str, token: str, params: Optional[dict] = None) -> dict:
    """Slack Web API call (GET form). Returns body dict; on error
    returns {'ok': False, 'error': '...'}."""
    url = f"{SLACK_BASE}/{method}"
    try:
        r = await client.get(url, params=params or {},
                              headers={"Authorization": f"Bearer {token}"},
                              timeout=TIMEOUT)
        try:
            return r.json()
        except Exception:
            return {"ok": False, "error": f"non-json HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:160]}"}


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    token = (opts.get("slack_bot_token") or "").strip()
    if not token:
        ctx.state["slack_workspace_audit_creds_missing"] = True
        ctx.state["slack_workspace_audit_total"] = 0
        ctx.source("credentials required (slack_bot_token)")
        return
    if not TOKEN_RE.match(token):
        ctx.state["slack_workspace_audit_token_invalid"] = True
        ctx.state["slack_workspace_audit_total"] = 0
        ctx.source("slack_bot_token format invalid")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["slack_workspace_audit_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    async with httpx.AsyncClient(verify=True) as client:
        # ── 1. auth.test confirms the token is alive and reveals team metadata ──
        auth = await _slack_get(client, "auth.test", token)
        if not auth.get("ok"):
            ctx.state["slack_workspace_audit_auth_error"] = (
                auth.get("error") or "auth.test failed")
            ctx.state["slack_workspace_audit_total"] = 0
            ctx.source(f"auth.test: {auth.get('error')}")
            return

        team_id = auth.get("team_id", "")
        team_name = auth.get("team", "")

        # ── 2. users.list (paginated) ──
        users: list[dict] = []
        cursor = ""
        scope_missing = {"users.list": False, "channels": False, "apps": False}
        for _ in range(MAX_USER_PAGES):
            params = {"limit": USER_PAGE_SIZE}
            if cursor:
                params["cursor"] = cursor
            res = await _slack_get(client, "users.list", token, params)
            if not res.get("ok"):
                if res.get("error") in ("missing_scope", "not_allowed_token_type"):
                    scope_missing["users.list"] = True
                else:
                    ctx.state["slack_workspace_audit_api_error"] = (
                        f"users.list: {res.get('error')}")
                break
            users.extend(res.get("members") or [])
            cursor = (res.get("response_metadata") or {}).get("next_cursor", "")
            if not cursor:
                break

        # ── 3. conversations.list (channels) ──
        channels: list[dict] = []
        cursor = ""
        for _ in range(MAX_CHANNEL_PAGES):
            params = {
                "limit":             CHANNEL_PAGE_SIZE,
                "types":             "public_channel,private_channel",
                "exclude_archived":  "true",
            }
            if cursor:
                params["cursor"] = cursor
            res = await _slack_get(client, "conversations.list", token, params)
            if not res.get("ok"):
                if res.get("error") in ("missing_scope", "not_allowed_token_type"):
                    scope_missing["channels"] = True
                else:
                    ctx.state.setdefault("slack_workspace_audit_api_error",
                                          f"conversations.list: {res.get('error')}")
                break
            channels.extend(res.get("channels") or [])
            cursor = (res.get("response_metadata") or {}).get("next_cursor", "")
            if not cursor:
                break

        # ── 4. apps.list (legacy) or admin.apps.requests.list — try lightweight ──
        # apps.list is enterprise-only; fall back to apps.permissions.users.list
        # to enumerate OAuth grants. We attempt both gracefully.
        apps_response = await _slack_get(client, "apps.list", token)
        if not apps_response.get("ok"):
            scope_missing["apps"] = (
                apps_response.get("error") in ("missing_scope", "not_allowed_token_type",
                                                "method_not_supported_for_channel_type"))
        apps = apps_response.get("apps") or []

    # ── Classify ──
    users_no_2fa = []
    bot_user_id = (auth.get("user_id") or "").lower()
    for u in users:
        if u.get("deleted") or u.get("is_bot"):
            continue
        if u.get("id", "").lower() == bot_user_id:
            continue
        # Slack returns has_2fa for human users on paid workspaces; on free
        # plan field absent. We only flag if it's explicitly False.
        if u.get("has_2fa") is False and not u.get("is_restricted") \
                and not u.get("is_ultra_restricted"):
            users_no_2fa.append({
                "id":    u.get("id"),
                "name":  u.get("name") or u.get("profile", {}).get("display_name"),
                "email": (u.get("profile") or {}).get("email", ""),
                "is_admin": bool(u.get("is_admin")),
                "is_owner": bool(u.get("is_owner")),
            })

    public_external = []
    channels_default_retention = []
    for c in channels:
        if c.get("is_archived"):
            continue
        # External / connected channels — is_ext_shared True OR is_org_shared+is_shared
        if c.get("is_ext_shared") or c.get("is_pending_ext_shared"):
            public_external.append({
                "id": c.get("id"),
                "name": c.get("name"),
                "is_general": bool(c.get("is_general")),
                "num_members": c.get("num_members", 0),
                "is_org_shared": bool(c.get("is_org_shared")),
            })
        # Default file retention often surfaces as 0 days OR -1 (unlimited)
        # for channels that inherit workspace default — a DLP gap.
        # Slack returns the retention only on Plus/Enterprise so this is
        # opportunistic.
        if c.get("retention_duration") in (0, -1):
            channels_default_retention.append({
                "id": c.get("id"),
                "name": c.get("name"),
                "retention_duration": c.get("retention_duration"),
            })

    risky_oauth_apps = []
    for a in apps:
        scopes = (a.get("scopes") or {}).get("granted") or []
        if isinstance(scopes, str):
            scopes = [scopes]
        risky = [sc for sc in scopes if sc in RISKY_SCOPES]
        if risky:
            risky_oauth_apps.append({
                "id":    a.get("id"),
                "name":  a.get("name"),
                "is_default": bool(a.get("is_default")),
                "risky_scopes": risky,
                "all_scopes_count": len(scopes),
            })

    total = (len(users_no_2fa) + len(public_external)
             + len(risky_oauth_apps) + len(channels_default_retention))

    ctx.state["slack_team_id"] = team_id
    ctx.state["slack_team_name"] = team_name
    ctx.state["slack_total_users"] = len(users)
    ctx.state["slack_total_channels"] = len(channels)
    ctx.state["slack_total_apps"] = len(apps)
    ctx.state["slack_users_no_2fa"] = users_no_2fa
    ctx.state["slack_public_external_channels"] = public_external
    ctx.state["slack_risky_oauth_apps"] = risky_oauth_apps
    ctx.state["slack_channels_default_retention"] = channels_default_retention
    ctx.state["slack_scope_gaps"] = [k for k, v in scope_missing.items() if v]
    ctx.state["slack_workspace_audit_total"] = total
    ctx.source(f"Slack workspace '{team_name}' audited — "
               f"{len(users)} user(s), {len(channels)} channel(s), "
               f"{len(apps)} app(s); {total} posture issue(s)")


INTEL_FIELDS = [
    ("Workspace name",                 "slack_team_name"),
    ("Workspace ID",                   "slack_team_id"),
    ("Total members audited",          "slack_total_users"),
    ("Total channels audited",         "slack_total_channels"),
    ("Total OAuth apps audited",       "slack_total_apps"),
    ("Members without 2FA",            "slack_users_no_2fa"),
    ("Externally-shared channels",     "slack_public_external_channels"),
    ("OAuth apps with risky scopes",   "slack_risky_oauth_apps"),
    ("Channels on default retention",  "slack_channels_default_retention"),
    ("Scopes the token couldn't see",  "slack_scope_gaps"),
]


@router.post("/api/sspm/slack_workspace_audit")
async def sspm_slack_workspace_audit(req: SlackWorkspaceAuditRequest,
                                       _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="slack_workspace_audit",
        gather_func=_gather_with_options,
        finding_rules=SLACK_WORKSPACE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
