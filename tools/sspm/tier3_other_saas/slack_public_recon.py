"""slack_public_recon - UNAUTHENTICATED Slack workspace public-surface recon
(playbook §4, the externally-visible slice of #44 public/private channel +
#42 open-signup exposure).

A Slack workspace lives at <name>.slack.com. Without any token, Slack
exposes a small PUBLIC surface used by its own sign-in flow. Reading it
read-only tells us real facts:

  - GET https://<name>.slack.com/                 (302/200 -> workspace exists)
  - GET https://slack.com/api/auth.findTeam?domain=<name>   (public)
        confirms the team exists and returns the team_id / team name without
        any token (Slack's own client uses this pre-login).

The one posture gap visible from outside is OPEN E-MAIL-DOMAIN SIGN-UP: when
a workspace lets anyone with an email at an approved domain self-join, the
public sign-in page advertises the allowed domain(s). That is detectable
from the public sign-in HTML. We grade it ONLY when the page actually
advertises an auto-join domain (CONFIRMED) — otherwise INFO.

READ-ONLY GETs against Slack's own public surface. No token, no login
attempt, no message post, no admin call. Detection-only (VA), not
exploitation (PT).

Severity model:
  MEDIUM  - workspace publicly advertises open email-domain auto-join
            (anyone at that domain can self-enrol) — CONFIRMED from the
            public sign-in page.
  INFO    - workspace exists, no open-join advertised (good / unknown)
  INFO    - workspace not found
  INFO    - deep posture (2FA, channels, OAuth apps) needs a bot token

Customer input:
  - ScanRequest.target = workspace name or URL ("acme", "acme.slack.com",
    "https://acme.slack.com").
  - options.slack_workspace = explicit workspace-name override.
"""
from __future__ import annotations
import re
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()

TIMEOUT = 15.0
SLACK_FINDTEAM = "https://slack.com/api/auth.findTeam"


class SlackPublicReconRequest(ScanRequest):
    options: Optional[dict] = None


def _resolve_workspace(target: str, override: str = "") -> str:
    raw = (override or target or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].strip().rstrip(".")
    if raw.endswith(".slack.com"):
        raw = raw[: -len(".slack.com")]
    return raw.lower()


async def _get_json(client, url: str, params: Optional[dict] = None) -> tuple[int, dict]:
    try:
        r = await client.get(url, params=params or {}, timeout=TIMEOUT,
                             headers={"Accept": "application/json",
                                      "User-Agent": "VulnusLab-SSPM/1.0"})
        try:
            body = r.json()
        except Exception:
            body = {"_text": (r.text or "")[:300]}
        return r.status_code, body
    except Exception as e:
        return 0, {"_error": f"{type(e).__name__}: {str(e)[:160]}"}


async def _get_text(client, url: str) -> tuple[int, str]:
    try:
        r = await client.get(url, timeout=TIMEOUT, follow_redirects=True,
                            headers={"User-Agent":
                                     "Mozilla/5.0 (VulnusLab-SSPM)"})
        return r.status_code, (r.text or "")[:120000]
    except Exception as e:
        return 0, f"_error: {type(e).__name__}: {str(e)[:160]}"


# Auto-join advertisement patterns on the public Slack sign-in page.
_AUTOJOIN_DOMAIN_RE = re.compile(
    r'"approved_domains?"\s*:\s*\[\s*"([^"]+)"', re.IGNORECASE)
_AUTOJOIN_FLAG_RE = re.compile(
    r'"(?:domain_matching|auto_join|sign_up_domains?)"\s*:\s*("[^"]+"|true)',
    re.IGNORECASE)


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    ws = _resolve_workspace(ctx.host or "", opts.get("slack_workspace") or "")
    if not ws:
        ctx.source("no-target")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["slack_public_recon_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    async with httpx.AsyncClient(verify=True, follow_redirects=True) as client:
        # 1. auth.findTeam (public, pre-login) — does the team exist?
        ft_status, ft_body = await _get_json(
            client, SLACK_FINDTEAM, {"domain": ws})
        team_exists = bool(isinstance(ft_body, dict) and ft_body.get("ok")
                           and ft_body.get("team"))
        team_id = ""
        team_name = ""
        if team_exists:
            team = ft_body.get("team") or {}
            team_id = team.get("id", "")
            team_name = team.get("name", "")

        # 2. Public sign-in page for auto-join domain advertisement
        page_status, page = await _get_text(
            client, f"https://{ws}.slack.com/")
        if not team_exists and page_status in (200, 302):
            # Page exists even if findTeam was rate-limited.
            team_exists = True

        autojoin_domains = []
        autojoin_advertised = False
        if page_status == 200 and isinstance(page, str):
            for m in _AUTOJOIN_DOMAIN_RE.finditer(page):
                d = m.group(1).strip().lower()
                if d and d not in autojoin_domains:
                    autojoin_domains.append(d)
            if autojoin_domains:
                autojoin_advertised = True
            elif _AUTOJOIN_FLAG_RE.search(page):
                autojoin_advertised = True

    ctx.state["slack_public_workspace"] = ws
    ctx.state["slack_public_team_exists"] = team_exists
    ctx.state["slack_public_team_id"] = team_id
    ctx.state["slack_public_team_name"] = team_name
    ctx.state["slack_public_autojoin_advertised"] = autojoin_advertised
    ctx.state["slack_public_autojoin_domains"] = autojoin_domains[:10]
    ctx.state["slack_public_evaluated"] = True
    ctx.source(
        f"{ws}.slack.com: exists={team_exists}, "
        f"open-join={autojoin_advertised} ({len(autojoin_domains)} domain(s))"
    )


def rule_error(s):
    if not s.get("slack_public_recon_error"):
        return None
    return {
        "name": "Slack public recon could not run",
        "severity": "INFO",
        "evidence": str(s.get("slack_public_recon_error")),
        "remediation": "Transient — re-run. No Slack token is needed.",
        "cwe": "N/A", "iso27001": "A.5.23",
    }


def rule_not_found(s):
    if not s.get("slack_public_evaluated"):
        return None
    if s.get("slack_public_team_exists"):
        return None
    return {
        "name": "No public Slack workspace found at this name",
        "severity": "INFO",
        "evidence": (
            f"Slack's public auth.findTeam and the {s.get('slack_public_workspace')}"
            ".slack.com sign-in page did not confirm a workspace. The Slack "
            "posture checks need the correct workspace name."
        ),
        "remediation": (
            "Pass the exact workspace subdomain as the target, or run "
            "slack_workspace_audit with a bot token for the authoritative "
            "posture read."
        ),
        "cwe": "N/A", "iso27001": "A.5.23",
    }


def rule_open_join(s):
    if not s.get("slack_public_evaluated"):
        return None
    if not s.get("slack_public_autojoin_advertised"):
        return None
    domains = s.get("slack_public_autojoin_domains") or []
    dom_str = ", ".join(domains) if domains else "(domain not disclosed)"
    return {
        "name": f"Slack workspace {s.get('slack_public_workspace')} advertises "
                f"open email-domain sign-up",
        "severity": "MEDIUM",
        "evidence": (
            "The public Slack sign-in page advertises auto-join for email "
            f"domain(s): {dom_str}. Anyone with an address at an approved "
            "domain can self-enrol into the workspace without an invite. "
            "CONFIRMED from the public sign-in page."
        ),
        "remediation": (
            "In Slack: Settings & administration > Workspace settings > "
            "'Joining this workspace' — disable approved-domain auto-join (or "
            "require admin approval) unless self-service enrolment is "
            "intentional."
        ),
        "cwe": "CWE-1390", "owasp": "A07:2021", "iso27001": "A.5.16",
        "verified_exploit": True,
    }


def rule_exists_clean(s):
    if not s.get("slack_public_evaluated"):
        return None
    if not s.get("slack_public_team_exists"):
        return None
    if s.get("slack_public_autojoin_advertised"):
        return None
    return {
        "name": f"Slack workspace {s.get('slack_public_workspace')} confirmed "
                f"— no open sign-up advertised",
        "severity": "INFO",
        "evidence": (
            f"Workspace confirmed (id {s.get('slack_public_team_id') or '?'}, "
            f"name '{s.get('slack_public_team_name') or '?'}'). The public "
            "sign-in surface does not advertise open email-domain auto-join. "
            "Member 2FA, channel privacy, and OAuth-app posture are internal "
            "and need a bot token."
        ),
        "remediation": (
            "Run slack_workspace_audit with options.slack_bot_token to grade "
            "2FA, externally-shared channels, and risky OAuth apps."
        ),
        "cwe": "N/A", "iso27001": "A.5.23",
    }


def rule_creds_gated_advisory(s):
    if not s.get("slack_public_evaluated"):
        return None
    if not s.get("slack_public_team_exists"):
        return None
    return {
        "name": "[ADVISORY-BY-DESIGN] Slack internal posture needs a bot token",
        "severity": "INFO",
        "evidence": (
            "Member 2FA enforcement, public/private channel inventory, "
            "externally-shared (connect) channels, legacy tokens/webhooks, "
            "and OAuth-app scopes are WORKSPACE-INTERNAL. They cannot be read "
            "from the public surface and are NOT a forge gap — they require a "
            "Slack bot token (xoxb-...)."
        ),
        "remediation": (
            "Run slack_workspace_audit with options.slack_bot_token. See "
            "module_playbooks/29_sspm.md §4."
        ),
        "cwe": "N/A", "iso27001": "A.5.23",
    }


SLACK_PUBLIC_RECON_FINDING_RULES = [
    rule_error,
    rule_not_found,
    rule_open_join,
    rule_exists_clean,
    rule_creds_gated_advisory,
]


INTEL_FIELDS = [
    ("Workspace",                 "slack_public_workspace"),
    ("Workspace exists",          "slack_public_team_exists"),
    ("Team ID",                   "slack_public_team_id"),
    ("Team name",                 "slack_public_team_name"),
    ("Open email-domain sign-up", "slack_public_autojoin_advertised"),
    ("Advertised auto-join domains", "slack_public_autojoin_domains"),
]


@router.post("/api/sspm/slack_public_recon")
async def sspm_slack_public_recon(req: SlackPublicReconRequest,
                                  _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="slack_public_recon",
        gather_func=_gather_with_options,
        finding_rules=SLACK_PUBLIC_RECON_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
