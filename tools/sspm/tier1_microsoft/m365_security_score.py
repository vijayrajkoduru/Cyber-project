"""m365_security_score - Microsoft 365 Secure Score readout (playbook §1 #2).

Uses MSAL (msal-python) with the customer's app-registration credentials
(client credentials / app-only flow) to obtain a Microsoft Graph access
token, then queries:

  GET https://graph.microsoft.com/v1.0/security/secureScores?$top=1
  GET https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles

The first call returns the tenant's latest secure-score snapshot
(currentScore / maxScore / activeUserCount / licensedUserCount).
The second call enumerates all control profiles so we can surface the
controls with the lowest implementation status (e.g. MFA enforcement,
conditional access, mail-flow rules).

Customer input via ScanRequest.options:
  - tenant_id           = Entra tenant GUID (required)
  - client_id           = App registration client_id (required)
  - client_secret       = App registration client secret (required)
                          Required Graph scopes (application):
                            SecurityEvents.Read.All
                            (or the lower-priv SecureScores.Read.All)
  - graph_base          = optional Graph base URL (default
                          https://graph.microsoft.com)

READ-ONLY: only GET calls; no posture changes are written.

Findings:
  - INFO       : credentials missing  |  Graph auth failed
  - LOW        : current score < 70% of max
  - MEDIUM     : per "Not Implemented" control with maxScore >= 5
  - HIGH       : per "Not Implemented" control mapped to MFA / CA / legacy auth
"""
from __future__ import annotations
import asyncio
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.m365_security_score_findings import (
    M365_SECURITY_SCORE_FINDING_RULES,
)

router = APIRouter()

# Controls flagged HIGH when "Not Implemented" — these map directly to
# the highest-impact M365 posture failures (MFA off, legacy auth open,
# conditional access bypass) per CISA / ScubaGear baselines.
_HIGH_RISK_CONTROL_NAMES = (
    "mfa", "multifactor", "conditional access", "legacy authentication",
    "block legacy", "self-service password reset", "password reset",
    "atp safe attachments", "atp safe links", "anti-phishing",
    "privileged identity", "global admin",
)


class M365SecurityScoreRequest(ScanRequest):
    options: Optional[dict] = None


async def _msal_token(tenant_id: str, client_id: str,
                       client_secret: str) -> dict:
    """Acquire a Graph app-only token via MSAL ConfidentialClientApplication.
    Returns the raw MSAL result dict — caller checks for 'access_token'."""
    try:
        import msal  # image-installed
    except ImportError:
        return {"error": "msal not installed"}

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scope = ["https://graph.microsoft.com/.default"]

    def _acquire():
        try:
            app = msal.ConfidentialClientApplication(
                client_id=client_id,
                client_credential=client_secret,
                authority=authority,
            )
            return app.acquire_token_for_client(scopes=scope)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)[:160]}"}

    # MSAL is sync — push it to a thread so we don't block the event loop.
    return await asyncio.to_thread(_acquire)


async def _graph_get(client, url: str, token: str) -> dict:
    """Issue a Graph GET with bearer auth. Returns a JSON dict; on error
    returns {'_error': '...', '_status': N}."""
    try:
        r = await client.get(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }, timeout=30.0)
        if r.status_code >= 400:
            try:
                body = r.json()
            except Exception:
                body = {"text": r.text[:400]}
            return {"_error": f"HTTP {r.status_code}", "_status": r.status_code,
                    "_body": body}
        return r.json()
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {str(e)[:160]}", "_status": 0}


def _classify_control(name: str, max_score) -> str:
    n = (name or "").lower()
    if any(k in n for k in _HIGH_RISK_CONTROL_NAMES):
        return "HIGH"
    try:
        m = float(max_score or 0)
    except (TypeError, ValueError):
        m = 0
    if m >= 5:
        return "MEDIUM"
    return "LOW"


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    tenant_id = (opts.get("tenant_id") or "").strip()
    client_id = (opts.get("client_id") or "").strip()
    client_secret = (opts.get("client_secret") or "").strip()
    graph_base = (opts.get("graph_base") or "https://graph.microsoft.com").rstrip("/")

    if not tenant_id or not client_id or not client_secret:
        ctx.state["m365_secure_score_creds_missing"] = True
        ctx.state["m365_secure_score_total"] = 0
        ctx.source("credentials required (tenant_id + client_id + client_secret)")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["m365_secure_score_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    # ── 1. Acquire Graph app-only token via MSAL ──
    token_resp = await _msal_token(tenant_id, client_id, client_secret)
    if "error" in token_resp and "access_token" not in token_resp:
        ctx.state["m365_secure_score_auth_error"] = (
            token_resp.get("error_description") or token_resp.get("error"))
        ctx.state["m365_secure_score_total"] = 0
        ctx.source("MSAL auth failed")
        return
    access_token = token_resp.get("access_token")
    if not access_token:
        ctx.state["m365_secure_score_auth_error"] = "no access_token in MSAL response"
        ctx.state["m365_secure_score_total"] = 0
        ctx.source("MSAL: no token")
        return

    # ── 2. Query Graph: secure scores + control profiles ──
    score_url = f"{graph_base}/v1.0/security/secureScores?$top=1"
    profile_url = f"{graph_base}/v1.0/security/secureScoreControlProfiles?$top=200"

    async with httpx.AsyncClient(verify=True) as client:
        score_resp, profile_resp = await asyncio.gather(
            _graph_get(client, score_url, access_token),
            _graph_get(client, profile_url, access_token),
        )

    if score_resp.get("_error"):
        ctx.state["m365_secure_score_api_error"] = (
            f"secureScores: {score_resp['_error']}")
        ctx.state["m365_secure_score_total"] = 0
        ctx.source(f"Graph API error: {score_resp['_error']}")
        return

    scores = (score_resp.get("value") or [])
    if not scores:
        ctx.state["m365_secure_score_no_data"] = True
        ctx.state["m365_secure_score_total"] = 0
        ctx.source("Graph returned no secureScores entries")
        return

    latest = scores[0]
    current = latest.get("currentScore") or 0
    maxs = latest.get("maxScore") or 0
    score_pct = round((current / maxs) * 100, 1) if maxs else 0.0
    active_users = latest.get("activeUserCount") or 0
    licensed_users = latest.get("licensedUserCount") or 0
    created = latest.get("createdDateTime", "")
    score_id = latest.get("id", "")

    # Pull "Not Implemented" controls from the secureScore.controlScores array
    weak_controls = []
    for c in (latest.get("controlScores") or []):
        impl = (c.get("implementationStatus") or "").lower()
        cscore = c.get("score") or 0
        cmax = 0
        # cross-ref control profile maxScore by controlName
        cname = c.get("controlName", "")
        # We'll enrich with profile maxScore in next step
        weak_controls.append({
            "name": cname,
            "category": c.get("controlCategory", ""),
            "current": cscore,
            "max": cmax,
            "implementation_status": c.get("implementationStatus", ""),
            "description": (c.get("description", "") or "")[:240],
        })

    # Enrich with maxScore + category from profiles, build "Not Implemented" list
    by_name = {}
    if not profile_resp.get("_error"):
        for p in (profile_resp.get("value") or []):
            t = p.get("title") or p.get("id") or ""
            by_name[t.lower()] = p
    not_implemented = []
    for c in weak_controls:
        prof = by_name.get((c.get("name") or "").lower())
        if prof:
            try:
                c["max"] = float(prof.get("maxScore") or 0)
            except (TypeError, ValueError):
                pass
            c["title"] = prof.get("title") or c.get("name")
            c["remediation"] = (prof.get("remediation") or "")[:400]
            c["service"] = prof.get("service") or ""
        if (c.get("implementation_status") or "").lower() == "notimplemented" \
                or (c.get("current") or 0) == 0:
            sev = _classify_control(c.get("name") or "", c.get("max") or 0)
            c["severity"] = sev
            not_implemented.append(c)

    # Sort weakest first (highest max + zero current)
    not_implemented.sort(key=lambda x: -(x.get("max") or 0))

    ctx.state["m365_score_id"] = score_id
    ctx.state["m365_score_created"] = created
    ctx.state["m365_score_current"] = current
    ctx.state["m365_score_max"] = maxs
    ctx.state["m365_score_pct"] = score_pct
    ctx.state["m365_active_users"] = active_users
    ctx.state["m365_licensed_users"] = licensed_users
    ctx.state["m365_not_implemented_controls"] = not_implemented[:40]
    ctx.state["m365_total_controls"] = len(weak_controls)
    ctx.state["m365_secure_score_total"] = len(not_implemented)
    ctx.source(f"Graph secureScores OK — {current}/{maxs} ({score_pct}%), "
               f"{len(not_implemented)} not-implemented control(s)")


INTEL_FIELDS = [
    ("Secure score (current)",      "m365_score_current"),
    ("Secure score (max possible)", "m365_score_max"),
    ("Secure score (%)",            "m365_score_pct"),
    ("Active users",                "m365_active_users"),
    ("Licensed users",              "m365_licensed_users"),
    ("Total controls evaluated",    "m365_total_controls"),
    ("Not-implemented controls",    "m365_not_implemented_controls"),
    ("Score snapshot timestamp",    "m365_score_created"),
]


@router.post("/api/sspm/m365_security_score")
async def sspm_m365_security_score(req: M365SecurityScoreRequest,
                                     _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="m365_security_score",
        gather_func=_gather_with_options,
        finding_rules=M365_SECURITY_SCORE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
