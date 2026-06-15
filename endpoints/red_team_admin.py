"""Internal RED TEAM console API — /api/admin/redteam/* — SUPERADMIN ONLY.

This is the ONLY bridge between the dashboard and the isolated `red_team_ops`
adversary-emulation engine (which lives at repo root and is never autoloaded).
It is intentionally locked to the `superadmin` role so paying customers can
NEVER see or drive it — it is an internal owner-only capability.

The engine itself stays isolated: this file imports it on demand and calls its
public functions; it does not move any engine code into the app. The hard
non-destructive + authorized-scope safety contract is enforced inside the
engine (scope.py / safety.py) and is surfaced — never bypassed — here.
"""
from __future__ import annotations

import os
import sys

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from tools._shared import verify_token

router = APIRouter()

# red_team_ops lives at the repo root (NOT under tools/ or endpoints/), so the
# autoloader never touches it. Make sure the repo root is importable, then pull
# in the engine's public surface on demand.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from red_team_ops import attack_catalog as cat        # noqa: E402
from red_team_ops import engine as rt_engine          # noqa: E402
from red_team_ops import report as rt_report          # noqa: E402
from red_team_ops import scope as rt_scope            # noqa: E402
from red_team_ops.safety import (                     # noqa: E402
    ALLOWED_IMPACTS, FORBIDDEN, assert_technique_safe, contract_text,
)
from red_team_ops.safety import SafetyViolation       # noqa: E402


def verify_superadmin(payload=Depends(verify_token)):
    """Owner-only gate. Offensive emulation is never exposed to customers."""
    if payload.get("role") != "superadmin":
        raise HTTPException(403, "Superadmin role required — Red Team is internal only")
    return payload


def _technique_view(t: dict) -> dict:
    """Public-safe view of a catalog technique, with emulation/blocked status."""
    blocked, reason = False, ""
    try:
        assert_technique_safe(t, "emulation")
    except SafetyViolation as sv:
        blocked, reason = True, str(sv)
    return {
        "id": t["id"], "name": t["name"], "tactic": t["tactic"],
        "desc": t.get("desc", ""), "emulation": t.get("emulation", ""),
        "detection": t.get("detection", ""), "risk": t.get("risk", []),
        "atomic_safe": bool(t.get("atomic_safe")),
        "blocked": blocked, "blocked_reason": reason,
    }


# ── Catalog (scenarios + techniques + contract) ──────────────────────────────
@router.get("/api/admin/redteam/catalog")
async def redteam_catalog(_=Depends(verify_superadmin)):
    scenarios = []
    for name in cat.all_scenarios():
        steps = [_technique_view(t) for t in cat.scenario(name)]
        meta = cat.scenario_meta(name)
        scenarios.append({
            "name": name,
            "label": meta.get("label", name),
            "adversary": meta.get("adversary", ""),
            "description": meta.get("description", ""),
            "steps": steps,
            "technique_count": len(steps),
            "blocked_count": sum(1 for s in steps if s["blocked"]),
            "tactics": sorted({s["tactic"] for s in steps}),
        })
    return {
        "tactics": cat.TACTICS,
        "scenarios": scenarios,
        "techniques": [_technique_view(t) for t in cat.TECHNIQUES],
        "technique_count": len(cat.TECHNIQUES),
        "impact_levels": list(ALLOWED_IMPACTS),
        "forbidden": FORBIDDEN,
        "contract": contract_text(),
        "curated": True,
    }


# ── Engagements ──────────────────────────────────────────────────────────────
@router.get("/api/admin/redteam/engagements")
async def redteam_list_engagements(_=Depends(verify_superadmin)):
    out = []
    for eid in rt_scope.list_engagements():
        try:
            out.append(rt_scope.load_engagement(eid))
        except Exception:
            continue
    return {"engagements": out}


class EngagementRequest(BaseModel):
    client: str
    authorized_by: str
    in_scope: list[str]
    out_of_scope: list[str] | None = None
    impact_level: str = "emulation"
    window_days: int = 14
    auth_ref: str = ""
    accept_roe: bool = False


@router.post("/api/admin/redteam/engagements")
async def redteam_create_engagement(req: EngagementRequest, _=Depends(verify_superadmin)):
    try:
        eng = rt_scope.create_engagement(
            client=req.client, authorized_by=req.authorized_by,
            in_scope=req.in_scope, out_of_scope=req.out_of_scope or [],
            impact_level=req.impact_level, window_days=req.window_days,
            auth_ref=req.auth_ref or "",
        )
        if req.accept_roe:
            eng = rt_scope.acknowledge_roe(eng["id"])
    except rt_scope.ScopeError as e:
        raise HTTPException(400, str(e))
    return eng


@router.post("/api/admin/redteam/engagements/{engagement_id}/ack")
async def redteam_ack_roe(engagement_id: str, _=Depends(verify_superadmin)):
    try:
        return rt_scope.acknowledge_roe(engagement_id)
    except rt_scope.ScopeError as e:
        raise HTTPException(404, str(e))


# ── Run a scenario (scope + safety gated inside the engine) ───────────────────
class RunRequest(BaseModel):
    engagement_id: str
    scenario: str
    target: str


@router.post("/api/admin/redteam/run")
async def redteam_run(req: RunRequest, _=Depends(verify_superadmin)):
    try:
        run = rt_engine.run_scenario(req.engagement_id, req.scenario, req.target)
    except (rt_scope.ScopeError, ValueError) as e:
        # Out-of-scope / RoE-not-acked / expired / unknown scenario -> REFUSED.
        raise HTTPException(400, f"REFUSED: {e}")
    return run


# ── Runs + report ────────────────────────────────────────────────────────────
@router.get("/api/admin/redteam/runs/{engagement_id}")
async def redteam_runs(engagement_id: str, _=Depends(verify_superadmin)):
    out = []
    for p in rt_engine.latest_runs(engagement_id):
        try:
            r = rt_engine.load_run(p)
            out.append({
                "scenario": r.get("scenario"), "target": r.get("target"),
                "started_at": r.get("started_at"), "finished_at": r.get("finished_at"),
                "emulated": r.get("emulated"), "blocked": r.get("blocked"),
                "tactics_covered": r.get("tactics_covered", []),
            })
        except Exception:
            continue
    return {"runs": out}


@router.get("/api/admin/redteam/report/{engagement_id}")
async def redteam_report(engagement_id: str, _=Depends(verify_superadmin)):
    runs = rt_engine.latest_runs(engagement_id)
    if not runs:
        raise HTTPException(404, "no runs for that engagement")
    run = rt_engine.load_run(runs[-1])
    return {"run": run, "markdown": rt_report.render_markdown(run)}


def register(app):
    app.include_router(router)
