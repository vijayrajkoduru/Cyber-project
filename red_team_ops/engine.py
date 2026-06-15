"""Scenario / attack-path emulation runner.

For each technique in a scenario the engine: (1) enforces the scope gate,
(2) enforces the safety contract, and (3) records a NON-DESTRUCTIVE emulation
step (plan + log). Destructive/forbidden techniques are recorded as BLOCKED —
they become detection/resilience objectives, never actions.

This produces an emulation run (a kill-chain tabletop with ATT&CK mapping and
detection guidance), not a live attack.
"""
from __future__ import annotations

import datetime
import json
import os

from . import attack_catalog as cat
from . import scope as scopemod
from .safety import assert_technique_safe, SafetyViolation, contract_text

_RUNDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engagements", "_runs")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run_scenario(engagement_id: str, scenario_name: str, target: str) -> dict:
    eng = scopemod.load_engagement(engagement_id)
    # Scope gate — raises ScopeError if not authorized / out of scope / expired.
    scopemod.assert_can_run(eng, target)

    techniques = cat.scenario(scenario_name)
    if not techniques:
        raise ValueError(f"unknown scenario {scenario_name!r}; "
                         f"choose from {cat.all_scenarios()}")

    impact = eng.get("impact_level", "emulation")
    steps = []
    for seq, t in enumerate(techniques, 1):
        step = {"seq": seq, "id": t["id"], "name": t["name"], "tactic": t["tactic"],
                "emulation": t["emulation"], "detection": t["detection"],
                "timestamp": _now()}
        try:
            assert_technique_safe(t, impact)
            step["status"] = "emulated"
            step["note"] = f"[{impact}] {t['emulation']}"
        except SafetyViolation as sv:
            step["status"] = "blocked"
            step["note"] = f"BLOCKED by safety contract: {sv}"
        steps.append(step)

    run = {
        "engagement_id": engagement_id,
        "client": eng.get("client"),
        "target": target,
        "scenario": scenario_name,
        "impact_level": impact,
        "contract": contract_text(),
        "started_at": steps[0]["timestamp"] if steps else _now(),
        "finished_at": _now(),
        "steps": steps,
        "emulated": sum(1 for s in steps if s["status"] == "emulated"),
        "blocked": sum(1 for s in steps if s["status"] == "blocked"),
        "tactics_covered": sorted({s["tactic"] for s in steps if s["status"] == "emulated"}),
    }

    os.makedirs(_RUNDIR, exist_ok=True)
    fn = f"{engagement_id}_{scenario_name}_{steps and steps[0]['timestamp'][:10] or 'run'}.json".replace(":", "")
    with open(os.path.join(_RUNDIR, fn), "w", encoding="utf-8") as fh:
        json.dump(run, fh, indent=2)
    run["_saved"] = os.path.join(_RUNDIR, fn)
    return run


def latest_runs(engagement_id: str) -> list[str]:
    if not os.path.isdir(_RUNDIR):
        return []
    return sorted(os.path.join(_RUNDIR, f) for f in os.listdir(_RUNDIR)
                  if f.startswith(engagement_id) and f.endswith(".json"))


def load_run(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
