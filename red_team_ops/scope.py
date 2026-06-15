"""Engagement + authorized-scope + RoE gate.

An engagement is a JSON file under red_team_ops/engagements/. Nothing in the
engine runs against a target unless that target is in the engagement's
in-scope list, not in the out-of-scope list, and the RoE is acknowledged.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import uuid

from .safety import ALLOWED_IMPACTS, IMPACT_EMULATION

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engagements")


class ScopeError(Exception):
    pass


def _ensure_dir():
    os.makedirs(_DIR, exist_ok=True)


def _path(engagement_id: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", engagement_id or "")
    return os.path.join(_DIR, f"{safe}.json")


def create_engagement(client: str, authorized_by: str, in_scope: list[str],
                      out_of_scope: list[str] | None = None,
                      impact_level: str = IMPACT_EMULATION,
                      window_days: int = 14, auth_ref: str = "") -> dict:
    if impact_level not in ALLOWED_IMPACTS:
        raise ScopeError(f"impact_level must be one of {ALLOWED_IMPACTS}")
    if not in_scope:
        raise ScopeError("at least one in-scope target is required")
    _ensure_dir()
    now = datetime.datetime.now(datetime.timezone.utc)
    eng = {
        "id": "eng-" + uuid.uuid4().hex[:10],
        "client": client,
        "authorized_by": authorized_by,
        "authorization_reference": auth_ref,
        "in_scope": [s.strip() for s in in_scope if s.strip()],
        "out_of_scope": [s.strip() for s in (out_of_scope or []) if s.strip()],
        "impact_level": impact_level,
        "created_at": now.isoformat(),
        "expires_at": (now + datetime.timedelta(days=window_days)).isoformat(),
        "roe_acknowledged": False,
    }
    with open(_path(eng["id"]), "w", encoding="utf-8") as fh:
        json.dump(eng, fh, indent=2)
    return eng


def load_engagement(engagement_id: str) -> dict:
    p = _path(engagement_id)
    if not os.path.exists(p):
        raise ScopeError(f"engagement {engagement_id} not found")
    with open(p, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_engagement(eng: dict) -> None:
    with open(_path(eng["id"]), "w", encoding="utf-8") as fh:
        json.dump(eng, fh, indent=2)


def acknowledge_roe(engagement_id: str) -> dict:
    eng = load_engagement(engagement_id)
    eng["roe_acknowledged"] = True
    eng["roe_acknowledged_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save_engagement(eng)
    return eng


def list_engagements() -> list[str]:
    _ensure_dir()
    return sorted(f[:-5] for f in os.listdir(_DIR) if f.endswith(".json"))


def _matches(target: str, rule: str) -> bool:
    target = (target or "").strip().lower()
    rule = (rule or "").strip().lower()
    if not target or not rule:
        return False
    if rule == target:
        return True
    # CIDR / IP rule
    try:
        net = ipaddress.ip_network(rule, strict=False)
        return ipaddress.ip_address(target) in net
    except ValueError:
        pass
    # domain suffix (rule "example.com" matches "app.example.com")
    if target == rule or target.endswith("." + rule):
        return True
    # wildcard "*.example.com"
    if rule.startswith("*.") and (target == rule[2:] or target.endswith("." + rule[2:])):
        return True
    return False


def in_scope(eng: dict, target: str) -> bool:
    if any(_matches(target, r) for r in eng.get("out_of_scope", [])):
        return False
    return any(_matches(target, r) for r in eng.get("in_scope", []))


def assert_can_run(eng: dict, target: str) -> None:
    """Gate every action: RoE acknowledged, not expired, target in scope."""
    if not eng.get("roe_acknowledged"):
        raise ScopeError("RoE not acknowledged — run `init`/`ack` first.")
    exp = eng.get("expires_at")
    if exp:
        try:
            if datetime.datetime.fromisoformat(exp) < datetime.datetime.now(datetime.timezone.utc):
                raise ScopeError("engagement window has expired.")
        except ValueError:
            pass
    if not in_scope(eng, target):
        raise ScopeError(f"target {target!r} is OUT OF SCOPE for engagement {eng['id']}.")
