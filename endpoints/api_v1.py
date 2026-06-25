"""Public programmatic API v1 (Phase 2.4).

Authenticated by an org-scoped API key (X-API-Key header, or
Authorization: Bearer vl_live_...). Read-only in v1: pull scan results into a
SIEM / ticketing / CI pipeline. Every response is scoped to the key's org, so
one tenant can never read another's data. Scan-triggering via API is a later
slice (the scan orchestrator is streaming/long-running).
"""
import os
import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query

from tools._shared import api_principal
from tools._core.flow_scope import caller_org, org_can_see

router = APIRouter()

_BASE = Path(os.environ.get("VL_FLOW_DIR", "/app/vl_flow_data"))
_HIST = _BASE / "history"


def _safe(s):
    return "".join(c for c in (s or "") if c.isalnum() or c in ".-_")


@router.get("/api/v1/me")
def v1_me(principal=Depends(api_principal)):
    """Verify the API key — returns the org it is bound to and its role."""
    from tools.auth._orgs import get_org
    oid = caller_org(principal)
    org = get_org(oid) or {}
    return {"auth": "api_key", "org_id": oid, "org_name": org.get("name"),
            "role": principal.get("org_role"), "key_name": principal.get("key_name")}


@router.get("/api/v1/scans")
def v1_scans(target: str = Query(..., description="target/host the scans were run against"),
             principal=Depends(api_principal)):
    """List saved scans for a target that belong to the caller's org."""
    oid = caller_org(principal)
    d = _HIST / _safe(target)
    out = []
    if d.exists():
        for f in sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not org_can_see(rec, oid):
                continue
            out.append({"scan_id": rec.get("scan_id"), "target": rec.get("target"),
                        "timestamp": rec.get("timestamp")})
    return {"target": target, "count": len(out), "scans": out}


@router.get("/api/v1/scan")
def v1_scan(target: str = Query(...), scan_id: str = Query(...),
            principal=Depends(api_principal)):
    """Fetch one saved scan's findings (org-scoped)."""
    oid = caller_org(principal)
    f = _HIST / _safe(target) / f"{_safe(scan_id)}.json"
    if not f.exists():
        raise HTTPException(404, "scan not found")
    try:
        rec = json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        raise HTTPException(404, "scan not found")
    if not org_can_see(rec, oid):
        raise HTTPException(404, "scan not found")
    findings = []
    for tool, data in (rec.get("results") or {}).items():
        if isinstance(data, dict):
            for fn in (data.get("findings") or []):
                findings.append({
                    "tool": tool,
                    "name": fn.get("name") or fn.get("detail") or "",
                    "severity": (fn.get("severity") or "INFO").upper(),
                    "evidence": (fn.get("evidence") or "")[:500],
                    "cwe": fn.get("cwe", ""),
                    "remediation": (fn.get("remediation") or "")[:500],
                })
    return {"scan_id": rec.get("scan_id"), "target": rec.get("target"),
            "timestamp": rec.get("timestamp"), "finding_count": len(findings),
            "findings": findings}


def register(app):
    app.include_router(router)
