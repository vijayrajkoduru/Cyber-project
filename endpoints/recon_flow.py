"""VL-FLOW Session 1: Scan history + diff endpoints.
Routes:
  POST /api/recon/scan/save          — save a completed scan (auto-called by run_all)
  GET  /api/recon/scan/history?target=X  — list historical scans for a target
  GET  /api/recon/scan/diff?a=ID1&b=ID2  — diff two scans (what changed)
"""
import json, os, hashlib, time
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Body, Query
from pydantic import BaseModel
from tools._shared import verify_scan_quota

router = APIRouter()
_HISTORY_DIR = Path(os.environ.get("VL_FLOW_HISTORY_DIR", "/app/scan_history"))
_HISTORY_DIR.mkdir(parents=True, exist_ok=True)


class SaveScanReq(BaseModel):
    target: str
    scan_results: dict  # the full r{} object
    metadata: Optional[dict] = None


def _scan_id(target: str, ts: int) -> str:
    return hashlib.sha1(f"{target}-{ts}".encode()).hexdigest()[:12]


def _target_dir(target: str) -> Path:
    safe = "".join(c for c in target if c.isalnum() or c in ".-_")
    d = _HISTORY_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


@router.post("/api/recon/scan/save")
async def save_scan(req: SaveScanReq, _=Depends(verify_scan_quota)):
    ts = int(time.time())
    sid = _scan_id(req.target, ts)
    record = {
        "scan_id": sid,
        "target": req.target,
        "timestamp": ts,
        "results": req.scan_results,
        "metadata": req.metadata or {},
    }
    out = _target_dir(req.target) / f"{sid}.json"
    out.write_text(json.dumps(record, default=str), encoding="utf-8")
    return {"ok": True, "scan_id": sid, "path": str(out)}


@router.get("/api/recon/scan/history")
async def list_history(target: str = Query(...), _=Depends(verify_scan_quota)):
    d = _target_dir(target)
    items = []
    for f in sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
            findings = []
            for k, v in (rec.get("results") or {}).items():
                if isinstance(v, dict) and isinstance(v.get("findings"), list):
                    findings.extend(v["findings"])
            sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f_ in findings:
                s = (f_.get("severity") or "INFO").upper()
                sev_count[s] = sev_count.get(s, 0) + 1
            items.append({
                "scan_id": rec["scan_id"],
                "timestamp": rec["timestamp"],
                "date": time.strftime("%Y-%m-%d %H:%M", time.gmtime(rec["timestamp"])),
                "total_findings": len(findings),
                "severity_counts": sev_count,
            })
        except Exception:
            continue
    return {"target": target, "scan_count": len(items), "scans": items}


@router.get("/api/recon/scan/diff")
async def diff_scans(a: str = Query(...), b: str = Query(...),
                      target: str = Query(...), _=Depends(verify_scan_quota)):
    d = _target_dir(target)
    fa = d / f"{a}.json"
    fb = d / f"{b}.json"
    if not fa.exists() or not fb.exists():
        raise HTTPException(404, f"Scan(s) not found. a={fa.exists()} b={fb.exists()}")
    rec_a = json.loads(fa.read_text(encoding="utf-8"))
    rec_b = json.loads(fb.read_text(encoding="utf-8"))

    def extract_findings(rec):
        out = []
        for tool, data in (rec.get("results") or {}).items():
            if isinstance(data, dict):
                for f in (data.get("findings") or []):
                    out.append({
                        "tool": tool,
                        "name": f.get("name") or f.get("detail") or "",
                        "severity": f.get("severity", "INFO"),
                        "evidence": f.get("evidence", "")[:200],
                    })
        return out

    findings_a = extract_findings(rec_a)
    findings_b = extract_findings(rec_b)

    # Hash each finding for diff
    def fhash(f):
        return hashlib.md5(f"{f['tool']}|{f['name']}|{f['severity']}".encode()).hexdigest()

    set_a = {fhash(f): f for f in findings_a}
    set_b = {fhash(f): f for f in findings_b}

    new = [set_b[k] for k in set_b if k not in set_a]
    resolved = [set_a[k] for k in set_a if k not in set_b]
    unchanged = [set_b[k] for k in set_b if k in set_a]

    return {
        "scan_a": {"id": a, "timestamp": rec_a["timestamp"],
                    "total_findings": len(findings_a)},
        "scan_b": {"id": b, "timestamp": rec_b["timestamp"],
                    "total_findings": len(findings_b)},
        "new_findings": new,
        "resolved_findings": resolved,
        "unchanged_count": len(unchanged),
        "delta": {
            "new": len(new),
            "resolved": len(resolved),
            "net_change": len(new) - len(resolved),
        },
    }


def register(app):
    app.include_router(router)
