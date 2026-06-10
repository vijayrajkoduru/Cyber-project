"""VL-FOUNDRY Layer 13 — Observability.

Tracks per-scanner success/failure metrics so we can detect drift in
production (e.g. a scanner silently returning 0 findings on a known-
vulnerable target = degraded).

Persists to /var/log/vulnuslab/scanner-health.jsonl (one JSON-line per scan).
Cheap, append-only, no external dependencies.

Read with:
  python scripts/scanner_health.py --module recon --window 30d
"""
from __future__ import annotations
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Default log location (overridable via env var)
_LOG_DIR = Path(os.environ.get("VULNUSLAB_LOG_DIR", "/var/log/vulnuslab"))
_LOG_FILE = _LOG_DIR / "scanner-health.jsonl"
# In dev / Windows, fall back to repo-local
if not _LOG_DIR.parent.exists():
    _LOG_FILE = Path(__file__).resolve().parent.parent.parent / "logs" / "scanner-health.jsonl"


def _ensure_log_dir():
    """Best-effort create log dir; never raise (observability must not break scans)."""
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def record_scan(
    module: str,
    scanner: str,
    target: str,
    status: str,                # "ok" | "skipped" | "failed" | "timeout"
    duration_s: float,
    findings_count: int = 0,
    error: str | None = None,
) -> None:
    """Append one scan-attempt record. Called by orchestrator after each scanner.

    Never raises — observability failure must not break the scan.
    """
    _ensure_log_dir()
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "module": module,
        "scanner": scanner,
        "target": target,
        "status": status,
        "duration_s": round(duration_s, 3),
        "findings": findings_count,
    }
    if error:
        record["error"] = error[:200]  # cap error length
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass  # silent — never crash the scan


def health_summary(module: str | None = None, window_days: int = 7) -> dict[str, Any]:
    """Compute per-scanner success rate over a time window.

    Returns:
      {
        "scanner_name": {
          "total_runs": int,
          "ok_pct": float,
          "skipped_pct": float,
          "failed_pct": float,
          "avg_duration_s": float,
          "avg_findings": float,
        }, ...
      }
    """
    if not _LOG_FILE.exists():
        return {}
    cutoff = time.time() - (window_days * 86400)
    by_scanner: dict[str, list[dict]] = {}
    try:
        with open(_LOG_FILE, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                # Parse ISO ts — best effort
                try:
                    t = datetime.fromisoformat(r["ts"]).timestamp()
                except Exception:
                    continue
                if t < cutoff: continue
                if module and r.get("module") != module: continue
                by_scanner.setdefault(r["scanner"], []).append(r)
    except Exception:
        return {}

    summary = {}
    for scanner, runs in by_scanner.items():
        n = len(runs)
        ok = sum(1 for r in runs if r["status"] == "ok")
        skipped = sum(1 for r in runs if r["status"] == "skipped")
        failed = sum(1 for r in runs if r["status"] in ("failed", "timeout"))
        summary[scanner] = {
            "total_runs": n,
            "ok_pct": round(ok / n * 100, 1),
            "skipped_pct": round(skipped / n * 100, 1),
            "failed_pct": round(failed / n * 100, 1),
            "avg_duration_s": round(sum(r["duration_s"] for r in runs) / n, 2),
            "avg_findings": round(sum(r.get("findings", 0) for r in runs) / n, 1),
        }
    return summary


def alert_degraded(threshold_pct: float = 80.0) -> list[dict]:
    """Return list of scanners whose 7-day success rate dropped below threshold.

    Use case: nightly cron emits Slack alert for any entry returned.
    """
    summary = health_summary(window_days=7)
    degraded = []
    for scanner, stats in summary.items():
        if stats["total_runs"] < 5:
            continue  # too few data points
        if stats["ok_pct"] < threshold_pct:
            degraded.append({
                "scanner": scanner,
                "ok_pct": stats["ok_pct"],
                "failed_pct": stats["failed_pct"],
                "total_runs": stats["total_runs"],
                "avg_findings": stats["avg_findings"],
            })
    return sorted(degraded, key=lambda x: x["ok_pct"])
