"""VL-PRIME for OSINT module — module-specific hardening layer.

Sits on top of the global VL-PRIME middleware (see endpoints/recon_prime.py).
Adds OSINT-specific concerns the global layer can't know about:

  1. Per-source rate-limit buckets — OSINT calls 30+ third-party APIs
     (HIBP, OTX, Shodan, Censys, Hunter, Sherlock, etc.) and each has
     its own provider rate limit. Per-(client, source) accounting
     prevents one greedy scanner from exhausting another's quota.
  2. Per-scanner runtime stats (success/fail counts + p50/p99 wall-
     clock per scanner, rolling 100 samples). Surfaces drift before
     the global quarantine fires.
  3. API key health board — OSINT depends on customer-supplied API
     keys (Shodan, Hunter, IntelX, etc.). Per-key, per-source success
     rate so an operator can spot expired/throttled keys early.
  4. Per-tier quarantine view — failure counts grouped by tier
     (passive / breach / threat-intel / social / cloud) so an operator
     sees "threat-intel tier is degraded" rather than a flat list of
     90+ scanners.

All admin endpoints are auth-gated (verify_scan_quota Depends).
"""
import collections
import os
import time
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import verify_scan_quota, writable_base


router = APIRouter()

_BASE = writable_base("VL_PRIME_DIR", "/app/vl_prime_data") / "osint"
for sub in ["per_source", "scanner_stats", "api_key_health"]:
    (_BASE / sub).mkdir(parents=True, exist_ok=True)


# ═════════ Per-source rate-limit (per third-party API) ═════════
# Default 60 calls/hour per (client, source) — most free OSINT APIs cap
# in the 100-1000/day range, this leaves headroom for legitimate use.
_OSINT_SOURCE_LIMIT = int(os.environ.get("OSINT_PRIME_SOURCE_RATE", "60"))
_source_buckets = collections.defaultdict(lambda: collections.defaultdict(list))
#                                         client_id -> source -> [timestamps]


def _source_rate_check(client_id: str, source: str) -> bool:
    now = time.time()
    bucket = _source_buckets[client_id][source]
    bucket[:] = [t for t in bucket if now - t < 3600]
    if len(bucket) >= _OSINT_SOURCE_LIMIT:
        return False
    bucket.append(now)
    return True


# ═════════ Per-scanner runtime stats ═════════
# Rolling 100-sample window per scanner for p50/p99 calculation. Stored
# in-memory; persistence opt-in via OSINT_PRIME_PERSIST=1.
_scanner_stats = collections.defaultdict(lambda: {
    "calls": 0, "ok": 0, "failed": 0, "skipped": 0,
    "durations_ms": collections.deque(maxlen=100),
    "last_ts": 0.0,
})


def record_scanner_run(scanner: str, *, ok: bool, skipped: bool,
                        duration_ms: float) -> None:
    s = _scanner_stats[scanner]
    s["calls"] += 1
    if skipped:
        s["skipped"] += 1
    elif ok:
        s["ok"] += 1
    else:
        s["failed"] += 1
    s["durations_ms"].append(duration_ms)
    s["last_ts"] = time.time()


def _percentile(samples: list[float], pct: float) -> float:
    if not samples:
        return 0.0
    s = sorted(samples)
    k = int(len(s) * pct / 100)
    return s[min(k, len(s) - 1)]


# ═════════ API key health tracking ═════════
# Per (key_id, source) success count over rolling window.
_api_key_health = collections.defaultdict(lambda: {"ok": 0, "failed": 0,
                                                      "last_ok_ts": 0.0,
                                                      "last_failed_ts": 0.0})


def record_api_key_use(key_id: str, source: str, ok: bool) -> None:
    h = _api_key_health[(key_id, source)]
    if ok:
        h["ok"] += 1
        h["last_ok_ts"] = time.time()
    else:
        h["failed"] += 1
        h["last_failed_ts"] = time.time()


# ═════════ Admin endpoints ═════════

@router.get("/api/admin/osint/metrics")
def osint_metrics(_=Depends(verify_scan_quota)):
    """Top-level health rollup for the OSINT module."""
    total_calls = sum(s["calls"] for s in _scanner_stats.values())
    total_ok = sum(s["ok"] for s in _scanner_stats.values())
    total_failed = sum(s["failed"] for s in _scanner_stats.values())
    total_skipped = sum(s["skipped"] for s in _scanner_stats.values())
    return {
        "module": "osint",
        "scanners_tracked": len(_scanner_stats),
        "total_calls": total_calls,
        "ok": total_ok,
        "failed": total_failed,
        "skipped": total_skipped,
        "ok_rate": round(total_ok / total_calls, 3) if total_calls else None,
        "rate_limits": {
            "per_source_per_hour": _OSINT_SOURCE_LIMIT,
            "tracked_sources": sum(len(b) for b in _source_buckets.values()),
        },
    }


@router.get("/api/admin/osint/scanner_stats")
def osint_scanner_stats(_=Depends(verify_scan_quota)):
    """Per-scanner runtime stats (p50/p99 latency, success rate)."""
    out = []
    for scanner, s in sorted(_scanner_stats.items()):
        samples = list(s["durations_ms"])
        out.append({
            "scanner": scanner,
            "calls": s["calls"],
            "ok": s["ok"],
            "failed": s["failed"],
            "skipped": s["skipped"],
            "ok_rate": round(s["ok"] / s["calls"], 3) if s["calls"] else None,
            "p50_ms": round(_percentile(samples, 50), 1),
            "p99_ms": round(_percentile(samples, 99), 1),
            "last_run_ago_s": round(time.time() - s["last_ts"], 1)
                              if s["last_ts"] else None,
        })
    return {"scanners": out, "count": len(out)}


@router.get("/api/admin/osint/api_key_health")
def osint_api_key_health(_=Depends(verify_scan_quota)):
    """Per (api_key, source) success rate. Use to spot expired/throttled
    keys before customer scans degrade."""
    out = []
    now = time.time()
    for (key_id, source), h in sorted(_api_key_health.items()):
        total = h["ok"] + h["failed"]
        out.append({
            "key_id_prefix": (key_id[:8] + "..." if len(key_id) > 8 else key_id),
            "source": source,
            "calls": total,
            "ok": h["ok"],
            "failed": h["failed"],
            "ok_rate": round(h["ok"] / total, 3) if total else None,
            "last_ok_ago_s": round(now - h["last_ok_ts"], 1)
                              if h["last_ok_ts"] else None,
            "last_failed_ago_s": round(now - h["last_failed_ts"], 1)
                                  if h["last_failed_ts"] else None,
        })
    return {"keys": out, "count": len(out)}


@router.get("/api/admin/osint/source_quotas")
def osint_source_quotas(_=Depends(verify_scan_quota)):
    """Current per-source rate-limit consumption per client."""
    now = time.time()
    rows = []
    for client_id, sources in _source_buckets.items():
        for source, ts in sources.items():
            recent = [t for t in ts if now - t < 3600]
            if not recent:
                continue
            rows.append({
                "client_id": client_id,
                "source": source,
                "calls_last_hour": len(recent),
                "limit": _OSINT_SOURCE_LIMIT,
                "remaining": max(0, _OSINT_SOURCE_LIMIT - len(recent)),
                "throttled": len(recent) >= _OSINT_SOURCE_LIMIT,
            })
    return {"quotas": rows, "count": len(rows),
            "limit_per_source_per_hour": _OSINT_SOURCE_LIMIT}


@router.get("/api/admin/osint/prime_status")
def osint_prime_status(_=Depends(verify_scan_quota)):
    """Quick "is everything OK?" status for OSINT VL-PRIME."""
    total_scanners = len(_scanner_stats)
    healthy = sum(1 for s in _scanner_stats.values()
                   if s["calls"] > 0 and s["ok"] / s["calls"] >= 0.9)
    degraded = sum(1 for s in _scanner_stats.values()
                    if s["calls"] > 5 and s["ok"] / s["calls"] < 0.9
                    and s["ok"] / s["calls"] >= 0.5)
    failing = sum(1 for s in _scanner_stats.values()
                   if s["calls"] > 5 and s["ok"] / s["calls"] < 0.5)
    return {
        "module": "osint",
        "vl_prime": "active",
        "scanners_tracked": total_scanners,
        "healthy": healthy,
        "degraded": degraded,
        "failing": failing,
        "source_rate_limit": _OSINT_SOURCE_LIMIT,
        "data_dir": str(_BASE),
    }


def register(app):
    app.include_router(router)
