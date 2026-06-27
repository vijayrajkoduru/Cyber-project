"""VL-PRIME for Webapp module — module-specific hardening layer.

Sits on top of the global VL-PRIME middleware in endpoints/recon_prime.py
(misleadingly named but module-agnostic — handles rate limit, audit log,
metrics, quarantine, multi-tenant, encryption). The middleware already
exempts internal fan-out (localhost / 172.x / 10.x / 192.168.x) from
counter-billing, so /api/webapp/scan/run_all bursts don't 429 themselves.

Webapp-specific concerns this layer adds:

  1. Per-tier rate-limit buckets — Webapp has 24 tiers + 60+ scanners.
     The heaviest tiers (tier3_injection fan-out + tier9_ai_curated)
     can swamp the global bucket. Per-(client, tier) accounting gives
     light tiers (tier1_discovery, tier6_network) breathing room.
  2. Per-scanner runtime stats (success/fail counts + p50/p99 wall-
     clock per tool, rolling 100 samples). Surfaces slow drift before
     the global quarantine fires.
  3. Authenticated-scan session freshness — Webapp scans often use a
     customer-supplied cookie/JWT. We surface the age of the last
     successful authenticated scan per tenant so an operator knows if
     a captured session is stale (likely 401 cascade in next run).
  4. Per-tier quarantine view — failure counts grouped by tier so
     an operator can see "tier3_injection is degraded" rather than
     reading a flat global list of 60+ tools.

All admin endpoints are auth-gated (verify_scan_quota Depends).
"""
import collections
import os
import time
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import verify_scan_quota, writable_base

router = APIRouter()

# Reuse the shared base dir so vuln + webapp + recon don't fragment storage.
_BASE = writable_base("VL_PRIME_DIR", "/app/vl_prime_data") / "webapp"
for sub in ["per_tier", "scanner_stats", "session_freshness"]:
    (_BASE / sub).mkdir(parents=True, exist_ok=True)

# ═════════ Webapp-specific rate-limit (per-tier buckets) ═════════
# Tier names mirror WEBAPP_TOOLS_BY_TIER in endpoints/webapp_orchestrator.py.
# Each (client, tier) tuple gets its own hourly counter.
_WEBAPP_TIER_LIMIT = int(os.environ.get("WEBAPP_PRIME_TIER_RATE", "30"))
_tier_buckets = collections.defaultdict(lambda: collections.defaultdict(list))
#                                       client_id -> tier -> [timestamps]


def _tier_rate_check(client_id: str, tier: str) -> bool:
    now = time.time()
    bucket = _tier_buckets[client_id][tier]
    bucket[:] = [t for t in bucket if now - t < 3600]
    if len(bucket) >= _WEBAPP_TIER_LIMIT:
        return False
    bucket.append(now)
    return True


# ═════════ Per-scanner runtime stats ═════════
_scanner_stats = collections.defaultdict(
    lambda: {"ok": 0, "fail": 0, "durations_ms": collections.deque(maxlen=100)})


def record_scanner_run(tool: str, success: bool, duration_ms: int):
    """Called by orchestrator (in tools/_framework/orchestrator.py) after each
    Webapp tool_complete event. Best-effort - never raises."""
    s = _scanner_stats[tool]
    s["ok" if success else "fail"] += 1
    s["durations_ms"].append(int(duration_ms))


def _quantile(values, q):
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * q))]


# ═════════ Authenticated-scan session freshness ═════════
# Recorded each time an authenticated /api/webapp/scan/run_all completes
# successfully. Tenants whose stored session is older than 1 hour are likely
# to see 401-cascade on next run (cookie expiry, OAuth token refresh, etc.).
_last_auth_scan = {}    # client_id -> {when: epoch, status: "ok"/"401"}


def record_auth_scan(client_id: str, status: str):
    _last_auth_scan[client_id] = {"when": time.time(), "status": status}


# ═════════ Admin endpoints ═════════
@router.get("/api/admin/webapp/metrics")
async def webapp_metrics(_=Depends(verify_scan_quota)):
    tier_summary = {}
    for cid, by_tier in _tier_buckets.items():
        for tier, bucket in by_tier.items():
            if tier not in tier_summary:
                tier_summary[tier] = {"clients": 0, "calls_in_window": 0}
            tier_summary[tier]["clients"] += 1
            tier_summary[tier]["calls_in_window"] += len(bucket)
    return {
        "per_tier": tier_summary,
        "tier_rate_limit": _WEBAPP_TIER_LIMIT,
        "scanners_tracked": len(_scanner_stats),
    }


@router.get("/api/admin/webapp/scanner_stats")
async def webapp_scanner_stats(_=Depends(verify_scan_quota)):
    """p50/p99 wall-clock + success/fail per scanner."""
    out = []
    for tool, s in sorted(_scanner_stats.items()):
        ds = list(s["durations_ms"])
        out.append({
            "tool": tool,
            "ok": s["ok"],
            "fail": s["fail"],
            "samples": len(ds),
            "p50_ms": _quantile(ds, 0.5),
            "p99_ms": _quantile(ds, 0.99),
        })
    return {"count": len(out), "scanners": out}


@router.get("/api/admin/webapp/session_freshness")
async def webapp_session_freshness(_=Depends(verify_scan_quota)):
    """Per-tenant: when was the last successful authenticated scan?
    Stale (>1h) sessions are likely to fail with 401 cascade on next run."""
    now = time.time()
    out = []
    for cid, info in _last_auth_scan.items():
        age_s = now - info["when"]
        out.append({
            "client_id":   cid[:8] + "...",  # redacted for admin UI
            "age_minutes": int(age_s / 60),
            "last_status": info["status"],
            "stale":       age_s > 3600,
        })
    return {"tenants_tracked": len(out), "tenants": out, "stale_threshold_minutes": 60}


@router.get("/api/admin/webapp/tier_quarantine")
async def webapp_tier_quarantine(_=Depends(verify_scan_quota)):
    """Group scanner failure counts by tier. Uses the live WEBAPP_TOOLS_BY_TIER
    map from the orchestrator (single source of truth)."""
    try:
        from endpoints.webapp_orchestrator import WEBAPP_TOOLS_BY_TIER
    except Exception:
        WEBAPP_TOOLS_BY_TIER = {}
    tier_map = {}
    for tier, tools in WEBAPP_TOOLS_BY_TIER.items():
        for name, _path in tools:
            tier_map[name] = tier
    by_tier = collections.defaultdict(lambda: {"tools": [], "fail_total": 0})
    for tool, s in _scanner_stats.items():
        tier = tier_map.get(tool, "unknown")
        by_tier[tier]["tools"].append({"tool": tool, "fail": s["fail"], "ok": s["ok"]})
        by_tier[tier]["fail_total"] += s["fail"]
    return {"by_tier": dict(by_tier), "total_tools_tracked": len(_scanner_stats)}


@router.get("/api/admin/webapp/prime_status")
async def webapp_prime_status(_=Depends(verify_scan_quota)):
    return {
        "module": "webapp",
        "per_tier_rate_limit": {"active": True, "limit_per_tier_per_hour": _WEBAPP_TIER_LIMIT},
        "scanner_stats": {"active": True, "tools_tracked": len(_scanner_stats)},
        "session_freshness": {"active": True, "tenants_tracked": len(_last_auth_scan)},
        "tier_quarantine_view": {"active": True},
        "note": "Global rate-limit / audit / metrics / quarantine / encryption "
                "from endpoints/recon_prime.py (shared infrastructure).",
    }


def register(app):
    app.include_router(router)
