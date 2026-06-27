"""VL-PRIME for Vuln module — module-specific hardening layer.

Sits on top of the global VL-PRIME middleware in endpoints/recon_prime.py
(which is misleadingly named but is module-agnostic — handles rate limit,
audit log, metrics, quarantine, multi-tenant, encryption, CVE feed sync).

Vuln-specific concerns this layer adds:

  1. Per-tier rate-limit buckets — Vuln has 15 tiers + 214 scanners.
     Without per-tier accounting, the heaviest tier (tier2_cve_match,
     which fans out to NVD) can blow the global bucket and starve the
     lighter tiers (tier1_network).
  2. CVE freshness tracking — Vuln depends on CISA KEV + EPSS + NVD;
     surface staleness explicitly so a stale cache doesn't silently
     produce stale findings.
  3. Per-tier quarantine view — global quarantine groups all scanners
     together; Vuln's tier metadata lets us see *which tier* is failing
     and degrade gracefully (e.g. skip a sick tier rather than killing
     run_all).
  4. Per-scanner success/fail histogram — track p50/p99 per scanner
     so we can detect slow drift before quarantine fires.

All admin endpoints are auth-gated (verify_scan_quota Depends).
"""
import asyncio
import collections
import json
import os
import time
from pathlib import Path
from fastapi import APIRouter, Depends, Request
from tools._shared import verify_scan_quota, writable_base

router = APIRouter()

# Reuse the shared base dir for cache/audit so vuln + recon don't
# fragment storage. Subdir under it is vuln-specific.
_BASE = writable_base("VL_PRIME_DIR", "/app/vl_prime_data") / "vuln"
for sub in ["per_tier", "cve_intel", "scanner_stats"]:
    (_BASE / sub).mkdir(parents=True, exist_ok=True)

# ═════════ Vuln-specific rate-limit (per-tier buckets) ═════════
# Tier names mirror tools/vuln/tier*_* on disk. Each tier gets its own
# bucket; running tier2_cve_match exhaustively won't starve tier1_network.
_VULN_TIER_LIMIT = int(os.environ.get("VULN_PRIME_TIER_RATE", "30"))   # scans/h/tier/client
_tier_buckets = collections.defaultdict(lambda: collections.defaultdict(list))
#                                       client_id -> tier -> [timestamps]


def _tier_rate_check(client_id: str, tier: str) -> bool:
    now = time.time()
    bucket = _tier_buckets[client_id][tier]
    bucket[:] = [t for t in bucket if now - t < 3600]
    if len(bucket) >= _VULN_TIER_LIMIT:
        return False
    bucket.append(now)
    return True


# ═════════ Per-scanner runtime stats ═════════
# Tracks success/fail counts + last-seen p50/p99 wall-clock per scanner so
# we can detect *gradual* degradation (the kind quarantine misses because
# the scanner technically returns 200 but takes 30s).
_scanner_stats = collections.defaultdict(
    lambda: {"ok": 0, "fail": 0, "durations_ms": collections.deque(maxlen=100)})


def record_scanner_run(tool: str, success: bool, duration_ms: int):
    """Called by orchestrator after each scanner completes. Tracks roll-up
    stats for the /api/admin/vuln/scanner_stats endpoint."""
    s = _scanner_stats[tool]
    s["ok" if success else "fail"] += 1
    s["durations_ms"].append(int(duration_ms))


def _quantile(values, q):
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * q))]


# ═════════ CVE freshness tracking ═════════
# Vuln scanners (esp. CISA KEV crossref + cve_match tier) depend on fresh
# vuln data. Make staleness visible so a stale cache doesn't produce
# silently stale findings.

def _file_age_h(p: Path) -> float:
    if not p.exists():
        return -1.0
    return (time.time() - p.stat().st_mtime) / 3600.0


# ═════════ Admin endpoints ═════════
@router.get("/api/admin/vuln/metrics")
async def vuln_metrics(_=Depends(verify_scan_quota)):
    """Vuln-specific metrics on top of global VL-PRIME metrics."""
    tier_summary = {}
    for cid, by_tier in _tier_buckets.items():
        for tier, bucket in by_tier.items():
            if tier not in tier_summary:
                tier_summary[tier] = {"clients": 0, "calls_in_window": 0}
            tier_summary[tier]["clients"] += 1
            tier_summary[tier]["calls_in_window"] += len(bucket)
    return {
        "per_tier": tier_summary,
        "tier_rate_limit": _VULN_TIER_LIMIT,
        "scanners_tracked": len(_scanner_stats),
    }


@router.get("/api/admin/vuln/scanner_stats")
async def vuln_scanner_stats(_=Depends(verify_scan_quota)):
    """p50/p99 wall-clock + success/fail per scanner. Use to spot slow drift."""
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


@router.get("/api/admin/vuln/cve_freshness")
async def vuln_cve_freshness(_=Depends(verify_scan_quota)):
    """Surface staleness of the Vuln CVE intel caches. Returns hours since
    last write per cache file. -1 means file missing (sync never ran)."""
    cache_dir = _BASE / "cve_intel"
    files = {
        "kev_catalog": cache_dir / "kev_catalog.json",
        "epss_scores": cache_dir / "epss_scores.json",
        "nvd_recent": Path(os.environ.get("VL_PRIME_DIR", "/app/vl_prime_data"))
                        / "cve_cache" / "recent.json",
    }
    return {
        "ages_hours": {name: _file_age_h(p) for name, p in files.items()},
        "warn_threshold_h": 24,
        "stale": {name: _file_age_h(p) > 24 for name, p in files.items()
                  if _file_age_h(p) >= 0},
    }


@router.get("/api/admin/vuln/tier_quarantine")
async def vuln_tier_quarantine(_=Depends(verify_scan_quota)):
    """Group scanner failure counts by tier so an operator can see which
    tier is degraded rather than just one global quarantine list."""
    # Lookup tier per tool by walking tools/vuln on disk
    tier_map = {}
    root = Path(__file__).resolve().parent.parent / "tools" / "vuln"
    if root.is_dir():
        for tier_dir in root.glob("tier*_*"):
            for fp in tier_dir.glob("*.py"):
                if fp.name == "__init__.py" or fp.name.startswith("_"):
                    continue
                tier_map[fp.stem] = tier_dir.name
    by_tier = collections.defaultdict(lambda: {"tools": [], "fail_total": 0})
    for tool, s in _scanner_stats.items():
        tier = tier_map.get(tool, "unknown")
        by_tier[tier]["tools"].append({"tool": tool, "fail": s["fail"], "ok": s["ok"]})
        by_tier[tier]["fail_total"] += s["fail"]
    return {"by_tier": dict(by_tier), "total_tools_tracked": len(_scanner_stats)}


@router.get("/api/admin/vuln/prime_status")
async def vuln_prime_status(_=Depends(verify_scan_quota)):
    return {
        "module": "vuln",
        "per_tier_rate_limit": {"active": True, "limit_per_tier_per_hour": _VULN_TIER_LIMIT},
        "scanner_stats": {"active": True, "tools_tracked": len(_scanner_stats)},
        "cve_freshness_tracking": {"active": True},
        "tier_quarantine_view": {"active": True},
        "note": "Global rate-limit / audit / metrics / quarantine / encryption "
                "from endpoints/recon_prime.py (shared infrastructure).",
    }


def register(app):
    app.include_router(router)
