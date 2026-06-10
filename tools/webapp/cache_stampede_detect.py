"""cache_stampede_detect — race detector for cache miss fan-out.

Cache stampede: cached page expires; N concurrent requests all miss
cache and hit origin simultaneously. Without lock/locking-cache pattern,
origin overloads. Test: send 10 parallel requests to a likely-cached
path and measure if avg response time spikes vs sequential.
"""
import time
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()


def _timed_get(url, req):
    t0 = time.time()
    r = safe_request("GET", url,
        headers={"User-Agent": "VulnusLab/1.0",
                  # cache-buster to force miss
                  "Cache-Control": "no-cache"},
        req=req, timeout=15, allow_redirects=False)
    return int((time.time() - t0) * 1000), r.status_code if r else 0


@router.post("/api/webapp/scan/cache_stampede_detect")
@vl_turbo()
@vl_verify()
def scan_cache_stampede_detect(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target).rstrip("/") + "/"
    # Sequential baseline (10 reqs)
    seq_times = []
    for _ in range(5):
        ms, _ = _timed_get(url, req)
        seq_times.append(ms)
    if not seq_times:
        return standard_response(
            tool="cache_stampede_detect", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="no baseline responses")
    seq_avg = sum(seq_times) / len(seq_times)

    # Parallel burst (10 simultaneous, all with no-cache to force miss)
    par_times = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(_timed_get, url, req) for _ in range(10)]
        for fut in futures:
            try:
                ms, _ = fut.result(timeout=20)
                par_times.append(ms)
            except Exception: continue
    if not par_times:
        return standard_response(
            tool="cache_stampede_detect", target=req.target, findings=[],
            tests_performed=15, vulnerable=False,
            skipped_reason="no parallel responses")
    par_avg = sum(par_times) / len(par_times)
    ratio = par_avg / seq_avg if seq_avg > 0 else 0

    findings = []
    if ratio > 3.0 and par_avg > 1500:
        findings.append(wrap_finding(
            f"Cache stampede likely — parallel {ratio:.1f}x slower than sequential",
            "MEDIUM", cvss="5.3", cwe="CWE-400", owasp="A04:2021",
            remediation="Implement single-flight cache fill: only ONE request "
                        "regenerates an expired cache entry; others wait or get "
                        "stale. Patterns: Django local memory cache + lock, Redis "
                        "SETNX for cache-fill locks, golang singleflight. Or "
                        "early-refresh: warm cache before expiry.",
            evidence_marker=f"sequential avg {seq_avg:.0f}ms, parallel avg {par_avg:.0f}ms "
                              f"(ratio {ratio:.1f}x)"))
    else:
        findings.append(wrap_finding(
            f"No cache-stampede pattern (ratio {ratio:.1f}x)",
            "POSITIVE", cwe="CWE-400",
            remediation="Maintain.",
            evidence_marker=f"seq {seq_avg:.0f}ms vs parallel {par_avg:.0f}ms"))
    return standard_response(
        tool="cache_stampede_detect", target=req.target, findings=findings,
        tests_performed=15, vulnerable=any(f.get("severity") == "MEDIUM" for f in findings),
        tests_summary=f"seq {seq_avg:.0f}ms, par {par_avg:.0f}ms, ratio {ratio:.1f}",
        raw_data={"sequential_avg_ms": seq_avg, "parallel_avg_ms": par_avg, "ratio": ratio})


def register(app): app.include_router(router)
