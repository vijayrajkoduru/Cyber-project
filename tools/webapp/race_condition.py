"""Webapp: Race condition detection via parallel-fire requests."""
import asyncio
import aiohttp
import ssl
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding, standard_response

router = APIRouter()

_RACE_PATHS = [
    "/api/purchase","/api/buy","/api/transfer","/api/withdraw","/api/vote",
    "/api/like","/api/redeem","/api/claim","/api/coupon",
    "/checkout","/cart/checkout","/api/cart/checkout",
]


async def _fire_parallel(url, n=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = aiohttp.TCPConnector(ssl=ctx)
    async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=15)) as s:
        async def go():
            try:
                async with s.get(url, allow_redirects=False) as r:
                    return r.status, len(await r.read())
            except Exception:
                return None, 0
        return await asyncio.gather(*[go() for _ in range(n)])


@router.post("/api/webapp/race_condition")
async def webapp_race_condition(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    suspect = []
    
    for path in _RACE_PATHS:
        tests += 1
        url = base + path
        try:
            results = await _fire_parallel(url, n=10)
        except Exception:
            continue
        statuses = [r[0] for r in results if r[0] is not None]
        sizes = [r[1] for r in results if r[1] > 0]
        if len(statuses) < 5:
            continue  # endpoint mostly unreachable
        unique_statuses = set(statuses)
        # Race condition heuristic: mix of 2xx and 4xx in parallel responses
        # (suggests state-dependent behavior where some succeeded, others got "already done")
        has_success = any(200 <= s < 300 for s in unique_statuses)
        has_failure = any(400 <= s < 500 for s in unique_statuses)
        if has_success and has_failure and len(unique_statuses) >= 2:
            suspect.append({"path": path, "statuses": list(unique_statuses), "samples": statuses[:5]})
            findings.append(wrap_finding(
                f"Suspected race condition - {path} returns mixed status codes under parallel load",
                "MEDIUM",
                cvss="6.5", cwe="CWE-362",
                cwe_name="Concurrent Execution using Shared Resource with Improper Synchronization",
                owasp="A04:2021",
                remediation="Use database transactions with appropriate isolation (SERIALIZABLE for state-changing operations). Use optimistic/pessimistic locking. Implement idempotency keys.",
                evidence_marker=f"GET {path} x10 parallel returned mixed statuses: {sorted(unique_statuses)}",
            ))

    return standard_response(
        tool="race_condition", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"{tests} race probes; {len(suspect)} endpoints suspect under parallel load",
        raw_data={"race_condition": {"suspect": suspect}},
    )


def register(app):
    app.include_router(router)
