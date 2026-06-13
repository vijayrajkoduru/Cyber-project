"""Webapp: IDOR (Insecure Direct Object Reference) detector.

Tests numeric ID enumeration on common REST endpoints. Compares responses
for IDs 1/2/999 - if all 200 with differing content, suggests no access control.

VL-VERIFY: existing `max(sizes) - min(sizes) < 50` gate already filters
SPA catch-all (all responses are byte-identical shells). Belt-and-braces
canary check + stamp added for transparency.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary
from tools._vl_core.verify import vl_verify

router = APIRouter()

_ID_PATHS = [
    "/api/users/{id}","/api/user/{id}","/users/{id}",
    "/api/orders/{id}","/api/order/{id}",
    "/api/posts/{id}","/api/post/{id}",
    "/api/accounts/{id}","/api/account/{id}",
    "/api/profile/{id}","/api/customer/{id}",
    "/api/v1/users/{id}","/api/v2/users/{id}",
    "/admin/users/{id}","/admin/user/{id}",
]


@router.post("/api/webapp/idor_detector")
@vl_verify()
async def webapp_idor_detector(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    spa_suppressed = []
    findings = []
    suspect = []
    tests = len(_ID_PATHS) * 3

    async def _fetch(url):
        return await asyncio.to_thread(safe_get, url, req=req, allow_redirects=False, timeout=8)

    async def _probe_tpl(tpl):
        urls = [base + tpl.replace("{id}", str(n)) for n in (1, 2, 999)]
        rs = await asyncio.gather(*[_fetch(u) for u in urls],
                                   return_exceptions=True)
        responses = []
        bodies = []
        for r in rs:
            if isinstance(r, BaseException) or r is None:
                responses.append(None); bodies.append(""); continue
            responses.append({"status": r.status_code, "size": len(r.content)})
            bodies.append(r.text or "")
        return (tpl, responses, bodies)

    tpl_results = await asyncio.gather(
        *[_probe_tpl(tpl) for tpl in _ID_PATHS],
        return_exceptions=True)
    for tres in tpl_results:
        if isinstance(tres, BaseException) or tres is None:
            continue
        tpl, responses, bodies = tres
        if not all(r and r["status"] == 200 for r in responses):
            continue
        # SPA catch-all suppression: if ANY of the three responses matches the
        # canary body, the endpoint isn't routed - SPA shell served everywhere.
        if spa["is_spa"] and any(is_same_as_canary(b, spa["canary_body"]) for b in bodies):
            spa_suppressed.append(tpl)
            continue
        sizes = [r["size"] for r in responses]
        if max(sizes) - min(sizes) < 50:
            continue  # responses too similar - probably template, not real user data
        suspect.append({"path": tpl, "sizes": sizes})
        findings.append(wrap_finding(
            f"Suspected IDOR - {tpl} returns different data for IDs 1/2/999 without auth check",
            "HIGH",
            cvss="7.5", cwe="CWE-639",
            cwe_name="Authorization Bypass Through User-Controlled Key",
            owasp="A01:2021",
            remediation="Enforce per-user authorization checks. Verify the requesting user owns or has permission to access the resource. Don't rely solely on object IDs from the URL.",
            evidence_marker=f"GET {tpl.replace('{id}','1')} ({sizes[0]}B), GET {tpl.replace('{id}','2')} ({sizes[1]}B), GET {tpl.replace('{id}','999')} ({sizes[2]}B) - all 200 with differing content",
        ))

    if not findings and tests:
        findings.append(wrap_finding(
            "No IDOR — REST id patterns enforced authorization, no suspect access",
            "POSITIVE", cwe="CWE-639",
            remediation="Maintain per-object authorization checks. Re-test after "
                        "adding id-addressable REST resources.",
            evidence_marker=f"{tests} IDOR probe(s) across {len(_ID_PATHS)} REST "
                            f"pattern(s); {len(suspect)} suspect"))
    return standard_response(
        tool="idor_detector", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"{tests} IDOR probes across {len(_ID_PATHS)} REST patterns; {len(suspect)} suspect",
        raw_data={"idor_detector": {"suspect_paths": suspect,
                                       "spa_catchall": spa["is_spa"],
                                       "spa_suppressed_paths": spa_suppressed}},
    )


def register(app):
    app.include_router(router)
