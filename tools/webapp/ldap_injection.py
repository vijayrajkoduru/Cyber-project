"""Webapp: LDAP filter injection detection (VL-TURBO async-parallel)."""
import asyncio
from fastapi import APIRouter, Depends
from urllib.parse import quote
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync

router = APIRouter()

_PARAMS = ["username","user","email","login","uid","cn","ou","search","filter","name"]
# (payload, description). Differential response vs baseline indicates LDAP processing.
_FALLBACK_PAYLOADS = [
    ("*",                "wildcard - matches all entries"),
    ("*)(uid=*",         "filter break + always-true"),
    ("*)(|(uid=*",       "OR-injection always-true"),
    ("admin*",           "wildcard append"),
    (")(cn=*",           "filter close + wildcard"),
]
# AI-curated 81-entry list, capped to top 20 for runtime
try:
    from tools._payloads.ldap_injection_payloads import LDAP_INJECTION_PAYLOADS as _AI_LDAP
    _PAYLOADS = list(_FALLBACK_PAYLOADS)
    seen = {p[0] for p in _PAYLOADS}
    for _p in _AI_LDAP:
        if not isinstance(_p, dict): continue
        s = _p.get("payload")
        if s and s not in seen:
            _PAYLOADS.append((s, _p.get("category", "ai_curated")))
            seen.add(s)
    _PAYLOADS = _PAYLOADS[:20]
except Exception:
    _PAYLOADS = _FALLBACK_PAYLOADS


@router.post("/api/webapp/ldap_injection")
async def webapp_ldap_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []

    # VL-TURBO: parallelize baselines (10 params) AND injection probes (200 reqs)
    # Sem caps concurrency to avoid hammering the target. Wall-clock cap at 60s.
    sem = asyncio.Semaphore(15)

    async def _fetch(url):
        async with sem:
            return await asyncio.to_thread(safe_get, url, req=req, timeout=5)

    # Phase 1: fetch all baselines in parallel
    baseline_urls = [f"{base}/?{param}=normaluser" for param in _PARAMS]
    try:
        baselines = await asyncio.wait_for(
            asyncio.gather(*(_fetch(u) for u in baseline_urls)), timeout=30
        )
    except asyncio.TimeoutError:
        baselines = [None] * len(_PARAMS)

    valid_baselines = {}  # param -> (status, size)
    for param, b in zip(_PARAMS, baselines):
        if b is None or b.status_code >= 500:
            continue
        valid_baselines[param] = (b.status_code, len(b.content))

    # Phase 2: fetch all injection probes in parallel
    probe_tasks = []
    probe_meta = []  # (param, payload_str, desc)
    for param in valid_baselines:
        for p, desc in _PAYLOADS:
            probe_meta.append((param, p, desc))
            probe_tasks.append(_fetch(f"{base}/?{param}={quote(p)}"))
    try:
        probe_results = await asyncio.wait_for(
            asyncio.gather(*probe_tasks), timeout=60
        )
    except asyncio.TimeoutError:
        probe_results = [None] * len(probe_tasks)

    # Phase 3: evaluate — one finding per affected param (de-dupe)
    seen_params = set()
    for (param, p, desc), r in zip(probe_meta, probe_results):
        if param in seen_params or r is None: continue
        b_status, b_size = valid_baselines[param]
        if r.status_code != b_status: continue
        if abs(len(r.content) - b_size) < 200: continue
        seen_params.add(param)
        findings.append(wrap_finding(
            f"Suspected LDAP injection - parameter '{param}' shows behavior change on filter payload",
            "HIGH",
            cvss="7.5", cwe="CWE-90",
            cwe_name="Improper Neutralization of Special Elements used in an LDAP Query",
            owasp="A03:2021",
            remediation=("Escape LDAP special chars: \\, *, (, ), NUL, /. Use parameterized "
                         "LDAP queries via your LDAP library's binding API instead of string "
                         "concatenation. Validate input against an allow-list (alphanumeric)."),
            evidence_marker=f"GET ?{param}=normaluser ({b_size}B) vs GET ?{param}={p} ({len(r.content)}B) - {desc}",
        ))

    return standard_response(
        tool="ldap_injection", target=req.target,
        findings=findings, tests_performed=len(probe_tasks),
        tests_summary=f"{len(probe_tasks)} LDAP filter probes across {len(valid_baselines)} params x {len(_PAYLOADS)} payloads (parallel)",
        raw_data={"ldap_injection": {"payloads_tested": [p for p,_ in _PAYLOADS],
                                        "spa_catchall": spa["is_spa"]}},
    )


def register(app):
    app.include_router(router)
