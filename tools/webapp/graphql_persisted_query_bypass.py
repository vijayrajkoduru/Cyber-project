"""graphql_persisted_query_bypass — APQ (Apollo Persisted Queries) hash-bypass.

Apollo Persisted Queries: client sends only a SHA-256 hash of the query;
server resolves to the stored query. Misconfig: server STILL accepts
arbitrary `query` field when hash doesn't match → bypassing the whole
allow-list defense.

Test: POST a normal GraphQL query with a FAKE persisted-query hash.
If server runs the query anyway, APQ enforcement is broken.
"""
import json
import hashlib
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]


def _post(url, body, req):
    return safe_request("POST", url,
        headers={"Content-Type": "application/json",
                  "User-Agent": "VulnusLab/1.0"},
        data=json.dumps(body), req=req, timeout=10, allow_redirects=False)


@router.post("/api/webapp/scan/graphql_persisted_query_bypass")
@vl_turbo()
@vl_verify()
def scan_graphql_persisted_query_bypass(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    endpoint = None
    for path in GRAPHQL_PATHS:
        url = base + path
        r = _post(url, {"query": "{__typename}"}, req)
        if r is None or r.status_code >= 500: continue
        try:
            if "data" in r.json() or "errors" in r.json():
                endpoint = url; break
        except Exception:
            continue

    if not endpoint:
        return standard_response(
            tool="graphql_persisted_query_bypass", target=req.target, findings=[],
            tests_performed=len(GRAPHQL_PATHS), vulnerable=False,
            skipped_reason="No GraphQL endpoint found")

    # Test 1: APQ-style request with hash + NO query — should error PersistedQueryNotFound
    fake_hash = hashlib.sha256(b"vulnuslab-fake-query").hexdigest()
    apq_body = {
        "extensions": {
            "persistedQuery": {"version": 1, "sha256Hash": fake_hash},
        },
    }
    r1 = _post(endpoint, apq_body, req)
    apq_supported = False
    if r1 is not None and r1.status_code == 200:
        try:
            j = r1.json()
            errs = j.get("errors") or []
            if any("PersistedQueryNotFound" in str(e) for e in errs):
                apq_supported = True
        except Exception:
            pass

    if not apq_supported:
        return standard_response(
            tool="graphql_persisted_query_bypass", target=req.target,
            findings=[wrap_finding(
                "Server does not support Apollo Persisted Queries (APQ)",
                "POSITIVE", cwe="CWE-770",
                remediation="No APQ surface to bypass. APQ is a perf optimization "
                            "(send hash, server resolves). If you don't use it, "
                            "consider it as defense-in-depth — allow only whitelisted "
                            "queries via hash → blocks arbitrary attacker queries.",
                evidence_marker=f"APQ probe → {r1.status_code if r1 else 'no-resp'} no PersistedQueryNotFound")],
            tests_performed=2, vulnerable=False,
            tests_summary="No APQ support")

    # Test 2: Send a real query WITH a fake hash → should still reject if APQ is enforcing
    full_body = {
        "query": "{ __schema { types { name } } }",  # introspection — a real query
        "extensions": {
            "persistedQuery": {"version": 1, "sha256Hash": fake_hash},
        },
    }
    r2 = _post(endpoint, full_body, req)
    findings = []
    if r2 is not None and r2.status_code == 200:
        try:
            j2 = r2.json()
            if isinstance(j2.get("data"), dict) and j2["data"].get("__schema"):
                # BUG: query executed despite hash mismatch
                findings.append(wrap_finding(
                    "APQ BYPASS — server executes arbitrary query despite fake hash",
                    "HIGH", cvss="7.5", cwe="CWE-770", owasp="A04:2021",
                    remediation="Server accepts both APQ hash AND raw query — fake hash "
                                "doesn't reject the raw query field. If your APQ purpose "
                                "is allow-listing, this completely defeats it. Configure "
                                "Apollo Server to REJECT raw query field when hash is "
                                "present and doesn't match. Reference: Apollo docs "
                                "'forbidOperations' security mode.",
                    evidence_marker=f"POST with query + fake hash {fake_hash[:12]}… → "
                                      f"got __schema response"))
        except Exception:
            pass

    if not findings:
        findings.append(wrap_finding(
            "APQ properly enforced — fake hash rejects raw query",
            "POSITIVE", cwe="CWE-770",
            remediation="Maintain. APQ defending against arbitrary query injection.",
            evidence_marker="fake-hash + raw-query → properly rejected"))

    return standard_response(
        tool="graphql_persisted_query_bypass", target=req.target, findings=findings,
        tests_performed=3,
        vulnerable=any(f.get("severity") == "HIGH" for f in findings),
        tests_summary=f"APQ supported: {apq_supported}, bypass: {bool(findings) and any(f.get('severity')=='HIGH' for f in findings)}",
        raw_data={"endpoint": endpoint, "apq_supported": apq_supported})


def register(app):
    app.include_router(router)
