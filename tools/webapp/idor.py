"""IDOR / BOLA — broken object-level authorization on /api/<resource>/<id>.

ZERO-FP MANDATE
---------------
"Different IDs return different record bodies" is NORMAL REST behaviour
(every `/api/x/{id}` does that) and is NOT proof of IDOR. We only emit a
GRADED finding when broken object-level authorization is actually PROVEN:

  (a) Unauthenticated access to a gated record:
      /{id} returns 401/403 unauthenticated for one id, but returns a real
      200 record body for another id *with no credentials* — and that
      anonymous body matches the body an authorized session gets for the
      same id (so it is the real gated record, not a generic/public page).

  (b) Cross-user access (requires a second session):
      User A's session successfully retrieves a record that demonstrably
      belongs to user B (owner). Needs caller-supplied second credentials
      (auth_cookie2 / auth_bearer2) and a victim record id (idor_victim_id).

Anything weaker — "auth required AND distinct records per id" with NO
cross-user / no-auth proof — is reported as INFO (advisory), never graded.
"""
import hashlib
import re
import time
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

_DEFAULT_PATTERNS = [
    "/api/Users/{id}", "/api/BasketItems/{id}", "/api/Feedbacks/{id}",
    "/api/Products/{id}", "/api/Recycles/{id}", "/api/SecurityQuestions/{id}",
    "/users/{id}", "/orders/{id}", "/invoices/{id}", "/messages/{id}",
]
_NUMERIC_ID_RE = re.compile(r"/(\d+)(/|$|\?)")

# Bodies that prove a record was NOT actually returned (anonymous 200 that
# is really an error / empty / SPA shell must not count as "got the record").
_NON_RECORD_RE = re.compile(
    r"(not\s*authoriz|unauthor|access\s*denied|forbidden|please\s*log\s*in|"
    r"login\s*required|\"error\"|<!doctype html|<html)", re.I)


def _hash(text):
    return hashlib.md5((text or "")[:2000].encode("utf-8", errors="ignore")).hexdigest()


def _looks_like_record(text):
    """A real per-record body: non-trivial length and not an error/SPA shell.
    Used to make sure an anonymous 200 actually returned object data, not a
    generic error page that happened to come back 200."""
    body = (text or "").strip()
    if len(body) < 8:
        return False
    if _NON_RECORD_RE.search(body[:512]):
        return False
    return True


class _CredReq:
    """Lightweight ScanRequest-shaped object carrying a chosen credential set
    (or none). safe_get reads auth_cookie / auth_bearer off whatever req it is
    handed, so this lets us probe the same URL as anon / user-A / user-B."""
    def __init__(self, target, cookie=None, bearer=None):
        self.target = target
        self.auth_cookie = cookie
        self.auth_bearer = bearer


@router.post("/api/webapp/scan/idor")
@vl_turbo()
@vl_verify()
def scan_idor(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    has_auth = bool(getattr(req, "auth_cookie", None) or getattr(req, "auth_bearer", None))
    if not has_auth:
        return standard_response(tool="idor", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="IDOR test requires auth credentials — without a session, all unauthenticated paths return 401/403 by design.")

    # Optional second user session (enables cross-user PROOF, case b). Absent
    # by default; activated only when the caller supplies a real victim session.
    cookie2 = getattr(req, "auth_cookie2", None)
    bearer2 = getattr(req, "auth_bearer2", None)
    victim_id = getattr(req, "idor_victim_id", None)
    has_second_user = bool(cookie2 or bearer2) and victim_id not in (None, "")

    spa = load_spa_state(req.target)
    patterns = list(_DEFAULT_PATTERNS)
    for url in list(spa.get("urls", [])) + list(spa.get("endpoints", {}).keys()):
        m = _NUMERIC_ID_RE.search(url)
        if m:
            templated = url[:m.start()+1] + "{id}" + url[m.end()-1:]
            if templated.count("{id}") == 1 and templated not in patterns:
                patterns.append(templated)

    findings, tests, confirmed, suppressed, advisories = [], 0, [], [], []

    no_auth = _CredReq(req.target)                 # anonymous probe
    user_b = _CredReq(req.target, cookie2, bearer2)  # second session (case b)

    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 45.0
    _bailed = False

    def _probe_pattern(pattern):
        """Returns a verdict tuple. Verdicts:
        unreachable / public / auth_failed / unauth_idor (PROOF a) /
        cross_user (PROOF b) / advisory (distinct records, NO proof) / clean.
        """
        url1 = base + pattern.replace("{id}", "1")
        local_tests = 1

        # 1) Is /{id} gated at all? If anon gets a non-401/403, the endpoint is
        #    public by design — distinct bodies per id is correct, not IDOR.
        unauth_r = safe_get(url1, req=no_auth, allow_redirects=False, timeout=10)
        if unauth_r is None:
            return ("unreachable", pattern, local_tests, None, None)
        if unauth_r.status_code not in (401, 403):
            return ("public", pattern, local_tests, unauth_r.status_code, None)

        # 2) Authorized session must actually receive a real record for id=1,
        #    establishing the gated endpoint serves per-record data.
        local_tests += 1
        r1 = safe_get(url1, req=req, allow_redirects=False, timeout=10)
        if r1 is None or r1.status_code not in (200, 304):
            return ("auth_failed", pattern, local_tests, unauth_r.status_code, None)

        auth_hashes = {1: _hash(r1.text or "")}
        # ---- PROOF PATH (a): anonymous retrieval of a gated record ----
        # The endpoint is gated (anon /1 -> 401/403). If anon can pull a REAL
        # record body for some id, and that anon body is byte-identical to what
        # an authorized session gets for the SAME id, an unauthenticated client
        # just read a protected object. That is CONFIRMED broken authz.
        for tid in (2, 3, 5, 10, 99):
            local_tests += 1
            ru = base + pattern.replace("{id}", str(tid))
            anon = safe_get(ru, req=no_auth, allow_redirects=False, timeout=10)
            if anon is None or anon.status_code != 200:
                continue
            if not _looks_like_record(anon.text or ""):
                continue
            # Confirm it is the genuine gated record: authorized session sees
            # the identical body for the same id.
            local_tests += 1
            auth = safe_get(ru, req=req, allow_redirects=False, timeout=10)
            if (auth is not None and auth.status_code == 200
                    and _hash(auth.text or "") == _hash(anon.text or "")):
                return ("unauth_idor", pattern, local_tests, unauth_r.status_code,
                        {"id": tid, "anon_status": anon.status_code,
                         "body_len": len((anon.text or ""))})

        # ---- PROOF PATH (b): cross-user access with a real victim session ----
        if has_second_user:
            local_tests += 1
            vurl = base + pattern.replace("{id}", str(victim_id))
            owner = safe_get(vurl, req=user_b, allow_redirects=False, timeout=10)
            if owner is not None and owner.status_code == 200 and _looks_like_record(owner.text or ""):
                local_tests += 1
                attacker = safe_get(vurl, req=req, allow_redirects=False, timeout=10)
                if (attacker is not None and attacker.status_code == 200
                        and _hash(attacker.text or "") == _hash(owner.text or "")):
                    return ("cross_user", pattern, local_tests, unauth_r.status_code,
                            {"victim_id": victim_id, "owner_status": owner.status_code,
                             "attacker_status": attacker.status_code})

        # No proof. Gather the distinct-records signal for an ADVISORY only.
        for tid in (2, 3, 5, 10, 99):
            local_tests += 1
            ru = base + pattern.replace("{id}", str(tid))
            r = safe_get(ru, req=req, allow_redirects=False, timeout=10)
            if r is None or r.status_code != 200:
                continue
            auth_hashes[tid] = _hash(r.text or "")
        unique = set(auth_hashes.values())
        if len(unique) >= 3 and len(auth_hashes) >= 4:
            # Authorized session sees distinct records per id. WITHOUT a
            # cross-user / no-auth proof this is normal REST — INFO, not graded.
            return ("advisory", pattern, local_tests, unauth_r.status_code,
                    {"distinct_responses": len(unique),
                     "ids_tested": sorted(auth_hashes.keys())})
        return ("clean", pattern, local_tests, unauth_r.status_code, None)

    pattern_slice = patterns[:15]
    try:
        with ThreadPoolExecutor(max_workers=min(10, len(pattern_slice))) as pool:
            for verdict, pattern, n, unauth_status, info in \
                    pool.map(_probe_pattern, pattern_slice, timeout=_WALLCLOCK_BUDGET):
                tests += n
                if verdict == "public":
                    suppressed.append({"pattern": pattern,
                                        "reason": "public_endpoint",
                                        "unauth_status": unauth_status})
                elif verdict == "unauth_idor":
                    findings.append(wrap_finding(
                        f"IDOR / BOLA — {pattern} serves a protected record to an UNAUTHENTICATED client",
                        "HIGH", cvss="7.5", cwe="CWE-639", owasp="A01:2021",
                        cwe_name="Authorization Bypass Through User-Controlled Key",
                        verified_exploit=True,
                        remediation=("Enforce server-side authorization on every record fetch. The "
                                     "endpoint is gated for some IDs but returns the real record to "
                                     "anonymous clients for others — require a valid session and verify "
                                     "the caller is permitted to read each object."),
                        evidence_marker=(f"{pattern}: anon /1 = HTTP{unauth_status} (gated), but anon /"
                                         f"{info['id']} returned HTTP{info['anon_status']} with the same "
                                         f"{info['body_len']}-byte record body an authorized session sees")))
                    confirmed.append({"pattern": pattern, "proof": "unauthenticated_access",
                                      "unauth_status": unauth_status, **info})
                elif verdict == "cross_user":
                    findings.append(wrap_finding(
                        f"IDOR / BOLA — {pattern} lets user A read user B's record (cross-user access)",
                        "HIGH", cvss="8.1", cwe="CWE-639", owasp="A01:2021",
                        cwe_name="Authorization Bypass Through User-Controlled Key",
                        verified_exploit=True,
                        remediation=("Verify object ownership on every fetch: the requesting user must own "
                                     "(or be explicitly granted) the record identified by the URL id. Do not "
                                     "authorize on session-present alone."),
                        evidence_marker=(f"{pattern} id={info['victim_id']}: user B (owner) HTTP{info['owner_status']} "
                                         f"and user A HTTP{info['attacker_status']} returned the identical record body "
                                         f"— user A read user B's object")))
                    confirmed.append({"pattern": pattern, "proof": "cross_user_access",
                                      "unauth_status": unauth_status, **info})
                elif verdict == "advisory":
                    findings.append(wrap_finding(
                        f"Object-addressable endpoint {pattern} returns distinct records per ID (no cross-user proof)",
                        "INFO", cwe="CWE-639",
                        remediation=("Manually verify object-level authorization: confirm a second user's "
                                     "session cannot read these records, or supply auth_cookie2/auth_bearer2 "
                                     "+ idor_victim_id to let the scanner prove cross-user access. Distinct "
                                     "records per ID alone is normal REST behaviour, not a vulnerability."),
                        evidence_marker=(f"{pattern}: auth required (anon=HTTP{unauth_status}); authorized "
                                         f"session saw {info['distinct_responses']} distinct record bodies "
                                         f"across IDs {info['ids_tested']} — NO unauthenticated or cross-user "
                                         f"access proven")))
                    advisories.append({"pattern": pattern, "unauth_status": unauth_status, **info})
    except TimeoutError:
        _bailed = True

    summary = (f"IDOR: {tests} probes across {len(patterns[:15])} ID patterns "
               f"(auth=on{', 2nd-user=on' if has_second_user else ''}) in "
               f"{time.time() - _wallclock_start:.1f}s; {len(confirmed)} confirmed, "
               f"{len(advisories)} advisory, {len(suppressed)} public-endpoint FP(s) suppressed")
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"

    graded = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
    if not graded and tests:
        findings.append(wrap_finding(
            "No IDOR — no unauthenticated or cross-user object access proven",
            "POSITIVE", cwe="CWE-639",
            remediation="Maintain object-level authorization (verify ownership per "
                        "request). Supply a second user session (auth_cookie2/auth_bearer2 "
                        "+ idor_victim_id) to prove cross-user isolation on re-test.",
            evidence_marker=f"{tests} IDOR probe(s); no anonymous or cross-user "
                            "object access confirmed"))
    return standard_response(tool="idor", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=summary,
        raw_data={"idor": {"confirmed": confirmed,
                            "advisory_distinct_records": advisories,
                            "suppressed_public_endpoints": suppressed,
                            "second_user_proof_enabled": has_second_user,
                            "patterns_tested": patterns[:15],
                            "wallclock_bailed": _bailed}})


def register(app):
    app.include_router(router)
