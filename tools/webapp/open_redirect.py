"""Open Redirect — Location-header attacker-host verification.

Payload source: tools/_payloads/open_redirect.py (OPEN_REDIRECT_PAYLOADS,
~50 entries across absolute / schemeless / backslash / userinfo / subdomain /
url-encoded / double-encoded / whitespace / null-byte / scheme-bypass /
fragment / unicode / protocol-rel).

Zero-FP rule: the Location header must actually REDIRECT to the attacker
host. Earlier substring matching produced false positives on sites that
preserved the malicious URL inside a same-origin redirect query string
(e.g. 302 -> /login?next=/protected?goto=https://evil-attacker.example).
"""
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.open_redirect import OPEN_REDIRECT_PAYLOADS, ATTACKER_HOST
from tools.webapp._webapp_common import vuln_response, precheck_target
from tools._payloads.webapp._loader import load_json
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify
# AI-curated extras: more bypass families (userinfo, subdomain, double-encoded, unicode, fragment).
_AI_EXTRA_REDIR = load_json("open_redirect_extra", fallback=[])
_MERGED_REDIR = list(OPEN_REDIRECT_PAYLOADS) + [p for p in _AI_EXTRA_REDIR if isinstance(p, dict) and "payload" in p]

router = APIRouter()
_COMMON_KEYS = ["url", "next", "redirect", "return", "returnTo", "return_url",
                "goto", "rurl", "dest", "destination", "redir", "u",
                "continue", "forward", "site", "view", "image_url"]


def _build_payload_set():
    """Interleave by category so the per-param burst exercises every
    bypass family (absolute / schemeless / backslash / userinfo / subdomain /
    url-encoded / double-encoded / whitespace / scheme-bypass / etc.)
    before exhausting any one. The most-effective patterns lead.
    """
    order = ["schemeless", "absolute", "backslash", "userinfo", "subdomain",
             "url-encoded", "double-encoded", "whitespace", "null-byte",
             "protocol-rel", "scheme-bypass", "fragment", "unicode"]
    buckets = {cat: [] for cat in order}
    for p in _MERGED_REDIR:
        cat = p.get("category")
        if cat not in buckets: continue
        buckets[cat].append(p)
    out, idx = [], 0
    while any(idx < len(buckets[cat]) for cat in order):
        for cat in order:
            if idx < len(buckets[cat]):
                out.append(buckets[cat][idx])
        idx += 1
    return out


_PAYLOAD_SET = _build_payload_set()


def _redirects_to_attacker(location: str, target_host: str) -> bool:
    """True only if the Location header's DESTINATION host is the attacker.

    Handles the forms attackers actually exploit:
      - absolute:        https://evil-attacker.example/path
      - schemeless:      //evil-attacker.example/path
      - backslash:       /\\evil-attacker.example  (Chrome/Firefox quirk)
      - user-info bypass: https://target.com@evil-attacker.example
      - subdomain trick: https://target.com.evil-attacker.example

    Rejects what's NOT an open redirect:
      - same-origin redirect that *contains* the attacker string in the
        query, e.g. /login?next=https://evil-attacker.example
    """
    if not location:
        return False
    loc = location.strip()
    low_attacker = ATTACKER_HOST.lower()

    if loc.startswith("//"):
        host = loc[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in host:
            host = host.split("@", 1)[1]
        return low_attacker in host.lower()

    if loc.startswith(("/\\", "\\\\", "\\")):
        rest = loc.lstrip("/\\")
        host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in host:
            host = host.split("@", 1)[1]
        return low_attacker in host.lower()

    try:
        parsed_loc = urlparse(loc)
        if parsed_loc.netloc:
            host = parsed_loc.netloc.lower()
            if "@" in host:
                host = host.split("@", 1)[1]
            return low_attacker in host
    except Exception:
        pass

    return False


_CANARY_HOST = "benign-canary-vulnuslab.example"


@router.post("/api/webapp/scan/open_redirect")
@vl_turbo()
@vl_verify()
def scan_open_redirect(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    unreachable = precheck_target(base, req)
    if unreachable:
        return vuln_response(tool="open_redirect", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
    parsed = urlparse(base)
    target_host = (parsed.netloc or "").lower()
    params = parse_qs(parsed.query)
    candidates = set(params.keys()) | set(_COMMON_KEYS)
    # Per-param cap: 24 covers every interesting bypass family while keeping
    # the per-param probe budget bounded.
    payload_set = _PAYLOAD_SET[:24]
    findings, tests, confirmed = [], 0, []

    canary_redirects = False
    canary_location = ""
    canary_params = {k: v[0] for k, v in params.items()}
    canary_params["__vl_canary"] = f"https://{_CANARY_HOST}/canary"
    canary_url = urlunparse(parsed._replace(query=urlencode(canary_params)))
    cr = safe_get(canary_url, req=req, allow_redirects=False, timeout=10)
    if cr is not None and cr.status_code in (301, 302, 303, 307, 308):
        canary_location = cr.headers.get("Location", "") or cr.headers.get("location", "") or ""
        if _CANARY_HOST in canary_location.lower():
            canary_redirects = True

    location_counts = {}
    MAX_PER_LOCATION = 1

    # VL-TURBO deep: parallelize (key, payload) probes via thread pool.
    # Was |candidates| * 24 sequential GETs * 10s = up to ~70min (capped at 45s).
    # Now ~30s in pool(20) for full sweep. First-hit-per-key preserved by
    # ordered iteration after parallel collection.
    import time as _time
    _wallclock_start = _time.time()
    _WALLCLOCK_BUDGET = 45.0
    _bailed = False

    candidates_list = list(candidates)
    jobs = [(key, entry) for key in candidates_list for entry in payload_set]

    def _probe(job):
        key, entry = job
        inj = entry["payload"]
        new_params = {k: v[0] for k, v in params.items()}
        new_params[key] = inj
        test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
        r = safe_get(test_url, req=req, allow_redirects=False, timeout=10)
        if r is None or r.status_code not in (301, 302, 303, 307, 308):
            return ("miss", key, entry, None, None)
        location = r.headers.get("Location", "") or r.headers.get("location", "") or ""
        if not _redirects_to_attacker(location, target_host):
            return ("miss", key, entry, None, None)
        return ("hit", key, entry, location, r.status_code)

    raw_results = []
    if jobs:
        try:
            with ThreadPoolExecutor(max_workers=min(20, len(jobs))) as pool:
                for res in pool.map(_probe, jobs, timeout=_WALLCLOCK_BUDGET):
                    raw_results.append(res)
                    tests += 1
        except TimeoutError:
            _bailed = True

    # First-hit-per-key in original (key, payload_set) order.
    by_key = {}
    for verdict, key, entry, location, status in raw_results:
        if verdict != "hit":
            continue
        by_key.setdefault(key, (entry, location, status))

    for key in candidates_list:
        if key not in by_key:
            continue
        entry, location, status = by_key[key]
        inj = entry["payload"]
        cat = entry.get("category", "?")
        loc_key = location.split("?", 1)[0].split("#", 1)[0]
        location_counts[loc_key] = location_counts.get(loc_key, 0) + 1
        if location_counts[loc_key] > MAX_PER_LOCATION:
            confirmed.append({"param": key, "payload": inj, "category": cat,
                               "location": location, "suppressed": "duplicate destination"})
            continue
        confidence = "SUSPECTED" if canary_redirects else "CONFIRMED"
        f = wrap_finding(
            f"Open Redirect via {key!r} ({cat} bypass)",
            "MEDIUM", cvss="6.1", cwe="CWE-601", owasp="A01:2021",
            remediation="Validate redirect destinations against an internal allow-list.",
            evidence_marker=f"{key}={inj} -> HTTP {status} Location: {location}")
        f["confidence"] = confidence
        findings.append(f)
        confirmed.append({"param": key, "payload": inj, "category": cat,
                           "location": location, "confidence": confidence})

    summary = (f"Open redirect: {tests} probes across {len(candidates)} candidate params "
               f"using {len(payload_set)}-entry payload set (merged: {len(OPEN_REDIRECT_PAYLOADS)} baked-in + {len(_AI_EXTRA_REDIR)} AI-curated, "
               f"13 bypass categories; host-verified, dedupe-by-destination) "
               f"in {_time.time() - _wallclock_start:.1f}s")
    if _bailed:
        summary += f" — wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    if canary_redirects:
        summary += " — canary baseline redirected to off-host, findings marked SUSPECTED"

    return vuln_response(tool="open_redirect", target=req.target, findings=findings,
        tested=tests,
        what_checked=f"URL parameters for open redirect to attacker host ({len(_MERGED_REDIR)}-entry merged library, Location-verified)",
        tests_summary=summary,
        raw_data={"open_redirect": {
            "confirmed": confirmed,
            "canary_redirects": canary_redirects,
            "canary_location": canary_location,
            "unique_destinations": len(location_counts),
            "library_size": len(_MERGED_REDIR),
            "ai_extras_loaded": len(_AI_EXTRA_REDIR),
        }})


def register(app):
    app.include_router(router)
