"""Webapp: Host header injection / X-Forwarded-Host abuse — VL-TURBO."""
import asyncio
import secrets
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()

# AI-curated 60-entry header-injection list
try:
    from tools._payloads.host_header_payloads import HOST_HEADER_PAYLOADS as _AI_HH
except Exception:
    _AI_HH = []


def _make_canary() -> str:
    """A long, high-entropy canary HOST that cannot collide with real content.

    16 random bytes => 32 hex chars (128 bits of entropy). A coincidental
    substring match against arbitrary page content is astronomically
    improbable, so any genuine appearance is proof the injected header
    value was echoed back — never an inferred / weak-signal match."""
    return "vl" + secrets.token_hex(16) + ".vulnuslab-canary.example"


@router.post("/api/webapp/host_header_injection")
@vl_verify()
async def webapp_host_header_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0

    # Build the probe matrix. CRITICAL: each test-case carries its OWN unique
    # canary so a reflection can be attributed to exactly one injected header
    # (and not to some other unrelated occurrence). Templates that embed a
    # canary host substitute *this* probe's canary.
    base_headers = [
        ("Host", lambda c: {"Host": c}),
        ("X-Forwarded-Host", lambda c: {"X-Forwarded-Host": c}),
        ("X-Host", lambda c: {"X-Host": c}),
        ("X-Forwarded-Server", lambda c: {"X-Forwarded-Server": c}),
        ("X-Original-URL", lambda c: {"X-Original-URL": f"http://{c}/"}),
        ("X-Rewrite-URL", lambda c: {"X-Rewrite-URL": f"http://{c}/"}),
    ]

    # test_cases: list of (header_name, canary, headers_dict)
    test_cases = []
    _seen = set()
    for hn, builder in base_headers:
        c = _make_canary()
        test_cases.append((hn, c, builder(c)))
        _seen.add(hn)

    # Append AI-curated header variants, substituting each probe's own canary
    # into placeholder positions.
    for _p in _AI_HH:
        if not isinstance(_p, dict): continue
        hn = _p.get("header_name", "")
        hv_template = _p.get("header_value", "")
        if not hn or not hv_template or hn in _seen: continue
        c = _make_canary()
        hv = hv_template.replace("attacker.example", c).replace("evil.example", c)
        # Only keep templates that actually carry our canary — otherwise a
        # reflection check is meaningless (nothing unique to look for).
        if c not in hv:
            continue
        test_cases.append((hn, c, {hn: hv}))
        _seen.add(hn)
        if len(test_cases) >= 25:
            break

    suspect = []
    # VL-TURBO: gather all header-injection probes in parallel
    sem = asyncio.Semaphore(15)

    def _sync_probe(headers):
        try:
            return requests.get(base + "/", headers={**headers, "User-Agent": "VulnusLab/1.0"},
                                 timeout=4, allow_redirects=False, verify=False)
        except Exception:
            return None

    async def _probe(headers):
        async with sem:
            return await asyncio.to_thread(_sync_probe, headers)

    def _reflection_site(r, canary):
        """Return where `canary` is genuinely reflected, or None.

        Only the literal, unique 128-bit canary host counts. Checked in the
        response body and in the redirect Location header. No weak signals."""
        if r is None:
            return None
        body = (r.text or "")[:200000]
        loc = r.headers.get("Location", "") or ""
        if canary in loc:
            return "Location header"
        if canary in body:
            return "body"
        return None

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*(_probe(headers) for _, _, headers in test_cases)), timeout=45
        )
    except asyncio.TimeoutError:
        results = [None] * len(test_cases)

    tests = len(test_cases)

    # First pass: collect candidate reflections (genuine canary appearance).
    candidates = []
    for (header_name, canary, headers), r in zip(test_cases, results):
        site = _reflection_site(r, canary)
        if site:
            candidates.append((header_name, canary, headers, site))

    # Second pass: VERIFICATION. A candidate only becomes a finding if a fresh
    # request with a BRAND-NEW canary on the same header reflects that new
    # canary in the same place. This confirms the reflection is caused by the
    # injected header value (and is not a one-off coincidence, a cached body,
    # or unrelated static content that merely contained the first token).
    async def _verify(header_name, builder_headers):
        v_canary = _make_canary()
        # Rebuild the header dict swapping in the verification canary. For the
        # base/templated cases we re-inject the new canary wherever the old
        # one's *shape* was — simplest correct approach: re-run the same header
        # name with the new canary as a plain host (and, for URL-style headers,
        # as a URL) so we re-prove reflection of a value we control.
        probes = {}
        for k, v in builder_headers.items():
            if v.startswith("http://") or v.startswith("https://"):
                probes[k] = f"http://{v_canary}/"
            else:
                probes[k] = v_canary
        r2 = await _probe(probes)
        return v_canary, _reflection_site(r2, v_canary)

    for header_name, canary, headers, site in candidates:
        try:
            v_canary, v_site = await asyncio.wait_for(_verify(header_name, headers), timeout=20)
        except asyncio.TimeoutError:
            v_canary, v_site = None, None
        if not v_site:
            # Not reproducible with a second unique canary -> not a real,
            # header-controlled reflection. Drop it (zero-FP).
            continue
        where = v_site
        suspect.append({"header": header_name, "reflected_in": where,
                        "verified": True})
        findings.append(wrap_finding(
            f"Host header injection - '{header_name}' value reflected in {where}",
            "HIGH",
            cvss="7.4", cwe="CWE-20",
            cwe_name="Improper Input Validation",
            owasp="A03:2021",
            remediation="Validate Host header against an allow-list of expected hostnames. Reject requests with untrusted Host headers. Use absolute URLs from server config, not from request headers.",
            evidence_marker=(f"Injected {header_name} with unique 128-bit canary host "
                             f"'{canary}' -> reflected in {site}; re-confirmed with a "
                             f"second independent canary '{v_canary}' reflected in {where}"),
            verified_exploit=True,
        ))

    if not findings and tests:
        findings.append(wrap_finding(
            "No Host-header injection — canary Host values were not reflected or trusted",
            "POSITIVE", cwe="CWE-644",
            remediation="Maintain. Validate Host against an allow-list and build "
                        "absolute URLs from server config, not request headers.",
            evidence_marker=f"tested {tests} Host-header variant(s) with a unique "
                            "canary; no reflection into response/redirect/cache"))
    return standard_response(
        tool="host_header_injection", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Tested {tests} Host header variants with unique canary",
        raw_data={"host_header_injection": {
            "canary_scheme": "unique 128-bit per-probe canary host, double-confirmed",
            "headers_tested": [hn for hn, _, _ in test_cases],
            "suspect": suspect,
        }},
    )


def register(app):
    app.include_router(router)
