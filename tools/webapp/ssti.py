"""SSTI — server-side template injection detection across 6 template engines."""
import secrets
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
from tools._payloads.webapp._loader import load_json
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

# Arithmetic probes — if the response contains the COMPUTED value (49),
# the template engine evaluated our input. Zero-FP by design.
_PROBES = [
    ("{{7*7}}",            "49",   "Jinja2/Twig/Django"),
    ("${7*7}",             "49",   "FreeMarker/JSP-EL"),
    ("<%= 7*7 %>",         "49",   "ERB/Ruby"),
    ("#{7*7}",             "49",   "Pug/Ruby"),
    ("{{constructor.constructor('return 49')()}}", "49", "Angular"),
    ("[[${7*7}]]",         "49",   "Thymeleaf"),
]

# === SSTI-AI-EXTRA-V1 ===
# AI-curated detection probes (cat=detect) get merged into _PROBES; RCE
# entries (cat=rce / sandbox-escape / file-read / etc.) are reserved for
# follow-up confirmation passes — only invoked when a detect-probe fires.
# Keeping confirmation OUT of the primary loop avoids hammering the target
# with destructive payloads on every parameter.
_AI_EXTRA_SSTI = load_json("ssti_payloads", fallback=[])
for _p in _AI_EXTRA_SSTI:
    if not isinstance(_p, dict): continue
    if _p.get("category") != "detect": continue
    payload = _p.get("payload"); engine = _p.get("engine") or _p.get("name") or "?"
    # Extract literal "49" matcher value if matcher is the arithmetic probe regex
    matcher = _p.get("matcher", "")
    # Skip probes that don't use the arithmetic 49-marker so we keep _PROBES uniform
    if "49" in matcher and payload and (payload, "49", engine) not in _PROBES:
        _PROBES.append((payload, "49", engine))
# === /SSTI-AI-EXTRA-V1 ===


@router.post("/api/webapp/scan/ssti")
@vl_turbo()
@vl_verify()
def scan_ssti(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target)
    parsed = urlparse(base)
    test_urls = []
    params_base = parse_qs(parsed.query)
    if params_base:
        test_urls.append((base, parsed, params_base))

    spa = load_spa_state(req.target)
    for u in spa.get("urls", []):
        try:
            up = urlparse(u)
            ps = parse_qs(up.query)
            if ps:
                test_urls.append((u, up, ps))
        except Exception:
            continue

    if not test_urls:
        return standard_response(tool="ssti", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters on base or SPA-discovered endpoints")

    findings, tests = [], 0
    # VL-TURBO wall-clock cap.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 45.0
    _bailed = False
    for tu_url, tu_parsed, params in test_urls[:6]:
        if _bailed: break
        for key in list(params.keys())[:3]:
            if _bailed: break
            for payload, expected, engine in _PROBES:
                if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
                    _bailed = True; break
                tests += 1
                new_params = {k: v[0] for k, v in params.items()}
                # Wrap payload with markers so we don't false-positive on "49" appearing organically
                marker_pre = "VL" + secrets.token_hex(3)
                marker_post = "x" + secrets.token_hex(3)
                new_params[key] = marker_pre + payload + marker_post
                test_url = urlunparse(tu_parsed._replace(query=urlencode(new_params)))
                r = safe_get(test_url, req=req, allow_redirects=True, timeout=10)
                if r is None or not r.text:
                    continue
                # Critical zero-FP: payload must have been evaluated (not echoed verbatim)
                # i.e. marker_pre+"49"+marker_post should appear, NOT marker_pre+payload+marker_post
                if marker_pre + expected + marker_post in r.text and \
                   marker_pre + payload + marker_post not in r.text:
                    findings.append(wrap_finding(
                        f"Server-Side Template Injection in {key!r} ({engine})",
                        "CRITICAL", cvss="9.8", cwe="CWE-1336", owasp="A03:2021",
                        remediation=("Never evaluate user input as template syntax. "
                                   "Use templates with auto-escaping, separate variable interpolation "
                                   "from logic, and sandbox the template engine where possible."),
                        evidence_marker=f"param={key} payload {payload!r} evaluated → got {expected} in response"))
                    break
    summary = (f"SSTI: {tests} probes across {len(_PROBES)} engines "
               f"(Jinja2/FreeMarker/ERB/Pug/Angular/Thymeleaf) in {time.time() - _wallclock_start:.1f}s")
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return standard_response(tool="ssti", target=req.target, findings=findings,
        tests_performed=max(tests, 1),
        tests_summary=summary,
        raw_data={"ssti": {"engines_probed": [e for _,_,e in _PROBES], "wallclock_bailed": _bailed}})


def register(app):
    app.include_router(router)
