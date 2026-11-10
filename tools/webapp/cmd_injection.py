"""OS Command Injection — timing-based zero-FP with AI-curated payload library.

Payload source: tools/_payloads/cmd_injection.py (CMD_PAYLOADS, ~60 entries
across linux-shell / windows-cmd / node-js / php-cli / python-cli /
perl-ruby / waf-bypass / encoded / blind-dns). Each timing-confirmable
entry has a {N} placeholder that we substitute with two different sleep
values to confirm via the double-sleep dance (zero-FP).
"""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, safe_post, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
from tools.webapp import _post_forms as pf
from tools._payloads.cmd_injection import CMD_PAYLOADS
from tools.webapp._webapp_common import vuln_response, precheck_target
from tools._payloads.webapp._loader import load_json
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
# AI-curated extras: more shell variants + powershell + template-injection + WAF-bypass.
_AI_EXTRA_CMD = load_json("cmd_injection_extra", fallback=[])
_MERGED_CMD = list(CMD_PAYLOADS) + [p for p in _AI_EXTRA_CMD if isinstance(p, dict) and "payload" in p]


def _build_payload_set():
    """Filter to confirmable entries (skip blind-DNS for now) and interleave
    by category so the first per-param HTTP burst exercises every variant
    family — linux/windows/node/php/python/perl-ruby/waf-bypass/encoded —
    instead of burning the budget on 18 linux-shell variants in a row.
    """
    order = ["linux-shell", "windows-cmd", "node-js", "php-cli",
             "python-cli", "perl-ruby", "waf-bypass", "encoded"]
    buckets = {cat: [] for cat in order}
    for p in _MERGED_CMD:
        if not p.get("confirmable"): continue
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


def _time_get(url, req, timeout):
    t0 = time.time()
    r = safe_get(url, req=req, allow_redirects=True, timeout=timeout)
    return r, time.time() - t0


def _time_post(url, data, req, timeout):
    t0 = time.time()
    r = safe_post(url, req=req, data=data, allow_redirects=True, timeout=timeout)
    return r, time.time() - t0


@router.post("/api/webapp/scan/cmd_injection")
@vl_turbo(timeout_s=120)   # 60s GET phase + 40s POST-form phase + in-flight probe
@vl_verify()
def scan_cmd_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    unreachable = precheck_target(base, req)
    if unreachable:
        return vuln_response(tool="cmd_injection", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
    parsed = urlparse(base)
    params_base = parse_qs(parsed.query)
    test_urls = []
    if params_base:
        test_urls.append((base, parsed, params_base))
    spa = load_spa_state(req.target)
    post_forms = pf.normalized_post_forms(spa, limit=6)
    for u in spa.get("urls", []):
        try:
            up = urlparse(u)
            ps = parse_qs(up.query)
            if ps:
                test_urls.append((u, up, ps))
        except Exception:
            continue
    if not test_urls and not post_forms:
        return standard_response(tool="cmd_injection", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters or POST forms present on base or SPA-discovered endpoints")

    findings, tests, confirmed = [], 0, []
    _, t0 = _time_get(base, req, timeout=20)
    # Per-param cap: 32 covers every interesting variant family while keeping
    # latency bounded (each tested payload may cost up to 5s of sleep delay).
    payload_set = _PAYLOAD_SET[:32]
    # SPEED-V2 — wall-clock cap to prevent 240s orchestrator-timeout cascades.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 60.0
    _bailed = False

    for tu_url, tu_parsed, params in test_urls[:8]:
        if _bailed: break
        for key in list(params.keys())[:3]:
            if _bailed: break
            original = params[key][0]
            for entry in payload_set:
                if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
                    _bailed = True; break
                tests += 1
                tmpl = entry["payload"]
                name = entry.get("name", entry.get("category", "cmd"))
                inj5 = tmpl.replace("{N}", "5")
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = original + inj5
                url1 = urlunparse(tu_parsed._replace(query=urlencode(new_params)))
                # TIMING-FP-V1 — use the SAME timeout ceiling for both probes.
                # Previously url1 used 25s and url2 used 15s, so an endpoint
                # that merely HANGS (not a real sleep) returned t1~=25 > t2~=15
                # purely because the ceilings differed, faking "timing scaled
                # with N" and confirming a bogus CRITICAL (e.g. a Node.js
                # payload on PHP DVWA that can never execute).
                _, t1 = _time_get(url1, req, timeout=12)
                d1 = t1 - t0
                # The injected `sleep 5` must land as ~5s of ADDED delay — not
                # a timeout/hang. Reject anything that didn't move (<4s) or that
                # looks like a ceiling hang (>9s, well above a real 5s sleep).
                if d1 < 4 or d1 > 9: continue
                # Confirm with a shorter sleep — the delay must SCALE with N.
                inj2 = tmpl.replace("{N}", "2")
                new_params[key] = original + inj2
                url2 = urlunparse(tu_parsed._replace(query=urlencode(new_params)))
                _, t2 = _time_get(url2, req, timeout=12)
                d2 = t2 - t0
                # `sleep 2` must land as ~2s, and the 3s gap between sleep 5 and
                # sleep 2 must actually appear (d1 - d2 >= 2). A hang gives
                # d1~=d2 and is rejected here.
                if (1.0 <= d2 <= 4.0) and (d1 - d2) >= 2.0:
                    sev = str(entry.get("severity", "CRITICAL")).upper()
                    cvss = str(entry.get("cvss", "9.8"))
                    findings.append(wrap_finding(
                        f"OS command injection in {key!r} via {name} ({entry['category']})",
                        sev, cvss=cvss, cwe="CWE-78", owasp="A03:2021",
                        remediation="Never pass user input to a shell. Use argv-style exec (shell=False).",
                        evidence_marker=(f"param={key} {inj5!r}={t1:.2f}s, {inj2!r}={t2:.2f}s, "
                                         f"baseline={t0:.2f}s — double-sleep dance confirmed")))
                    confirmed.append({"param": key, "payload": tmpl,
                                       "category": entry["category"], "name": name})
                    break
            else:
                continue
            break

    # POST-FORM-CMD-V1 / POST-FORM-INJECT-V1 — command injection also lives
    # behind POST forms (e.g. DVWA /vulnerabilities/exec/ field 'ip'), which
    # the GET-param loop above can never reach. For each crawled/seeded POST
    # form, inject ONE field at a time (other fields at defaults, fresh CSRF
    # token fetched before every submission — outside the timed window), and
    # apply the exact TIMING-FP-V1 double-sleep rules against a per-form
    # benign baseline. The POST phase has its own budget so a slow GET phase
    # cannot starve it.
    _post_start = time.time()
    _POST_BUDGET = 40.0
    _post_bailed = False
    post_forms_tested = []
    for form in post_forms:
        if _post_bailed: break
        action = form["action"]
        post_forms_tested.append(action)
        for key in form["injectable"][:3]:
            if _post_bailed: break
            # Per-form benign baseline: the form's own command (e.g. DVWA's
            # ping 127.0.0.1) takes time on its own, so measure it and compare
            # ADDED delay, isolating the injected sleep.
            _bd = pf.build_data(form, req, key, "127.0.0.1")
            _, tb = _time_post(action, _bd, req, timeout=12)
            for entry in payload_set:
                if (time.time() - _post_start > _POST_BUDGET or
                        time.time() - _wallclock_start > 90):  # stay under vl_turbo cap
                    _post_bailed = True; break
                tests += 1
                tmpl = entry["payload"]
                name = entry.get("name", entry.get("category", "cmd"))
                d = pf.build_data(form, req, key, "127.0.0.1" + tmpl.replace("{N}", "5"))
                _, t1 = _time_post(action, d, req, timeout=12)
                dd1 = t1 - tb
                if dd1 < 4 or dd1 > 9:
                    continue
                d2 = pf.build_data(form, req, key, "127.0.0.1" + tmpl.replace("{N}", "2"))
                _, t2 = _time_post(action, d2, req, timeout=12)
                dd2 = t2 - tb
                if (1.0 <= dd2 <= 4.0) and (dd1 - dd2) >= 2.0:
                    sev = str(entry.get("severity", "CRITICAL")).upper()
                    findings.append(wrap_finding(
                        f"OS command injection in POST field {key!r} via {name} ({entry['category']})",
                        sev, cvss=str(entry.get("cvss", "9.8")), cwe="CWE-78", owasp="A03:2021",
                        remediation="Never pass user input to a shell. Use argv-style exec (shell=False).",
                        evidence_marker=(f"POST {action} field={key} sleep5={t1:.2f}s, sleep2={t2:.2f}s, "
                                         f"form-baseline={tb:.2f}s — double-sleep dance confirmed"
                                         + (" (fresh CSRF token per request)" if form["csrf_fields"] else ""))))
                    confirmed.append({"param": key, "payload": tmpl, "url": action,
                                       "category": entry["category"], "name": name, "method": "POST"})
                    break
            else:
                continue
            break

    summary = (f"Cmd injection: {tests} variants from {len(payload_set)}-entry payload set "
               f"(merged: {len(CMD_PAYLOADS)} baked-in + {len(_AI_EXTRA_CMD)} AI-curated, 8 categories) "
               f"with double-sleep timing confirmation in {time.time() - _wallclock_start:.1f}s")
    summary += f"; {len(post_forms_tested)} POST form(s) tested"
    if _bailed:
        summary += f" — wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    if _post_bailed:
        summary += f" — POST-form phase bailed at {_POST_BUDGET}s"
    return vuln_response(tool="cmd_injection", target=req.target, findings=findings,
        tested=max(tests, 1),
        what_checked=f"URL parameters and POST form fields for OS command injection (timing-based, 8-category merged library: {len(CMD_PAYLOADS)} baked-in + {len(_AI_EXTRA_CMD)} AI-curated)",
        tests_summary=summary,
        raw_data={"cmd_injection": {"baseline_seconds": t0,
                                     "confirmed": confirmed,
                                     "library_size": len(_MERGED_CMD),
                                     "filtered_confirmable": len(_PAYLOAD_SET),
                                     "ai_extras_loaded": len(_AI_EXTRA_CMD),
                                     "post_forms_tested": post_forms_tested,
                                     "wallclock_bailed": _bailed,
                                     "post_wallclock_bailed": _post_bailed}})


def register(app):
    app.include_router(router)
