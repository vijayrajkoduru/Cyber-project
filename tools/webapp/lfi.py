"""Path Traversal / LFI — marker-based zero-FP.

Payload source: tools/_payloads/lfi.py (LFI_PAYLOADS, 142 entries across
linux-passwd / windows-ini / php-filter / proc-self / encoded-bypass /
double-encoded / null-byte / log-poison). Each entry carries its own
matcher regex; php-filter uses a smart base64-decode-and-check-for-<?php
fallback because the literal "{base64 chars}" matcher false-positives on
inline JWTs, CSS, and data URIs.
"""
import base64, re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
from tools.webapp import _post_forms as pf
from tools._payloads.lfi import LFI_PAYLOADS
from tools.webapp._webapp_common import vuln_response, precheck_target
from tools._payloads.webapp._loader import load_json
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify
# AI-curated extras: system files, history, logs, configs, cloud-meta, container indicators.
_AI_EXTRA_LFI = load_json("lfi_extra_paths", fallback=[])
_MERGED_LFI = list(LFI_PAYLOADS) + [p for p in _AI_EXTRA_LFI if isinstance(p, dict) and "payload" in p]

router = APIRouter()


def _build_lfi_payloads():
    """Interleave by category so the first per-param HTTP burst exercises
    every variant family — instead of burning the budget on N linux-passwd
    variants in a row.

    Uses _MERGED_LFI (baked-in LFI_PAYLOADS + AI-curated lfi_extra_paths).
    """
    order = ["linux-passwd", "linux-shadow", "linux-hosts", "linux-ssh",
             "linux-history", "windows-ini", "windows-sam", "proc-self",
             "var-log", "config", "cloud-meta",
             "encoded-bypass", "double-encoded", "null-byte",
             "log-poison", "php-filter", "linux-resolv", "linux-fstab", "linux-issue"]
    buckets = {cat: [] for cat in order}
    for p in _MERGED_LFI:
        cat = p.get("category")
        if cat not in buckets: continue
        buckets[cat].append({
            "payload":  p["payload"],
            "matcher":  p.get("matcher", ""),
            "category": cat,
            "desc":     f"{cat} ({p.get('target_os', 'any')})",
            "severity": (p.get("severity") or "high").upper(),
            "cvss":     str(p.get("cvss", "7.5")),
        })
    out, idx = [], 0
    while any(idx < len(buckets[cat]) for cat in order):
        for cat in order:
            if idx < len(buckets[cat]):
                out.append(buckets[cat][idx])
        idx += 1
    return out


_PAYLOADS = _build_lfi_payloads()


def _check_marker(body, matcher, category):
    body = body or ""
    if category == "php-filter":
        # Smart fallback: decode any long base64 chunk and check for raw PHP
        for chunk in re.findall(r"[A-Za-z0-9+/=]{40,}", body):
            try:
                decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
                if "<?php" in decoded or "<?PHP" in decoded:
                    return True
            except Exception:
                pass
        if matcher:
            try: return re.search(matcher, body, re.IGNORECASE) is not None
            except Exception: return False
        return False
    if not matcher:
        return False
    try:
        return re.search(matcher, body, re.IGNORECASE) is not None
    except Exception:
        return False


def _strip_echo(body, payload):
    """ECHO-STRIP-V1 — remove the submitted payload (raw + HTML-escaped) from
    the response before marker matching. A page that merely echoes the input
    (search box, guestbook) must not confirm because e.g. '.ssh/id_rsa' in the
    payload satisfies an 'ssh' matcher."""
    import html as _html
    if not body or not payload:
        return body or ""
    for v in {payload, _html.escape(payload), _html.escape(payload, quote=False)}:
        body = body.replace(v, "")
    return body


@router.post("/api/webapp/scan/lfi")
@vl_turbo(timeout_s=120)   # 60s GET phase + 35s POST-form phase + in-flight probe
@vl_verify()
def scan_lfi(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    unreachable = precheck_target(base, req)
    if unreachable:
        return vuln_response(tool="lfi", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
    parsed = urlparse(base)
    params_base = parse_qs(parsed.query)
    test_urls = []
    if params_base:
        test_urls.append((base, parsed, params_base))
    # Augment with SPA-discovered URLs
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
        return standard_response(tool="lfi", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters or POST forms present on base or SPA-discovered endpoints")
    # PRIORITIZE-LFI-ENDPOINTS-V1 — rank URLs whose path/params look like a
    # file-include sink (page, file, doc, include, path, template, ...) to the
    # FRONT, so the genuinely vulnerable endpoint is tested within the budget
    # instead of being buried behind unrelated discovered URLs. Without this,
    # DVWA's /vulnerabilities/fi/?page= was reached inconsistently (LFI=0 on a
    # vulnerable target). Mirrors the SQLi scanner's injectable-first ordering.
    _LFI_HINTS = ("page", "file", "doc", "include", "path", "template", "view",
                  "dir", "folder", "download", "read", "load", "inc",
                  "document", "lang", "locale", "pg", "cat", "action")
    def _lfi_rank(entry):
        _u, _p, _ps = entry
        hay = (_u + " " + " ".join(_ps.keys())).lower()
        return -sum(1 for h in _LFI_HINTS if h in hay)
    test_urls.sort(key=_lfi_rank)

    findings, tests, confirmed = [], 0, []
    # Per-param cap: 60 covers every interesting variant family (Linux + Windows +
    # PHP filter + null-byte + double-encoded + AI-curated system files / logs / configs).
    payload_set = _PAYLOADS[:60]
    # SPEED-V2 — wall-clock cap to prevent 240s orchestrator-timeout cascades.
    import time as _time
    _wallclock_start = _time.time()
    _WALLCLOCK_BUDGET = 60.0
    _bailed = False
    for tu_url, tu_parsed, params in test_urls[:12]:
        if _bailed: break
        for key in list(params.keys())[:3]:
            if _bailed: break
            # BASELINE-DIFF-V1 — fetch the endpoint with a benign value for
            # THIS param. A marker only confirms LFI if it appears in the
            # injected response AND is ABSENT from this baseline. That makes
            # matcher text which is merely part of the app's normal page
            # (DVWA help text containing "sudo"/"ssh", any "<html>", etc.) or
            # an over-broad matcher like ".*" unable to confirm — it matches
            # the baseline too, so it is rejected. Kills the whole class of
            # content-word false positives (fake Windows-SAM / bash_history
            # CRITICALs) while preserving real file reads like /etc/passwd,
            # whose signature (root:.*:0:0) is absent from the baseline page.
            _bl_params = {k: v[0] for k, v in params.items()}
            _bl_params[key] = "1"
            _bl_url = urlunparse(tu_parsed._replace(query=urlencode(_bl_params)))
            _bl = safe_get(_bl_url, req=req, allow_redirects=True, timeout=12)
            baseline_body = ((_bl.text or "")[:50000]
                             if (_bl is not None and _bl.status_code == 200) else None)
            for entry in payload_set:
                if _time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
                    _bailed = True; break
                tests += 1
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = entry["payload"]
                test_url = urlunparse(tu_parsed._replace(query=urlencode(new_params)))
                r = safe_get(test_url, req=req, allow_redirects=True, timeout=12)
                if r is None or r.status_code != 200: continue
                body = _strip_echo((r.text or "")[:50000], entry["payload"])
                if not _check_marker(body, entry["matcher"], entry["category"]):
                    continue
                # Conservative zero-FP gate: require a usable baseline that
                # does NOT already contain the marker. No baseline => do not
                # confirm (a false "CRITICAL" in a paid report is far costlier
                # than missing one exotic case).
                if baseline_body is None or _check_marker(
                        baseline_body, entry["matcher"], entry["category"]):
                    continue
                findings.append(wrap_finding(
                    f"Path Traversal / LFI in {key!r} — {entry['desc']}",
                    "CRITICAL", cvss="9.8", cwe="CWE-22", owasp="A01:2021",
                    remediation="Validate paths against whitelist; reject '..' and absolute paths.",
                    evidence_marker=(f"param={key} payload={entry['payload']!r} "
                                     f"matched {entry['matcher'] or 'PHP base64'} "
                                     f"(absent from baseline)")))
                confirmed.append({"param": key, "payload": entry["payload"],
                                  "category": entry["category"]})
                break
            else:
                continue
            break
    # POST-FORM-INJECT-V1 — file-include sinks behind POST forms. One field at
    # a time (others at defaults, fresh CSRF token per submission) under the
    # SAME BASELINE-DIFF-V1 gate: the marker must appear in the injected
    # response AND be absent from a benign POST of that same field; no usable
    # baseline => no finding.
    _post_start = _time.time()
    _POST_BUDGET = 35.0
    _post_bailed = False
    post_forms_tested = []
    # Rank include-looking fields first (page/file/path/...), like the GET loop.
    for form in post_forms:
        if _post_bailed: break
        action = form["action"]
        post_forms_tested.append(action)
        fields = sorted(form["injectable"],
                        key=lambda n: -sum(1 for h in _LFI_HINTS if h in n.lower()))
        for key in fields[:3]:
            if _post_bailed: break
            _bl = pf.submit(form, req, key, "1", timeout=12)
            baseline_body = ((_bl.text or "")[:50000]
                             if (_bl is not None and _bl.status_code == 200) else None)
            if baseline_body is None:
                continue   # conservative: never confirm without a baseline
            for entry in payload_set:
                if (_time.time() - _post_start > _POST_BUDGET or
                        _time.time() - _wallclock_start > 90):  # stay under vl_turbo cap
                    _post_bailed = True; break
                tests += 1
                r = pf.submit(form, req, key, entry["payload"], timeout=12)
                if r is None or r.status_code != 200: continue
                body = _strip_echo((r.text or "")[:50000], entry["payload"])
                if not _check_marker(body, entry["matcher"], entry["category"]):
                    continue
                if _check_marker(baseline_body, entry["matcher"], entry["category"]):
                    continue
                # STORED-ECHO guard (POST only): forms that persist input
                # (guestbooks, comments) re-render EARLIER payloads, so text
                # from a previous probe can satisfy this matcher. Re-take the
                # benign baseline NOW — if the marker is there too, it is
                # stored echo, not a file read.
                _bl2 = pf.submit(form, req, key, "1", timeout=12)
                if _bl2 is None or _bl2.status_code != 200 or _check_marker(
                        (_bl2.text or "")[:50000], entry["matcher"], entry["category"]):
                    continue
                findings.append(wrap_finding(
                    f"Path Traversal / LFI in POST field {key!r} — {entry['desc']}",
                    "CRITICAL", cvss="9.8", cwe="CWE-22", owasp="A01:2021",
                    remediation="Validate paths against whitelist; reject '..' and absolute paths.",
                    evidence_marker=(f"POST {action} field={key} payload={entry['payload']!r} "
                                     f"matched {entry['matcher'] or 'PHP base64'} "
                                     f"(absent from baseline)")))
                confirmed.append({"param": key, "payload": entry["payload"], "url": action,
                                  "category": entry["category"], "method": "POST"})
                break
            else:
                continue
            break

    summary = (f"Path traversal: {tests} variants from {len(payload_set)}-entry interleaved set "
               f"(merged: {len(LFI_PAYLOADS)} baked-in + {len(_AI_EXTRA_LFI)} AI-curated) "
               f"in {_time.time() - _wallclock_start:.1f}s")
    summary += f"; {len(post_forms_tested)} POST form(s) tested"
    if _bailed:
        summary += f" — wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    if _post_bailed:
        summary += f" — POST-form phase bailed at {_POST_BUDGET}s"
    return vuln_response(tool="lfi", target=req.target, findings=findings,
        tested=max(tests, 1),
        what_checked=f"URL parameters and POST form fields for path traversal / LFI (marker-verified, {len(_MERGED_LFI)}-entry merged library covering ~19 categories)",
        tests_summary=summary,
        raw_data={"lfi": {"confirmed": confirmed,
                           "library_size": len(_PAYLOADS),
                           "merged_size": len(_MERGED_LFI),
                           "ai_extras_loaded": len(_AI_EXTRA_LFI),
                           "post_forms_tested": post_forms_tested,
                           "wallclock_bailed": _bailed,
                           "post_wallclock_bailed": _post_bailed}})


def register(app):
    app.include_router(router)
