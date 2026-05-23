"""SSRF — multi-cloud metadata + localhost markers with SPA-baseline FP suppression.

Payload source: tools/_payloads/ssrf.py (SSRF_PAYLOADS, ~50 entries across
aws-imds / gcp-metadata / azure-imds / do-metadata / oracle-imds /
alibaba-imds / tencent-imds / ibm-imds / kubelet / docker-api / localhost /
internal-net / schema-bypass / dns-rebind).

SPA-baseline FP suppression preserved: each param gets a benign canary
fingerprinted first; any SSRF probe that returns the IDENTICAL response
is dropped (the site is ignoring the param — typical SPA behaviour).
"""
import hashlib
import re
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.ssrf import SSRF_PAYLOADS
from tools.vuln._vuln_common import vuln_response, precheck_target
from tools._payloads.vuln._loader import load_json
# AI-curated extras: more cloud metadata endpoints, k8s, docker, redis, vault, etcd.
_AI_EXTRA_SSRF = load_json("ssrf_extra_targets", fallback=[])
_MERGED_SSRF = list(SSRF_PAYLOADS) + [p for p in _AI_EXTRA_SSRF if isinstance(p, dict) and "url" in p]

router = APIRouter()

_COMMON_KEYS = ["url", "uri", "src", "fetch", "image", "img", "avatar",
                "callback", "redirect", "webhook", "proxy", "host",
                "next", "return", "site", "feed", "import"]


def _build_payload_set():
    """Interleave by category so the per-param HTTP burst exercises every
    cloud family (AWS / GCP / Azure / DO / Oracle / Alibaba / Tencent / IBM)
    plus k8s / docker / localhost / internal-net before exhausting any one.
    Schema-bypass + dns-rebind go last (lower expected hit-rate).
    """
    order = ["aws-imds", "gcp-metadata", "azure-imds", "do-metadata",
             "oracle-imds", "alibaba-imds", "tencent-imds", "ibm-imds",
             "kubelet", "docker-api", "localhost", "internal-net",
             "schema-bypass", "dns-rebind"]
    buckets = {cat: [] for cat in order}
    for p in _MERGED_SSRF:
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


def _resp_fingerprint(r):
    """Hash status + first 2KB of body so we can compare baseline vs probe."""
    if r is None:
        return None
    body = (r.text or "")[:2000]
    h = hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest()
    return f"{r.status_code}:{len(r.content)}:{h}"


def _extra_headers_for(ssrf_url):
    """Some cloud metadata endpoints require a specific header to respond."""
    if "metadata.google" in ssrf_url:
        return {"Metadata-Flavor": "Google"}
    if "metadata/instance" in ssrf_url and "169.254.169.254" in ssrf_url:
        return {"Metadata": "true"}  # Azure IMDS
    return {}


@router.post("/api/scan/ssrf")
def scan_ssrf(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    unreachable = precheck_target(base, req)
    if unreachable:
        return vuln_response(tool="ssrf", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
    parsed = urlparse(base)
    existing = parse_qs(parsed.query)
    candidates = set(existing.keys()) | set(_COMMON_KEYS)
    if not candidates:
        return standard_response(tool="ssrf", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters — append ?url=http://... to test")

    # Per-param cap: 24 covers AWS+GCP+Azure+DO+Oracle+Alibaba+k8s+docker+
    # localhost+internal+schema while keeping the per-param probe budget bounded.
    payload_set = _PAYLOAD_SET[:24]

    findings, tests, confirmed, suppressed = [], 0, [], []

    baselines = {}
    canary_token = "vlcanary" + secrets.token_hex(4)
    for key in candidates:
        new_params = {k: v[0] for k, v in existing.items()}
        new_params[key] = f"https://benign-{canary_token}.example/"
        canary_url = urlunparse(parsed._replace(query=urlencode(new_params)))
        cr = safe_get(canary_url, req=req, allow_redirects=False, timeout=10)
        baselines[key] = _resp_fingerprint(cr)

    # SPEED-V2 — wall-clock cap to prevent 240s orchestrator-timeout cascades.
    import time as _time
    _wallclock_start = _time.time()
    _WALLCLOCK_BUDGET = 45.0
    _bailed = False
    for key in candidates:
        if _bailed: break
        baseline_fp = baselines.get(key)
        for entry in payload_set:
            if _time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
                _bailed = True; break
            tests += 1
            ssrf_url = entry["url"]
            marker = entry["matcher"]
            cloud = entry.get("name", entry.get("category", "internal"))
            cat = entry.get("category", "internal")

            new_params = {k: v[0] for k, v in existing.items()}
            new_params[key] = ssrf_url
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
            extra = _extra_headers_for(ssrf_url)
            r = safe_get(test_url, headers=extra, req=req, allow_redirects=False, timeout=10)
            if r is None or r.status_code != 200:
                continue
            probe_fp = _resp_fingerprint(r)
            if baseline_fp is not None and probe_fp == baseline_fp:
                suppressed.append({"param": key, "cloud": cloud,
                                    "reason": "matches_spa_baseline"})
                continue
            try:
                if re.search(marker, (r.text or "")[:8000], re.IGNORECASE):
                    sev = str(entry.get("severity", "CRITICAL")).upper()
                    cvss = str(entry.get("cvss", "9.1"))
                    findings.append(wrap_finding(
                        f"SSRF — param {key!r} reaches {cloud} ({cat})",
                        sev, cvss=cvss, cwe="CWE-918", owasp="A10:2021",
                        remediation=("Validate URLs against allow-list. Reject private IP ranges "
                                     "(10/8, 172.16/12, 192.168/16, 169.254/16, 127/8, ::1, fc00::/7). "
                                     "Block file://, gopher://, dict://, ldap:// schemes."),
                        evidence_marker=f"param={key} payload {ssrf_url!r} returned content matching {marker!r} ({cloud})"))
                    confirmed.append({"param": key, "payload": ssrf_url,
                                       "cloud": cloud, "category": cat})
                    break
            except re.error:
                continue

    summary = (f"SSRF: {tests} probes across {len(candidates)} params using "
               f"{len(payload_set)}-entry payload set (merged: {len(SSRF_PAYLOADS)} baked-in + {len(_AI_EXTRA_SSRF)} AI-curated, "
               f"14 categories); {len(suppressed)} SPA matches filtered as non-vulnerable "
               f"({_time.time() - _wallclock_start:.1f}s)")
    if _bailed:
        summary += f" — wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return vuln_response(tool="ssrf", target=req.target, findings=findings,
        tested=tests,
        what_checked=f"URL parameters for SSRF to cloud metadata / localhost / k8s / docker / IPC ({len(_MERGED_SSRF)}-entry merged library)",
        tests_summary=summary,
        raw_data={"ssrf": {"confirmed": confirmed,
                            "suppressed_fps": suppressed,
                            "baseline_fingerprints": len([b for b in baselines.values() if b]),
                            "library_size": len(_MERGED_SSRF),
                            "ai_extras_loaded": len(_AI_EXTRA_SSRF),
                            "wallclock_bailed": _bailed}})


def register(app):
    app.include_router(router)
