"""Webapp secrets scanner — regex match against AI-curated 97-pattern catalog.

Route: POST /api/webapp/secrets
Loads tools/_payloads/secrets_patterns.py (97 handcrafted regex patterns
covering AWS / GCP / Azure / GitHub / Slack / Stripe / Twilio / JWT /
RSA keys / DB connection strings / Indian fintech / AI provider keys).

Workflow:
  1. Fetch homepage + crawl ≤ 10 same-origin JS files
  2. Run every AI pattern against each response body
  3. Grade each hit through a ZERO-FP gate, then emit (capped to avoid spam)

ZERO-FP gate (stops fake "Cohere API Key" hits on minified bundles):
  * "vendor"-class patterns (AWS AKIA, Slack xox*, Google AIza*, Stripe
    sk_live_, GitHub ghp_, private-key PEM headers, …) — precise prefix
    shapes; graded as cataloged after a light shape sanity check.
  * "generic"-class patterns (loose proximity / high-entropy / bare-charset
    shapes that collide with webpack chunk hashes, base64 fragments, SRI
    integrity hashes, source-map refs, data-URIs, long hex consts) — only
    graded when the captured blob clears a Shannon-entropy floor AND survives
    the allowlist; otherwise INFO. Graded generic hits are capped at MEDIUM.
  * Anything not confidently a live secret -> INFO, never HIGH/CRITICAL.
"""
import math
import re

import httpx

from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()


# ── Zero-FP helpers (load from patterns module; safe local fallback) ─────────
try:
    from tools._payloads.secrets_patterns import (
        GENERIC_MIN_ENTROPY as _MIN_ENTROPY,
        shannon_entropy as _shannon_entropy,
        looks_like_false_match as _looks_like_false_match,
    )
except Exception:
    _MIN_ENTROPY = 3.6

    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(s)
        ent = 0.0
        for c in freq.values():
            p = c / n
            ent -= p * math.log2(p)
        return ent

    _FALSE_MATCH_RES = [re.compile(p, re.I) for p in (
        r"integrity\s*=\s*[\"']?(?:sha256|sha384|sha512)-",
        r"\b(?:sha256|sha384|sha512)-[A-Za-z0-9+/]{20,}={0,2}",
        r"sourceMappingURL\s*=", r"\.js\.map\b", r"\.css\.map\b",
        r"data:[a-z0-9.+/\-]+;base64,",
        r"[\w./~-]+\.[0-9a-f]{6,}\.(?:js|css|mjs|map|woff2?|png|jpe?g|gif|svg|webp)\b",
        r"__webpack_require__|webpackJsonp|webpackChunk",
        r"[?&](?:v|h|hash|rev|ver)=[0-9a-f]{6,}",
    )]

    def _looks_like_false_match(candidate: str, context: str = "") -> bool:
        hay = candidate + "\n" + (context or "")
        return any(rx.search(hay) for rx in _FALSE_MATCH_RES)


# Longest run of secret-shaped chars inside a (possibly proximity-keyword)
# match — this is the actual blob we entropy-test, not the keyword prefix.
_BLOB_RE = re.compile(r"[A-Za-z0-9+/_\-]{16,}")

_FALLBACK_PATTERNS = [
    {"name": "AWS Access Key ID", "regex": r"AKIA[0-9A-Z]{16}",
     "service": "aws", "severity": "CRITICAL", "cvss": "9.8",
     "remediation": "Rotate the AWS key immediately."},
    {"name": "RSA Private Key", "regex": r"-----BEGIN RSA PRIVATE KEY-----",
     "service": "private_key", "severity": "CRITICAL", "cvss": "10.0",
     "remediation": "Rotate key pair IMMEDIATELY."},
    {"name": "JWT Token", "regex": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}",
     "service": "jwt", "severity": "MEDIUM", "cvss": "5.5",
     "remediation": "Move JWT to HttpOnly cookies."},
]
try:
    from tools._payloads.secrets_patterns import SECRETS_PATTERNS as _AI_SECRETS
    _PATTERNS = list(_AI_SECRETS) if isinstance(_AI_SECRETS, list) and _AI_SECRETS else _FALLBACK_PATTERNS
except Exception:
    _PATTERNS = _FALLBACK_PATTERNS

# Pre-compile patterns once for speed. Default class is "vendor" (precise,
# prefix-anchored shapes); "generic" patterns are entropy+allowlist gated.
_COMPILED = []
for _p in _PATTERNS:
    try:
        _COMPILED.append((_p, re.compile(_p["regex"], re.IGNORECASE)))
    except Exception:
        continue  # skip malformed regex


def _candidate_blob(matched: str) -> str:
    """Pull the longest secret-shaped run out of a match (drops the keyword
    prefix from proximity patterns so entropy is measured on the real blob)."""
    runs = _BLOB_RE.findall(matched)
    return max(runs, key=len) if runs else matched


def _vendor_shape_ok(entry: dict, matched: str) -> bool:
    """Light sanity check that a precise-vendor match is really key-shaped and
    not a structural artifact. Conservative: only rejects obvious non-keys
    (private-key PEM headers / connection-string URIs are always real)."""
    svc = entry.get("service", "")
    if svc == "private_key" or "://" in matched:
        return True  # PEM header / DB URI literal — unambiguous
    blob = _candidate_blob(matched)
    if len(blob) >= 18 and _shannon_entropy(blob) < 2.2:
        # e.g. "AAAAAAAAAAAAAAAA..." after a real prefix — degenerate filler
        return False
    return True


def _grade_hit(entry: dict, matched: str, context: str):
    """Return (severity, note) for one regex hit, enforcing the ZERO-FP gate.

    - generic class: must clear the entropy floor AND survive the allowlist,
      else INFO. Never escalates a generic hit above its catalog severity.
    - vendor class: graded as cataloged once a light shape check passes,
      else downgraded to INFO.
    """
    cls = entry.get("class", "vendor")
    cat_sev = entry.get("severity", "MEDIUM")
    blob = _candidate_blob(matched)

    if cls == "generic":
        if _looks_like_false_match(matched, context):
            return "INFO", "allowlisted benign build artifact (SRI/source-map/data-URI/hashed-asset)"
        if _shannon_entropy(blob) < _MIN_ENTROPY:
            return "INFO", f"low entropy ({_shannon_entropy(blob):.2f} < {_MIN_ENTROPY} bits/char) — not key-like"
        # Real entropy + not allowlisted: still NOT confidently a live secret
        # from a black-box HTTP body, so cap graded severity at MEDIUM.
        if cat_sev in ("CRITICAL", "HIGH"):
            return "MEDIUM", "high-entropy candidate (capped: unverified generic match)"
        return cat_sev, "high-entropy candidate"

    # vendor class
    if not _vendor_shape_ok(entry, matched):
        return "INFO", "matched vendor prefix but value is not key-shaped"
    if _looks_like_false_match(matched, context):
        return "INFO", "vendor-prefixed but inside a benign build artifact"
    return cat_sev, "precise vendor pattern, shape-verified"

_TIMEOUT = httpx.Timeout(connect=4.0, read=6.0, write=3.0, pool=8.0)
_MAX_JS_FILES = 10
_MAX_BODY_BYTES = 1_500_000  # cap per-file scan to 1.5MB
_MAX_FINDINGS = 30


async def _fetch_with_extracted_js(client, base):
    """Fetch homepage; extract up to N same-origin .js URLs; fetch each."""
    bodies = []  # list of (label, content)
    try:
        r = await client.get(base + "/")
        bodies.append((base + "/", (r.text or "")[:_MAX_BODY_BYTES]))
        html = r.text or ""
    except Exception:
        return bodies
    # Extract <script src="..."> URLs (same-origin only)
    src_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
    seen = set()
    for m in src_re.finditer(html):
        url = m.group(1)
        if url.startswith("//"): continue
        if url.startswith("http") and not url.startswith(base): continue
        if not url.startswith("http"):
            url = base + ("" if url.startswith("/") else "/") + url.lstrip("/")
        if url in seen: continue
        seen.add(url)
        if len(seen) > _MAX_JS_FILES: break
        try:
            jr = await client.get(url)
            bodies.append((url, (jr.text or "")[:_MAX_BODY_BYTES]))
        except Exception:
            continue
    return bodies


@router.post("/api/webapp/secrets")
@vl_verify(check_spa=True)
async def webapp_secrets(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    hits = []

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=_TIMEOUT,
        headers={"User-Agent": "VulnusLab/1.0"}
    ) as client:
        bodies = await _fetch_with_extracted_js(client, base)

    # Scan each body against every compiled pattern. Every hit is graded
    # through the ZERO-FP gate (_grade_hit) at match time so that generic /
    # high-entropy patterns that collide with minified JS get downgraded to
    # INFO instead of producing fake HIGH/CRITICAL "leaks".
    _MATCH_BUDGET = 400  # raw matches to evaluate before we stop (INFO included)
    raw_count = 0
    stop = False
    for label, body in bodies:
        if not body or stop: continue
        for entry, compiled in _COMPILED:
            for m in compiled.finditer(body):
                raw_count += 1
                matched = m.group(0)
                # ±60 chars of context for allowlist (SRI / data-URI / map next to blob)
                lo = max(0, m.start() - 60)
                ctx = body[lo:m.end() + 60]
                graded_sev, note = _grade_hit(entry, matched, ctx)
                hits.append({
                    "name": entry["name"], "service": entry["service"],
                    "severity": graded_sev, "cat_severity": entry.get("severity"),
                    "cls": entry.get("class", "vendor"), "note": note,
                    "url": label, "snippet": matched[:80],
                })
                if raw_count >= _MATCH_BUDGET:
                    stop = True
                    break
            if stop:
                break

    # Dedupe by (service, snippet) so we don't report the same key twice
    seen = set()
    unique_hits = []
    for h in hits:
        k = (h["service"], h["snippet"])
        if k in seen: continue
        seen.add(k)
        unique_hits.append(h)

    # Graded (real) hits first, INFO last; cap total emitted findings.
    _RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    unique_hits.sort(key=lambda h: _RANK.get(h["severity"], 0), reverse=True)
    graded_hits = [h for h in unique_hits if h["severity"] != "INFO"]

    for h in unique_hits[:_MAX_FINDINGS]:
        sev = h["severity"] if h["severity"] in (
            "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "INFO"
        # Find the original entry to grab cvss + remediation
        orig = next((e for e in _PATTERNS if e.get("name") == h["name"]), {})
        cvss = orig.get("cvss", "5.0") if sev != "INFO" else "0.0"
        rem = orig.get("remediation", "Rotate the leaked credential immediately.")
        if sev == "INFO":
            detail = (f"Unverified secret-shaped match (not graded): {h['name']}")
            rem = ("Pattern matched but the value did not clear the zero-FP gate "
                   "(" + h["note"] + "). Manually confirm whether this is a live "
                   "credential before acting; rotate only if real.")
        else:
            detail = f"Secret leaked in client-side response: {h['name']}"
        findings.append(wrap_finding(
            detail,
            sev, cvss=cvss, cwe="CWE-200",
            cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
            owasp="A02:2021",
            remediation=rem,
            evidence_marker=(f"At {h['url']}: matched pattern '{h['name']}' "
                             f"[class={h['cls']}, gate={h['note']}] "
                             f"(snippet: {h['snippet'][:60]}...)"),
        ))

    # Positive only when NO graded leak was confirmed (INFO-only counts as clean).
    if not graded_hits and bodies:
        findings.append(wrap_finding(
            "No exposed secrets — no client-side response matched a verified "
            "API-key / token / credential pattern (entropy + allowlist gated)",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain. Keep secrets server-side and add gitleaks/trufflehog "
                        "to CI plus a post-deploy scan. Re-test after front-end changes.",
            evidence_marker=f"scanned {len(bodies)} response body(ies) against "
                            f"{len(_COMPILED)} AI-curated regex pattern(s); "
                            f"{len(unique_hits) - len(graded_hits)} unverified/INFO match(es), "
                            f"0 graded leaks"))
    return standard_response(
        tool="secrets", target=req.target,
        findings=findings,
        tests_performed=len(_COMPILED) * len(bodies),
        tests_summary=(f"Scanned {len(bodies)} response bodies against "
                       f"{len(_COMPILED)} AI-curated regex patterns; "
                       f"{len(graded_hits)} graded leak(s), "
                       f"{len(unique_hits) - len(graded_hits)} unverified/INFO"),
        raw_data={"secrets": {
            "patterns_loaded": len(_COMPILED),
            "bodies_scanned": len(bodies),
            "unique_hits": len(unique_hits),
            "graded_hits": len(graded_hits),
            "info_hits": len(unique_hits) - len(graded_hits),
            "wordlist_source": f"AI-curated ({len(_PATTERNS)} patterns)",
            "services_with_hits": sorted({h["service"] for h in graded_hits}),
        }},
    )


def register(app):
    app.include_router(router)
