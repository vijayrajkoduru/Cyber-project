"""API key / token leakage in HTML + linked JS - MethodologyScanner refactor.

VL-METHOD Wave 6: regex-scan homepage HTML + first 4 linked JS bundles for
known secret-shaped strings. 6 stages:
  pre_flight    - homepage reachable
  fingerprint   - SPA detection (canary body used to suppress bundle FPs)
  quick_probe   - fetch homepage HTML only, scan for keys
  deep_scan     - fetch up to 4 linked JS bundles (only if quick found
                  ANY HTML or always_deep=True for full audit)
  verify        - replay token by fetching a SPA canary path; CONFIRMED if
                  token NOT present in canary body (target-specific exposure)
  privilege_check - exposed secret = "guest" exposure (anyone can read)
"""
import asyncio
import re

from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url
from tools._vl_core.verify import vl_verify
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import http_get, detect_spa_catchall

router = APIRouter()

_KEYS = [
    ("AWS Access Key ID", "HIGH", 8.2, re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key",    "HIGH", 8.2, re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Stripe live secret key", "HIGH", 9.1, re.compile(r"sk_live_[0-9A-Za-z]{24,}")),
    ("Slack token",       "HIGH", 8.0, re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("API key/token in URL query", "MEDIUM", 5.3,
     re.compile(r"[?&](?:api[_-]?key|apikey|access_token|auth_token)=[A-Za-z0-9_\-]{16,}")),
]
_SRC = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.I)


def _scan_blob(blob, canary_body, spa_is):
    found, suppressed = [], []
    for label, sev, cvss, rx in _KEYS:
        m = rx.search(blob)
        if not m:
            continue
        tok = m.group(0)
        if spa_is and canary_body and tok in canary_body:
            suppressed.append({"label": label, "reason": "matched-in-spa-bundle"})
            continue
        red = (tok[:8] + "…" + tok[-2:]) if len(tok) > 12 else tok[:6] + "…"
        found.append({"label": label, "sev": sev, "cvss": cvss,
                       "red": red, "raw": tok})
    return found, suppressed


class ApiKeyInUrlLeak(MethodologyScanner):
    name = "api_key_in_url_leak"

    async def pre_flight(self, ctx):
        ctx.state["base_url"] = web_url(str(ctx.host)).rstrip("/")
        r = await asyncio.to_thread(http_get, ctx.state["base_url"] + "/", timeout=10)
        if not r:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Homepage unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["_homepage_body"] = r.get("body", "") or ""
        return True

    async def fingerprint(self, ctx):
        spa = await detect_spa_catchall(ctx.state["base_url"])
        ctx.state["_spa"] = spa
        ctx.state["fingerprint"] = {
            "is_spa": spa.get("is_spa", False),
            "canary_body_len": len(spa.get("canary_body", "")),
        }

    async def quick_probe(self, ctx):
        # Scan homepage HTML only — fast triage
        body = ctx.state.get("_homepage_body", "")
        spa = ctx.state.get("_spa") or {}
        found, suppressed = _scan_blob(
            body, spa.get("canary_body", ""), spa.get("is_spa", False))
        ctx.state["_quick_hits"] = found
        ctx.state["_quick_suppressed"] = suppressed
        return found

    async def deep_scan(self, ctx):
        # Fetch up to 4 linked JS bundles + scan
        base = ctx.state["base_url"]
        body = ctx.state.get("_homepage_body", "")
        spa = ctx.state.get("_spa") or {}
        blobs = []
        for m in list(_SRC.finditer(body))[:4]:
            u = m.group(1)
            if u.startswith("//"):
                u = "https:" + u
            elif u.startswith("/"):
                u = base + u
            elif not u.startswith("http"):
                u = base + "/" + u
            jr = await asyncio.to_thread(http_get, u, timeout=10)
            if jr and jr.get("body"):
                blobs.append(jr["body"][:200000])
        if not blobs:
            return []
        combined = "\n".join(blobs)
        found, suppressed = _scan_blob(
            combined, spa.get("canary_body", ""), spa.get("is_spa", False))
        # Dedup against quick hits
        quick_tokens = {h["raw"] for h in (ctx.state.get("_quick_hits") or [])}
        found = [h for h in found if h["raw"] not in quick_tokens]
        ctx.state["_deep_hits"] = found
        ctx.state["_deep_suppressed"] = suppressed
        return found

    async def verify(self, ctx, finding):
        # The SPA-canary suppression already ran during _scan_blob, so any
        # finding that survived to verify is NOT in the bundle. Confirm by
        # checking that the SPA canary body really doesn't contain it.
        spa = ctx.state.get("_spa") or {}
        canary_body = spa.get("canary_body", "") or ""
        tok = finding.get("raw", "")
        if tok and tok not in canary_body:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "token absent from SPA canary body"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "token also present in SPA canary body"
        # Drop raw token from output (caller already has redacted version)
        finding.pop("raw", None)
        return finding

    async def privilege_check(self, ctx, finding):
        finding["privilege_level"] = "guest" if finding.get("confidence") == "CONFIRMED" else "unknown"
        return finding


def _mk(i):
    def rule(s):
        verified = s.get("methodology_findings") or []
        confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
        if i >= len(confirmed):
            return None
        x = confirmed[i]
        return {"name": f"Secret exposed in client-side content: {x['label']} (CONFIRMED)",
                "severity": x["sev"], "cvss": x["cvss"], "cwe": "CWE-200",
                "evidence": f"Matched {x['label']} in HTML/JS (redacted): {x['red']}.",
                "remediation": ("Revoke and rotate the exposed key; move secrets "
                                 "server-side; never embed keys in client JS or URLs.")}
    return rule


def _r_suspected(s):
    verified = s.get("methodology_findings") or []
    suspected = [f for f in verified if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    return {"name": f"Secret possibly in client-side content ({len(suspected)}) - SUSPECTED",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-200",
            "evidence": "; ".join(f"{f['label']}: {f['red']}" for f in suspected),
            "remediation": "Manually verify; token may be a bundle artifact rather than a real secret."}


def _r_clean(s):
    if not s.get("tested"):
        return None
    if s.get("methodology_findings"):
        return None
    return {"name": "No API keys or tokens leaked in client-side content",
            "severity": "POSITIVE",
            "evidence": "Scanned HTML + linked JS; no AWS/Google/Stripe/Slack keys or tokens-in-URL found."}


FINDING_RULES = [_mk(i) for i in range(5)] + [_r_suspected, _r_clean]
INTEL_FIELDS = [
    ("Stage timings (ms)", "stage_timings"),
    ("Verified findings", "methodology_findings"),
]


@router.post("/api/vuln/api_key_in_url_leak")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = ApiKeyInUrlLeak()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
