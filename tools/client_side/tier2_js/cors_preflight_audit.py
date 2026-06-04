"""cors_preflight_audit - CORS preflight reflection / null / wildcard audit
(playbook §5 #41 + §7 #69).

Cross-Origin Resource Sharing relaxes the Same-Origin Policy. When
mis-configured it lets an attacker page issue authenticated XHR/fetch
against the victim API and READ the response, defeating the
fundamental browser security boundary.

This probe sends 8 OPTIONS preflight requests to the target URL with
varying Origin headers, parses the returned
Access-Control-Allow-Origin (ACAO) + Access-Control-Allow-Credentials
(ACAC), and flags every dangerous configuration:

  CRITICAL  - ACAO reflects ANY Origin AND ACAC: true
              (full session-credentialed cross-origin read)
  CRITICAL  - ACAO is "*" AND ACAC: true
              (spec violation, but some browsers / older middleware
               still accept this and authenticate the read)
  HIGH      - ACAO reflects ANY Origin, ACAC: false
              (no cookies but can still read public APIs / IP-bound
               internal endpoints)
  HIGH      - ACAO accepts "null" Origin
              (file://, data:, sandboxed iframes — easy attacker primitive)
  HIGH      - ACAO accepts a mistyped variant of the production domain
              (e.g. accepts `https://target-mistyped.com` when intended
               to allow `target.com`)
  MEDIUM    - ACAO uses a suffix-match bug (accepts `evil-target.com`
              when expecting `target.com`)
  INFO      - ACAO absent → CORS not configured (default deny → safe)
  POSITIVE  - ACAO present, locks to specific origin(s), no reflection

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.user_agent  = optional UA override

The 8 probes are intentionally fixed (no fuzzing) so this scan stays
predictable + fast.
"""
from __future__ import annotations
import asyncio
import re
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.cors_preflight_audit_findings import (
    CORS_PREFLIGHT_AUDIT_FINDING_RULES,
)

router = APIRouter()


class CorsPreflightRequest(ScanRequest):
    options: Optional[dict] = None


def _build_probes(target_url: str) -> list[dict]:
    """Build per-target probe set — some origins are computed from the host."""
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    # mistyped + suffix-match variants
    mistyped = host
    if "." in host:
        prefix, rest = host.split(".", 1)
        mistyped = prefix + "-mistyped." + rest
    suffix_attack = host + ".attacker.com"  # naive suffix-match bypass
    prefix_attack = "attacker-" + host       # naive prefix-match bypass

    return [
        {"id": "evil_com",          "origin": "https://evil.com",
         "intent": "Generic attacker origin"},
        {"id": "null_origin",       "origin": "null",
         "intent": "Sandboxed iframe / file:// / data: origin"},
        {"id": "file_scheme",       "origin": "file://",
         "intent": "Local-file Origin"},
        {"id": "mistyped_target",   "origin": f"https://{mistyped}",
         "intent": "Mistyped / lookalike of production domain"},
        {"id": "suffix_attack",     "origin": f"https://{suffix_attack}",
         "intent": "Suffix-match bypass (`target.com.attacker.com`)"},
        {"id": "prefix_attack",     "origin": f"https://{prefix_attack}",
         "intent": "Prefix-match bypass (`attacker-target.com`)"},
        {"id": "subdomain_evil",    "origin": f"https://evil.{host}",
         "intent": "Wildcard-subdomain abuse"},
        {"id": "http_target",       "origin": (f"http://{host}" if host else "http://localhost"),
         "intent": "Plain-HTTP version of same host (mixed-content downgrade)"},
    ]


async def _send_preflight(client, target_url: str, probe: dict) -> dict:
    """Fire one OPTIONS preflight, return parsed ACAO / ACAC / vary."""
    headers = {
        "Origin": probe["origin"],
        "Access-Control-Request-Method":  "GET",
        "Access-Control-Request-Headers": "content-type, authorization",
    }
    out = {
        "probe_id":          probe["id"],
        "origin_sent":       probe["origin"],
        "intent":            probe["intent"],
        "status":            0,
        "acao":              None,
        "acac":              None,
        "acam":              None,
        "acah":              None,
        "vary":              None,
        "error":             None,
    }
    try:
        r = await client.request("OPTIONS", target_url, headers=headers)
        out["status"] = r.status_code
        out["acao"] = r.headers.get("access-control-allow-origin")
        out["acac"] = r.headers.get("access-control-allow-credentials")
        out["acam"] = r.headers.get("access-control-allow-methods")
        out["acah"] = r.headers.get("access-control-allow-headers")
        out["vary"] = r.headers.get("vary")
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:80]}"
    return out


def _classify(probe_result: dict) -> dict:
    """Decide severity for one preflight result."""
    acao = (probe_result.get("acao") or "").strip()
    acac = (probe_result.get("acac") or "").strip().lower() == "true"
    origin_sent = probe_result.get("origin_sent") or ""
    probe_id = probe_result.get("probe_id")
    flags = {
        "reflected_origin":     False,
        "wildcard":             False,
        "credentials":          acac,
        "null_origin_allowed":  False,
        "evil_subdomain":       False,
        "mistyped_allowed":     False,
        "suffix_bypass":        False,
        "prefix_bypass":        False,
        "http_downgrade":       False,
        "acao_value":           acao,
        "severity":             "INFO",
    }
    if not acao:
        return flags
    if acao == "*":
        flags["wildcard"] = True
    if acao == origin_sent or acao.lower() == origin_sent.lower():
        flags["reflected_origin"] = True
    if probe_id == "null_origin" and acao == "null":
        flags["null_origin_allowed"] = True
    if probe_id == "mistyped_target" and acao == origin_sent:
        flags["mistyped_allowed"] = True
    if probe_id == "suffix_attack" and acao == origin_sent:
        flags["suffix_bypass"] = True
    if probe_id == "prefix_attack" and acao == origin_sent:
        flags["prefix_bypass"] = True
    if probe_id == "subdomain_evil" and acao == origin_sent:
        flags["evil_subdomain"] = True
    if probe_id == "http_target" and acao == origin_sent:
        flags["http_downgrade"] = True

    # Severity
    if (flags["reflected_origin"] or flags["wildcard"]) and acac:
        flags["severity"] = "CRITICAL"
    elif flags["null_origin_allowed"] and acac:
        flags["severity"] = "CRITICAL"
    elif flags["reflected_origin"] or flags["null_origin_allowed"]:
        flags["severity"] = "HIGH"
    elif (flags["mistyped_allowed"] or flags["suffix_bypass"]
          or flags["prefix_bypass"] or flags["evil_subdomain"]):
        flags["severity"] = "HIGH"
    elif flags["http_downgrade"]:
        flags["severity"] = "MEDIUM"
    elif acao:
        flags["severity"] = "POSITIVE"  # ACAO present, no reflection, no null
    return flags


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
        ctx.state["cors_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    opts = ctx.state.get("_options") or {}
    ua = opts.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    probes = _build_probes(target)
    results: list[dict] = []
    transport_errors = 0

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=20, follow_redirects=True,
            headers={"User-Agent": ua, "Accept": "*/*"},
        ) as client:
            sem = asyncio.Semaphore(4)

            async def _bound(p):
                nonlocal transport_errors
                async with sem:
                    res = await _send_preflight(client, target, p)
                    if res.get("error"):
                        transport_errors += 1
                    res["classify"] = _classify(res)
                    return res

            results = await asyncio.gather(*[_bound(p) for p in probes])
    except Exception as e:
        ctx.state["cors_error"] = f"audit failed: {type(e).__name__}: {str(e)[:120]}"
        ctx.source("audit failed")
        return

    # Aggregate flags
    any_acao_present = any(r.get("acao") for r in results)
    any_credentials = any(
        (r.get("acac") or "").strip().lower() == "true" for r in results
    )
    crit_hits = [r for r in results if r.get("classify", {}).get("severity") == "CRITICAL"]
    high_hits = [r for r in results if r.get("classify", {}).get("severity") == "HIGH"]
    med_hits = [r for r in results if r.get("classify", {}).get("severity") == "MEDIUM"]
    null_allowed = [r for r in results if r.get("classify", {}).get("null_origin_allowed")]
    wildcard_with_creds = [
        r for r in results
        if r.get("classify", {}).get("wildcard")
        and (r.get("acac") or "").strip().lower() == "true"
    ]
    reflected = [
        r for r in results if r.get("classify", {}).get("reflected_origin")
    ]
    mistype_or_bypass = [
        r for r in results
        if r.get("classify", {}).get("mistyped_allowed")
        or r.get("classify", {}).get("suffix_bypass")
        or r.get("classify", {}).get("prefix_bypass")
        or r.get("classify", {}).get("evil_subdomain")
    ]
    http_downgrade = [
        r for r in results if r.get("classify", {}).get("http_downgrade")
    ]

    ctx.state["cors_target_url"] = target
    ctx.state["cors_probes_sent"] = len(probes)
    ctx.state["cors_probes_results"] = results
    ctx.state["cors_transport_errors"] = transport_errors
    ctx.state["cors_any_acao_present"] = any_acao_present
    ctx.state["cors_any_credentials"] = any_credentials
    ctx.state["cors_critical_hits"] = crit_hits
    ctx.state["cors_high_hits"] = high_hits
    ctx.state["cors_medium_hits"] = med_hits
    ctx.state["cors_null_allowed"] = null_allowed
    ctx.state["cors_wildcard_with_creds"] = wildcard_with_creds
    ctx.state["cors_reflected"] = reflected
    ctx.state["cors_mistype_or_bypass"] = mistype_or_bypass
    ctx.state["cors_http_downgrade"] = http_downgrade
    ctx.source(f"OPTIONS x{len(probes)} -> "
               f"{len(crit_hits)} crit / {len(high_hits)} high / "
               f"{len(med_hits)} med")


INTEL_FIELDS = [
    ("Target URL",                  "cors_target_url"),
    ("Probes sent",                 "cors_probes_sent"),
    ("Transport errors",            "cors_transport_errors"),
    ("ACAO observed at all",        "cors_any_acao_present"),
    ("ACAC: true observed",         "cors_any_credentials"),
    ("Critical hits",               "cors_critical_hits"),
    ("High hits",                   "cors_high_hits"),
    ("Reflected origins",           "cors_reflected"),
    ("Null origin allowed",         "cors_null_allowed"),
    ("Wildcard + credentials",      "cors_wildcard_with_creds"),
    ("Mistyped / bypass accepted",  "cors_mistype_or_bypass"),
    ("HTTP downgrade allowed",      "cors_http_downgrade"),
    ("Per-probe results",           "cors_probes_results"),
]


@router.post("/api/client_side/cors_preflight_audit")
async def client_side_cors_preflight_audit(req: CorsPreflightRequest,
                                            _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="cors_preflight_audit",
        gather_func=_gather_with_options,
        finding_rules=CORS_PREFLIGHT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
