"""breach_exposure_audit - domain breach exposure via Have I Been Pwned
(VL-METHOD methodology).

WHAT THIS SCANNER DOES (and does NOT do)
----------------------------------------
Detection-only (VA, not PT). It queries the PUBLIC Have I Been Pwned (HIBP)
breach database for breaches that name the target's domain. Disclosed
breaches are the fuel for credential-stuffing and password-spray attacks
(module_playbooks/08_password.md §3 #37 "Stolen credential reuse").

It performs a single read-only GET against the HIBP API. It does NOT submit
any credentials, does NOT query individual email addresses (which would be
PII handling), and does NOT brute-force anything.

ZERO-FP DISCIPLINE
------------------
  * A graded finding is emitted ONLY when HIBP returns one or more breaches
    naming this domain — a third-party-confirmed, disclosed fact.
  * If HIBP cannot be reached (no network / rate-limited / the breach-by-
    domain endpoint needs a verified API key in this deployment), the result
    is an honest INFO advisory — never a fake POSITIVE and never graded.

The HIBP breach-by-domain endpoint (/breaches?domain=) is public for the
breach METADATA (it returns breaches whose Domain field matches). If a key
is configured via options.hibp_api_key it is sent as hibp-api-key.

7-stage VL-METHOD flow
----------------------
  1. PRE-FLIGHT  - extract a registrable domain from target; require one.
  2. FINGERPRINT - record the domain queried.
  3. QUICK PROBE - GET https://haveibeenpwned.com/api/v3/breaches?domain=<d>
                    Parse the JSON breach list; each breach naming the domain
                    becomes a preliminary finding.
  4. DEEP SCAN   - gated: no-op (single authoritative source; nothing deeper
                    to safely probe without per-account PII queries).
  5. VERIFY      - structurally validate each breach object (has Name + a
                    Domain or matching domain). CONFIRMED on valid object.
  6. PRIVILEGE   - exposure label.
  7. CHAIN       - inert (VA-not-PT).

Customer input via ScanRequest.options:
  - target            = domain or URL (required)
  - options.hibp_api_key = optional HIBP API key for authoritative lookups
  - options.timeout    = request timeout seconds (default 10)

Safety: one read-only GET. Respects HIBP rate limits (single request).
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel  # noqa: F401

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.breach_exposure_audit_findings import (
    BREACH_EXPOSURE_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

DEFAULT_TIMEOUT = 10.0
HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"


class BreachExposureAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _extract_domain(target: str) -> str:
    """Return a bare registrable-ish domain from a URL/host/host:port."""
    if not target:
        return ""
    t = target.strip()
    if "://" in t:
        t = urlparse(t).netloc or t.split("://", 1)[1]
    t = t.split("/", 1)[0].split("?", 1)[0]
    # strip port
    if ":" in t and not t.startswith("["):
        t = t.rsplit(":", 1)[0]
    # strip leading www.
    if t.lower().startswith("www."):
        t = t[4:]
    return t.strip().lower()


async def _hibp_breaches_by_domain(domain: str, api_key: str,
                                   timeout: float) -> tuple[Optional[list], Optional[str]]:
    """GET the HIBP breach list filtered by domain. Returns (breaches, error).
    breaches is a list of breach dicts, or None on error (error string set)."""
    url = f"{HIBP_BREACHES_URL}?domain={domain}"
    headers = {
        "User-Agent": "VulnusLab-BreachExposureAudit/1.0",
        "Accept": "application/json",
    }
    if api_key:
        headers["hibp-api-key"] = api_key

    try:
        import httpx
    except ImportError:
        return await _hibp_requests(url, headers, timeout)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.get(url, headers=headers)
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    return None, "HIBP returned non-JSON body"
                if isinstance(data, list):
                    return data, None
                return [], None
            if r.status_code == 404:
                # 404 = no breaches for this domain (HIBP convention for some endpoints)
                return [], None
            if r.status_code == 401:
                return None, "HIBP requires a verified API key for breach-by-domain (401)"
            if r.status_code == 429:
                return None, "HIBP rate limit hit (429) - retry later"
            return None, f"HIBP returned HTTP {r.status_code}"
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:120]}"


async def _hibp_requests(url, headers, timeout):
    try:
        import requests
    except ImportError:
        return None, "no HTTP client available (httpx/requests missing)"
    def _run():
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    return None, "HIBP returned non-JSON body"
                return (data if isinstance(data, list) else []), None
            if r.status_code == 404:
                return [], None
            if r.status_code == 401:
                return None, "HIBP requires a verified API key for breach-by-domain (401)"
            if r.status_code == 429:
                return None, "HIBP rate limit hit (429) - retry later"
            return None, f"HIBP returned HTTP {r.status_code}"
        except Exception as e:
            return None, f"{type(e).__name__}: {str(e)[:120]}"
    return await asyncio.get_event_loop().run_in_executor(None, _run)


class BreachExposureAudit(MethodologyScanner):
    name = "breach_exposure_audit"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        domain = _extract_domain(ctx.host)
        ctx.state["target_domain"] = domain
        if not domain:
            ctx.state["skipped_reason"] = "no target supplied"
            return False
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        ctx.state["fingerprint"] = {"domain": ctx.state.get("target_domain")}

    # ── STAGE 3: QUICK PROBE (HIBP breach-by-domain) ─────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        domain = ctx.state.get("target_domain") or ""
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
        api_key = (opts.get("hibp_api_key") or "").strip()

        breaches, error = await _hibp_breaches_by_domain(domain, api_key, timeout)
        if error is not None:
            ctx.state["hibp_queried"] = False
            ctx.state["hibp_error"] = error
            return []

        ctx.state["hibp_queried"] = True
        breaches = breaches or []
        names = []
        findings: list[dict] = []
        for b in breaches:
            if not isinstance(b, dict):
                continue
            name = b.get("Name") or b.get("Title") or ""
            bdomain = (b.get("Domain") or "").lower()
            # Only count breaches that actually name this domain (defensive:
            # the endpoint already filters, but never trust without checking).
            if bdomain and domain not in bdomain and bdomain not in domain:
                continue
            if not name:
                continue
            names.append(name)
            findings.append({
                "id": f"breach_{name}",
                "kind": "domain_breach",
                "breach_name": name,
                "breach_domain": bdomain,
                "breach_date": b.get("BreachDate", ""),
                "pwn_count": b.get("PwnCount", 0),
                "data_classes": (b.get("DataClasses") or [])[:8],
                "discovery_method": "hibp_breach_by_domain",
            })
        ctx.state["hibp_breaches"] = names
        return findings

    # ── STAGE 4: DEEP SCAN (no-op) ───────────────────────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        return []

    # ── STAGE 5: VERIFY (structural validation of breach object) ─
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # VL-FOUNDRY evidence surfacing: stamp a concrete, per-finding
        # evidence string onto the methodology finding object. This rides
        # into the report via the methodology_findings intel field; it adds
        # no new finding and changes no severity (advisory-by-design safe).
        finding["evidence_marker"] = (
            f"{finding.get('discovery_method') or finding.get('kind') or 'probe'}"
            f" -> verifying {finding.get('kind') or 'finding'} for "
            f"{finding.get('user') or finding.get('attack_label') or ctx.host}")
        # A breach finding is valid if it has a name. HIBP is the authoritative
        # third-party source; we do not re-query per finding (rate limits).
        if finding.get("breach_name"):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "hibp_authoritative_breach_record"
            return finding
        return None

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        finding["privilege_level"] = "credential_reuse_exposure"
        return finding

    # ── STAGE 7: CHAIN HANDOFF (inert) ───────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        return []


@router.post("/api/password/breach_exposure_audit")
async def password_breach_exposure_audit(req: BreachExposureAuditRequest,
                                          _=Depends(verify_scan_quota)):
    scanner = BreachExposureAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=BREACH_EXPOSURE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
