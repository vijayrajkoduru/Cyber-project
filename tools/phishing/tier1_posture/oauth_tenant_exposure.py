"""oauth_tenant_exposure - Microsoft 365 / Entra ID tenant + OAuth surface
probe (playbook §5 #43 M365 OAuth consent phishing, #47 device-code
phishing).

OAuth "illicit consent grant" and "device-code" phishing target the
identity provider's PUBLIC OAuth surface. This probe reads that public
surface for the target domain to establish, factually, which tenant the
domain belongs to and which consent-phishing-relevant settings are exposed:

  1. Tenant discovery (PUBLIC, unauthenticated):
       GET https://login.microsoftonline.com/<domain>/.well-known/openid-configuration
       -> if 200, the domain is a federated Entra ID (Azure AD) tenant;
          parse the issuer to extract the tenant GUID + cloud instance.
  2. User-realm / federation type (PUBLIC):
       GET https://login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&xml=1
       -> Managed vs Federated; federation here changes the consent-phishing
          and device-code blast radius.
  3. Device-code endpoint reachability (PUBLIC metadata only):
       Read `device_authorization_endpoint` from the openid-configuration —
       its presence confirms the device-code flow (a top 2024-2026 phishing
       vector) is reachable for this tenant.

This is entirely READ-ONLY metadata retrieval from Microsoft's public
identity endpoints. It performs NO authentication, requests NO tokens,
creates NO app registration, and triggers NO consent prompt. It only tells
the customer what an attacker can already enumerate about their tenant
before crafting a consent / device-code lure.

Severity model — every graded item is a DETECTED FACT from the public
metadata; the consent-grant attack itself is advisory (you cannot probe a
victim clicking "Accept" without sending a lure, which is out of scope):

  LOW      - tenant is a federated Entra ID tenant AND the device-code flow
             endpoint is exposed (device-code phishing is reachable) — this
             is informational-leaning but a real, narrow exposure
  INFO     - tenant discovered (here is your tenant GUID / cloud / realm) —
             situational-awareness, plus the advisory that the actual
             consent-grant / device-code LURE delivery is out of SaaS scope
  INFO     - domain is not an Entra ID tenant (no M365) / endpoint
             unreachable / httpx missing
  POSITIVE - (none — there is no "secure" verdict to assert here; absence of
             a tenant is just INFO)

ZERO-FP guard: graded/INFO findings only describe metadata that was
actually fetched (200 OK + parsed). Nothing is inferred. Crucially, no
finding ever claims a consent grant or token theft occurred — that would be
a fabricated CRITICAL. Consent-grant DEPLOYMENT is advisory-by-design.

Customer input via ScanRequest.target = the email domain (acme.com).
Optional ScanRequest.options:
  - timeout_sec   = per-request timeout (default 12, hard cap 30)

References:
  - MITRE ATT&CK T1528 (Steal Application Access Token), T1566 (Phishing)
  - Microsoft "Illicit consent grant" + device-code phishing guidance
"""
from __future__ import annotations
import re
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.oauth_tenant_exposure_findings import (
    OAUTH_TENANT_EXPOSURE_FINDING_RULES,
)

router = APIRouter()


class OAuthTenantRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_domain(target: str) -> str:
    d = (target or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    if d.lower().startswith("www."):
        d = d[4:]
    return d.lower().rstrip(".")


_TENANT_GUID_RE = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/",
    re.IGNORECASE,
)


async def gather(ctx: ScanContext):
    domain = _normalize_domain(ctx.host or "")
    if not domain or "." not in domain:
        ctx.state["oauth_error"] = "target must be an email domain (e.g. acme.com)"
        ctx.source("bad-target")
        return

    opts = ctx.state.get("_options") or {}
    try:
        timeout = min(max(int(opts.get("timeout_sec") or 12), 4), 30)
    except (TypeError, ValueError):
        timeout = 12

    ctx.state["oauth_target_domain"] = domain

    try:
        import httpx
    except ImportError:
        ctx.state["oauth_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return

    headers = {"User-Agent": "VulnusLab-oauth-tenant-audit/1.0",
               "Accept": "application/json"}

    async with httpx.AsyncClient(
        verify=True, timeout=timeout, follow_redirects=True, headers=headers,
    ) as client:
        # ---- 1. OpenID configuration (tenant discovery) ------------
        oidc_url = (f"https://login.microsoftonline.com/{domain}"
                    "/.well-known/openid-configuration")
        try:
            r = await client.get(oidc_url)
            if r.status_code == 200:
                try:
                    cfg = r.json()
                except Exception:
                    cfg = {}
                ctx.state["oauth_is_entra_tenant"] = True
                issuer = cfg.get("issuer") or ""
                ctx.state["oauth_issuer"] = issuer
                m = _TENANT_GUID_RE.search(issuer)
                if m:
                    ctx.state["oauth_tenant_id"] = m.group(1)
                ctx.state["oauth_token_endpoint"] = cfg.get("token_endpoint")
                dev_ep = cfg.get("device_authorization_endpoint")
                ctx.state["oauth_device_endpoint"] = dev_ep
                ctx.state["oauth_device_flow_exposed"] = bool(dev_ep)
                ctx.state["oauth_cloud_instance"] = cfg.get("cloud_instance_name")
                ctx.source(
                    f"openid-configuration 200 -> tenant "
                    f"{ctx.state.get('oauth_tenant_id') or '(guid n/a)'}, "
                    f"device-code={'exposed' if dev_ep else 'absent'}")
            else:
                ctx.state["oauth_is_entra_tenant"] = False
                ctx.state["oauth_oidc_status"] = r.status_code
                ctx.source(f"openid-configuration -> HTTP {r.status_code} "
                           "(not an Entra ID tenant)")
        except Exception as e:
            ctx.state["oauth_error"] = (
                f"openid-configuration fetch failed: {type(e).__name__}: "
                f"{str(e)[:100]}"
            )
            ctx.source("openid-configuration unreachable")
            return

        # ---- 2. User-realm (Managed vs Federated) ------------------
        if ctx.state.get("oauth_is_entra_tenant"):
            realm_url = ("https://login.microsoftonline.com/getuserrealm.srf"
                         f"?login=user@{domain}&xml=1")
            try:
                rr = await client.get(realm_url)
                if rr.status_code == 200:
                    body = rr.text or ""
                    nm = re.search(r"<NameSpaceType>([^<]+)</NameSpaceType>",
                                   body, re.IGNORECASE)
                    fb = re.search(r"<FederationBrandName>([^<]+)"
                                   "</FederationBrandName>", body, re.IGNORECASE)
                    auth = re.search(r"<AuthURL>([^<]+)</AuthURL>",
                                     body, re.IGNORECASE)
                    realm_type = (nm.group(1).strip() if nm else None)
                    ctx.state["oauth_realm_type"] = realm_type
                    ctx.state["oauth_federation_brand"] = (
                        fb.group(1).strip() if fb else None)
                    ctx.state["oauth_is_federated"] = (
                        (realm_type or "").lower() == "federated")
                    if auth:
                        ctx.state["oauth_federation_authurl"] = auth.group(1).strip()[:200]
                    ctx.source(f"getuserrealm -> {realm_type or 'unknown'}")
            except Exception:
                # Non-fatal — tenant discovery already succeeded.
                ctx.source("getuserrealm unreachable (non-fatal)")


INTEL_FIELDS = [
    ("Target domain",            "oauth_target_domain"),
    ("Entra ID tenant",          "oauth_is_entra_tenant"),
    ("Tenant ID (GUID)",         "oauth_tenant_id"),
    ("Issuer",                   "oauth_issuer"),
    ("Cloud instance",           "oauth_cloud_instance"),
    ("Realm type",               "oauth_realm_type"),
    ("Federated",                "oauth_is_federated"),
    ("Federation brand",         "oauth_federation_brand"),
    ("Device-code endpoint",     "oauth_device_endpoint"),
    ("Device-code flow exposed", "oauth_device_flow_exposed"),
]


@router.post("/api/phishing/oauth_tenant_exposure")
async def phishing_oauth_tenant_exposure(req: OAuthTenantRequest,
                                         _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="oauth_tenant_exposure",
        gather_func=_gather_with_options,
        finding_rules=OAUTH_TENANT_EXPOSURE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
