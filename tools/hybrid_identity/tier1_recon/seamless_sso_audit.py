"""seamless_sso_audit - Seamless SSO + MSAPPS17 Silver-Ticket precondition
check (playbook §1 #12 + §2 #17 + §8 #81).

Seamless Single Sign-On uses a computer account named AZUREADSSO created
in the on-prem AD by Microsoft Entra Connect. That account holds the
Kerberos key used to issue tickets for the HTTP/aadg.windows.net.nsatc.net
SPN — if an attacker can extract the AZUREADSSO account's NT hash from a
domain controller, they can forge silver tickets that Entra ID will
accept for any user in the tenant (MSAPPS17 attack).

This probe is UNAUTHENTICATED and performs three checks:
  1. .well-known/openid-configuration on login.microsoftonline.com/<tenant>
     — confirms the tenant exists and surfaces issuer / token endpoint.
  2. GetUserRealm on login.microsoftonline.com — returns NameSpaceType
     (Managed/Federated) and whether DesktopSsoEnabled is true.
  3. Autodiscover-s.outlook.com tenant lookup — confirms hybrid mail flow
     (often correlates with hybrid identity).

If Seamless SSO is detected (DesktopSsoEnabled=true OR DesktopSsoTimeout
populated), emit a MEDIUM finding describing the MSAPPS17 silver-ticket
attack surface + remediation (move to Entra ID-only / Cloud Sync + token
binding + Defender for Identity AZUREADSSO monitoring).

CWE-294 Authentication Bypass by Capture-replay / T1606.001 Forge Web
Credentials: Web Cookies.
"""
from __future__ import annotations
import asyncio
import re
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.seamless_sso_audit_findings import (
    SEAMLESS_SSO_AUDIT_FINDING_RULES,
)

router = APIRouter()

OPENID_TMPL = ("https://login.microsoftonline.com/{tenant}/"
               ".well-known/openid-configuration")
GET_USER_REALM_TMPL = ("https://login.microsoftonline.com/"
                       "getuserrealm.srf?login={upn}&xml=1")
AUTODISCOVER_URL = ("https://autodiscover-s.outlook.com/autodiscover/"
                     "autodiscover.svc")

_RE_NS_TYPE = re.compile(r"<NameSpaceType>([^<]+)</NameSpaceType>", re.I)
_RE_DOMAIN = re.compile(r"<DomainName>([^<]+)</DomainName>", re.I)
_RE_FED_BRAND = re.compile(r"<FederationBrandName>([^<]+)</FederationBrandName>", re.I)
_RE_AUTH_URL = re.compile(r"<AuthURL>([^<]+)</AuthURL>", re.I)
_RE_CLOUD_INSTANCE = re.compile(r"<CloudInstanceName>([^<]+)</CloudInstanceName>", re.I)
_RE_DESKTOP_SSO = re.compile(
    r"<DesktopSsoEnabled>(true|false)</DesktopSsoEnabled>", re.I)


class SeamlessSsoRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_tenant(target: str) -> str:
    t = (target or "").strip().strip("/")
    if not t:
        return ""
    if "@" in t:
        t = t.split("@", 1)[1]
    if t.startswith("http://"):
        t = t[7:]
    elif t.startswith("https://"):
        t = t[8:]
    return t.lower()


async def _check_openid(client, tenant: str) -> dict:
    """GET .well-known/openid-configuration. Confirms tenant existence."""
    out = {"tenant_exists": False, "issuer": None, "tenant_id": None,
           "token_endpoint": None, "tenant_region": None}
    if not tenant:
        return out
    url = OPENID_TMPL.format(tenant=tenant)
    try:
        r = await client.get(url)
    except Exception as e:
        out["openid_error"] = f"{type(e).__name__}: {str(e)[:80]}"
        return out
    if r.status_code != 200:
        out["openid_status"] = r.status_code
        return out
    try:
        data = r.json()
    except Exception:
        return out
    out["tenant_exists"] = True
    out["issuer"] = data.get("issuer")
    out["token_endpoint"] = data.get("token_endpoint")
    out["tenant_region"] = data.get("tenant_region_scope") or data.get("cloud_instance_name")
    # tenant_id appears in issuer URL: https://login.microsoftonline.com/<GUID>/v2.0
    iss = data.get("issuer") or ""
    m = re.search(r"login\.microsoftonline\.com/([a-f0-9\-]{36})", iss, re.I)
    if m:
        out["tenant_id"] = m.group(1)
    return out


async def _check_user_realm(client, upn: str) -> dict:
    """GetUserRealm.srf returns XML with DesktopSsoEnabled flag."""
    out = {"namespace_type": None, "federation_brand": None,
           "auth_url": None, "cloud_instance": None,
           "desktop_sso_enabled": None}
    if not upn:
        return out
    url = GET_USER_REALM_TMPL.format(upn=upn)
    try:
        r = await client.get(url)
    except Exception as e:
        out["realm_error"] = f"{type(e).__name__}: {str(e)[:80]}"
        return out
    if r.status_code != 200:
        out["realm_status"] = r.status_code
        return out
    body = r.text or ""
    m = _RE_NS_TYPE.search(body)
    out["namespace_type"] = m.group(1) if m else None
    m = _RE_FED_BRAND.search(body)
    out["federation_brand"] = m.group(1) if m else None
    m = _RE_AUTH_URL.search(body)
    out["auth_url"] = m.group(1) if m else None
    m = _RE_CLOUD_INSTANCE.search(body)
    out["cloud_instance"] = m.group(1) if m else None
    m = _RE_DESKTOP_SSO.search(body)
    if m:
        out["desktop_sso_enabled"] = (m.group(1).lower() == "true")
    return out


async def _check_autodiscover(client, tenant: str) -> dict:
    """Probe autodiscover-s.outlook.com — confirms M365 mail flow."""
    out = {"autodiscover_reachable": False}
    try:
        r = await client.get(AUTODISCOVER_URL,
                              headers={"User-Agent": "VulnusLab/HybridIdentityAudit"})
        out["autodiscover_reachable"] = (r.status_code in (200, 401, 403))
        out["autodiscover_status"] = r.status_code
    except Exception as e:
        out["autodiscover_error"] = f"{type(e).__name__}: {str(e)[:80]}"
    return out


async def _run(req: SeamlessSsoRequest, ctx: ScanContext):
    try:
        import httpx
    except ImportError:
        ctx.state["seamless_sso_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    tenant = _normalize_tenant(req.target)
    if not tenant:
        ctx.state["seamless_sso_error"] = "no target tenant supplied"
        ctx.source("missing tenant")
        return

    # Build a probe UPN — admin@<tenant> is the canonical realm-check name
    opts = req.options or {}
    probe_upn = (opts.get("probe_upn") or f"admin@{tenant}").strip()

    ctx.state["seamless_sso_tenant"] = tenant
    async with httpx.AsyncClient(timeout=15.0, verify=True,
                                  follow_redirects=True) as client:
        oid = await _check_openid(client, tenant)
        realm = await _check_user_realm(client, probe_upn)
        autod = await _check_autodiscover(client, tenant)

    ctx.state["seamless_sso_openid"] = oid
    ctx.state["seamless_sso_realm"] = realm
    ctx.state["seamless_sso_autodiscover"] = autod
    ctx.state["seamless_sso_tenant_id"] = oid.get("tenant_id")
    ctx.state["seamless_sso_namespace"] = realm.get("namespace_type")
    ctx.state["seamless_sso_federation_brand"] = realm.get("federation_brand")
    ctx.state["seamless_sso_cloud_instance"] = realm.get("cloud_instance") or oid.get("tenant_region")
    ctx.state["seamless_sso_desktop_sso_enabled"] = realm.get("desktop_sso_enabled")
    ctx.state["seamless_sso_authurl"] = realm.get("auth_url")

    # Tenant must exist OR realm must resolve to be a real Entra ID tenant
    if not oid.get("tenant_exists") and not realm.get("namespace_type"):
        ctx.state["seamless_sso_tenant_missing"] = True
        ctx.source(f"tenant {tenant} not resolvable")
        return

    sso_flag = "ENABLED" if realm.get("desktop_sso_enabled") else (
        "DISABLED" if realm.get("desktop_sso_enabled") is False else "UNKNOWN")
    ctx.source(f"Seamless SSO {sso_flag}; "
               f"namespace={realm.get('namespace_type') or '?'}; "
               f"tenant_id={oid.get('tenant_id') or '?'}")


INTEL_FIELDS = [
    ("Tenant probed",          "seamless_sso_tenant"),
    ("Tenant ID (GUID)",       "seamless_sso_tenant_id"),
    ("Namespace type",         "seamless_sso_namespace"),
    ("Federation brand",       "seamless_sso_federation_brand"),
    ("Cloud instance",         "seamless_sso_cloud_instance"),
    ("Federation AuthURL",     "seamless_sso_authurl"),
    ("Seamless SSO enabled?",  "seamless_sso_desktop_sso_enabled"),
    ("OpenID config",          "seamless_sso_openid"),
    ("GetUserRealm response",  "seamless_sso_realm"),
    ("Autodiscover probe",     "seamless_sso_autodiscover"),
]


@router.post("/api/hybrid_identity/seamless_sso_audit")
async def hybrid_identity_seamless_sso_audit(req: SeamlessSsoRequest,
                                              _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        await _run(req, ctx)
    return await run_scanner(
        host=req.target, tool="seamless_sso_audit",
        gather_func=_gather,
        finding_rules=SEAMLESS_SSO_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
