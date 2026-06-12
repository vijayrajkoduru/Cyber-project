"""openid_tenant_recon - unauthenticated Entra ID tenant fingerprinting
(playbook §1 #11 Graph/OpenID exploration + #12 OpenID configuration enum
(.well-known) + #13 tenant ID + tenant name leak via DNS).

Three UNAUTHENTICATED public-exposure checks against Microsoft's own
public discovery surface — no credentials, no exploitation:

  (a) GET login.microsoftonline.com/<tenant>/.well-known/openid-configuration
        Confirms the tenant exists, leaks the tenant GUID (embedded in the
        issuer URL), token/authorize endpoints, cloud instance and the
        tenant_region_scope. This is Microsoft's own published OIDC metadata
        document; reading it is benign discovery.

  (b) GET login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration
        The v2.0 doc adds the msgraph_host + rbac_url + the
        kerberos endpoint. Used to confirm whether the tenant is in the
        commercial / GCC / GCC-High / DoD cloud.

  (c) DNS-based tenant-name leak (playbook #13)
        Resolves the customer domain's MX + autodiscover CNAME + the
        <tenant>-onmicrosoft.com pattern via the system resolver. MX
        pointing at *.mail.protection.outlook.com and an
        autodiscover CNAME of autodiscover.outlook.com are the canonical
        "this domain is an Exchange Online / Entra ID tenant" tells, and
        they leak the onmicrosoft tenant name.

Everything here is read-only public metadata. We emit graded severities
ONLY where the probe actually observed the condition; tenant existence and
cloud-instance disclosure are INFO (it is by-design public).

Customer input via ScanRequest.options:
  - options.onmicrosoft_hint = explicit <tenant>.onmicrosoft.com to confirm
                               the DNS tenant-name leak (optional)

CWE-200 Exposure of Sensitive Information to an Unauthorized Actor
MITRE T1590.002 Gather Victim Network Information: DNS /
       T1596 Search Open Technical Databases
"""
from __future__ import annotations
import asyncio
import re
import socket
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()

OPENID_V1_TMPL = ("https://login.microsoftonline.com/{tenant}/"
                  ".well-known/openid-configuration")
OPENID_V2_TMPL = ("https://login.microsoftonline.com/{tenant}/v2.0/"
                  ".well-known/openid-configuration")

_RE_TENANT_GUID = re.compile(r"login\.microsoftonline\.com/([a-f0-9\-]{36})", re.I)
_RE_ONMICROSOFT = re.compile(r"([a-z0-9\-]+)\.mail\.protection\.outlook\.com", re.I)

# tenant_region_scope -> cloud instance label
_CLOUD_LABELS = {
    "NA": "Commercial (North America)",
    "EU": "Commercial (Europe)",
    "AS": "Commercial (Asia)",
    "USG": "US Government (GCC-High / DoD)",
}


class OpenIdTenantReconRequest(ScanRequest):
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
    return t.split("/", 1)[0].lower()


async def _fetch_openid(client, url: str) -> dict:
    out: dict = {"reachable": False, "status": None}
    try:
        r = await client.get(url)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:80]}"
        return out
    out["status"] = r.status_code
    if r.status_code != 200:
        return out
    try:
        data = r.json()
    except Exception:
        return out
    out["reachable"] = True
    out["issuer"] = data.get("issuer")
    out["authorization_endpoint"] = data.get("authorization_endpoint")
    out["token_endpoint"] = data.get("token_endpoint")
    out["tenant_region_scope"] = data.get("tenant_region_scope")
    out["cloud_instance_name"] = data.get("cloud_instance_name")
    out["msgraph_host"] = data.get("msgraph_host")
    out["kerberos_endpoint"] = data.get("kerberos_endpoint")
    m = _RE_TENANT_GUID.search(data.get("issuer") or "")
    if m:
        out["tenant_id"] = m.group(1)
    return out


def _dns_query(name: str, rtype: str = "A") -> list[str]:
    """Best-effort DNS lookup using the stdlib resolver. Returns string
    records; never raises. (We avoid hard dependency on dnspython.)"""
    results: list[str] = []
    try:
        if rtype == "A":
            infos = socket.getaddrinfo(name, None)
            for fam, _stype, _proto, _canon, sockaddr in infos:
                ip = sockaddr[0]
                if ip and ip not in results:
                    results.append(ip)
    except Exception:
        return results
    return results


def _dns_mx_txt(domain: str) -> dict:
    """Resolve MX + autodiscover CNAME if dnspython is available; degrade to
    A-record probing of well-known Exchange Online hostnames otherwise."""
    out: dict = {"mx": [], "autodiscover_cname": None,
                 "onmicrosoft_tenant": None, "resolver": None}
    try:
        import dns.resolver  # type: ignore
        out["resolver"] = "dnspython"
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=5.0)
            for rdata in answers:
                host = str(rdata.exchange).rstrip(".")
                out["mx"].append(host)
        except Exception:
            pass
        try:
            cn = dns.resolver.resolve(f"autodiscover.{domain}", "CNAME", lifetime=5.0)
            for rdata in cn:
                out["autodiscover_cname"] = str(rdata.target).rstrip(".")
                break
        except Exception:
            pass
    except Exception:
        out["resolver"] = "stdlib"
        # Stdlib has no MX; fall back to checking whether the canonical
        # Exchange Online autodiscover host resolves for this domain.
        ad = _dns_query(f"autodiscover.{domain}", "A")
        if ad:
            out["autodiscover_cname"] = "autodiscover.outlook.com (resolved via A)"
    # Derive the onmicrosoft tenant name from any MX pointing at
    # *.mail.protection.outlook.com
    for host in out["mx"]:
        m = _RE_ONMICROSOFT.search(host)
        if m:
            out["onmicrosoft_tenant"] = m.group(1)
            break
    return out


async def _run(req: OpenIdTenantReconRequest, ctx: ScanContext):
    try:
        import httpx
    except ImportError:
        ctx.state["openid_recon_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    tenant = _normalize_tenant(req.target)
    if not tenant:
        ctx.state["openid_recon_no_target"] = True
        ctx.source("missing target tenant/domain")
        return

    ctx.state["openid_recon_tenant"] = tenant

    async with httpx.AsyncClient(timeout=15.0, verify=True,
                                 follow_redirects=True) as client:
        v1 = await _fetch_openid(client, OPENID_V1_TMPL.format(tenant=tenant))
        v2 = await _fetch_openid(client, OPENID_V2_TMPL.format(tenant=tenant))

    tenant_exists = bool(v1.get("reachable") or v2.get("reachable"))
    ctx.state["openid_recon_tenant_exists"] = tenant_exists
    ctx.state["openid_recon_v1"] = v1
    ctx.state["openid_recon_v2"] = v2
    tid = v1.get("tenant_id") or v2.get("tenant_id")
    ctx.state["openid_recon_tenant_id"] = tid
    region = v1.get("tenant_region_scope") or v2.get("tenant_region_scope")
    ctx.state["openid_recon_region"] = region
    ctx.state["openid_recon_cloud_label"] = _CLOUD_LABELS.get(
        (region or "").upper(), region)
    ctx.state["openid_recon_msgraph_host"] = v2.get("msgraph_host") or v1.get("msgraph_host")
    ctx.state["openid_recon_token_endpoint"] = v1.get("token_endpoint") or v2.get("token_endpoint")

    # DNS tenant-name leak — runs in executor to keep the event loop free.
    loop = asyncio.get_event_loop()
    dns_info = await loop.run_in_executor(None, lambda: _dns_mx_txt(tenant))
    ctx.state["openid_recon_dns"] = dns_info
    ctx.state["openid_recon_mx"] = dns_info.get("mx")
    onms = dns_info.get("onmicrosoft_tenant")
    hint = (req.options or {}).get("onmicrosoft_hint")
    if not onms and hint:
        h = str(hint).split(".onmicrosoft", 1)[0].strip().lower()
        onms = h or None
    ctx.state["openid_recon_onmicrosoft_tenant"] = onms
    ctx.state["openid_recon_exchange_online"] = bool(
        dns_info.get("onmicrosoft_tenant") or dns_info.get("autodiscover_cname"))

    if not tenant_exists and not ctx.state.get("openid_recon_exchange_online"):
        ctx.state["openid_recon_not_entra"] = True
        ctx.source(f"{tenant}: no Entra ID / Exchange Online surface resolvable")
        return

    ctx.source(
        f"OpenID recon: tenant_exists={tenant_exists} "
        f"tenant_id={tid or '?'} cloud={region or '?'} "
        f"onmicrosoft={onms or '?'}")


# ---------------------------------------------------------------------------
# Finding rules (defined inline to stay within tools/hybrid_identity/**).
# ZERO-FP rule: graded severity only on an OBSERVED condition; tenant
# metadata disclosure is by-design public, so it is INFO.
# ---------------------------------------------------------------------------

def rule_tenant_fingerprinted(s):
    if not s.get("openid_recon_tenant_exists"):
        return None
    tid = s.get("openid_recon_tenant_id") or "<not in issuer>"
    region = s.get("openid_recon_cloud_label") or "?"
    return {
        "name": "Entra ID tenant fingerprinted via public OpenID metadata",
        "severity": "INFO",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "mitre": "T1596",
        "evidence": (
            f"login.microsoftonline.com/{s.get('openid_recon_tenant')}/"
            ".well-known/openid-configuration returned HTTP 200. Tenant GUID: "
            f"{tid}. Cloud instance: {region}. Token endpoint: "
            f"{s.get('openid_recon_token_endpoint') or '?'}. This document is "
            "published by Microsoft by design and confirms the customer is an "
            "Entra ID tenant; the GUID + cloud instance are the seeds every "
            "Entra recon tool (ROADrecon, AADInternals, azurehound) starts "
            "from. This is normal exposure, NOT a misconfiguration."),
        "remediation": (
            "No action required — OpenID metadata is intentionally public. "
            "Treat the tenant GUID as non-secret. Focus hardening on the "
            "controls that gate authentication (Conditional Access, MFA, "
            "Smart Lockout) rather than trying to hide the tenant ID."),
    }


def rule_dns_tenant_leak(s):
    onms = s.get("openid_recon_onmicrosoft_tenant")
    if not onms:
        return None
    mx = s.get("openid_recon_mx") or []
    return {
        "name": "Tenant onmicrosoft name leaked via public DNS (MX -> outlook)",
        "severity": "INFO",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "mitre": "T1590.002",
        "evidence": (
            f"The domain's MX records ({', '.join(mx[:3]) or '?'}) point at "
            f"*.mail.protection.outlook.com, leaking the Exchange Online / "
            f"Entra ID tenant name '{onms}.onmicrosoft.com'. The onmicrosoft "
            "name is the canonical tenant identifier used to target "
            "GetCredentialType user enumeration and password spray. This is "
            "public DNS, disclosed by design when using Exchange Online."),
        "remediation": (
            "The onmicrosoft name cannot be hidden while using Exchange "
            "Online. Compensate by: (1) Smart Lockout + risk-based "
            "Conditional Access to blunt spray/enum from unknown IPs; "
            "(2) non-guessable UPNs for privileged accounts; (3) Sentinel "
            "alerting on bulk GetCredentialType / failed-auth patterns."),
    }


def rule_gcc_high(s):
    region = (s.get("openid_recon_region") or "").upper()
    if region != "USG":
        return None
    return {
        "name": "Tenant resides in US Government cloud (GCC-High / DoD)",
        "severity": "INFO",
        "cwe": "N/A",
        "evidence": (
            "openid-configuration tenant_region_scope=USG. This tenant is in "
            "Microsoft's US Government cloud, which has distinct compliance "
            "(FedRAMP High / DoD IL) and a separate Graph/login surface."),
        "remediation": (
            "Ensure all hybrid-identity tooling and Conditional Access "
            "baselines target the *.us Government endpoints, and validate "
            "against the DoD CIO / FedRAMP High control set."),
    }


def rule_not_entra(s):
    if not s.get("openid_recon_not_entra"):
        return None
    return {
        "name": f"{s.get('openid_recon_tenant') or '?'} has no resolvable Entra ID surface",
        "severity": "POSITIVE",
        "cwe": "N/A",
        "evidence": (
            "Neither the v1.0 nor v2.0 openid-configuration resolved and no "
            "Exchange Online DNS markers were found. Either the target is not "
            "an Entra ID customer or a non-tenant string was supplied."),
        "remediation": (
            "If the customer IS on Entra ID, re-run with their primary "
            "onmicrosoft.com domain or a vanity domain that is federated "
            "to the tenant."),
    }


def rule_no_target(s):
    if not s.get("openid_recon_no_target"):
        return None
    return {
        "name": "openid_tenant_recon skipped — no target supplied",
        "severity": "INFO", "cwe": "N/A",
        "evidence": "This probe requires a tenant domain or onmicrosoft name as the target.",
        "remediation": "Re-run with the customer's tenant domain (e.g. contoso.com or contoso.onmicrosoft.com).",
    }


def rule_httpx_missing(s):
    if "httpx not installed" not in (s.get("openid_recon_error") or ""):
        return None
    return {
        "name": "httpx not installed on scanner host",
        "severity": "INFO", "cwe": "N/A",
        "evidence": s.get("openid_recon_error"),
        "remediation": "pip install httpx>=0.27",
    }


OPENID_TENANT_RECON_FINDING_RULES = [
    rule_tenant_fingerprinted,
    rule_dns_tenant_leak,
    rule_gcc_high,
    rule_not_entra,
    rule_no_target,
    rule_httpx_missing,
]


INTEL_FIELDS = [
    ("Tenant probed",            "openid_recon_tenant"),
    ("Tenant exists?",           "openid_recon_tenant_exists"),
    ("Tenant ID (GUID)",         "openid_recon_tenant_id"),
    ("Cloud instance",           "openid_recon_cloud_label"),
    ("Region scope",             "openid_recon_region"),
    ("MS Graph host",            "openid_recon_msgraph_host"),
    ("Token endpoint",           "openid_recon_token_endpoint"),
    ("MX records",               "openid_recon_mx"),
    ("Leaked onmicrosoft name",  "openid_recon_onmicrosoft_tenant"),
    ("Exchange Online?",         "openid_recon_exchange_online"),
    ("OpenID v1.0 doc",          "openid_recon_v1"),
    ("OpenID v2.0 doc",          "openid_recon_v2"),
    ("DNS recon",                "openid_recon_dns"),
]


@router.post("/api/hybrid_identity/openid_tenant_recon")
async def hybrid_identity_openid_tenant_recon(req: OpenIdTenantReconRequest,
                                              _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        await _run(req, ctx)
    return await run_scanner(
        host=req.target, tool="openid_tenant_recon",
        gather_func=_gather,
        finding_rules=OPENID_TENANT_RECON_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
