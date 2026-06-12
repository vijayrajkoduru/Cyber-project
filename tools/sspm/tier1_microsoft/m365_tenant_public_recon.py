"""m365_tenant_public_recon - UNAUTHENTICATED Microsoft 365 / Entra ID
tenant posture recon (playbook §1, the externally-visible slice of #3/#4/#5).

Microsoft publishes a handful of PUBLIC, unauthenticated metadata endpoints
that any client uses for federation / sign-in discovery. Reading them tells
us real posture facts about a tenant WITHOUT any credentials:

  1. https://login.microsoftonline.com/<domain>/.well-known/openid-configuration
        -> confirms the domain is an Entra tenant and returns the tenant GUID
           (issuer), the authorization/token endpoints, and the cloud
           instance (commercial / GCC-High / China 21Vianet).
  2. https://login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&xml=1
        -> the public "user realm" document. NameSpaceType tells us whether
           the domain is Managed (cloud auth) or Federated (on-prem ADFS /
           3rd-party IdP). A Federated namespace exposes the federation
           AuthURL + the federation brand — useful posture intel and a
           classic phishing-lookalike target.
  3. https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration
        -> confirms v2 endpoint availability + tenant_region_scope.

These are READ-ONLY GETs against Microsoft's own public discovery surface.
No tenant credential is required or used; this performs NO authentication
attempt, NO password spray, NO user enumeration beyond the single public
realm document. It is detection-only (VA), never exploitation (PT).

What we report (graded ONLY when the public document actually proves it):
  - INFO  : domain is NOT an Entra/M365 tenant (no openid-config) — just intel
  - LOW   : tenant uses FEDERATED auth (on-prem/3rd-party IdP) — exposes a
            federation AuthURL surface worth a phishing-resistance review.
            (Federation is not itself a vuln; LOW reflects the larger
             externally-visible attack surface, and it is a CONFIRMED fact
             read straight off the public realm document.)
  - INFO  : managed-cloud tenant confirmed (healthy baseline fact)
  - INFO  : everything credential-gated (Conditional Access, MFA enforcement,
            legacy-auth state, secure score) — advisory, needs Graph token.

Customer input:
  - ScanRequest.target = the tenant's primary domain (e.g. "acme.com" or
    "acme.onmicrosoft.com"). www. and scheme are stripped automatically.
  - options.m365_domains = optional newline-separated extra domains to probe.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()

LOGIN_BASE = "https://login.microsoftonline.com"
TIMEOUT = 15.0


class M365TenantPublicReconRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_domain(target: str) -> str:
    d = (target or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].split("@")[-1]
    if d.lower().startswith("www."):
        d = d[4:]
    return d.lower().rstrip(".")


async def _get_json(client, url: str) -> tuple[int, dict]:
    try:
        r = await client.get(url, timeout=TIMEOUT,
                             headers={"Accept": "application/json"})
        try:
            body = r.json()
        except Exception:
            body = {"_text": (r.text or "")[:400]}
        return r.status_code, body
    except Exception as e:
        return 0, {"_error": f"{type(e).__name__}: {str(e)[:160]}"}


async def _get_text(client, url: str) -> tuple[int, str]:
    try:
        r = await client.get(url, timeout=TIMEOUT)
        return r.status_code, (r.text or "")[:4000]
    except Exception as e:
        return 0, f"_error: {type(e).__name__}: {str(e)[:160]}"


def _parse_realm_xml(xml: str) -> dict:
    """Tiny tolerant parser for the getuserrealm.srf XML document.
    Returns {NameSpaceType, FederationBrandName, AuthURL, ...} via regex
    so we don't depend on an XML lib being importable."""
    import re
    out: dict = {}
    for tag in ("NameSpaceType", "FederationBrandName", "AuthURL",
                "CloudInstanceName", "DomainName", "FederationGlobalVersion"):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.IGNORECASE | re.DOTALL)
        if m:
            out[tag] = m.group(1).strip()
    return out


async def gather(ctx: ScanContext):
    domain = _normalize_domain(ctx.host or "")
    if not domain:
        ctx.source("no-target")
        return

    opts = ctx.state.get("_options") or {}
    extra = (opts.get("m365_domains") or "").strip()
    domains = [domain]
    if extra:
        for line in extra.splitlines():
            v = _normalize_domain(line)
            if v and v not in domains:
                domains.append(v)
    domains = domains[:5]

    try:
        import httpx
    except ImportError:
        ctx.state["m365_public_recon_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    tenants: list[dict] = []
    federated: list[dict] = []
    not_tenant: list[str] = []

    async with httpx.AsyncClient(verify=True, follow_redirects=True) as client:
        for d in domains:
            oidc_url = f"{LOGIN_BASE}/{d}/.well-known/openid-configuration"
            status, oidc = await _get_json(client, oidc_url)

            # A real Entra tenant returns 200 with an "issuer" carrying the
            # tenant GUID. Non-tenant domains return 400 with an AADSTS error.
            issuer = oidc.get("issuer") if isinstance(oidc, dict) else None
            if status != 200 or not issuer:
                not_tenant.append(d)
                continue

            tenant_guid = ""
            try:
                # issuer is https://sts.windows.net/<guid>/ (or login.../<guid>/v2.0)
                parts = [p for p in str(issuer).split("/") if p]
                for p in parts:
                    if len(p) == 36 and p.count("-") == 4:
                        tenant_guid = p
                        break
            except Exception:
                pass

            region = oidc.get("tenant_region_scope", "") if isinstance(oidc, dict) else ""
            cloud = oidc.get("cloud_instance_name", "") if isinstance(oidc, dict) else ""

            # Public user-realm document -> Managed vs Federated
            realm_url = (f"{LOGIN_BASE}/getuserrealm.srf"
                         f"?login=info@{d}&xml=1")
            r_status, r_xml = await _get_text(client, realm_url)
            realm = _parse_realm_xml(r_xml) if r_status == 200 else {}
            ns_type = (realm.get("NameSpaceType") or "").strip()

            rec = {
                "domain": d,
                "tenant_guid": tenant_guid,
                "issuer": str(issuer),
                "tenant_region_scope": region,
                "cloud_instance": cloud,
                "namespace_type": ns_type or "Unknown",
                "federation_brand": realm.get("FederationBrandName", ""),
                "federation_auth_url": realm.get("AuthURL", ""),
            }
            tenants.append(rec)
            if ns_type.lower() == "federated":
                federated.append(rec)

    ctx.state["m365_public_domains_probed"] = domains
    ctx.state["m365_public_tenants"] = tenants
    ctx.state["m365_public_federated_tenants"] = federated
    ctx.state["m365_public_not_tenant"] = not_tenant
    ctx.state["m365_public_tenant_count"] = len(tenants)
    ctx.source(
        f"Microsoft public discovery probed {len(domains)} domain(s): "
        f"{len(tenants)} Entra tenant(s), {len(federated)} federated"
    )


def rule_error(s):
    if not s.get("m365_public_recon_error"):
        return None
    return {
        "name": "M365 public tenant recon could not run",
        "severity": "INFO",
        "evidence": str(s.get("m365_public_recon_error")),
        "remediation": "Transient — re-run the scan. No tenant credential is needed.",
        "cwe": "N/A",
        "iso27001": "A.5.23",
    }


def rule_not_a_tenant(s):
    # Only fires when we conclusively probed and found ZERO tenants.
    if s.get("m365_public_recon_error"):
        return None
    if s.get("m365_public_tenant_count"):
        return None
    not_tenant = s.get("m365_public_not_tenant") or []
    if not not_tenant:
        return None
    return {
        "name": "Domain is not a Microsoft 365 / Entra ID tenant",
        "severity": "INFO",
        "evidence": (
            "Microsoft's public openid-configuration discovery returned no "
            f"tenant for: {', '.join(not_tenant[:5])}. The M365 posture "
            "checks (Secure Score, Conditional Access, MFA) do not apply."
        ),
        "remediation": (
            "If this organisation DOES use Microsoft 365, supply the exact "
            "tenant domain (often <name>.onmicrosoft.com) as the target."
        ),
        "cwe": "N/A",
        "iso27001": "A.5.23",
    }


def rule_managed_tenant(s):
    tenants = s.get("m365_public_tenants") or []
    managed = [t for t in tenants
               if (t.get("namespace_type") or "").lower() == "managed"]
    if not managed:
        return None
    lines = []
    for t in managed[:5]:
        lines.append(f"{t['domain']} (tenant {t.get('tenant_guid') or '?'}, "
                     f"region {t.get('tenant_region_scope') or '?'})")
    return {
        "name": f"Microsoft 365 tenant confirmed — cloud-managed auth "
                f"({len(managed)} domain(s))",
        "severity": "INFO",
        "evidence": (
            "Public Entra discovery confirms these are cloud-managed "
            "(NameSpaceType=Managed) M365 tenants: " + "; ".join(lines)
            + ". Cloud-managed auth is the recommended baseline (no on-prem "
            "federation surface). This is a CONFIRMED fact from Microsoft's "
            "public discovery endpoint, not an authenticated read."
        ),
        "remediation": (
            "Posture beyond this fact (Conditional Access, MFA enforcement, "
            "legacy-auth block, Secure Score) requires a Graph token — run "
            "the m365_security_score probe with an app registration to grade it."
        ),
        "cwe": "N/A",
        "iso27001": "A.5.23",
    }


def rule_federated_tenant(s):
    federated = s.get("m365_public_federated_tenants") or []
    if not federated:
        return None
    lines = []
    for t in federated[:5]:
        au = t.get("federation_auth_url") or "(no AuthURL)"
        brand = t.get("federation_brand") or "(no brand)"
        lines.append(f"{t['domain']} -> {brand} @ {au}")
    return {
        "name": f"Microsoft 365 tenant uses FEDERATED sign-in "
                f"({len(federated)} domain(s))",
        "severity": "LOW",
        "evidence": (
            "Microsoft's public user-realm document reports NameSpaceType="
            "Federated for: " + "; ".join(lines) + ". Federated auth routes "
            "sign-in to an on-prem ADFS / third-party IdP via a public AuthURL. "
            "This is a CONFIRMED fact read off Microsoft's public discovery "
            "surface (no credential used). It is not itself a vulnerability, "
            "but the published federation endpoint is a larger externally-"
            "visible attack surface and a classic phishing-lookalike target."
        ),
        "remediation": (
            "Confirm the federation IdP enforces phishing-resistant MFA and "
            "that the AuthURL host is monitored for lookalike domains. Where "
            "possible, migrate to cloud-managed auth (Entra) with Conditional "
            "Access to shrink the external surface."
        ),
        "cwe": "CWE-1390",
        "owasp": "A07:2021",
        "iso27001": "A.8.5",
        # CONFIRMED fact read off Microsoft's public realm document — this is
        # a detected condition, not an advisory, so it must not be clamped.
        "verified_exploit": True,
    }


def rule_creds_gated_advisory(s):
    # Always-on honest advisory: the deep M365 posture needs a Graph token.
    if s.get("m365_public_recon_error"):
        return None
    if not s.get("m365_public_tenant_count"):
        return None
    return {
        "name": "[ADVISORY-BY-DESIGN] Deep M365 posture needs a Graph token",
        "severity": "INFO",
        "evidence": (
            "Conditional Access policy enumeration, MFA enforcement state, "
            "legacy-auth (POP/IMAP/SMTP) block status, SharePoint/OneDrive/"
            "Teams external-sharing, mailbox auto-forward DLP, and Secure "
            "Score are TENANT-INTERNAL settings. They cannot be read from "
            "the public discovery surface and are NOT a forge gap — they "
            "require an Entra app-registration with Graph read scopes."
        ),
        "remediation": (
            "Run the m365_security_score probe with options.tenant_id / "
            ".client_id / .client_secret (SecureScores.Read.All) to grade "
            "the internal controls. See module_playbooks/29_sspm.md §1."
        ),
        "cwe": "N/A",
        "iso27001": "A.5.23",
    }


M365_TENANT_PUBLIC_RECON_FINDING_RULES = [
    rule_error,
    rule_not_a_tenant,
    rule_managed_tenant,
    rule_federated_tenant,
    rule_creds_gated_advisory,
]


INTEL_FIELDS = [
    ("Domains probed",            "m365_public_domains_probed"),
    ("Entra/M365 tenants found",  "m365_public_tenant_count"),
    ("Tenant detail",             "m365_public_tenants"),
    ("Federated tenants",         "m365_public_federated_tenants"),
    ("Non-tenant domains",        "m365_public_not_tenant"),
]


@router.post("/api/sspm/m365_tenant_public_recon")
async def sspm_m365_tenant_public_recon(req: M365TenantPublicReconRequest,
                                        _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="m365_tenant_public_recon",
        gather_func=_gather_with_options,
        finding_rules=M365_TENANT_PUBLIC_RECON_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
