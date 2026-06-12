"""tenant_domain_enum - unauthenticated Entra ID tenant domain + namespace
enumeration (playbook §1 #1 ROADrecon-style domain dump (read-only subset),
#7 o365creeper domain enum, #8 AADInternals email/domain enum).

UNAUTHENTICATED. Implements the AADInternals Get-AADIntTenantDomains
primitive: a single SOAP POST to autodiscover-s.outlook.com asking
GetFederationInformation for the seed domain returns the FULL list of every
custom + onmicrosoft domain registered to the same Entra ID tenant. No
credentials are required — it is a public federation-discovery endpoint.

For each discovered domain we then call GetUserRealm (XML) to classify the
namespace (Managed / Federated) so the customer sees exactly which of their
domains are federated to ADFS / a third-party IdP (the federated ones being
the Solorigate / Storm-0558 / Golden-SAML target surface).

Everything is read-only public metadata. Domain disclosure is by-design and
reported as INFO; a federated domain is also INFO with a pointer to
adfs_extract_audit (we never auto-chain).

Customer input via ScanRequest.options:
  - options.max_domains = cap on # of domains we GetUserRealm-classify
                          (default 40, hard max 80) to bound runtime.

CWE-200 Exposure of Sensitive Information to an Unauthorized Actor
MITRE T1590 Gather Victim Network Information / T1087.004 Cloud Account Discovery
"""
from __future__ import annotations
import re
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()

AUTODISCOVER_SOAP_URL = ("https://autodiscover-s.outlook.com/autodiscover/"
                         "autodiscover.svc")
GET_USER_REALM_TMPL = ("https://login.microsoftonline.com/"
                       "getuserrealm.srf?login={upn}&xml=1")

HARD_MAX_DOMAINS = 80
DEFAULT_MAX_DOMAINS = 40

_RE_DOMAIN = re.compile(r"<Domain>([^<]+)</Domain>", re.I)
_RE_NS_TYPE = re.compile(r"<NameSpaceType>([^<]+)</NameSpaceType>", re.I)
_RE_FED_BRAND = re.compile(r"<FederationBrandName>([^<]+)</FederationBrandName>", re.I)
_RE_AUTH_URL = re.compile(r"<AuthURL>([^<]+)</AuthURL>", re.I)

_SOAP_TMPL = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" '
    'xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" '
    'xmlns:a="http://www.w3.org/2005/08/addressing" '
    'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
    'xmlns:autodiscover="http://schemas.microsoft.com/exchange/2010/Autodiscover">'
    '<soap:Header>'
    '<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>'
    '<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>'
    '<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>'
    '</soap:Header>'
    '<soap:Body>'
    '<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">'
    '<Request><Domain>{domain}</Domain></Request>'
    '</GetFederationInformationRequestMessage>'
    '</soap:Body>'
    '</soap:Envelope>'
)


class TenantDomainEnumRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_domain(target: str) -> str:
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


async def _get_federation_domains(client, seed_domain: str) -> tuple[list[str], Optional[str]]:
    """SOAP GetFederationInformation -> list of every domain in the tenant."""
    body = _SOAP_TMPL.format(domain=seed_domain)
    headers = {
        "Content-Type": 'text/xml; charset=utf-8',
        "SOAPAction": ('"http://schemas.microsoft.com/exchange/2010/'
                       'Autodiscover/Autodiscover/GetFederationInformation"'),
        "User-Agent": "AutodiscoverClient",
        "Accept": "text/xml",
    }
    try:
        r = await client.post(AUTODISCOVER_SOAP_URL, content=body, headers=headers)
    except Exception as e:
        return [], f"{type(e).__name__}: {str(e)[:80]}"
    if r.status_code != 200:
        return [], f"http {r.status_code}"
    text = r.text or ""
    domains = []
    seen = set()
    for m in _RE_DOMAIN.finditer(text):
        d = m.group(1).strip().lower()
        if d and d not in seen and "." in d:
            seen.add(d)
            domains.append(d)
    return domains, None


async def _classify_namespace(client, domain: str) -> dict:
    """GetUserRealm classification for a probe UPN in this domain."""
    out = {"domain": domain, "namespace": None,
           "federation_brand": None, "auth_url": None}
    url = GET_USER_REALM_TMPL.format(upn=f"info@{domain}")
    try:
        r = await client.get(url)
    except Exception:
        return out
    if r.status_code != 200:
        return out
    body = r.text or ""
    m = _RE_NS_TYPE.search(body)
    out["namespace"] = m.group(1) if m else None
    m = _RE_FED_BRAND.search(body)
    out["federation_brand"] = m.group(1) if m else None
    m = _RE_AUTH_URL.search(body)
    out["auth_url"] = m.group(1) if m else None
    return out


async def _run(req: TenantDomainEnumRequest, ctx: ScanContext):
    try:
        import httpx
    except ImportError:
        ctx.state["tenant_domain_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    seed = _normalize_domain(req.target)
    if not seed:
        ctx.state["tenant_domain_no_target"] = True
        ctx.source("missing target domain")
        return

    opts = req.options or {}
    max_domains = min(int(opts.get("max_domains") or DEFAULT_MAX_DOMAINS),
                      HARD_MAX_DOMAINS)
    ctx.state["tenant_domain_seed"] = seed

    async with httpx.AsyncClient(timeout=20.0, verify=True,
                                 follow_redirects=True) as client:
        domains, derr = await _get_federation_domains(client, seed)
        if derr:
            ctx.state["tenant_domain_soap_error"] = derr
        ctx.state["tenant_domain_count"] = len(domains)
        ctx.state["tenant_domains"] = domains[:HARD_MAX_DOMAINS]

        # Classify namespace for each discovered domain (bounded).
        classified: list[dict] = []
        federated: list[dict] = []
        onmicrosoft = [d for d in domains if d.endswith(".onmicrosoft.com")]
        for d in domains[:max_domains]:
            info = await _classify_namespace(client, d)
            classified.append(info)
            if (info.get("namespace") or "").lower() == "federated":
                federated.append(info)

    ctx.state["tenant_domain_classified"] = classified
    ctx.state["tenant_domain_federated"] = federated
    ctx.state["tenant_domain_federated_count"] = len(federated)
    ctx.state["tenant_domain_onmicrosoft"] = onmicrosoft
    if onmicrosoft:
        # First onmicrosoft entry is the canonical tenant name
        ctx.state["tenant_domain_primary_onmicrosoft"] = onmicrosoft[0]

    if not domains:
        ctx.state["tenant_domain_none"] = True
        ctx.source(f"{seed}: no federated domains returned "
                   f"({derr or 'not an Entra ID tenant'})")
        return

    ctx.source(f"GetFederationInformation: {len(domains)} domain(s) in tenant; "
               f"{len(federated)} federated; "
               f"onmicrosoft={ctx.state.get('tenant_domain_primary_onmicrosoft') or '?'}")


# ---------------------------------------------------------------------------
# Inline finding rules — zero-FP: every condition is OBSERVED, all INFO/POSITIVE
# because tenant domain disclosure is by-design public metadata.
# ---------------------------------------------------------------------------

def rule_domains_enumerated(s):
    n = s.get("tenant_domain_count") or 0
    if n <= 0:
        return None
    domains = s.get("tenant_domains") or []
    return {
        "name": (f"Tenant domain list disclosed via autodiscover "
                 f"GetFederationInformation ({n} domain(s))"),
        "severity": "INFO",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "mitre": "T1590",
        "evidence": (
            f"A single unauthenticated SOAP call to autodiscover-s.outlook.com "
            f"(seed '{s.get('tenant_domain_seed')}') enumerated {n} domain(s) "
            f"belonging to the same Entra ID tenant: "
            f"{', '.join(domains[:12])}{' ...' if n > 12 else ''}. This is the "
            "AADInternals Get-AADIntTenantDomains primitive; the federation "
            "endpoint is public by design. The full domain list maps the "
            "customer's brand/acquisition footprint and widens the UPN-enum "
            "and password-spray target space."),
        "remediation": (
            "Domain enumeration cannot be disabled while using Exchange "
            "Online federation. Compensate at the auth layer: enforce "
            "phishing-resistant MFA + Conditional Access on every domain, "
            "and treat all listed domains as in-scope for monitoring (a "
            "forgotten acquired domain is a common weak link)."),
    }


def rule_federated_domains(s):
    fed = s.get("tenant_domain_federated") or []
    if not fed:
        return None
    names = ", ".join(f"{f.get('domain')} ({f.get('federation_brand') or 'IdP'})"
                      for f in fed[:8])
    return {
        "name": (f"{len(fed)} tenant domain(s) federated to an external IdP "
                 "(ADFS / third-party)"),
        "severity": "INFO",
        "cwe": "CWE-287", "owasp": "A07:2021",
        "mitre": "T1606.002",
        "evidence": (
            f"GetUserRealm classified {len(fed)} domain(s) as "
            f"NameSpaceType=Federated: {names}. Federated domains delegate "
            "token issuance to an external IdP whose signing key is the "
            "'keys to the kingdom' (Golden SAML / Solorigate / Storm-0558 "
            "target). AuthURL example: "
            f"{(fed[0].get('auth_url') if fed else None) or '?'}."),
        "remediation": (
            "Run adfs_extract_audit against each federated domain's AuthURL "
            "(this scanner does NOT auto-chain). Rotate the token-signing "
            "certificate quarterly, enable Entra Connect Health for ADFS, "
            "and where possible migrate federated domains to cloud-managed "
            "auth (PHS/Cloud Sync) to shrink the Golden-SAML surface."),
    }


def rule_onmicrosoft_leak(s):
    onm = s.get("tenant_domain_primary_onmicrosoft")
    if not onm:
        return None
    return {
        "name": f"Canonical tenant name disclosed: {onm}",
        "severity": "INFO",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "evidence": (
            f"The domain enumeration returned the tenant's onmicrosoft "
            f"identity '{onm}'. This is the canonical tenant name used as the "
            "authority in OAuth/OIDC flows and as the seed for "
            "GetCredentialType user enumeration / MSOLSpray password spray."),
        "remediation": (
            "The onmicrosoft name is public and cannot be changed without "
            "creating a new tenant. Defend with Smart Lockout, risk-based "
            "Conditional Access, and Sentinel alerting on auth anomalies."),
    }


def rule_no_domains(s):
    if not s.get("tenant_domain_none"):
        return None
    return {
        "name": f"{s.get('tenant_domain_seed') or '?'} returned no tenant domains",
        "severity": "POSITIVE",
        "cwe": "N/A",
        "evidence": (
            "GetFederationInformation returned no domains for the seed — the "
            "target is likely not an Entra ID / Exchange Online tenant, or "
            "the seed domain is not associated with one."),
        "remediation": (
            "If the customer IS on Entra ID, re-run with a domain known to be "
            "verified in their tenant (the primary vanity or onmicrosoft "
            "domain)."),
    }


def rule_no_target(s):
    if not s.get("tenant_domain_no_target"):
        return None
    return {
        "name": "tenant_domain_enum skipped — no target supplied",
        "severity": "INFO", "cwe": "N/A",
        "evidence": "This probe requires a tenant domain as the target.",
        "remediation": "Re-run with the customer's primary domain (e.g. contoso.com).",
    }


def rule_httpx_missing(s):
    if "httpx not installed" not in (s.get("tenant_domain_error") or ""):
        return None
    return {
        "name": "httpx not installed on scanner host",
        "severity": "INFO", "cwe": "N/A",
        "evidence": s.get("tenant_domain_error"),
        "remediation": "pip install httpx>=0.27",
    }


TENANT_DOMAIN_ENUM_FINDING_RULES = [
    rule_domains_enumerated,
    rule_federated_domains,
    rule_onmicrosoft_leak,
    rule_no_domains,
    rule_no_target,
    rule_httpx_missing,
]


INTEL_FIELDS = [
    ("Seed domain",              "tenant_domain_seed"),
    ("Domains discovered",       "tenant_domain_count"),
    ("Tenant domains",           "tenant_domains"),
    ("Primary onmicrosoft name", "tenant_domain_primary_onmicrosoft"),
    ("onmicrosoft domains",      "tenant_domain_onmicrosoft"),
    ("Federated domains",        "tenant_domain_federated"),
    ("Federated count",          "tenant_domain_federated_count"),
    ("Namespace classification", "tenant_domain_classified"),
]


@router.post("/api/hybrid_identity/tenant_domain_enum")
async def hybrid_identity_tenant_domain_enum(req: TenantDomainEnumRequest,
                                             _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        await _run(req, ctx)
    return await run_scanner(
        host=req.target, tool="tenant_domain_enum",
        gather_func=_gather,
        finding_rules=TENANT_DOMAIN_ENUM_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
