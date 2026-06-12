"""legacy_wstrust_surface_audit - federated legacy WS-Trust endpoint surface
audit (playbook §3 #29 legacy auth (POP/IMAP/SMTP/WS-Trust) bypass + #36
Conditional Access policy enumeration (read-only) + §2 #26 ADFS proxy
attack surface).

UNAUTHENTICATED + detection only. For a federated tenant, the on-prem /
3rd-party IdP exposes WS-Trust endpoints. The legacy
".../trust/13/usernamemixed" (and 2005 "/usernamemixed") binding accepts a
raw username+password in a SOAP body — this is the classic "legacy auth"
path that Conditional Access "block legacy authentication" is meant to
close, and the exact endpoint MSOLSpray / AADInternals
Invoke-AADIntADFSpray hit because it sidesteps interactive MFA.

This probe:
  1. Resolves the tenant's federation AuthURL via GetUserRealm (XML).
  2. If federated, GET-probes the IdP's federation metadata MEX and checks
     whether the legacy usernamemixed WS-Trust endpoint is REACHABLE
     (HTTP reachability only — we send NO credentials, no SOAP login, no
     spray). A reachable usernamemixed binding == the legacy-auth bypass
     surface still exists.
  3. Reports whether idpinitiatedsignon-style legacy bindings are present.

We NEVER submit credentials and NEVER chain into a spray tool. Reachability
of a legacy binding is graded LOW (it is a real, observed exposure that
weakens CA legacy-auth blocking), everything else is INFO.

Customer input via ScanRequest.options:
  - options.probe_upn = a UPN in the federated domain to resolve the
                        AuthURL with (default admin@<target>).

CWE-287 Improper Authentication
CWE-1390 Weak Authentication
MITRE T1110.003 Password Spraying / T1078.004 Valid Accounts: Cloud
"""
from __future__ import annotations
import re
from typing import Optional
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()

GET_USER_REALM_TMPL = ("https://login.microsoftonline.com/"
                       "getuserrealm.srf?login={upn}&xml=1")
MEX_PATH = "/adfs/services/trust/mex"

# Legacy WS-Trust bindings that accept username/password (the bypass surface).
LEGACY_BINDINGS = [
    "/adfs/services/trust/13/usernamemixed",
    "/adfs/services/trust/2005/usernamemixed",
]

_RE_NS_TYPE = re.compile(r"<NameSpaceType>([^<]+)</NameSpaceType>", re.I)
_RE_AUTH_URL = re.compile(r"<AuthURL>([^<]+)</AuthURL>", re.I)
_RE_FED_BRAND = re.compile(r"<FederationBrandName>([^<]+)</FederationBrandName>", re.I)
_RE_STS_ADDR = re.compile(r"<wsa:Address>([^<]+)</wsa:Address>", re.I)


class LegacyWsTrustRequest(ScanRequest):
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


def _idp_base_from_authurl(auth_url: str) -> Optional[str]:
    try:
        p = urlparse(auth_url)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    except Exception:
        return None
    return None


async def _get_user_realm(client, upn: str) -> dict:
    out = {"namespace": None, "auth_url": None, "federation_brand": None}
    url = GET_USER_REALM_TMPL.format(upn=upn)
    try:
        r = await client.get(url)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:80]}"
        return out
    if r.status_code != 200:
        out["status"] = r.status_code
        return out
    body = r.text or ""
    m = _RE_NS_TYPE.search(body)
    out["namespace"] = m.group(1) if m else None
    m = _RE_AUTH_URL.search(body)
    out["auth_url"] = m.group(1) if m else None
    m = _RE_FED_BRAND.search(body)
    out["federation_brand"] = m.group(1) if m else None
    return out


async def _probe_reachable(client, url: str) -> dict:
    """HTTP reachability probe only — GET, no body, no credentials.
    A WS-Trust binding existing typically answers 200/405/500 to a bare GET
    (it wants a SOAP POST); 404 means the binding is not published."""
    out = {"url": url, "status": None, "reachable": False}
    try:
        r = await client.get(url, headers={
            "User-Agent": "VulnusLab/HybridIdentityAudit LegacyWSTrust/1.0",
            "Accept": "*/*"})
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:80]}"
        return out
    out["status"] = r.status_code
    # A published WS-Trust endpoint responds to a GET with 200/405/500/415;
    # 404 (and connection errors) mean it is not exposed.
    out["reachable"] = r.status_code in (200, 401, 405, 415, 500)
    return out


async def _run(req: LegacyWsTrustRequest, ctx: ScanContext):
    try:
        import httpx
    except ImportError:
        ctx.state["legacy_wstrust_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    tenant = _normalize_tenant(req.target)
    if not tenant:
        ctx.state["legacy_wstrust_no_target"] = True
        ctx.source("missing target tenant/domain")
        return

    opts = req.options or {}
    probe_upn = (opts.get("probe_upn") or f"admin@{tenant}").strip()
    ctx.state["legacy_wstrust_tenant"] = tenant

    async with httpx.AsyncClient(timeout=15.0, verify=False,
                                 follow_redirects=True) as client:
        realm = await _get_user_realm(client, probe_upn)
        ctx.state["legacy_wstrust_namespace"] = realm.get("namespace")
        ctx.state["legacy_wstrust_auth_url"] = realm.get("auth_url")
        ctx.state["legacy_wstrust_federation_brand"] = realm.get("federation_brand")

        ns = (realm.get("namespace") or "").lower()
        if ns != "federated":
            ctx.state["legacy_wstrust_managed"] = True
            ctx.source(f"{tenant}: namespace={realm.get('namespace') or '?'} "
                       "(not federated — no on-prem WS-Trust surface)")
            return

        idp_base = _idp_base_from_authurl(realm.get("auth_url") or "")
        ctx.state["legacy_wstrust_idp_base"] = idp_base
        if not idp_base:
            ctx.state["legacy_wstrust_idp_unresolved"] = True
            ctx.source(f"{tenant}: federated but AuthURL host unresolved")
            return

        # (1) MEX reachability — confirms a WS-Trust STS is published.
        mex = await _probe_reachable(client, idp_base + MEX_PATH)
        ctx.state["legacy_wstrust_mex"] = mex

        # (2) Legacy usernamemixed bindings — reachability only.
        legacy_results: list[dict] = []
        reachable_legacy: list[str] = []
        for binding in LEGACY_BINDINGS:
            res = await _probe_reachable(client, idp_base + binding)
            legacy_results.append(res)
            if res.get("reachable"):
                reachable_legacy.append(binding)
        ctx.state["legacy_wstrust_binding_results"] = legacy_results
        ctx.state["legacy_wstrust_reachable_bindings"] = reachable_legacy
        ctx.state["legacy_wstrust_reachable_count"] = len(reachable_legacy)

    ctx.source(
        f"Federated IdP {ctx.state.get('legacy_wstrust_idp_base')}: "
        f"mex_reachable={(ctx.state.get('legacy_wstrust_mex') or {}).get('reachable')} "
        f"legacy_usernamemixed_reachable={len(reachable_legacy)}")


# ---------------------------------------------------------------------------
# Inline finding rules. ZERO-FP: a graded (LOW) severity is emitted ONLY when
# a legacy usernamemixed binding was OBSERVED reachable on the target IdP.
# ---------------------------------------------------------------------------

def rule_legacy_binding_reachable(s):
    reach = s.get("legacy_wstrust_reachable_bindings") or []
    if not reach:
        return None
    return {
        "name": ("Legacy WS-Trust usernamemixed endpoint reachable — "
                 "Conditional Access legacy-auth bypass surface"),
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-1390", "owasp": "A07:2021",
        "mitre": "T1110.003",
        "evidence": (
            f"The federated IdP at {s.get('legacy_wstrust_idp_base')} publishes "
            f"{len(reach)} legacy WS-Trust username/password binding(s): "
            f"{', '.join(reach)} (reachability confirmed by HTTP probe — NO "
            "credentials were submitted). This binding accepts a raw "
            "username+password SOAP request that does not invoke interactive "
            "MFA, which is the exact path MSOLSpray / AADInternals "
            "Invoke-AADIntADFSpray use to bypass Conditional Access "
            "'block legacy authentication' policies. Federation brand: "
            f"{s.get('legacy_wstrust_federation_brand') or '?'}."),
        "remediation": (
            "1. Disable the WS-Trust Windows/usernamemixed endpoints on the "
            "IdP if no application requires them (ADFS: "
            "Set-AdfsEndpoint -TargetAddressPath '/adfs/services/trust/13/"
            "usernamemixed' -Enabled $false; -Proxy $false). "
            "2. Enable ADFS Extranet Smart Lockout. "
            "3. Migrate the federated domain to cloud-managed auth (PHS / "
            "Cloud Sync) so legacy WS-Trust disappears entirely. "
            "4. Enforce Conditional Access 'block legacy authentication' AND "
            "verify it actually blocks WS-Trust (CA legacy-block does not "
            "cover federated WS-Trust unless the endpoint is also disabled "
            "at the IdP)."),
    }


def rule_mex_published(s):
    mex = s.get("legacy_wstrust_mex") or {}
    if not mex.get("reachable"):
        return None
    # Only emit if no legacy binding was reachable, to avoid duplicate noise.
    if s.get("legacy_wstrust_reachable_bindings"):
        return None
    return {
        "name": "Federated IdP WS-Trust MEX published (legacy bindings not reachable)",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": (
            f"The IdP at {s.get('legacy_wstrust_idp_base')} publishes a "
            "WS-Trust Metadata Exchange (MEX) endpoint, but the legacy "
            "usernamemixed bindings were not reachable on a bare probe. "
            "Federation metadata is expected to be public."),
        "remediation": (
            "Confirm the usernamemixed endpoints are intentionally disabled "
            "and keep them disabled unless a specific legacy app needs them."),
    }


def rule_managed(s):
    if not s.get("legacy_wstrust_managed"):
        return None
    return {
        "name": "Tenant is cloud-managed (no federated WS-Trust surface)",
        "severity": "POSITIVE",
        "cwe": "N/A",
        "evidence": (
            f"GetUserRealm reported NameSpaceType="
            f"{s.get('legacy_wstrust_namespace') or '?'} (Managed) for tenant "
            f"{s.get('legacy_wstrust_tenant')}. There is no on-prem ADFS / "
            "WS-Trust legacy-auth endpoint to abuse."),
        "remediation": (
            "Keep the tenant cloud-managed (PHS / Cloud Sync). Enforce "
            "Conditional Access 'block legacy authentication' to close the "
            "remaining cloud legacy protocols (IMAP/POP/SMTP AUTH)."),
    }


def rule_idp_unresolved(s):
    if not s.get("legacy_wstrust_idp_unresolved"):
        return None
    return {
        "name": "Tenant federated but federation AuthURL host could not be parsed",
        "severity": "INFO",
        "cwe": "N/A",
        "evidence": (
            "GetUserRealm reported a federated namespace but no usable AuthURL "
            "host was returned, so the IdP WS-Trust surface could not be "
            "probed."),
        "remediation": (
            "Provide options.probe_upn for a user in the federated domain, or "
            "run adfs_extract_audit directly against the known IdP host."),
    }


def rule_no_target(s):
    if not s.get("legacy_wstrust_no_target"):
        return None
    return {
        "name": "legacy_wstrust_surface_audit skipped — no target supplied",
        "severity": "INFO", "cwe": "N/A",
        "evidence": "This probe requires a tenant domain as the target.",
        "remediation": "Re-run with the customer's federated domain.",
    }


def rule_httpx_missing(s):
    if "httpx not installed" not in (s.get("legacy_wstrust_error") or ""):
        return None
    return {
        "name": "httpx not installed on scanner host",
        "severity": "INFO", "cwe": "N/A",
        "evidence": s.get("legacy_wstrust_error"),
        "remediation": "pip install httpx>=0.27",
    }


LEGACY_WSTRUST_SURFACE_FINDING_RULES = [
    rule_legacy_binding_reachable,
    rule_mex_published,
    rule_managed,
    rule_idp_unresolved,
    rule_no_target,
    rule_httpx_missing,
]


INTEL_FIELDS = [
    ("Tenant probed",            "legacy_wstrust_tenant"),
    ("Namespace type",          "legacy_wstrust_namespace"),
    ("Federation brand",        "legacy_wstrust_federation_brand"),
    ("Federation AuthURL",      "legacy_wstrust_auth_url"),
    ("IdP base URL",            "legacy_wstrust_idp_base"),
    ("WS-Trust MEX probe",      "legacy_wstrust_mex"),
    ("Legacy binding probes",   "legacy_wstrust_binding_results"),
    ("Reachable legacy bindings", "legacy_wstrust_reachable_bindings"),
]


@router.post("/api/hybrid_identity/legacy_wstrust_surface_audit")
async def hybrid_identity_legacy_wstrust_surface_audit(req: LegacyWsTrustRequest,
                                                       _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        await _run(req, ctx)
    return await run_scanner(
        host=req.target, tool="legacy_wstrust_surface_audit",
        gather_func=_gather,
        finding_rules=LEGACY_WSTRUST_SURFACE_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
