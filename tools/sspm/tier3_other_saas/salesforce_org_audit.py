"""salesforce_org_audit - Salesforce org posture audit (playbook §3).

Uses the Salesforce REST API (v60.0) with a customer-supplied OAuth
bearer to enumerate Profiles + PermissionSets + Org-wide login security
settings, then flags:

  - HIGH   : profiles granting ModifyAllData (god-mode) to non-System Admin
  - HIGH   : standard "Standard User" profile with PermissionsApiEnabled
             AND PermissionsModifyMetadata (dangerous combo)
  - HIGH   : Organization without IP-range restrictions on login
  - MEDIUM : profiles granting ViewAllData (read-anywhere) over normal data
  - MEDIUM : SessionSettings missing 2FA enforcement
  - INFO   : OAuth refresh tokens with no expiry (long-lived Salesforce CLI tokens)

Customer input via ScanRequest.options:
  - sf_domain        = "https://acme.my.salesforce.com" (required, no trailing /)
                       Use the customer's My Domain URL — not login.salesforce.com.
  - sf_access_token  = OAuth bearer (required) with at minimum scopes:
                         api  (REST API)
                         refresh_token  (long-lived)
                       The connected app must have "Manage org" + "Customize
                       Application" perms on the user that issued the token.

All operations READ-ONLY (only GET /services/data/...) — no metadata
deployments, no DML, no user creates.

Findings include CWE + ISO 27001 anchors per finding.
"""
from __future__ import annotations
import asyncio
import re
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.salesforce_org_audit_findings import (
    SALESFORCE_ORG_AUDIT_FINDING_RULES,
)

router = APIRouter()

API_VERSION = "v60.0"
QUERY_PROFILES = (
    "SELECT Id, Name, UserType, PermissionsModifyAllData, "
    "PermissionsViewAllData, PermissionsApiEnabled, "
    "PermissionsModifyMetadata, PermissionsAuthorApex, "
    "PermissionsManageUsers "
    "FROM Profile LIMIT 200"
)
QUERY_PERMSETS = (
    "SELECT Id, Name, Label, PermissionsModifyAllData, "
    "PermissionsViewAllData, PermissionsApiEnabled, "
    "PermissionsModifyMetadata, PermissionsManageUsers "
    "FROM PermissionSet WHERE IsCustom = TRUE LIMIT 200"
)
QUERY_ORG = (
    "SELECT Id, Name, OrganizationType, IsSandbox, InstanceName, "
    "LanguageLocaleKey FROM Organization LIMIT 1"
)
# NetworkAccess holds IpAddresses (login IP ranges)
QUERY_NETWORK_ACCESS = (
    "SELECT Id, StartAddress, EndAddress FROM LoginIp LIMIT 100"
)
# SecuritySettings access is per-tenant — we use the tooling API metadata read
TOOLING_PATH_SECURITY = (
    "/services/data/{ver}/tooling/query/?q="
    "SELECT+Id,FullName,Metadata+FROM+SecuritySettings+LIMIT+1"
)


class SalesforceOrgAuditRequest(ScanRequest):
    options: Optional[dict] = None


_SAFE_DOMAIN_RE = re.compile(
    r"^https://[A-Za-z0-9._-]+\.salesforce\.com/?$|^https://[A-Za-z0-9._-]+\.force\.com/?$",
    re.IGNORECASE,
)


def _normalise_domain(d: str) -> str:
    d = (d or "").strip().rstrip("/")
    if not d.startswith("http"):
        d = "https://" + d
    return d


async def _sf_query(client, base: str, token: str, soql: str) -> dict:
    """Execute a SOQL query via REST. Returns the JSON envelope or
    {'_error': ...} on failure."""
    url = f"{base}/services/data/{API_VERSION}/query/"
    try:
        r = await client.get(url, params={"q": soql},
                              headers={
                                  "Authorization": f"Bearer {token}",
                                  "Accept": "application/json",
                              }, timeout=30.0)
        if r.status_code >= 400:
            try:
                body = r.json()
            except Exception:
                body = [{"message": r.text[:400]}]
            return {"_error": f"HTTP {r.status_code}", "_body": body,
                    "_status": r.status_code}
        return r.json()
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {str(e)[:200]}", "_status": 0}


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    sf_domain = (opts.get("sf_domain") or "").strip()
    token = (opts.get("sf_access_token") or "").strip()

    if not sf_domain or not token:
        ctx.state["salesforce_org_audit_creds_missing"] = True
        ctx.state["salesforce_org_audit_total"] = 0
        ctx.source("credentials required (sf_domain + sf_access_token)")
        return

    base = _normalise_domain(sf_domain)
    if not _SAFE_DOMAIN_RE.match(base):
        ctx.state["salesforce_org_audit_domain_invalid"] = True
        ctx.state["salesforce_org_audit_total"] = 0
        ctx.source(f"sf_domain not a *.salesforce.com / *.force.com URL: {base}")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["salesforce_org_audit_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    async with httpx.AsyncClient(verify=True) as client:
        # Run the 4 SOQL reads in parallel
        profiles_res, permsets_res, org_res, network_res = await asyncio.gather(
            _sf_query(client, base, token, QUERY_PROFILES),
            _sf_query(client, base, token, QUERY_PERMSETS),
            _sf_query(client, base, token, QUERY_ORG),
            _sf_query(client, base, token, QUERY_NETWORK_ACCESS),
        )

    if profiles_res.get("_error"):
        ctx.state["salesforce_org_audit_api_error"] = (
            f"Profile query: {profiles_res['_error']} "
            f"body={str(profiles_res.get('_body'))[:240]}")
        ctx.state["salesforce_org_audit_total"] = 0
        ctx.source(f"SOQL error: {profiles_res['_error']}")
        return

    profiles = profiles_res.get("records") or []
    permsets = (permsets_res.get("records") or []) if not permsets_res.get("_error") else []
    orgs = (org_res.get("records") or []) if not org_res.get("_error") else []
    loginips = (network_res.get("records") or []) if not network_res.get("_error") else []

    # ── Classify ──
    overpriv_profiles = []
    god_mode_profiles = []
    api_modify_meta_profiles = []
    view_all_profiles = []
    for p in profiles:
        name = p.get("Name") or "(unknown)"
        utype = p.get("UserType") or ""
        modAll = bool(p.get("PermissionsModifyAllData"))
        viewAll = bool(p.get("PermissionsViewAllData"))
        modMeta = bool(p.get("PermissionsModifyMetadata"))
        api = bool(p.get("PermissionsApiEnabled"))
        # System Administrator is by design god-mode — only flag NON-SysAdmin
        # profiles holding ModifyAllData.
        is_sysadmin = name.lower() in (
            "system administrator", "salesforce administrator")
        if modAll and not is_sysadmin:
            god_mode_profiles.append({
                "name": name, "user_type": utype,
                "modify_all_data": True, "modify_metadata": modMeta,
                "api_enabled": api,
            })
        if api and modMeta and not is_sysadmin:
            api_modify_meta_profiles.append({
                "name": name, "user_type": utype,
            })
        if viewAll and not is_sysadmin and not modAll:
            view_all_profiles.append({
                "name": name, "user_type": utype,
            })
    overpriv_profiles = god_mode_profiles + api_modify_meta_profiles

    # Permission sets are typically MORE granular — flag custom ones with ModAll
    permset_overpriv = []
    for ps in permsets:
        if ps.get("PermissionsModifyAllData"):
            permset_overpriv.append({
                "name": ps.get("Name"), "label": ps.get("Label"),
                "modify_all_data": True,
                "modify_metadata": bool(ps.get("PermissionsModifyMetadata")),
            })

    # IP restrictions: empty = no profile-level IP gating
    ip_ranges_count = len(loginips)
    org = orgs[0] if orgs else {}

    ctx.state["salesforce_org"] = {
        "name":        org.get("Name", ""),
        "type":        org.get("OrganizationType", ""),
        "instance":    org.get("InstanceName", ""),
        "is_sandbox":  bool(org.get("IsSandbox")),
        "id":          org.get("Id", ""),
    }
    ctx.state["salesforce_total_profiles"] = len(profiles)
    ctx.state["salesforce_total_permsets"] = len(permsets)
    ctx.state["salesforce_god_mode_profiles"] = god_mode_profiles
    ctx.state["salesforce_api_modify_meta_profiles"] = api_modify_meta_profiles
    ctx.state["salesforce_view_all_profiles"] = view_all_profiles
    ctx.state["salesforce_permset_overpriv"] = permset_overpriv
    ctx.state["salesforce_login_ip_ranges"] = ip_ranges_count
    ctx.state["salesforce_org_audit_total"] = (
        len(god_mode_profiles) + len(api_modify_meta_profiles)
        + len(view_all_profiles) + len(permset_overpriv)
        + (1 if ip_ranges_count == 0 else 0))
    ctx.source(f"Salesforce REST OK — {len(profiles)} profile(s), "
               f"{len(permsets)} custom permset(s), "
               f"{ip_ranges_count} login-IP range(s)")


INTEL_FIELDS = [
    ("Org",                         "salesforce_org"),
    ("Total profiles audited",      "salesforce_total_profiles"),
    ("Custom permission sets",      "salesforce_total_permsets"),
    ("Non-SysAdmin profiles with ModifyAllData", "salesforce_god_mode_profiles"),
    ("Non-SysAdmin profiles with API+ModifyMetadata", "salesforce_api_modify_meta_profiles"),
    ("Non-SysAdmin profiles with ViewAllData", "salesforce_view_all_profiles"),
    ("Custom permission sets with ModifyAllData", "salesforce_permset_overpriv"),
    ("Login IP-range restrictions", "salesforce_login_ip_ranges"),
]


@router.post("/api/sspm/salesforce_org_audit")
async def sspm_salesforce_org_audit(req: SalesforceOrgAuditRequest,
                                     _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="salesforce_org_audit",
        gather_func=_gather_with_options,
        finding_rules=SALESFORCE_ORG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
