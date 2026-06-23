"""entra_user_enum_unauth - unauthenticated Entra ID user enumeration
(playbook §1 #7 o365creeper + #2 AADInternals enumeration).

Sends benign POST requests to
https://login.microsoftonline.com/common/GetCredentialType with each
candidate UPN. Microsoft's own credential-type discovery endpoint returns
an `IfExistsResult` field that leaks whether the username corresponds to
a real tenant account. No authentication required — this is the same
technique used by o365creeper / Get-MsolUser enum / AADInternals
Invoke-AADIntUserEnumerationAsOutsider.

IfExistsResult encoding (Microsoft documented values):
  0  = user exists  (the ONLY value that proves a real tenant account)
  1  = user does not exist
  4  = throttled
  5  = federated namespace (resolvable) — a NAMESPACE-TYPE signal, NOT proof the
       specific user exists. On federated domains Microsoft does not reliably
       leak per-user existence via this endpoint, so 5/6 must NOT be counted as
       user-enumeration hits (that was a false positive).
  6  = federated (resolvable) — same: namespace info, not user existence.
  others = error

ZERO-FP: user-enumeration findings are graded ONLY on IfExistsResult=0
(EXISTS). FEDERATED (5/6) is reported as an INFO namespace signal.

Customer input via ScanRequest.options:
  - options.username_list = newline-separated UPNs (required)
  - options.max_users     = cap on # users probed (default 50, hard max 100)
  - options.delay_ms      = ms between requests (default 250 to dodge throttling)

Each existing user is reported as a MEDIUM information-disclosure finding
(CWE-204 / T1087.004 — Cloud Account Discovery).
"""
from __future__ import annotations
import asyncio
import json
import re
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.entra_user_enum_unauth_findings import (
    ENTRA_USER_ENUM_UNAUTH_FINDING_RULES,
)

router = APIRouter()

GET_CRED_TYPE_URL = "https://login.microsoftonline.com/common/GetCredentialType"
HARD_MAX_USERS = 100
DEFAULT_MAX = 50
DEFAULT_DELAY_MS = 250

_RE_VALID_UPN = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


class EntraUserEnumRequest(ScanRequest):
    options: Optional[dict] = None


def _split_users(raw: str, limit: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in (raw or "").splitlines():
        v = line.strip()
        if not v or v in seen:
            continue
        if not _RE_VALID_UPN.match(v):
            continue
        seen.add(v)
        out.append(v)
        if len(out) >= limit:
            break
    return out


def _decode_if_exists(value) -> str:
    """Map IfExistsResult integer -> human label."""
    try:
        i = int(value)
    except Exception:
        return f"unknown({value})"
    return {
        0: "EXISTS",
        1: "NOT_FOUND",
        4: "THROTTLED",
        5: "FEDERATED",
        6: "FEDERATED_RESOLVED",
    }.get(i, f"code_{i}")


async def _probe_user(client, upn: str, tenant_hint: str) -> dict:
    """Single GetCredentialType probe. Returns {upn, if_exists_code,
    if_exists_label, throttled, namespace_type, federation_brand_name}."""
    body = {
        "username": upn,
        "isOtherIdpSupported": True,
        "checkPhones": False,
        "isRemoteNGCSupported": True,
        "isCookieBannerShown": False,
        "isFidoSupported": True,
        "originalRequest": "",
        "country": "US",
        "forceotclogin": False,
        "isExternalFederationDisallowed": False,
        "isRemoteConnectSupported": False,
        "federationFlags": 0,
    }
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "Mozilla/5.0 (compatible; VulnusLab/HybridIdentityAudit)",
        "Accept": "application/json",
        "Origin": "https://login.microsoftonline.com",
        "Referer": (f"https://login.microsoftonline.com/{tenant_hint}/oauth2/authorize"
                    if tenant_hint else "https://login.microsoftonline.com/common/oauth2/authorize"),
    }
    try:
        r = await client.post(GET_CRED_TYPE_URL, json=body, headers=headers)
    except Exception as e:
        return {"upn": upn, "if_exists_code": None, "if_exists_label": "TRANSPORT_ERROR",
                "throttled": False, "error": f"{type(e).__name__}: {str(e)[:80]}"}
    out = {"upn": upn, "http_status": r.status_code}
    try:
        data = r.json()
    except Exception:
        try:
            data = json.loads(r.text or "{}")
        except Exception:
            data = {}
    code = data.get("IfExistsResult")
    out["if_exists_code"] = code
    out["if_exists_label"] = _decode_if_exists(code)
    out["throttled"] = (code == 4) or (r.status_code == 429)
    out["namespace_type"] = data.get("EstsProperties", {}).get("DesktopSsoEnabled")
    # Federation hint (DomainType=4 means federated)
    ep = data.get("EstsProperties") or {}
    out["domain_type"] = ep.get("DomainType")
    out["domain_name"] = ep.get("UserTenantBranding", {}).get("BannerLogo") if isinstance(
        ep.get("UserTenantBranding"), dict) else None
    return out


async def _run(req: EntraUserEnumRequest, ctx: ScanContext):
    try:
        import httpx
    except ImportError:
        ctx.state["entra_user_enum_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    opts = req.options or {}
    raw = (opts.get("username_list") or "").strip()
    if not raw:
        ctx.state["entra_user_enum_no_input"] = True
        ctx.source("missing options.username_list")
        return

    max_users = min(int(opts.get("max_users") or DEFAULT_MAX), HARD_MAX_USERS)
    delay_ms = max(0, int(opts.get("delay_ms") or DEFAULT_DELAY_MS))
    users = _split_users(raw, max_users)
    if not users:
        ctx.state["entra_user_enum_no_input"] = True
        ctx.source("no valid UPNs after parsing")
        return

    tenant_hint = (req.target or "").strip().lower()
    if "@" in tenant_hint:
        tenant_hint = tenant_hint.split("@", 1)[1]

    results: list[dict] = []
    throttled_count = 0
    async with httpx.AsyncClient(timeout=15.0, verify=True,
                                  follow_redirects=False) as client:
        for upn in users:
            r = await _probe_user(client, upn, tenant_hint)
            results.append(r)
            if r.get("throttled"):
                throttled_count += 1
                # exponential back-off on throttle
                await asyncio.sleep(min(2.0 * (throttled_count + 1), 8.0))
            elif delay_ms:
                await asyncio.sleep(delay_ms / 1000.0)

    # ZERO-FP: only IfExistsResult=0 (EXISTS) proves a real account. FEDERATED
    # (5/6) is a namespace-type signal, NOT user existence — exclude it from the
    # graded enumeration count.
    existing = [r for r in results if r.get("if_exists_label") == "EXISTS"]
    federated = [r for r in results if r.get("if_exists_label") in ("FEDERATED",
                                                                     "FEDERATED_RESOLVED")]
    not_found = [r for r in results if r.get("if_exists_label") == "NOT_FOUND"]

    ctx.state["entra_user_enum_tenant"] = tenant_hint
    ctx.state["entra_user_enum_probed"] = len(results)
    ctx.state["entra_user_enum_existing_count"] = len(existing)
    ctx.state["entra_user_enum_not_found_count"] = len(not_found)
    ctx.state["entra_user_enum_federated_count"] = len(federated)
    ctx.state["entra_user_enum_throttled_count"] = throttled_count
    ctx.state["entra_user_enum_existing"] = [
        {"upn": r["upn"], "label": r["if_exists_label"]} for r in existing
    ]
    # First federated row tells us tenant type
    if federated:
        ctx.state["entra_user_enum_namespace"] = "Federated"
    elif existing:
        ctx.state["entra_user_enum_namespace"] = "Managed"
    ctx.source(f"GetCredentialType -> {len(existing)}/{len(results)} valid UPN(s) "
               f"in tenant {tenant_hint or 'unknown'}")


INTEL_FIELDS = [
    ("Tenant probed",       "entra_user_enum_tenant"),
    ("Namespace type",      "entra_user_enum_namespace"),
    ("UPNs submitted",      "entra_user_enum_probed"),
    ("Valid UPNs found",    "entra_user_enum_existing_count"),
    ("Federated UPNs",      "entra_user_enum_federated_count"),
    ("Not-found UPNs",      "entra_user_enum_not_found_count"),
    ("Throttle responses",  "entra_user_enum_throttled_count"),
    ("Valid UPN details",   "entra_user_enum_existing"),
]


@router.post("/api/hybrid_identity/entra_user_enum_unauth")
async def hybrid_identity_entra_user_enum_unauth(req: EntraUserEnumRequest,
                                                  _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        await _run(req, ctx)
    return await run_scanner(
        host=req.target, tool="entra_user_enum_unauth",
        gather_func=_gather,
        finding_rules=ENTRA_USER_ENUM_UNAUTH_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
