"""gworkspace_admin_audit - Google Workspace admin / 2SV posture (playbook §2).

Uses the Google Admin SDK Directory API to enumerate users + admins and
flag posture gaps:

  - Super-admins / delegated admins WITHOUT 2-Step Verification enrolled
  - Suspended admins still holding directory roles
  - Super-admins with NO recent login (>= 90 days) — dormant high-priv
  - Admins NOT enrolled in Advanced Protection / hardware security key

Auth:
  - Customer provides options.gcp_service_account_json (base64-encoded
    service-account JSON key) AND options.delegated_admin (the Workspace
    super-admin email the SA will impersonate via domain-wide delegation).
    Required scopes (granted in the admin console for the SA client ID):
      https://www.googleapis.com/auth/admin.directory.user.readonly
      https://www.googleapis.com/auth/admin.directory.user.security

Strategy: prefer google-api-python-client if available; if not, fall back
to building a JWT with PyJWT (image-installed) and calling the REST API
directly with httpx. Both paths are READ-ONLY.

Findings:
  - INFO    : creds missing | bad SA JSON | API auth failed
  - HIGH    : admin without 2SV | super-admin dormant >180 days
  - MEDIUM  : admin without hardware key | suspended admin still privileged
  - POSITIVE: 100% admin 2SV enrolment, no dormant super-admins
"""
from __future__ import annotations
import asyncio
import base64
import json
import time
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.gworkspace_admin_audit_findings import (
    GWORKSPACE_ADMIN_AUDIT_FINDING_RULES,
)

router = APIRouter()

DORMANT_DAYS = 90
DORMANT_DAYS_CRITICAL = 180
ADMIN_SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.security",
]
TOKEN_URL = "https://oauth2.googleapis.com/token"
DIRECTORY_USERS_URL = "https://admin.googleapis.com/admin/directory/v1/users"


class GworkspaceAdminAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _decode_sa_json(b64_or_raw: str) -> dict:
    """Accept either base64-encoded JSON or raw JSON. Returns the parsed
    service-account dict. Raises ValueError on bad input."""
    s = (b64_or_raw or "").strip()
    if not s:
        raise ValueError("empty service account input")
    # Try base64 first
    try:
        # base64 padding tolerance
        padding = "=" * (-len(s) % 4)
        decoded = base64.b64decode(s + padding, validate=False)
        data = json.loads(decoded.decode("utf-8"))
        if isinstance(data, dict) and data.get("type") == "service_account":
            return data
    except Exception:
        pass
    # Try raw JSON
    try:
        data = json.loads(s)
        if isinstance(data, dict) and data.get("type") == "service_account":
            return data
    except Exception:
        pass
    raise ValueError("input is not a service_account JSON (raw or base64)")


def _build_signed_jwt(sa: dict, subject: str, scopes: list[str]) -> str:
    """Build a Google service-account JWT signed with the SA private key.
    Subject = delegated admin email (domain-wide delegation impersonation).
    Returns the encoded JWT string."""
    try:
        import jwt as _pyjwt  # PyJWT, image-installed (jose is jose; PyJWT may be too)
    except ImportError:
        try:
            from jose import jwt as _pyjwt  # type: ignore
        except ImportError as e:
            raise ImportError("Neither PyJWT nor python-jose available") from e

    now = int(time.time())
    claims = {
        "iss":   sa["client_email"],
        "scope": " ".join(scopes),
        "aud":   TOKEN_URL,
        "iat":   now,
        "exp":   now + 3600,
        "sub":   subject,
    }
    # Both PyJWT and python-jose accept RS256 + PEM key
    try:
        token = _pyjwt.encode(claims, sa["private_key"], algorithm="RS256")
    except Exception as e:
        raise RuntimeError(f"JWT sign failed: {e}") from e
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return token


async def _exchange_jwt_for_access_token(client, signed_jwt: str) -> str:
    """POST the signed assertion to Google's token endpoint, return access token."""
    body = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion":  signed_jwt,
    }
    r = await client.post(TOKEN_URL, data=body, timeout=30.0,
                          headers={"Accept": "application/json"})
    if r.status_code >= 400:
        try:
            err = r.json()
        except Exception:
            err = {"text": r.text[:400]}
        raise RuntimeError(f"Google token exchange HTTP {r.status_code}: {err}")
    j = r.json()
    if "access_token" not in j:
        raise RuntimeError(f"Token response missing access_token: {j}")
    return j["access_token"]


async def _list_users(client, access_token: str, customer: str = "my_customer") -> list[dict]:
    """Page through /admin/directory/v1/users. Returns up to 500 users.
    READ-ONLY — only GETs."""
    users: list[dict] = []
    page_token = None
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    for _ in range(5):  # cap 5 pages = 2500 users (safety)
        params = {
            "customer":   customer,
            "maxResults": 500,
            "projection": "full",
        }
        if page_token:
            params["pageToken"] = page_token
        r = await client.get(DIRECTORY_USERS_URL, params=params,
                              headers=headers, timeout=30.0)
        if r.status_code >= 400:
            try:
                err = r.json()
            except Exception:
                err = {"text": r.text[:400]}
            raise RuntimeError(f"Directory users HTTP {r.status_code}: {err}")
        body = r.json()
        users.extend(body.get("users") or [])
        page_token = body.get("nextPageToken")
        if not page_token:
            break
    return users


def _last_login_days(user: dict) -> int:
    """Returns whole days since lastLoginTime. Sentinel ~99999 if never."""
    s = user.get("lastLoginTime") or ""
    if not s or s.startswith("1970"):
        return 99999
    import datetime
    try:
        # Google returns RFC3339, e.g. "2024-09-05T12:30:00.000Z"
        dt = datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
        return (datetime.datetime.utcnow() - dt).days
    except Exception:
        return 99999


def _is_admin(u: dict) -> bool:
    return bool(u.get("isAdmin") or u.get("isDelegatedAdmin"))


def _security_key_field_present(u: dict) -> bool:
    """True only when the directory record explicitly populates the
    securityKeyAuthenticatorEnrolled field. Non-Enterprise editions of
    Workspace do NOT populate it — its absence is NOT evidence of a missing
    hardware key, so we must not grade on absence (zero-FP)."""
    return "securityKeyAuthenticatorEnrolled" in u


def _has_hardware_key(u: dict) -> bool:
    # Workspace exposes this via securityKeyAuthenticatorEnrolled.
    # We treat presence of an enrolled security key as best-of-breed posture.
    return bool(u.get("isEnrolledIn2Sv") and u.get("securityKeyAuthenticatorEnrolled"))


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    sa_input = (opts.get("gcp_service_account_json") or "").strip()
    delegated = (opts.get("delegated_admin") or "").strip()
    customer = (opts.get("customer_id") or "my_customer").strip() or "my_customer"

    if not sa_input or not delegated:
        ctx.state["gworkspace_admin_audit_creds_missing"] = True
        ctx.state["gworkspace_admin_audit_total"] = 0
        ctx.source("credentials required (gcp_service_account_json + delegated_admin)")
        return

    try:
        sa = _decode_sa_json(sa_input)
    except ValueError as e:
        ctx.state["gworkspace_admin_audit_creds_error"] = str(e)
        ctx.state["gworkspace_admin_audit_total"] = 0
        ctx.source(f"bad SA JSON: {e}")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["gworkspace_admin_audit_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    # ── 1. Build signed JWT + exchange for access token ──
    try:
        signed_jwt = _build_signed_jwt(sa, subject=delegated, scopes=ADMIN_SCOPES)
    except Exception as e:
        ctx.state["gworkspace_admin_audit_auth_error"] = (
            f"JWT build failed: {type(e).__name__}: {str(e)[:160]}")
        ctx.state["gworkspace_admin_audit_total"] = 0
        ctx.source("JWT build failed")
        return

    async with httpx.AsyncClient(verify=True) as client:
        try:
            access_token = await _exchange_jwt_for_access_token(client, signed_jwt)
        except Exception as e:
            ctx.state["gworkspace_admin_audit_auth_error"] = (
                f"{type(e).__name__}: {str(e)[:240]}")
            ctx.state["gworkspace_admin_audit_total"] = 0
            ctx.source("Google token exchange failed")
            return

        # ── 2. Enumerate users ──
        try:
            users = await _list_users(client, access_token, customer=customer)
        except Exception as e:
            ctx.state["gworkspace_admin_audit_api_error"] = (
                f"{type(e).__name__}: {str(e)[:240]}")
            ctx.state["gworkspace_admin_audit_total"] = 0
            ctx.source("Directory API call failed")
            return

    # ── 3. Classify ──
    admins = [u for u in users if _is_admin(u)]
    admins_no_2sv = []
    admins_dormant = []
    admins_no_hwkey = []
    admins_hwkey_field_unavailable = []
    suspended_admins = []
    for u in admins:
        email = u.get("primaryEmail", "(unknown)")
        is_super = bool(u.get("isAdmin"))
        is_suspended = bool(u.get("suspended"))
        twoSv = bool(u.get("isEnrolledIn2Sv"))
        last_days = _last_login_days(u)
        hwkey_field_present = _security_key_field_present(u)
        record = {
            "email": email,
            "super_admin": is_super,
            "delegated_admin": bool(u.get("isDelegatedAdmin")),
            "suspended": is_suspended,
            "isEnrolledIn2Sv": twoSv,
            "isEnforcedIn2Sv": bool(u.get("isEnforcedIn2Sv")),
            "security_key": bool(u.get("securityKeyAuthenticatorEnrolled")),
            "security_key_field_present": hwkey_field_present,
            "last_login_days": last_days,
        }
        if is_suspended:
            suspended_admins.append(record)
        if not twoSv:
            admins_no_2sv.append(record)
        elif hwkey_field_present:
            # Only grade hardware-key absence when the field is explicitly
            # populated (Enterprise edition). Absence != "no key" (zero-FP).
            if not _has_hardware_key(u):
                admins_no_hwkey.append(record)
        else:
            admins_hwkey_field_unavailable.append(record)
        if is_super and last_days >= DORMANT_DAYS:
            admins_dormant.append(record)

    # Hardware-key field unavailability is INFO-only (edition-dependent), NOT a
    # graded posture issue — keep it OUT of the issue tally.
    issues = (len(admins_no_2sv) + len(admins_dormant)
              + len(admins_no_hwkey) + len(suspended_admins))

    ctx.state["gworkspace_total_users"] = len(users)
    ctx.state["gworkspace_total_admins"] = len(admins)
    ctx.state["gworkspace_admins_no_2sv"] = admins_no_2sv
    ctx.state["gworkspace_admins_dormant"] = admins_dormant
    ctx.state["gworkspace_admins_no_hwkey"] = admins_no_hwkey
    ctx.state["gworkspace_admins_hwkey_field_unavailable"] = admins_hwkey_field_unavailable
    ctx.state["gworkspace_suspended_admins"] = suspended_admins
    ctx.state["gworkspace_admin_audit_total"] = issues
    ctx.source(f"Directory API OK — {len(admins)} admin(s) of {len(users)} user(s); "
               f"{issues} posture issue(s)")


INTEL_FIELDS = [
    ("Total users",                      "gworkspace_total_users"),
    ("Total admins",                     "gworkspace_total_admins"),
    ("Admins without 2-Step Verification","gworkspace_admins_no_2sv"),
    ("Super-admins dormant 90+ days",    "gworkspace_admins_dormant"),
    ("Admins without security key",      "gworkspace_admins_no_hwkey"),
    ("Admins (hardware-key field N/A on plan)", "gworkspace_admins_hwkey_field_unavailable"),
    ("Suspended users still admin",      "gworkspace_suspended_admins"),
]


@router.post("/api/sspm/gworkspace_admin_audit")
async def sspm_gworkspace_admin_audit(req: GworkspaceAdminAuditRequest,
                                       _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="gworkspace_admin_audit",
        gather_func=_gather_with_options,
        finding_rules=GWORKSPACE_ADMIN_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
