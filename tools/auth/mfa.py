"""MFA / 2FA via TOTP (RFC 6238) — compatible with Google Authenticator, Authy,
1Password, etc.

  POST /api/auth/mfa/enroll   -> {secret, otpauth_uri}  (not yet enabled)
  POST /api/auth/mfa/verify   {code}  -> enables MFA after one valid code
  POST /api/auth/mfa/disable  {code}  -> turns MFA off (requires a valid code)
  GET  /api/auth/mfa/status   -> {enabled: bool}

pyotp is imported lazily so the rest of the platform loads even if the library
isn't installed yet; the endpoints return a clear 501 until it's available.
Add `pyotp` to requirements.txt and rebuild to activate.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from tools._shared import verify_token
from tools.auth._db import (set_mfa_secret, enable_mfa, disable_mfa, get_mfa,
                            get_user_by_id, record_audit)

router = APIRouter()
_ISSUER = "VulnusLab"


def _pyotp():
    try:
        import pyotp
        return pyotp
    except Exception:
        raise HTTPException(501, "MFA not available: pyotp not installed (add to requirements + rebuild)")


def _ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    return xff.split(",")[0].strip() if xff else (request.client.host if request.client else "?")


class CodeRequest(BaseModel):
    code: str


@router.get("/api/auth/mfa/status")
async def mfa_status(payload=Depends(verify_token)):
    return {"enabled": get_mfa(payload.get("sub"))["enabled"]}


@router.post("/api/auth/mfa/enroll")
async def mfa_enroll(payload=Depends(verify_token)):
    pyotp = _pyotp()
    uid = payload.get("sub")
    if get_mfa(uid)["enabled"]:
        raise HTTPException(409, "MFA already enabled")
    secret = pyotp.random_base32()
    set_mfa_secret(uid, secret)  # pending until verified
    user = get_user_by_id(uid) or {}
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.get("email") or user.get("username") or uid, issuer_name=_ISSUER)
    return {"secret": secret, "otpauth_uri": uri,
            "note": "Add to your authenticator, then POST /api/auth/mfa/verify with a code."}


@router.post("/api/auth/mfa/verify")
async def mfa_verify(req: CodeRequest, request: Request, payload=Depends(verify_token)):
    pyotp = _pyotp()
    uid = payload.get("sub")
    mfa = get_mfa(uid)
    if not mfa["secret"]:
        raise HTTPException(400, "No enrollment in progress — call /enroll first")
    if not pyotp.TOTP(mfa["secret"]).verify(req.code.strip(), valid_window=1):
        raise HTTPException(401, "Invalid code")
    enable_mfa(uid)
    record_audit("mfa.enabled", actor_id=uid, actor_name=payload.get("username"), ip=_ip(request))
    return {"status": "enabled"}


@router.post("/api/auth/mfa/disable")
async def mfa_disable(req: CodeRequest, request: Request, payload=Depends(verify_token)):
    pyotp = _pyotp()
    uid = payload.get("sub")
    mfa = get_mfa(uid)
    if not mfa["enabled"]:
        return {"status": "already disabled"}
    if not pyotp.TOTP(mfa["secret"]).verify(req.code.strip(), valid_window=1):
        raise HTTPException(401, "Invalid code")
    disable_mfa(uid)
    record_audit("mfa.disabled", actor_id=uid, actor_name=payload.get("username"), ip=_ip(request))
    return {"status": "disabled"}


def register(app):
    app.include_router(router)
