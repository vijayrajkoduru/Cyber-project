"""Email verification.

  POST /api/auth/verify-email   {token}  -> marks the email verified
  POST /api/auth/resend-verification       -> re-sends the link (authed)

Registration (register.py) creates the user with email_verified=0 and sends
the first link. Verification is currently soft (we don't block login) so a
launch isn't gated on email deliverability — flip ENFORCE if you want to block
unverified users from scanning.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from tools._shared import verify_token
from tools.auth._db import (consume_email_token, mark_email_verified,
                            create_email_token, get_user_by_id, is_email_verified,
                            record_audit)
from tools._core.email_send import send_verification_email

router = APIRouter()


class TokenRequest(BaseModel):
    token: str


@router.post("/api/auth/verify-email")
async def verify_email(req: TokenRequest):
    uid = consume_email_token(req.token, purpose="verify")
    if not uid:
        raise HTTPException(400, "Invalid or expired verification link")
    mark_email_verified(uid)
    record_audit("email.verified", actor_id=uid)
    return {"status": "verified"}


@router.post("/api/auth/resend-verification")
async def resend_verification(payload=Depends(verify_token)):
    uid = payload.get("sub")
    if is_email_verified(uid):
        return {"status": "already verified"}
    user = get_user_by_id(uid)
    if not user or not user.get("email"):
        raise HTTPException(400, "No email on file")
    token = create_email_token(uid, purpose="verify")
    sent = send_verification_email(user["email"], token)
    return {"status": "sent" if sent else "queued",
            "note": None if sent else "Email not configured — link not delivered."}


def register(app):
    app.include_router(router)
