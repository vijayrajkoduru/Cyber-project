"""GET /api/auth/me — return the current user from JWT.

Frontend uses this on page load to verify the token is still valid
and refresh the user's plan/role state.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from tools._shared import verify_token
from tools.auth._db import get_db

router = APIRouter()


@router.get("/api/auth/me")
async def auth_me(request: Request, response: Response, payload=Depends(verify_token)):
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(401, "Invalid token payload")

    with get_db() as con:
        row = con.execute(
            "SELECT id, username, email, role, plan, status, created_at "
            "FROM users WHERE id=?",
            (user_id,),
        ).fetchone()

    if not row:
        raise HTTPException(404, "User not found")
    if row["status"] != "active":
        raise HTTPException(403, f"Account is {row['status']}")

    out = dict(row)
    # SESSION-COOKIE-V1: a cookie session whose CSRF cookie went missing gets a
    # fresh one; the SPA also keeps the value from this response in memory.
    from tools.auth._session_cookie import SESSION_COOKIE, CSRF_COOKIE, set_csrf_cookie
    if request.cookies.get(SESSION_COOKIE):
        csrf = request.cookies.get(CSRF_COOKIE) or set_csrf_cookie(response, request)
        out["csrf_token"] = csrf
        out["session"] = "cookie"
    return out


def register(app):
    app.include_router(router)
