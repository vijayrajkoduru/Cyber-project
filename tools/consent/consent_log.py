"""Consent audit log — appends every scan-start consent to a SQLite log.

The /api/scan/consent_log route is hit by the WebApp + Vuln modules right
before the first scan request fires. It records who, what, when, where
from. If a customer is later challenged ("you scanned our site without
permission"), this is the legal record showing they explicitly ticked
the authorization checkbox before the scan ran.

Records are append-only. The file lives under /app/data/consent_audit.db
so it survives container rebuilds (the volume is bind-mounted).
"""
from __future__ import annotations

import datetime
import os
import sqlite3
import threading
from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from tools._shared import verify_scan_quota

router = APIRouter()

_DB_PATH = os.environ.get("CONSENT_DB_PATH", "/app/data/consent_audit.db")
_DB_LOCK = threading.Lock()


def _init_db():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    with sqlite3.connect(_DB_PATH) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS consent_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT    NOT NULL,
                user_email  TEXT,
                target      TEXT    NOT NULL,
                module      TEXT    NOT NULL,
                client_ip   TEXT,
                user_agent  TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_consent_target ON consent_log(target)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_consent_ts ON consent_log(ts)")


class ConsentBody(BaseModel):
    target: str
    module: str
    user_agent: Optional[str] = ""


@router.post("/api/scan/consent_log")
async def log_consent(body: ConsentBody, request: Request,
                       payload=Depends(verify_scan_quota)):
    try:
        _init_db()
    except Exception as e:
        return {"ok": False, "error": f"db init failed: {e}"}

    user_email = ""
    if isinstance(payload, dict):
        user_email = payload.get("sub") or payload.get("email") or ""

    # Per-plan quota gate. One consent_log call == one scan, so this is the
    # single place that meters scans. If the user is over their monthly cap
    # (or on an expired subscription that fell back to free), block here and
    # the dashboard aborts the scan before any scanner fires.
    try:
        from tools._quota import check_and_consume
        q = check_and_consume(user_email)
    except Exception:
        q = {"ok": True}
    if not q.get("ok", True):
        return {"ok": False, "quota_exceeded": True,
                "message": q.get("message", "Monthly scan limit reached. Upgrade to run more scans."),
                "plan": q.get("effective_plan"), "used": q.get("used"), "cap": q.get("cap")}

    client_ip = request.client.host if request.client else ""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        client_ip = fwd.split(",")[0].strip() or client_ip

    try:
        with _DB_LOCK, sqlite3.connect(_DB_PATH) as c:
            c.execute(
                "INSERT INTO consent_log (ts, user_email, target, module, client_ip, user_agent) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 user_email, body.target, body.module, client_ip,
                 (body.user_agent or "")[:500]))
        return {"ok": True, "plan": q.get("effective_plan"),
                "used": q.get("used"), "cap": q.get("cap"), "remaining": q.get("remaining")}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def register(app):
    app.include_router(router)
