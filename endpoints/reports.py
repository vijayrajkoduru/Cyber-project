"""Report persistence — store generated PDFs per-user and serve them back.

Fixes the "close the tab = deliverable lost" gap. The customer report is built
client-side (jsPDF), so the browser uploads the finished PDF blob here on every
generation. Files live under the user's isolated zone
(/data/users/<uid>/reports/<report_id>.pdf) and reports/_index.json tracks
metadata for the Saved Reports list. Everything is JWT-gated and ownership is
enforced structurally: a user can only ever read/write paths inside their own
zone (userzone.safe_path blocks traversal), so report_id is never a cross-user
handle.

Endpoints:
  POST   /api/reports/upload        multipart PDF blob + metadata -> stored
  GET    /api/reports/list          this user's report metadata, newest first
  GET    /api/reports/{report_id}   stream the stored PDF back
  DELETE /api/reports/{report_id}   remove a stored report
"""
from __future__ import annotations

import re
import time

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse

from tools._shared import verify_scan_quota
from tools._core.userzone import init_zone, safe_path, read_json, write_json

router = APIRouter()

MAX_PDF_BYTES = 25 * 1024 * 1024          # 25 MB — generous for a findings-heavy report
MAX_INDEX_ENTRIES = 500                     # cap per-user index growth
_RID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_INDEX = "reports/_index.json"


def _safe_rid(report_id: str) -> str:
    rid = (report_id or "").strip()
    if not _RID_RE.match(rid):
        raise HTTPException(400, "invalid report_id (allowed: A-Z a-z 0-9 . _ - , 1-80 chars)")
    return rid


def _read_index(uid: str) -> list:
    idx = read_json(uid, _INDEX)
    return idx if isinstance(idx, list) else []


def _clean_filename(name: str, fallback: str) -> str:
    cleaned = "".join(c for c in (name or "") if c.isalnum() or c in "._-")[:120]
    return cleaned or fallback


@router.post("/api/reports/upload")
async def upload_report(
    file: UploadFile = File(...),
    report_id: str = Form(...),
    module: str = Form(""),
    target: str = Form(""),
    content_hash: str = Form(""),
    payload=Depends(verify_scan_quota),
):
    uid = payload["sub"]
    init_zone(uid)
    rid = _safe_rid(report_id)

    head = await file.read(5)
    if not head.startswith(b"%PDF"):
        raise HTTPException(400, "uploaded file is not a PDF")
    await file.seek(0)
    data = await file.read(MAX_PDF_BYTES + 1)
    if len(data) > MAX_PDF_BYTES:
        raise HTTPException(413, f"PDF exceeds {MAX_PDF_BYTES} bytes")

    dest = safe_path(uid, f"reports/{rid}.pdf")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)

    filename = _clean_filename(file.filename, f"{rid}.pdf")
    idx = _read_index(uid)
    idx = [e for e in idx if e.get("report_id") != rid]   # re-upload overwrites entry
    idx.insert(0, {
        "report_id": rid,
        "module": (module or "")[:40],
        "target": (target or "")[:200],
        "content_hash": (content_hash or "")[:32],
        "filename": filename,
        "size": len(data),
        "created_ts": int(time.time()),
    })
    write_json(uid, _INDEX, idx[:MAX_INDEX_ENTRIES])
    return {"ok": True, "report_id": rid, "size": len(data)}


@router.get("/api/reports/list")
async def list_reports(payload=Depends(verify_scan_quota)):
    uid = payload["sub"]
    return {"reports": _read_index(uid)}


@router.get("/api/reports/{report_id}")
async def get_report(report_id: str, payload=Depends(verify_scan_quota)):
    uid = payload["sub"]
    rid = _safe_rid(report_id)
    path = safe_path(uid, f"reports/{rid}.pdf")
    if not path.exists():
        raise HTTPException(404, "report not found")
    fname = f"{rid}.pdf"
    for e in _read_index(uid):
        if e.get("report_id") == rid:
            fname = e.get("filename") or fname
            break
    return FileResponse(str(path), media_type="application/pdf", filename=fname)


@router.delete("/api/reports/{report_id}")
async def delete_report(report_id: str, payload=Depends(verify_scan_quota)):
    uid = payload["sub"]
    rid = _safe_rid(report_id)
    path = safe_path(uid, f"reports/{rid}.pdf")
    existed = path.exists()
    if existed:
        path.unlink()
    idx = [e for e in _read_index(uid) if e.get("report_id") != rid]
    write_json(uid, _INDEX, idx)
    return {"ok": True, "deleted": existed}


def register(app):
    app.include_router(router)
