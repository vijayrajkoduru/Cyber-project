"""Unauthenticated health endpoint — used by frontend's "Kali Online" badge.

GET /api/health — returns {"ok": true} fast, no JWT required. Used every 30s
by the React UI to render the green/red status pill in the sidebar.
"""
from fastapi import APIRouter

router = APIRouter()


@router.get("/api/health")
async def health():
    return {"ok": True, "service": "vulnuslab-backend"}


def register(app):
    app.include_router(router)
