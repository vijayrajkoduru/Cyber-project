"""Auth scan module orchestrator."""
from fastapi import APIRouter

router = APIRouter()

AUTH_SCAN_TOOLS_BY_TIER = {
    "default": [
        ("login_helper", "/api/auth_scan/login_helper"),
    ],
}


def _all_tools():
    out = []
    for tools in AUTH_SCAN_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


def register(app):
    app.include_router(router)
