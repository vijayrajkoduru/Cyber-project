"""Admin module orchestrator."""
from fastapi import APIRouter

router = APIRouter()

ADMIN_TOOLS_BY_TIER = {
    "default": [
        ("backups", "/api/admin/backups"),
        ("users", "/api/admin/users"),
        ("vault", "/api/admin/vault"),
    ],
}


def _all_tools():
    out = []
    for tools in ADMIN_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


def register(app):
    app.include_router(router)
