"""User module orchestrator."""
from fastapi import APIRouter

router = APIRouter()

USER_TOOLS_BY_TIER = {
    "default": [
        ("backup", "/api/user/backup"),
    ],
}


def _all_tools():
    out = []
    for tools in USER_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


def register(app):
    app.include_router(router)
