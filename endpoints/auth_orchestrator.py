"""Auth module orchestrator."""
from fastapi import APIRouter

router = APIRouter()

AUTH_TOOLS_BY_TIER = {
    "default": [
        ("login", "/api/auth/login"),
        ("me", "/api/auth/me"),
        ("register", "/api/auth/register"),
    ],
}


def _all_tools():
    out = []
    for tools in AUTH_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


def register(app):
    app.include_router(router)
