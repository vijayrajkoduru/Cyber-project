"""Consent module orchestrator."""
from fastapi import APIRouter

router = APIRouter()

CONSENT_TOOLS_BY_TIER = {
    "default": [
        ("consent_log", "/api/consent/consent_log"),
    ],
}


def _all_tools():
    out = []
    for tools in CONSENT_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


def register(app):
    app.include_router(router)
