"""Secret accessor — one place to read secrets, so swapping env for a real
secret manager (Vault, AWS/GCP Secrets Manager, Doppler) is a one-file change
instead of a project-wide grep-and-replace.

Today: reads from the process environment (12-factor). Tomorrow: set
SECRETS_BACKEND=vault|aws|gcp and implement the corresponding _load_* hook —
every call site already routes through get_secret()/require_secret().

Usage:
    from tools._core.secrets import get_secret, require_secret
    dsn = get_secret("SENTRY_DSN")                 # -> str | None
    jwt = require_secret("JWT_SECRET")             # raises if missing/empty
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("vulnuslab.secrets")

_BACKEND = os.getenv("SECRETS_BACKEND", "env").lower()

# Secrets that, if found with a known placeholder value, indicate an
# un-rotated / template credential (see docs/ROTATE-SECRETS.md).
_PLACEHOLDER_MARKERS = (
    "your_actual_key_here", "paste_new_token_here", "your_token", "<key>",
    "changeme", "your_abuseipdb_key_here", "your_", "rzp_test_",
)


def _is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    return any(m in v for m in _PLACEHOLDER_MARKERS)


def get_secret(name: str, default: str | None = None) -> str | None:
    """Return the secret value or `default`. Never raises."""
    if _BACKEND == "env":
        val = os.getenv(name)
        return val if val not in (None, "") else default
    # Future backends plug in here; fall back to env so nothing breaks.
    log.warning("SECRETS_BACKEND=%s not implemented — falling back to env", _BACKEND)
    val = os.getenv(name)
    return val if val not in (None, "") else default


def require_secret(name: str) -> str:
    """Return the secret or raise RuntimeError if missing/empty/placeholder."""
    val = get_secret(name)
    if not val:
        raise RuntimeError(
            f"Required secret {name!r} is missing. Set it in the environment "
            f"(or your configured SECRETS_BACKEND). Never bake it into the image."
        )
    if _is_placeholder(val):
        raise RuntimeError(
            f"Secret {name!r} still holds a placeholder/template value. "
            f"Rotate it — see docs/ROTATE-SECRETS.md."
        )
    return val


def audit_placeholders(names: list[str]) -> list[str]:
    """Return the subset of `names` whose current value looks like a
    placeholder/template. Used by tests + the ops console to surface
    un-rotated credentials without ever printing the value."""
    flagged = []
    for n in names:
        v = os.getenv(n)
        if v and _is_placeholder(v):
            flagged.append(n)
    return flagged
