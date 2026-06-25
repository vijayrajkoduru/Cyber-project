"""Org-scoped API keys (Phase 2.4).

Underscore-prefixed so the tool autoloader skips it. A key authenticates a
programmatic caller AS an organization (bound to org_id at issuance) with a
fixed role. Only a SHA-256 hash is stored — the plaintext is shown once at
creation and never again (same model as a password).

Key format: vl_live_<43 url-safe chars>. Lookup is by hash (indexed).
"""
import uuid
import hashlib
import secrets
import datetime

from tools.auth._db import get_db


def _now() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def _hash(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


def create_api_key(org_id: str, name: str, role: str, created_by: str = None):
    """Mint a new key for the org. Returns (key_id, plaintext, prefix). The
    plaintext is the ONLY time the full key is available."""
    kid = uuid.uuid4().hex[:16]
    plaintext = "vl_live_" + secrets.token_urlsafe(32)
    prefix = plaintext[:16]   # 'vl_live_' + first 8 chars, safe to display
    with get_db() as con:
        con.execute(
            "INSERT INTO api_keys (id, org_id, name, key_hash, prefix, role, "
            "created_by, created_at, last_used, revoked) VALUES (?,?,?,?,?,?,?,?,?,0)",
            (kid, org_id, (name or "API key")[:100], _hash(plaintext), prefix,
             role, created_by, _now(), None))
    return kid, plaintext, prefix


def list_api_keys(org_id: str):
    """All keys for the org — metadata only, never the hash or plaintext."""
    with get_db() as con:
        return [dict(r) for r in con.execute(
            "SELECT id, name, prefix, role, created_by, created_at, last_used, revoked "
            "FROM api_keys WHERE org_id=? ORDER BY created_at DESC", (org_id,)).fetchall()]


def revoke_api_key(org_id: str, key_id: str) -> bool:
    """Revoke a key (scoped to the org so one tenant can't revoke another's).
    Returns False if no such key in this org."""
    with get_db() as con:
        res = con.execute("UPDATE api_keys SET revoked=1 WHERE org_id=? AND id=?",
                          (org_id, key_id))
        return res.rowcount > 0


def verify_api_key(plaintext: str):
    """Resolve a presented key to its org binding, or None if invalid/revoked.
    Updates last_used (best-effort). Constant-time-ish: lookup is by hash."""
    if not plaintext or not plaintext.startswith("vl_"):
        return None
    h = _hash(plaintext)
    with get_db() as con:
        r = con.execute(
            "SELECT id, org_id, name, role, created_by FROM api_keys "
            "WHERE key_hash=? AND revoked=0", (h,)).fetchone()
        if not r:
            return None
        try:
            con.execute("UPDATE api_keys SET last_used=? WHERE id=?", (_now(), r["id"]))
        except Exception:
            pass
        return {"key_id": r["id"], "org_id": r["org_id"], "name": r["name"],
                "role": r["role"], "created_by": r["created_by"]}
