"""Customer Credential Vault - core DB + encryption.

Underscore-prefixed so main.py's tool autoloader skips it. Endpoints
that need this import from here.

SECURITY DESIGN:
- Storage: SQLite at /app/data/credentials.db (separate DB from users.db
  to allow independent backup/rotation).
- Encryption: AES-256-GCM with per-user 32-byte key derived via HKDF-SHA256
  from CREDENTIAL_VAULT_MASTER_KEY (32 bytes, base64-encoded in env).
- AAD (Additional Authenticated Data): user_id - binds ciphertext to user,
  so even with DB exfiltration an attacker cannot swap user_a's blob into
  user_b's row and decrypt.
- Nonce: 12 random bytes per credential (regenerated on every update).
- Masked display: last 4 chars of the SECRET portion only.
- Audit log: every decrypt is logged to credential_usage_log with cred_id,
  user_id, scan_id, used_for, used_at.
- Memory hygiene: decrypted values returned as bytes; callers should overwrite
  with zeros after use (best-effort - Python GC limits).

ROTATION:
- Master key rotation requires re-encrypting all rows. Not implemented in
  v1 (manual procedure documented in ops runbook).
"""
from __future__ import annotations

import base64
import datetime
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ──────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────

DB_PATH = Path(os.getenv("CREDENTIALS_DB", "/app/data/credentials.db"))

# Master key must be 32 bytes base64-encoded in env. Generate with:
#   python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
_MASTER_KEY_B64 = os.getenv("CREDENTIAL_VAULT_MASTER_KEY", "")
# Fallback for dev: derive a deterministic key from JWT_SECRET (NOT for prod).
# In prod, CREDENTIAL_VAULT_MASTER_KEY must be set explicitly.
_FALLBACK_SEED = os.getenv("JWT_SECRET", "vulnuslab-dev-only-do-not-use-in-prod")


def _master_key() -> bytes:
    """Return 32-byte master key. Prefer env-supplied; fall back to JWT-derived for dev."""
    if _MASTER_KEY_B64:
        try:
            k = base64.b64decode(_MASTER_KEY_B64)
            if len(k) == 32:
                return k
        except Exception:
            pass
    # Dev fallback: SHA256 of JWT_SECRET (NOT cryptographically isolated from JWT signing!)
    import hashlib
    return hashlib.sha256(_FALLBACK_SEED.encode("utf-8")).digest()


# Supported credential types with their schemas
# Each schema lists field names + sensitivity flag (secret fields are masked)
SUPPORTED_TYPES = {
    "aws": {
        "label": "AWS Access Keys",
        "fields": [
            {"name": "access_key_id", "label": "Access Key ID", "secret": False, "required": True},
            {"name": "secret_access_key", "label": "Secret Access Key", "secret": True, "required": True},
            {"name": "session_token", "label": "Session Token (optional)", "secret": True, "required": False},
            {"name": "region", "label": "Default Region", "secret": False, "required": False, "default": "us-east-1"},
        ],
        "modules": ["cloud", "supply_chain", "sspm"],
    },
    "azure": {
        "label": "Azure Service Principal",
        "fields": [
            {"name": "tenant_id", "label": "Tenant ID", "secret": False, "required": True},
            {"name": "client_id", "label": "Client ID (App ID)", "secret": False, "required": True},
            {"name": "client_secret", "label": "Client Secret", "secret": True, "required": True},
            {"name": "subscription_id", "label": "Subscription ID", "secret": False, "required": False},
        ],
        "modules": ["cloud", "hybrid_identity", "sspm"],
    },
    "gcp": {
        "label": "GCP Service Account",
        "fields": [
            {"name": "service_account_json", "label": "Service Account JSON",
             "secret": True, "required": True, "multiline": True},
            {"name": "project_id", "label": "Project ID", "secret": False, "required": False},
        ],
        "modules": ["cloud", "sspm"],
    },
    "ad": {
        "label": "Active Directory Domain User",
        "fields": [
            {"name": "domain", "label": "AD Domain (e.g. corp.example.com)", "secret": False, "required": True},
            {"name": "username", "label": "Username", "secret": False, "required": True},
            {"name": "password", "label": "Password", "secret": True, "required": True},
            {"name": "dc_ip", "label": "DC IP (optional)", "secret": False, "required": False},
        ],
        "modules": ["ad", "post_exploit", "hybrid_identity"],
    },
    "k8s": {
        "label": "Kubernetes Kubeconfig",
        "fields": [
            {"name": "kubeconfig", "label": "Kubeconfig YAML", "secret": True, "required": True, "multiline": True},
            {"name": "context", "label": "Context (optional)", "secret": False, "required": False},
        ],
        "modules": ["container_k8s", "cloud"],
    },
    "ssh": {
        "label": "SSH Credentials",
        "fields": [
            {"name": "username", "label": "Username", "secret": False, "required": True},
            {"name": "password", "label": "Password (or private_key)", "secret": True, "required": False},
            {"name": "private_key", "label": "Private Key (PEM)", "secret": True, "required": False, "multiline": True},
            {"name": "port", "label": "Port", "secret": False, "required": False, "default": "22"},
        ],
        "modules": ["privesc", "post_exploit", "red_team"],
    },
    "github": {
        "label": "GitHub Personal Access Token",
        "fields": [
            {"name": "token", "label": "GitHub PAT (ghp_... / github_pat_...)", "secret": True, "required": True},
            {"name": "org", "label": "Org (for org-scoped audits)", "secret": False, "required": False},
        ],
        "modules": ["supply_chain", "sspm", "osint"],
    },
    "okta": {
        "label": "Okta API Token",
        "fields": [
            {"name": "org_url", "label": "Okta Org URL (https://acme.okta.com)", "secret": False, "required": True},
            {"name": "api_token", "label": "API Token", "secret": True, "required": True},
        ],
        "modules": ["auth_attacks", "sspm"],
    },
    "slack": {
        "label": "Slack Bot Token",
        "fields": [
            {"name": "bot_token", "label": "Bot Token (xoxb-...)", "secret": True, "required": True},
            {"name": "team_id", "label": "Team ID (optional)", "secret": False, "required": False},
        ],
        "modules": ["sspm"],
    },
    "gworkspace": {
        "label": "Google Workspace Service Account",
        "fields": [
            {"name": "service_account_json", "label": "Service Account JSON",
             "secret": True, "required": True, "multiline": True},
            {"name": "delegated_subject", "label": "Delegated Admin Email",
             "secret": False, "required": True},
        ],
        "modules": ["sspm"],
    },
    "salesforce": {
        "label": "Salesforce OAuth",
        "fields": [
            {"name": "instance_url", "label": "Instance URL (https://acme.my.salesforce.com)",
             "secret": False, "required": True},
            {"name": "access_token", "label": "Access Token", "secret": True, "required": True},
            {"name": "refresh_token", "label": "Refresh Token (optional)", "secret": True, "required": False},
        ],
        "modules": ["sspm"],
    },
    "api_token": {
        "label": "Generic API Token (Bearer)",
        "fields": [
            {"name": "endpoint", "label": "API Endpoint URL", "secret": False, "required": False},
            {"name": "token", "label": "Bearer Token / API Key", "secret": True, "required": True},
            {"name": "header_name", "label": "Header name (default Authorization)",
             "secret": False, "required": False, "default": "Authorization"},
        ],
        "modules": ["auth_attacks", "apisec", "ai_llm"],
    },
    "generic": {
        "label": "Generic Username/Password",
        "fields": [
            {"name": "username", "label": "Username", "secret": False, "required": False},
            {"name": "password", "label": "Password / Secret", "secret": True, "required": True},
            {"name": "extra_json", "label": "Extra fields (JSON)", "secret": False, "required": False, "multiline": True},
        ],
        "modules": ["password", "auth_attacks"],
    },
}


# ──────────────────────────────────────────────────────────────────────
# DB schema + lifecycle
# ──────────────────────────────────────────────────────────────────────


def _ensure_dir():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def init_db():
    """Create vault tables if not exist."""
    _ensure_dir()
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS credential_sets (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            cred_type TEXT NOT NULL,
            encrypted_blob BLOB NOT NULL,
            nonce BLOB NOT NULL,
            masked_hint TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            last_used_at TEXT,
            use_count INTEGER DEFAULT 0,
            UNIQUE(user_id, name)
        );
        CREATE INDEX IF NOT EXISTS idx_credset_user ON credential_sets(user_id);
        CREATE INDEX IF NOT EXISTS idx_credset_type ON credential_sets(cred_type);

        CREATE TABLE IF NOT EXISTS credential_usage_log (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            cred_id TEXT NOT NULL,
            scan_id TEXT,
            used_for TEXT,
            used_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_usage_cred ON credential_usage_log(cred_id);
        CREATE INDEX IF NOT EXISTS idx_usage_user ON credential_usage_log(user_id);
    """)
    con.commit()
    con.close()


@contextmanager
def get_db():
    """SQLite connection context manager."""
    init_db()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


# ──────────────────────────────────────────────────────────────────────
# Crypto helpers
# ──────────────────────────────────────────────────────────────────────


def _derive_user_key(user_id: str) -> bytes:
    """HKDF-derive a per-user 32-byte AES-256-GCM key from the master."""
    if not user_id:
        raise ValueError("user_id required for key derivation")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=f"vulnuslab-credvault-v1::{user_id}".encode("utf-8"))
    return hkdf.derive(_master_key())


def encrypt_credential(user_id: str, fields: dict) -> tuple[bytes, bytes]:
    """Encrypt the fields dict for storage. Returns (nonce, ciphertext)."""
    if not isinstance(fields, dict):
        raise TypeError("fields must be a dict")
    key = _derive_user_key(user_id)
    plaintext = json.dumps(fields, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(12)
    aad = user_id.encode("utf-8")
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    # Zero out the derived key from memory (best-effort)
    del key
    return nonce, ciphertext


def decrypt_credential(user_id: str, nonce: bytes, ciphertext: bytes) -> dict:
    """Decrypt a stored credential blob. Returns the fields dict."""
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    key = _derive_user_key(user_id)
    aesgcm = AESGCM(key)
    aad = user_id.encode("utf-8")
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    del key
    try:
        return json.loads(plaintext.decode("utf-8"))
    finally:
        # Best-effort plaintext zeroing
        del plaintext


def mask_secret_value(value: str) -> str:
    """Return a customer-safe masked representation of a secret value.
    e.g. 'AKIAIOSFODNN7EXAMPLE' -> '***LE (20 chars)'
    """
    if not value:
        return "(empty)"
    s = str(value)
    if len(s) <= 4:
        return f"*** ({len(s)} chars)"
    return f"***{s[-2:]} ({len(s)} chars)"


# ──────────────────────────────────────────────────────────────────────
# High-level CRUD
# ──────────────────────────────────────────────────────────────────────


def list_credentials(user_id: str) -> list[dict]:
    """List all credential sets for a user (masked, never decrypted)."""
    with get_db() as con:
        rows = con.execute(
            "SELECT id, name, cred_type, masked_hint, created_at, updated_at, "
            "last_used_at, use_count FROM credential_sets "
            "WHERE user_id=? ORDER BY name ASC", (user_id,)).fetchall()
    return [dict(r) for r in rows]


def get_credential_metadata(user_id: str, cred_id: str) -> Optional[dict]:
    """Get one credential's metadata (NOT decrypted)."""
    with get_db() as con:
        row = con.execute(
            "SELECT id, name, cred_type, masked_hint, created_at, updated_at, "
            "last_used_at, use_count FROM credential_sets "
            "WHERE id=? AND user_id=?", (cred_id, user_id)).fetchone()
    return dict(row) if row else None


def create_credential(user_id: str, name: str, cred_type: str, fields: dict) -> str:
    """Create a new credential set. Returns the new ID."""
    if cred_type not in SUPPORTED_TYPES:
        raise ValueError(f"unsupported cred_type: {cred_type}")
    schema = SUPPORTED_TYPES[cred_type]
    # Validate required fields
    field_specs = {f["name"]: f for f in schema["fields"]}
    for spec in schema["fields"]:
        if spec.get("required") and not fields.get(spec["name"]):
            raise ValueError(f"required field missing: {spec['name']}")
    # Build a masked hint from the FIRST secret field
    masked_hint = "(no secret)"
    for spec in schema["fields"]:
        if spec.get("secret"):
            v = fields.get(spec["name"])
            if v:
                masked_hint = mask_secret_value(v)
                break

    nonce, ciphertext = encrypt_credential(user_id, fields)
    new_id = str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat() + "Z"

    with get_db() as con:
        try:
            con.execute(
                "INSERT INTO credential_sets "
                "(id, user_id, name, cred_type, encrypted_blob, nonce, masked_hint, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (new_id, user_id, name, cred_type, ciphertext, nonce, masked_hint, now))
        except sqlite3.IntegrityError as e:
            if "UNIQUE" in str(e):
                raise ValueError(f"credential set named '{name}' already exists")
            raise
    return new_id


def update_credential(user_id: str, cred_id: str, name: Optional[str], fields: Optional[dict]) -> bool:
    """Update name and/or fields. Returns True if updated."""
    with get_db() as con:
        row = con.execute(
            "SELECT cred_type FROM credential_sets WHERE id=? AND user_id=?",
            (cred_id, user_id)).fetchone()
        if not row:
            return False
        updates = []
        params: list = []
        now = datetime.datetime.utcnow().isoformat() + "Z"
        if name:
            updates.append("name=?")
            params.append(name)
        if fields:
            schema = SUPPORTED_TYPES.get(row["cred_type"])
            if not schema:
                raise ValueError(f"unknown cred_type stored: {row['cred_type']}")
            for spec in schema["fields"]:
                if spec.get("required") and not fields.get(spec["name"]):
                    raise ValueError(f"required field missing: {spec['name']}")
            nonce, ciphertext = encrypt_credential(user_id, fields)
            updates.extend(["encrypted_blob=?", "nonce=?"])
            params.extend([ciphertext, nonce])
            # Recompute masked hint
            for spec in schema["fields"]:
                if spec.get("secret"):
                    v = fields.get(spec["name"])
                    if v:
                        updates.append("masked_hint=?")
                        params.append(mask_secret_value(v))
                        break
        if not updates:
            return False
        updates.append("updated_at=?")
        params.append(now)
        params.extend([cred_id, user_id])
        con.execute(
            f"UPDATE credential_sets SET {', '.join(updates)} "
            f"WHERE id=? AND user_id=?", params)
    return True


def delete_credential(user_id: str, cred_id: str) -> bool:
    """Delete one credential set + its usage logs."""
    with get_db() as con:
        cur = con.execute(
            "DELETE FROM credential_sets WHERE id=? AND user_id=?",
            (cred_id, user_id))
        deleted = cur.rowcount > 0
        if deleted:
            con.execute("DELETE FROM credential_usage_log WHERE cred_id=?", (cred_id,))
    return deleted


def use_credential(user_id: str, cred_id: str, used_for: str = "",
                    scan_id: str = "") -> Optional[dict]:
    """Decrypt + return credential for one-shot scan use. Logs usage.
    Returns the fields dict OR None if not found.

    Callers MUST NOT cache the returned dict; use it immediately and let
    it go out of scope. The audit log records every decrypt call.
    """
    with get_db() as con:
        row = con.execute(
            "SELECT encrypted_blob, nonce FROM credential_sets "
            "WHERE id=? AND user_id=?", (cred_id, user_id)).fetchone()
        if not row:
            return None
        fields = decrypt_credential(user_id, row["nonce"], row["encrypted_blob"])
        now = datetime.datetime.utcnow().isoformat() + "Z"
        con.execute(
            "UPDATE credential_sets SET last_used_at=?, use_count=use_count+1 "
            "WHERE id=? AND user_id=?", (now, cred_id, user_id))
        con.execute(
            "INSERT INTO credential_usage_log "
            "(id, user_id, cred_id, scan_id, used_for, used_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), user_id, cred_id, scan_id, used_for, now))
    return fields


def get_usage_log(user_id: str, cred_id: Optional[str] = None,
                   limit: int = 100) -> list[dict]:
    """Get usage audit log entries (for compliance / forensics)."""
    with get_db() as con:
        if cred_id:
            rows = con.execute(
                "SELECT * FROM credential_usage_log "
                "WHERE user_id=? AND cred_id=? "
                "ORDER BY used_at DESC LIMIT ?",
                (user_id, cred_id, limit)).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM credential_usage_log WHERE user_id=? "
                "ORDER BY used_at DESC LIMIT ?", (user_id, limit)).fetchall()
    return [dict(r) for r in rows]
