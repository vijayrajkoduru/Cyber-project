"""VL-FOUNDRY Layer 10 — Cross-module data contract.

Persists what each module DISCOVERED so downstream modules can consume it.

Example flow:
  1. Recon scans vulnuslab.com → writes:
        {"recon": {"subdomains": [...], "open_ports": [...], "tech_stack": [...]}}
  2. Vuln scan starts with same scan_id → reads recon.open_ports →
        only probes those ports, skips closed ones
  3. Webapp scan reads recon.subdomains → scans all discovered subs,
        not just apex

Schema is strict: scanners get IntelMissing if they try to read a field
upstream module didn't write. Forces explicit contract documentation.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any

# Default state location (overridable via env var)
_STATE_DIR = Path(os.environ.get("VULNUSLAB_STATE_DIR", "/tmp/vulnuslab-state"))
if not _STATE_DIR.parent.exists():
    _STATE_DIR = Path(__file__).resolve().parent.parent.parent / "logs" / "scan-state"


# ── Schema (Layer 10 contract) ──────────────────────────────────────────────
# When a module updates state, ONLY these keys are allowed. Adding a new key
# requires updating this schema + bumping the contract version.

SCHEMA = {
    "version": "1.0",
    "modules": {
        "recon": {
            "subdomains":       "list[str]",
            "resolved_ips":     "list[str]",
            "open_ports":       "list[int]",
            "tech_stack":       "list[str]",
            "behind_cdn":       "bool",
            "cdn_vendor":       "str|None",
            "tls_protocols":    "list[str]",
            "email_domain":     "str|None",
            "asn":              "str|None",
        },
        "vuln": {
            "detected_cves":    "list[str]",
            "service_versions": "dict[str,str]",  # port → "product version"
            "exposed_dbs":      "list[str]",      # service names
            "weak_auth":        "list[dict]",
        },
        "webapp": {
            "discovered_endpoints": "list[str]",
            "discovered_params":    "list[str]",
            "framework_detected":   "str|None",
            "auth_required":        "bool",
            "open_redirect":        "bool",
        },
    },
}


class IntelMissing(Exception):
    """Raised when a scanner reads a field upstream module didn't populate."""


def _state_path(scan_id: str) -> Path:
    """Per-scan state file."""
    safe = "".join(c for c in scan_id if c.isalnum() or c in "-_")[:64]
    return _STATE_DIR / f"{safe}.json"


def init_state(scan_id: str, target: str) -> None:
    """Create a new scan-state file (called by orchestrator at scan start)."""
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    state = {
        "scan_id": scan_id,
        "target": target,
        "schema_version": SCHEMA["version"],
        "recon": {},
        "vuln": {},
        "webapp": {},
    }
    _state_path(scan_id).write_text(json.dumps(state, indent=2), encoding="utf-8")


def update_state(scan_id: str, module: str, fields: dict[str, Any]) -> None:
    """Merge `fields` into state under `module`. Validates schema.

    Raises ValueError if a field is not in SCHEMA["modules"][module].
    """
    if module not in SCHEMA["modules"]:
        raise ValueError(f"Unknown module: {module}")
    allowed = set(SCHEMA["modules"][module].keys())
    for k in fields:
        if k not in allowed:
            raise ValueError(
                f"Field '{k}' not in Layer 10 schema for {module}. "
                f"Allowed: {sorted(allowed)}"
            )
    path = _state_path(scan_id)
    if not path.exists():
        return  # state was never initialized — silent no-op
    state = json.loads(path.read_text(encoding="utf-8"))
    state.setdefault(module, {}).update(fields)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def read_intel(scan_id: str, module: str, field: str, default: Any = None) -> Any:
    """Read a discovered field from upstream module's intel.

    Returns `default` if not populated. Raises IntelMissing if you pass
    `default=...` (sentinel) — useful for strict scanners that depend on
    upstream data.
    """
    path = _state_path(scan_id)
    if not path.exists():
        if default is None:
            return None
        return default
    state = json.loads(path.read_text(encoding="utf-8"))
    val = state.get(module, {}).get(field)
    if val is None:
        if default is None:
            return None
        return default
    return val


def read_intel_strict(scan_id: str, module: str, field: str) -> Any:
    """Same as read_intel but raises IntelMissing instead of returning default.

    Use when a scanner has a hard dependency on upstream data.
    """
    val = read_intel(scan_id, module, field, default="__MISSING__")
    if val == "__MISSING__":
        raise IntelMissing(
            f"Scanner expected {module}.{field} but upstream module didn't "
            f"populate it. Was {module} run first? Check scan order in "
            f"orchestrator."
        )
    return val


def get_full_state(scan_id: str) -> dict:
    """Return entire state dict (useful for debugging + PDF generation)."""
    path = _state_path(scan_id)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def cleanup_state(scan_id: str) -> None:
    """Delete state file after scan completes + PDF generated."""
    path = _state_path(scan_id)
    if path.exists():
        try:
            path.unlink()
        except Exception:
            pass
