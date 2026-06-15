"""VL-CORE: module isolation contract.

Each scanner module (Recon, Vuln, Webapp, OSINT, Mobile, Cloud, etc.) owns
a self-contained resource pool under `tools/_payloads/<module>/`:

    tools/
    ├── <module>/                  ← engine scanners
    └── _payloads/<module>/
        ├── _loader.py             ← canonical loader (load_json, load_lines)
        ├── ai_*.txt               ← AI-curated wordlists
        ├── *.txt                  ← generic wordlists
        ├── *.json                 ← structured payload lists
        └── *.py                   ← payload constants modules (optional)

VL-CORE rule: **scanners in module X import ONLY from `_payloads/<X>/`**.

Cross-module imports are anti-pattern. A Webapp scanner pulling from
`_payloads/vuln/` couples the modules — change vuln's wordlist and a
seemingly-unrelated webapp scanner shifts behavior. Each module ships,
versions, and is sellable independently when isolation is enforced.

Truly shared concepts (e.g. a generic password top-list) get their own
slot at `_payloads/_shared/` — explicit and opt-in. The default is
isolated.

This module is the registry. Each module's `_loader.py` consults
`VL_CORE.module_root(name)` to compute its data root. Future audits
(VL-AUDIT pass) walk every scanner and assert it imports only its own
module's loader.
"""
from __future__ import annotations
import os
from pathlib import Path

# Canonical module registry. Add a row when forging a new module.
MODULES = (
    "recon",
    "vuln",
    "webapp",
    "osint",
    "mobile",
    "cloud",
    "container_k8s",
    "apisec",
    "auth_attacks",
    "network",
    "wireless",
    "system_exploit",
    "post_exploit",
    "credentials",
    "ai_llm",
    "iot_ot",
    "supply_chain",
    "phishing",
    "ad",
    "av_evasion",
    "bof",
    "client_side",
    "firmware",
    "hybrid_identity",
    "metasploit",
    "password",
    "pivot",
    "privesc",
    "red_team",
    "sspm",
    "tunnel",
    "exploit",
)

# Filesystem root for VL-CORE payloads. Resolved once on import.
_PAYLOADS_ROOT = Path(__file__).resolve().parent.parent / "_payloads"


def module_root(name: str) -> Path:
    """Return the on-disk root for a module's payload pool.

    Raises if `name` is not a registered module — prevents typos creating
    orphan directories outside the registry.
    """
    if name not in MODULES:
        raise ValueError(
            f"VL-CORE: '{name}' is not a registered module. Add it to "
            f"tools/_framework/vl_core.MODULES before using.")
    return _PAYLOADS_ROOT / name


def shared_root() -> Path:
    """Root for the explicit, opt-in cross-module payload pool.

    Use sparingly. Anything here is a CONSCIOUS cross-module dependency —
    not an accidental import.
    """
    return _PAYLOADS_ROOT / "_shared"


def assert_isolated_import(caller_module: str, payload_module: str) -> None:
    """Helper for VL-AUDIT to assert at scan time that a scanner imports
    only from its own module's payload pool.

    Call from any scanner's import block:

        from tools._framework.vl_core import assert_isolated_import
        assert_isolated_import("webapp", "webapp")  # OK
        assert_isolated_import("webapp", "vuln")    # raises in audit mode
    """
    if os.environ.get("VL_CORE_STRICT") != "1":
        return  # only enforced under VL-AUDIT
    if caller_module != payload_module and payload_module != "_shared":
        raise RuntimeError(
            f"VL-CORE isolation violated: {caller_module} scanner is "
            f"importing from {payload_module}. Move the dependency to "
            f"_payloads/{caller_module}/ or _payloads/_shared/.")
