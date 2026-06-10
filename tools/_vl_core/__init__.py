"""VL-CORE — the central hub all VulnusLab modules connect to.

The product is built as N isolated MODULES (Recon / Vuln / Webapp / OSINT /
Mobile / Cloud / etc.). Each module's scanners are independent from every
other module's scanners — they don't share state, payloads, or imports at
runtime.

Everything that ALL modules need — orchestrator, scan-state cache, advisory
severity policy, Nuclei wrapper, external-binary wrappers, reserved-domain
detection — lives in VL-CORE. Each module's scanners reach into VL-CORE for
shared infrastructure but never reach into another module.

Architecture:

    ┌─────────────────────────── VL-CORE ───────────────────────────┐
    │  orchestrator   scan_state   severity_policy   nuclei_runner  │
    │  spa_canary     reserved_domains   exposure_catalog (future)  │
    │  framework_engine   advisory_cap   external_bins (future)     │
    └────────────┬────────────┬────────────┬────────────┬───────────┘
                 │            │            │            │
        ┌────────▼───┐  ┌─────▼───┐  ┌────▼─────┐  ┌───▼─────┐
        │   Recon    │  │  Vuln   │  │  Webapp  │  │  OSINT  │
        │  scanners  │  │ scanners│  │ scanners │  │ scanners│
        │            │  │         │  │          │  │         │
        │  _payloads/│  │_payloads│  │ _payloads│  │_payloads│
        │  /recon/   │  │ /vuln/  │  │ /webapp/ │  │ /osint/ │
        └────────────┘  └─────────┘  └──────────┘  └─────────┘

Module isolation rules (enforced via tools._framework.vl_core):
  1. A scanner in module X imports from VL-CORE OR _payloads/X/ only.
  2. Cross-module imports (webapp pulling from vuln) are anti-pattern.
  3. Genuinely shared payloads live in _payloads/_shared/ (opt-in).

VL-CORE is the API surface. Backing files live in tools/_framework/ for
historical reasons; this module re-exports them under stable names so
modules can import once from VL-CORE and not chase file paths.

Usage:

    from tools._vl_core import (
        # Orchestration
        run_module_parallel, run_module_streaming,
        # Scanner framework
        ScanContext, run_scanner,
        # Findings + policy
        wrap_finding, cap_if_advisory, run_rules,
        # Shared state
        detect_spa_catchall_sync, is_same_as_canary,
        # Pre-flight guards
        is_reserved, reserved_reason,
        # Engine wrappers
        run_nuclei, nuclei_available,
        # Module registry
        MODULES, module_root,
    )
"""
from __future__ import annotations

# ── Orchestration ────────────────────────────────────────────────────────
from tools._vl_core.orchestrator import (
    run_module_parallel,
    run_module_streaming,
)

# ── Scanner framework (per-scanner runtime) ──────────────────────────────
from tools._vl_core.scanner import run_scanner, ScanContext

# ── Finding shape + policy ───────────────────────────────────────────────
from tools._shared import wrap_finding, standard_response
from tools._vl_core.findings import run_rules, severity_counts
from tools._vl_core.severity_policy import (
    cap_if_advisory,
    is_advisory,
    apply_policy,
)

# ── Pre-flight target guards ─────────────────────────────────────────────
from tools._vl_core.reserved_domains import (
    is_reserved,
    reason as reserved_reason,
)

# ── Shared engine wrappers ───────────────────────────────────────────────
from tools._vl_core.nuclei_runner import run_nuclei, nuclei_available
from tools._vl_core.spa_canary import (
    detect_spa_catchall_sync,
    is_same_as_canary,
)

# ── Module registry + isolation contract ─────────────────────────────────
from tools._vl_core.vl_core import (
    MODULES,
    module_root,
    shared_root,
    assert_isolated_import,
)


__all__ = [
    # Orchestration
    "run_module_parallel", "run_module_streaming",
    # Scanner framework
    "ScanContext", "run_scanner",
    # Findings + policy
    "wrap_finding", "standard_response",
    "run_rules", "severity_counts",
    "cap_if_advisory", "is_advisory", "apply_policy",
    # Pre-flight guards
    "is_reserved", "reserved_reason",
    # Engine wrappers
    "run_nuclei", "nuclei_available",
    "detect_spa_catchall_sync", "is_same_as_canary",
    # Module registry
    "MODULES", "module_root", "shared_root", "assert_isolated_import",
]
