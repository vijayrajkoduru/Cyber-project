"""tools._framework — backwards-compatibility shim.

The real shared infrastructure lives in tools._vl_core/ (VL-CORE — the
central hub all modules connect to). Pre-VL-CORE code imported these
symbols from tools._framework; this module re-exports them so existing
imports keep working.

NEW CODE should import from tools._vl_core, e.g.:

    from tools._vl_core import wrap_finding, run_nuclei, is_reserved
"""
from tools._vl_core import (
    ScanContext, run_scanner,
    run_rules, severity_counts,
    run_module_parallel, run_module_streaming,
    wrap_finding, standard_response,
    cap_if_advisory, is_advisory, apply_policy,
    is_reserved, reserved_reason,
    run_nuclei, nuclei_available,
    detect_spa_catchall_sync, is_same_as_canary,
    MODULES, module_root, shared_root, assert_isolated_import,
)
# Legacy gathering / parser helpers (kept at framework level)
from tools._vl_core.gathering import (
    cli_run, whois_cli, team_cymru_asn,
    http_json, http_json_async,
    dns_resolve, dns_resolve_many,
)
from tools._vl_core.parsers import (
    grab, grab_all, parse_iso_date, days_between,
)

__all__ = [
    # scanner runtime
    "ScanContext", "run_scanner",
    # findings + rules
    "run_rules", "severity_counts",
    "wrap_finding", "standard_response",
    "cap_if_advisory", "is_advisory", "apply_policy",
    # orchestrator
    "run_module_parallel", "run_module_streaming",
    # pre-flight guards
    "is_reserved", "reserved_reason",
    # engine wrappers
    "run_nuclei", "nuclei_available",
    "detect_spa_catchall_sync", "is_same_as_canary",
    # module registry
    "MODULES", "module_root", "shared_root", "assert_isolated_import",
    # gathering
    "cli_run", "whois_cli", "team_cymru_asn",
    "http_json", "http_json_async",
    "dns_resolve", "dns_resolve_many",
    # parsers
    "grab", "grab_all", "parse_iso_date", "days_between",
]
