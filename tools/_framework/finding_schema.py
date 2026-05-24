"""Runtime finding schema — catches malformed NDJSON before it hits the UI.

VL-FOUNDRY Layer 6 (Quality Bar) defines the 7 required fields on every
finding. Layer 20 (E2E) confirms the WIRE shape is recognizable. This
module bridges them: a single validator a scanner can call before emitting,
plus a strict mode for tests that fails fast on any divergence.

Why this exists separately from `findings.py`:
  `findings.py` is the BUILDER — it constructs findings. This module is
  the VALIDATOR — it enforces the contract at runtime AND in tests.
  A scanner can bypass `findings.py` (legacy code, custom paths), so we
  need an independent guard.

Usage:
    from tools._framework.finding_schema import validate_finding, FindingError

    f = {"severity": "HIGH", "cvss": 7.5, ...}
    validate_finding(f)                     # raises on invalid
    ok, errs = validate_finding(f, raise_on_error=False)  # returns tuple
"""
from __future__ import annotations
from typing import Any

SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "POSITIVE"}
STATUSES = {"VULNERABLE", "CLEAN", "INCONCLUSIVE", "POSITIVE", "ERROR"}

# Required when status is VULNERABLE — the 7-check DoD fields
REQUIRED_VULN_FIELDS = (
    "severity",
    "cvss",
    "cwe",
    "owasp",
    "remediation",
    "evidence_marker",
)

# Required for ALL findings (any status)
REQUIRED_BASE_FIELDS = ("tool", "target", "status")


class FindingError(ValueError):
    """Raised when a finding dict doesn't satisfy the VL-FOUNDRY contract."""


def _check_base(f: dict, errs: list[str]) -> None:
    for k in REQUIRED_BASE_FIELDS:
        if k not in f:
            errs.append(f"missing required field: {k}")
    if "status" in f and f["status"] not in STATUSES:
        errs.append(f"status={f['status']!r} not in {sorted(STATUSES)}")


def _check_vuln(f: dict, errs: list[str]) -> None:
    """Extra checks when a finding represents an actual vulnerability."""
    for k in REQUIRED_VULN_FIELDS:
        if k not in f or f[k] in (None, "", []):
            errs.append(f"VULNERABLE finding missing/empty: {k}")
    if "severity" in f and f["severity"] not in SEVERITIES:
        errs.append(f"severity={f['severity']!r} not in {sorted(SEVERITIES)}")
    if "cvss" in f:
        try:
            v = float(f["cvss"])
            if not (0.0 <= v <= 10.0):
                errs.append(f"cvss={v} out of range [0.0, 10.0]")
        except (TypeError, ValueError):
            errs.append(f"cvss={f['cvss']!r} not numeric")
    if "cwe" in f and isinstance(f["cwe"], str):
        if not f["cwe"].startswith("CWE-"):
            errs.append(f"cwe={f['cwe']!r} must start with 'CWE-'")


def validate_finding(
    f: Any,
    raise_on_error: bool = True,
) -> tuple[bool, list[str]]:
    """Validate one finding dict.

    Returns (ok, errors). If raise_on_error=True, raises FindingError on
    any violation. Default raise behavior makes it safe to drop into
    scanner code as a guard:

        validate_finding(my_finding)   # blows up loudly in dev/CI
    """
    errs: list[str] = []

    if not isinstance(f, dict):
        errs.append(f"finding is not a dict: {type(f).__name__}")
    else:
        _check_base(f, errs)
        if f.get("status") == "VULNERABLE":
            _check_vuln(f, errs)

    ok = not errs
    if not ok and raise_on_error:
        raise FindingError("; ".join(errs))
    return ok, errs


def validate_ndjson_record(rec: Any) -> tuple[bool, list[str]]:
    """Looser shape check for orchestrator NDJSON envelopes.

    Used by `scripts/e2e_test.py` Gate 5. Accepts EITHER:
      • a scanner result envelope (tool/target/findings/...)
      • a heartbeat / progress event (event/timestamp/...)

    Strict finding validation should still be done by `validate_finding`
    on each entry in the `findings` array.
    """
    errs: list[str] = []
    if not isinstance(rec, dict):
        return False, [f"record is not a dict: {type(rec).__name__}"]
    recognized = {"tool", "target", "findings", "scanner", "error",
                  "event", "phase"}
    if not (set(rec.keys()) & recognized):
        errs.append(f"no recognizable key, got: {sorted(rec.keys())}")
    return not errs, errs


# Convenience for tests
def assert_all_valid(findings: list[dict]) -> None:
    """Validate every finding in a list. Raises on first failure with index."""
    for i, f in enumerate(findings):
        ok, errs = validate_finding(f, raise_on_error=False)
        if not ok:
            raise FindingError(f"finding[{i}]: {'; '.join(errs)}")
