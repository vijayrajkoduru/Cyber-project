"""Non-destructive safety contract — enforced before every emulation step.

This is the guardrail that keeps the engine on the right side of "red team"
(authorized adversary emulation) vs an attack tool. It is intentionally
conservative and must not be weakened.
"""
from __future__ import annotations

# Impact levels an engagement may declare. The engine never exceeds the
# engagement's declared level, and never the absolute ceiling below.
IMPACT_EMULATION = "emulation"          # plan/log only — no action on the target (default)
IMPACT_ATOMIC = "atomic"               # benign Atomic-Red-Team-style detection tests on AUTHORIZED hosts
ALLOWED_IMPACTS = (IMPACT_EMULATION, IMPACT_ATOMIC)

# Categories that are ALWAYS forbidden, regardless of engagement settings.
FORBIDDEN = {
    "data_destruction": "Deleting/encrypting/corrupting data (ransomware, wiper).",
    "denial_of_service": "Service/network disruption or resource exhaustion.",
    "real_exfiltration": "Actually moving customer data off the target.",
    "out_of_scope_spread": "Touching any host not explicitly in scope.",
    "credential_harvest_live": "Capturing real production credentials for reuse.",
    "destructive_persistence": "Persistence that survives beyond the engagement window.",
}


class SafetyViolation(Exception):
    pass


def assert_technique_safe(technique: dict, impact_level: str) -> None:
    """Raise SafetyViolation if a technique would breach the contract.

    A catalog technique declares `risk` tags; any tag in FORBIDDEN is blocked.
    `atomic`-impact tests are only allowed if the technique is marked
    `atomic_safe` (a vetted, non-destructive detection test)."""
    if impact_level not in ALLOWED_IMPACTS:
        raise SafetyViolation(f"Unknown impact level: {impact_level!r}")

    for tag in (technique.get("risk") or []):
        if tag in FORBIDDEN:
            raise SafetyViolation(
                f"Technique {technique.get('id')} '{technique.get('name')}' is blocked: "
                f"{FORBIDDEN[tag]}"
            )

    if impact_level == IMPACT_ATOMIC and not technique.get("atomic_safe"):
        raise SafetyViolation(
            f"Technique {technique.get('id')} is not vetted for atomic execution; "
            f"emulation-only is permitted."
        )


def contract_text() -> str:
    return (
        "NON-DESTRUCTIVE CONTRACT: no data destruction, no DoS, no real "
        "exfiltration, no out-of-scope activity, no credential reuse, no "
        "persistence beyond the engagement window. Emulation/planning by default."
    )
