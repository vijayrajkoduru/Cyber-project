"""Red-team report generator — Markdown from an emulation run.

Renders: header + RoE, executive summary, kill-chain walk (ATT&CK-mapped),
an ATT&CK tactic coverage heatmap, blocked/destructive objectives, and a
detection-gap / recommendations section.
"""
from __future__ import annotations

from . import attack_catalog as cat

_TACTIC_LABEL = {
    "reconnaissance": "Reconnaissance", "initial_access": "Initial Access",
    "execution": "Execution", "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation", "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access", "discovery": "Discovery",
    "lateral_movement": "Lateral Movement", "collection": "Collection",
    "command_and_control": "Command & Control", "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def render_markdown(run: dict) -> str:
    L = []
    L.append(f"# RED TEAM EMULATION REPORT — {run.get('client','(client)')}")
    L.append("")
    L.append(f"- Engagement: `{run.get('engagement_id')}`")
    L.append(f"- Target (in-scope): `{run.get('target')}`")
    L.append(f"- Scenario: **{run.get('scenario')}**  |  Impact level: **{run.get('impact_level')}**")
    L.append(f"- Window: {run.get('started_at')} -> {run.get('finished_at')}")
    L.append(f"- Contract: {run.get('contract')}")
    L.append("")

    emulated, blocked = run.get("emulated", 0), run.get("blocked", 0)
    covered = run.get("tactics_covered", [])
    L.append("## Executive Summary")
    L.append(f"Emulated **{emulated}** ATT&CK technique(s) across **{len(covered)}** tactic(s) "
             f"against the authorized target; **{blocked}** destructive/forbidden technique(s) "
             f"were blocked by the non-destructive contract and recorded as resilience objectives. "
             f"This was an authorized, non-destructive emulation — no data was harmed.")
    L.append("")

    L.append("## ATT&CK Tactic Coverage")
    L.append("")
    L.append("| # | Tactic | Emulated |")
    L.append("|---|--------|----------|")
    for i, tac in enumerate(cat.TACTICS, 1):
        mark = "yes" if tac in covered else "-"
        L.append(f"| {i} | {_TACTIC_LABEL.get(tac, tac)} | {mark} |")
    L.append("")

    L.append("## Kill-Chain Walk")
    L.append("")
    for s in run.get("steps", []):
        flag = "EMULATED" if s["status"] == "emulated" else "BLOCKED"
        L.append(f"### {s['seq']}. [{s['id']}] {s['name']}  — {_TACTIC_LABEL.get(s['tactic'], s['tactic'])}  ({flag})")
        L.append(f"- Action: {s['note']}")
        L.append(f"- Detection: {s['detection']}")
        L.append("")

    blocked_steps = [s for s in run.get("steps", []) if s["status"] == "blocked"]
    if blocked_steps:
        L.append("## Blocked (destructive) objectives — detect & build resilience")
        for s in blocked_steps:
            L.append(f"- [{s['id']}] {s['name']}: {s['detection']}")
        L.append("")

    L.append("## Detection Gaps & Recommendations")
    L.append("- Validate that each EMULATED technique above raised an alert in your SIEM/EDR; "
             "any that didn't is a detection gap to close.")
    L.append("- Prioritize controls for the tactics with the deepest emulated chain "
             "(initial access -> execution -> lateral movement).")
    L.append("- Confirm ransomware/DoS/exfil resilience for the BLOCKED objectives via "
             "tabletop + backup/restore tests (these were never executed).")
    L.append("")
    L.append("— Authorized adversary emulation. Non-destructive. For the in-scope targets only.")
    return "\n".join(L)
