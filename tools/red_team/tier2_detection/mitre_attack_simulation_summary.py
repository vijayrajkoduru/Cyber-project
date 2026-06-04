"""mitre_attack_simulation_summary - MITRE ATT&CK Navigator rollup
   (playbook §1 #1 ATT&CK Navigator coverage + §7 #72 detection heat-map).

Generates a JSON ATT&CK Navigator layer file listing every MITRE technique
exercised by the red_team module (the 4 other scanners) + a coverage
matrix the customer can paste into their SIEM-detection-engineering
backlog.

Customer input via ScanRequest.options:
  - options.layer_name         - friendly name in the Navigator UI
                                  (default "VulnusLab Red Team Run <ts>")
  - options.attack_version     - "14" (default, latest supported v14.x)
  - options.include_atomic     - "true"/"false", include T-ids from atomic
                                  runner (default true)
  - options.include_c2         - include C2 beacon T-ids (default true)
  - options.include_exfil      - include exfil DNS T-ids (default true)
  - options.include_lateral    - include lateral pivot T-ids (default true)
  - options.expected_detected  - comma list of T-ids the customer's SIEM
                                  is supposed to detect (overlay scoring)

The output is rendered as INTEL fields + a single INFO finding with the
ATT&CK Navigator JSON layer as evidence. Customer can copy this JSON
into https://mitre-attack.github.io/attack-navigator/ to visualize.

This scanner does NOT make network calls; it's a deterministic rollup
of techniques exercised by tools 1-4 in this module. We hard-code the
technique list to match the other 4 probes' MITRE IDs.

MITRE techniques (reported, not exercised): TA0043 (Reconnaissance) /
N/A — this is a summary artifact.
"""
from __future__ import annotations
import json
import time
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.mitre_attack_simulation_summary_findings import (
    MITRE_ATTACK_SIMULATION_SUMMARY_FINDING_RULES,
)

router = APIRouter()


# Hard-coded technique map: which probe exercises which T-id.
# Format: (technique_id, technique_name, tactic, probe_source)
TECHNIQUE_MAP = {
    "atomic": [
        ("T1003.001", "OS Credential Dumping: LSASS Memory", "credential-access"),
        ("T1027.005", "Obfuscated Files or Information: Indicator Removal from Tools", "defense-evasion"),
        ("T1053.005", "Scheduled Task/Job: Scheduled Task",   "execution"),
        ("T1059.001", "Command and Scripting Interpreter: PowerShell", "execution"),
        ("T1059.004", "Command and Scripting Interpreter: Unix Shell", "execution"),
        ("T1082",     "System Information Discovery",        "discovery"),
        ("T1087.001", "Account Discovery: Local Account",    "discovery"),
        ("T1105",     "Ingress Tool Transfer",                "command-and-control"),
        ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control"),
        ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "persistence"),
    ],
    "c2": [
        ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control"),
        ("T1071.004", "Application Layer Protocol: DNS",      "command-and-control"),
        ("T1572",     "Protocol Tunneling",                   "command-and-control"),
        ("T1573.001", "Encrypted Channel: Symmetric Cryptography", "command-and-control"),
    ],
    "exfil": [
        ("T1071.004", "Application Layer Protocol: DNS",          "command-and-control"),
        ("T1048.003", "Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol", "exfiltration"),
        ("T1041",     "Exfiltration Over C2 Channel",             "exfiltration"),
    ],
    "lateral": [
        ("T1078",     "Valid Accounts",                       "defense-evasion"),
        ("T1550.002", "Use Alternate Authentication Material: Pass the Hash", "lateral-movement"),
        ("T1570",     "Lateral Tool Transfer",                "lateral-movement"),
        ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement"),
        ("T1021.006", "Remote Services: Windows Remote Management", "lateral-movement"),
    ],
}


def _build_navigator_layer(name: str, version: str,
                            techniques: list[tuple[str, str, str, list[str]]],
                            expected_detected: set[str]) -> dict:
    """Build a MITRE ATT&CK Navigator-compatible JSON layer."""
    technique_entries: list[dict] = []
    for t_id, t_name, tactic, sources in techniques:
        detected = t_id in expected_detected
        score = 100 if detected else 50  # detection coverage score
        color = "#7fc97f" if detected else "#fdc086"  # green if detected, orange if not
        technique_entries.append({
            "techniqueID": t_id,
            "tactic": tactic,
            "color": color,
            "score": score,
            "comment": (
                f"Exercised by VulnusLab probes: {', '.join(sources)}. "
                + ("Customer reports detected." if detected
                    else "Customer detection status: VERIFY.")
            ),
            "enabled": True,
            "metadata": [
                {"name": "probe_source", "value": ",".join(sources)},
                {"name": "vulnuslab_module", "value": "red_team"},
            ],
            "showSubtechniques": "." in t_id,
        })
    return {
        "name": name,
        "versions": {
            "attack":    version,
            "navigator": "4.9.1",
            "layer":     "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            "Auto-generated layer from VulnusLab red_team module. "
            "Techniques are coloured green if the customer reports their SIEM "
            "detected the test signal, orange if detection is unverified."
        ),
        "filters":     {"platforms": ["Windows", "Linux", "macOS", "Network"]},
        "sorting":     0,
        "layout":      {"layout": "side", "aggregateFunction": "average"},
        "hideDisabled": False,
        "techniques":  technique_entries,
        "gradient": {
            "colors":  ["#ffe766", "#7fc97f"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Customer SIEM detected", "color": "#7fc97f"},
            {"label": "Detection unverified",   "color": "#fdc086"},
        ],
        "metadata": [
            {"name": "generator", "value": "VulnusLab red_team module"},
            {"name": "generated_at", "value": str(int(time.time()))},
        ],
        "showTacticRowBackground":  False,
        "tacticRowBackground":      "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def _parse_bool(v, default: bool) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off", ""):
        return False
    return default


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    layer_name = (opts.get("layer_name")
                   or f"VulnusLab Red Team Run {int(time.time())}").strip()
    attack_version = (opts.get("attack_version") or "14").strip()
    include_atomic = _parse_bool(opts.get("include_atomic"),  True)
    include_c2 = _parse_bool(opts.get("include_c2"),      True)
    include_exfil = _parse_bool(opts.get("include_exfil"),   True)
    include_lateral = _parse_bool(opts.get("include_lateral"), True)
    expected_str = (opts.get("expected_detected") or "").strip()
    expected_set = {
        s.strip().upper() for s in expected_str.split(",") if s.strip()
    }

    # Merge technique map -> dedupe by T-id, track which sources hit each
    merged: dict[str, dict] = {}
    sources_for: dict[str, list[str]] = {}

    def _add(source_name: str):
        for t_id, t_name, tactic in TECHNIQUE_MAP[source_name]:
            sources_for.setdefault(t_id, []).append(source_name)
            if t_id not in merged:
                merged[t_id] = {
                    "id": t_id, "name": t_name, "tactic": tactic
                }

    if include_atomic: _add("atomic")
    if include_c2: _add("c2")
    if include_exfil: _add("exfil")
    if include_lateral: _add("lateral")

    techniques: list[tuple[str, str, str, list[str]]] = []
    for t_id, meta in sorted(merged.items()):
        srcs = sorted(set(sources_for.get(t_id, [])))
        techniques.append((t_id, meta["name"], meta["tactic"], srcs))

    if not techniques:
        ctx.state["mitre_summary_total"] = 0
        ctx.state["mitre_summary_no_includes"] = True
        ctx.source("no include_* set true")
        return

    navigator_layer = _build_navigator_layer(layer_name, attack_version,
                                              techniques, expected_set)
    navigator_json = json.dumps(navigator_layer, indent=2)

    # Coverage matrix: per-tactic counts
    by_tactic: dict[str, int] = {}
    for t in techniques:
        by_tactic[t[2]] = by_tactic.get(t[2], 0) + 1
    coverage_matrix = sorted(
        ({"tactic": k, "techniques_exercised": v} for k, v in by_tactic.items()),
        key=lambda x: -x["techniques_exercised"],
    )
    detected_count = sum(1 for t in techniques if t[0] in expected_set)
    not_detected_count = len(techniques) - detected_count

    # Build a flat list customer can read
    technique_list_display = [
        {
            "id": t[0],
            "name": t[1],
            "tactic": t[2],
            "exercised_by": t[3],
            "detected_by_customer_siem": t[0] in expected_set,
        }
        for t in techniques
    ]

    ctx.state["mitre_summary_layer_name"]   = layer_name
    ctx.state["mitre_summary_attack_ver"]   = attack_version
    ctx.state["mitre_summary_total"]        = len(techniques)
    ctx.state["mitre_summary_detected"]     = detected_count
    ctx.state["mitre_summary_undetected"]   = not_detected_count
    ctx.state["mitre_summary_techniques"]   = technique_list_display
    ctx.state["mitre_summary_coverage"]     = coverage_matrix
    ctx.state["mitre_summary_navigator_json"] = navigator_json
    ctx.state["mitre_summary_navigator_size_kb"] = round(len(navigator_json) / 1024, 1)
    ctx.source(f"ATT&CK Navigator rollup -> {len(techniques)} techniques across "
                f"{len(by_tactic)} tactics; detected={detected_count}/"
                f"{len(techniques)}; layer={round(len(navigator_json)/1024,1)} KB")


INTEL_FIELDS = [
    ("Layer name",                "mitre_summary_layer_name"),
    ("ATT&CK version",            "mitre_summary_attack_ver"),
    ("Techniques exercised",      "mitre_summary_total"),
    ("Detected by customer SIEM", "mitre_summary_detected"),
    ("Detection unverified",      "mitre_summary_undetected"),
    ("Coverage by tactic",        "mitre_summary_coverage"),
    ("Technique list",            "mitre_summary_techniques"),
    ("Navigator layer (JSON)",    "mitre_summary_navigator_json"),
    ("Layer size (KB)",           "mitre_summary_navigator_size_kb"),
]


class MitreAttackSummaryRequest(ScanRequest):
    options: Optional[dict] = None


@router.post("/api/red_team/mitre_attack_simulation_summary")
async def red_team_mitre_attack_simulation_summary(
    req: MitreAttackSummaryRequest, _=Depends(verify_scan_quota)
):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="mitre_attack_simulation_summary",
        gather_func=_gather_with_options,
        finding_rules=MITRE_ATTACK_SIMULATION_SUMMARY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
