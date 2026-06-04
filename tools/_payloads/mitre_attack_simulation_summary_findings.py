"""mitre_attack_simulation_summary - findings rules.

Severity model:
  INFO     - Navigator layer + coverage matrix (informational artifact)
  POSITIVE - customer confirmed detection of >=80% techniques exercised
"""


def rule_navigator_layer(s):
    total = int(s.get("mitre_summary_total") or 0)
    if not total:
        return None
    layer_json = s.get("mitre_summary_navigator_json") or "{}"
    detected = int(s.get("mitre_summary_detected") or 0)
    undetected = int(s.get("mitre_summary_undetected") or 0)
    layer_name = s.get("mitre_summary_layer_name") or "VL Red Team"
    coverage = s.get("mitre_summary_coverage") or []
    size_kb = s.get("mitre_summary_navigator_size_kb") or 0

    # Cap layer JSON evidence at 6 KB so PDF doesn't blow up
    evidence_layer = layer_json if len(layer_json) <= 6000 else (layer_json[:6000] + "\n... [TRUNCATED, full layer in artifact]")
    tactic_breakdown = ", ".join(
        f"{c['tactic']}={c['techniques_exercised']}" for c in coverage
    )

    return {
        "name": (f"MITRE ATT&CK Navigator rollup: {total} technique(s) exercised "
                  f"across red_team module; {detected} confirmed-detected, "
                  f"{undetected} unverified"),
        "severity": "INFO",
        "cwe": "CWE-693",
        "owasp": "A09:2021",
        "evidence": (
            f"Layer name: {layer_name} (size {size_kb} KB). "
            f"Tactic coverage: {tactic_breakdown}. "
            "Customer can paste the JSON below into "
            "https://mitre-attack.github.io/attack-navigator/ "
            "(File -> Open Existing Layer -> Paste). Techniques in green were "
            "reported as detected by the customer SIEM; orange = unverified.\n\n"
            "===== ATT&CK Navigator Layer JSON =====\n"
            f"{evidence_layer}\n"
            "===== END Layer JSON ====="
        ),
        "remediation": (
            "1. Open the Navigator UI, paste the JSON layer. "
            "2. For each orange (unverified) technique, query your SIEM for "
            "events in the test window; if no alert, that technique = detection "
            "gap (priority Sigma-rule build). "
            "3. Use the layer in your monthly purple-team review — track "
            "month-over-month detection coverage as a trendline metric. "
            "4. Re-run this scanner with options.expected_detected='T1003.001,"
            "T1059.001,...' to lock in techniques whose detection you've "
            "verified — those flip green in the next run."
        ),
        "mitre_techniques": [t.get("id") for t in (s.get("mitre_summary_techniques") or [])][:20],
        "references": [
            "https://mitre-attack.github.io/attack-navigator/",
            "https://attack.mitre.org/",
            "https://github.com/center-for-threat-informed-defense/adversary_emulation_library",
        ],
    }


def rule_no_includes(s):
    if not s.get("mitre_summary_no_includes"):
        return None
    return {
        "name": "MITRE ATT&CK summary skipped - all include_* flags set false",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": ("All four include flags (include_atomic / include_c2 / "
                     "include_exfil / include_lateral) were false, so no "
                     "techniques were rolled into the layer."),
        "remediation": (
            "Re-run without explicit include_*=false, or set at least one to "
            "true. Most useful: leave all four at default (true) to get the "
            "full red_team module coverage map."
        ),
    }


def rule_positive_coverage(s):
    detected = int(s.get("mitre_summary_detected") or 0)
    total = int(s.get("mitre_summary_total") or 0)
    if not total or not detected:
        return None
    pct = (detected / total) * 100
    if pct < 80:
        return None
    return {
        "name": (f"Strong detection coverage: customer SIEM verified detection of "
                  f"{detected}/{total} techniques ({round(pct)}%)"),
        "severity": "POSITIVE",
        "evidence": (
            f"Customer supplied options.expected_detected covering "
            f"{round(pct)}% of techniques exercised by this module. "
            "This is above industry benchmark (Optiv 2024 purple-team report: "
            "median detection coverage = 47%)."
        ),
        "remediation": (
            "Maintain the cadence. Add the remaining undetected techniques to "
            "the detection-engineering backlog. Aim for 90%+ on quarterly cycles."
        ),
        "cwe": "CWE-693",
        "owasp": "A09:2021",
    }


MITRE_ATTACK_SIMULATION_SUMMARY_FINDING_RULES = [
    rule_navigator_layer,
    rule_no_includes,
    rule_positive_coverage,
]
