"""red_team_advisory_pack - honest advisory-by-design INFO catalogue for the
adversary-emulation / red-team playbook techniques that CANNOT be detected
from an external, unauthenticated SaaS VA scan (module_playbooks/27_red_team.md).

This scanner performs NO exploitation and NO authentication. It optionally
does ONE benign HTTP GET to record that the target is reachable, then emits
one INFO finding per advisory technique-group. Every emitted finding is
INFO with an [ADVISORY-BY-DESIGN] marker — the planned playbook severity (if
the technique were exercised on a real engagement) is recorded in the
remediation text ONLY and is NEVER used as a finding severity. This guarantees
the report can never show a fabricated graded severity for a technique we did
not actually verify (zero false positives — HARD RULE #1).

For each group we name the matching REAL probe in this module (or the manual /
on-host procedure) so the customer knows exactly how to close the gap.

Customer input:
  - ScanRequest.target = informational label only (one benign GET, no attacks).
  - options.headers    = optional extra request headers for the reachability GET.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()

_ADV_PREFIX = "[ADVISORY-BY-DESIGN] "

# Each entry: (key, title, playbook_refs, planned_sev, why_advisory,
#              how_to_close, cwe)
# `planned_sev` is INFORMATIONAL ONLY — never the finding severity.
ADVISORY_TECHNIQUES: list[tuple] = [
    # ── §1 Adversary Emulation Plans ──
    ("emulation_plans",
     "Adversary Emulation Plan design (ATT&CK Navigator coverage, MITRE "
     "Adversary Emulation Library APT29/FIN6, custom plan builder, scope/ROE, "
     "ROP, pre-engagement threat modelling, reporting template)",
     "§1 #1-#10", "INFO",
     "Emulation-plan authoring and scoping are analyst-driven planning "
     "artifacts (ATT&CK layers, ROE documents, threat models). They are not "
     "an observable property of a remote target.",
     "The mitre_attack_simulation_summary probe generates the ATT&CK Navigator "
     "layer for techniques this module exercises. Plan/ROE/threat-model "
     "authoring is delivered as a manual engagement.",
     "CWE-1059"),

    # ── §2 Atomic Red Team (on-host execution) ──
    ("atomic_onhost",
     "Atomic Red Team test execution across Windows / Linux / macOS "
     "(invoke-atomicredteam, per-technique YAML, T1059/T1055/T1003/T1078/"
     "T1547/T1110/T1190/T1566/T1486 atomics, custom atomic runner)",
     "§2 #11-#24", "INFO",
     "Atomic Red Team tests EXECUTE code on the endpoint (process injection, "
     "credential-dumping, ransomware-impact simulation). That requires host "
     "credentials and on-host execution — it is active emulation on a "
     "customer-owned host, not a remote black-box check. T1055/T1003/T1486 "
     "in particular touch memory/data and must never be run blind.",
     "The atomic_red_team_runner probe runs a LOW-risk subset of Atomic tests "
     "over SSH/WinRM when you supply options.atomic_user + credentials and a "
     "NON-PROD lab host. Full ransomware-impact (T1486) and process-injection "
     "(T1055) atomics stay manual + scoped on isolated hosts.",
     "CWE-1395"),

    # ── §3 MITRE CALDERA operations (on-host agents) ──
    ("caldera_ops",
     "MITRE CALDERA operations (server setup, Sandcat/Manx/Ragdoll agent "
     "deployment, autonomous + guided operations, planner ability-chaining, "
     "adversary profiles, ability authoring, Atomic integration)",
     "§3 #25-#34", "INFO",
     "Running a CALDERA operation deploys an autonomous agent on the "
     "endpoint and chains real ATT&CK abilities (post-foothold execution). It "
     "needs an installed agent + operator server inside the customer estate — "
     "out of scope for an external VA scan, and it is active emulation.",
     "An EXPOSED CALDERA operator UI is detected live by the "
     "detection_tooling_exposure probe (tier3_c2_infra). Operating CALDERA "
     "against your own hosts is a manual, scoped purple-team engagement.",
     "CWE-1395"),

    # ── §4 C2 frameworks (active operation) — exposure IS probed live ──
    ("c2_operation",
     "C2-framework OPERATION (Cobalt Strike, Sliver, Havoc, Mythic, Brute "
     "Ratel, Empire, Metasploit, Merlin beacon ops; Malleable/domain-fronting "
     "profiles; multi-stage Donut+Sliver; EDR-aware C2 selection)",
     "§4 #35-#48", "INFO",
     "Beaconing a live implant, building Malleable-C2 profiles, abusing CDNs "
     "for domain-fronting, and staging Donut shellcode are active "
     "command-and-control operations against a compromised host. VulnusLab is "
     "VA, not PT — it never establishes C2 or runs an implant.",
     "EXTERNAL EXPOSURE of a C2 team-server / operator console (Cobalt Strike, "
     "Sliver, Mythic, Empire, Havoc, Metasploit, Merlin) IS detected live + "
     "graded by the c2_framework_exposure probe. The c2_beacon_test probe "
     "exercises a benign beacon pattern against a customer-OWNED receiver for "
     "SIEM validation. Running an actual C2 operation is a manual engagement.",
     "CWE-1395"),

    # ── §5 Initial Access simulation (delivery / social) ──
    ("initial_access",
     "Initial-Access simulation (GoPhish+AiTM phishing, macro/HTA/LNK "
     "delivery, watering-hole, trusted-vendor + supply-chain compromise sim, "
     "hardware/USB drop, drive-by, cloud-account compromise sim, pretext build)",
     "§5 #49-#58", "INFO",
     "These require sending real lures to real users, building weaponised "
     "documents, dropping hardware on-site, or compromising a cloud account — "
     "social-engineering and active-access operations that depend on the "
     "customer's people, mail flow, and physical estate. They cannot and must "
     "not be launched from a remote scanner.",
     "An EXPOSED GoPhish admin console IS detected live by the "
     "c2_framework_exposure probe. Authorised phishing simulations, payload "
     "delivery, and hardware drops are delivered as a manual, consent-gated "
     "engagement using the customer's own GoPhish/AiTM infrastructure.",
     "CWE-1395"),

    # ── §6 Detection-engineering validation (SIEM-internal) ──
    ("detection_engineering",
     "Detection-engineering validation (Sigma/Splunk-SPL/Sentinel-KQL/"
     "CrowdStrike/SentinelOne-STAR/Elastic/YARA rule coverage, "
     "detection-as-code via Panther/Anvilogic, gap analysis)",
     "§6 #59-#68", "INFO",
     "Measuring rule coverage and authoring detection-as-code happen INSIDE "
     "the customer's SIEM/EDR with privileged console access to the detection "
     "content and telemetry. There is no external signal for whether a Sigma/"
     "KQL/STAR rule fired.",
     "The LOUD-signal probes (atomic_red_team_runner, c2_beacon_test, "
     "exfil_dns_simulation, lateral_pivot_signal_check) emit known TTP "
     "telemetry against customer-owned receivers so you can confirm your rules "
     "fired; mitre_attack_simulation_summary maps coverage to ATT&CK. EXPOSED "
     "SIEM consoles are detected live by detection_tooling_exposure. Rule "
     "authoring itself is done in your SIEM as a manual purple-team task.",
     "CWE-778"),

    # ── §7 Purple-teaming workflow (joint blue/red) ──
    ("purple_team",
     "Purple-teaming workflow (joint red-blue exercise design, SIEM event "
     "correlation review, EDR alert tuning, coverage heat-map, MTTD/MTTR "
     "measurement, lessons-learned, remediation roadmap)",
     "§7 #69-#76", "INFO",
     "Purple-teaming is a collaborative blue-team exercise: tuning alerts, "
     "measuring mean-time-to-detect/respond, and building remediation roadmaps "
     "require live access to the customer's SOC tooling and people. These are "
     "process/metric outcomes, not remotely-observable conditions.",
     "The detection-validation probes provide the red-side signal for a purple "
     "exercise and mitre_attack_simulation_summary provides the coverage "
     "heat-map JSON. MTTD/MTTR measurement, alert tuning, and the roadmap are "
     "delivered jointly with the customer SOC as a manual engagement.",
     "CWE-1059"),

    # ── §8 Threat-actor TTP emulation (active chains) ──
    ("threat_actor_emulation",
     "Threat-actor TTP emulation (APT28, APT29, Lazarus, FIN7/FIN8, Conti/"
     "LockBit, Volt Typhoon, Cl0p/BlackCat, Akira, Scattered Spider; custom "
     "actor profiles; threat-intel-driven + TIBER-EU/CBEST engagements)",
     "§8 #77-#88", "INFO",
     "Emulating a named threat actor chains that actor's real techniques "
     "(initial access -> persistence -> credential access -> lateral movement "
     "-> impact, including ransomware emulation) end-to-end against the "
     "customer estate. This is full active adversary emulation with a "
     "post-foothold position — strictly a manual, scoped PT/red-team "
     "engagement, never a remote VA scan. Chaining one technique into the next "
     "is explicitly out of scope (VA, not PT).",
     "Individual TTP signals (credential-access, lateral, exfil, C2 beacon) "
     "are exercised in isolation by the tier1/tier2 probes against "
     "customer-owned receivers for detection validation. Full actor-chain "
     "emulation and TIBER-EU/CBEST engagements are delivered as a manual, "
     "regulator-aligned red-team engagement.",
     "CWE-1395"),
]


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    ctx.state["rt_advisory_count"] = len(ADVISORY_TECHNIQUES)
    ctx.state["rt_advisory_groups"] = [t[0] for t in ADVISORY_TECHNIQUES]

    if not target:
        ctx.state["rt_advisory_reachable_status"] = None
        ctx.source("advisory-by-design catalogue (no target)")
        return

    probe_url = target
    if not probe_url.startswith(("http://", "https://")):
        probe_url = "https://" + probe_url

    reachable = None
    try:
        import httpx
        opts = getattr(ctx, "options", None) or {}
        extra = opts.get("headers") if isinstance(opts, dict) else None
        headers = {"User-Agent": "VulnusLab/RedTeam-Advisory"}
        if isinstance(extra, dict):
            for k, v in extra.items():
                try:
                    headers[str(k)] = str(v)
                except Exception:
                    continue
        async with httpx.AsyncClient(verify=False, timeout=10,
                                     follow_redirects=True) as client:
            r = await client.get(probe_url, headers=headers)
            reachable = r.status_code
    except Exception:
        reachable = None

    ctx.state["rt_advisory_target"] = probe_url
    ctx.state["rt_advisory_reachable_status"] = reachable
    ctx.source("advisory-by-design catalogue")


def _make_advisory_rule(key, title, refs, planned_sev, why, how, cwe):
    def _rule(s):
        return {
            "name": _ADV_PREFIX + title,
            "severity": "INFO",          # ALWAYS INFO — never the planned severity
            "cvss": "0.0",
            "cwe": cwe,
            "owasp": "N/A",
            "evidence": (
                f"Playbook {refs}. This adversary-emulation technique-group is "
                "advisory-by-design (NOT a forge gap): it cannot be safely or "
                "honestly detected from an external, unauthenticated VA scan. "
                + why + " No live attack was performed and NO vulnerability is "
                "asserted (vulnerable:false)."
            ),
            "remediation": (
                f"Planned engagement severity if exercised on-site: {planned_sev} "
                "(informational only — NOT a finding severity). How to close the "
                f"gap: {how} VulnusLab performs vulnerability assessment (VA), "
                "not active exploitation (PT); it never chains techniques. See "
                f"module_playbooks/27_red_team.md {refs}."
            ),
        }
    _rule.__name__ = f"rule_advisory_{key}"
    return _rule


RED_TEAM_ADVISORY_PACK_FINDING_RULES = [
    _make_advisory_rule(*t) for t in ADVISORY_TECHNIQUES
]


INTEL_FIELDS = [
    ("Target",                        "rt_advisory_target"),
    ("Reachable (HTTP status)",       "rt_advisory_reachable_status"),
    ("Advisory-by-design groups",     "rt_advisory_count"),
    ("Groups",                        "rt_advisory_groups"),
]


class RedTeamAdvisoryRequest(ScanRequest):
    options: Optional[dict] = None


@router.post("/api/red_team/red_team_advisory_pack")
async def red_team_red_team_advisory_pack(req: RedTeamAdvisoryRequest,
                                          _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        ctx.options = req.options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="red_team_advisory_pack",
        gather_func=_gather,
        finding_rules=RED_TEAM_ADVISORY_PACK_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
