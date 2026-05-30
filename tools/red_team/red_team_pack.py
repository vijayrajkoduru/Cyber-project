"""§27 Red Team / Adversary Emulation — 88 endpoints under /api/red_team/<tool>.

MITRE ATT&CK Enterprise + Caldera + Atomic Red Team + TIBER-EU / CBEST.
Rendered as structured advisories — each entry is a documented emulation
primitive with MITRE technique mapping + defender detection guidance.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding

router = APIRouter()


def _adv(tool, target, title, *, sev="MEDIUM", cvss="5.0", cwe="CWE-1395",
         remediation="See module_playbooks/27_red_team.md.",
         evidence="Advisory — adversary-emulation primitive."):
    return {"tool":tool,"target":target,"scan_time":0,
            "vulnerable": sev in ("CRITICAL","HIGH","MEDIUM"),
            "severity": sev,
            "findings":[wrap_finding(title, sev, cvss=cvss, cwe=cwe, owasp="A05:2021",
                remediation=remediation, evidence_marker=evidence)],
            "tests_performed":1, "tests_summary":title[:80], "raw_data":{}}


TECHNIQUES = [
    # §1 Adversary Emulation Plans (10)
    ("mitre_navigator_coverage", "MITRE ATT&CK Navigator coverage map.", "INFO", "0.0"),
    ("mitre_emulation_library",  "MITRE Adversary Emulation Library (APT29, FIN6).", "INFO", "0.0"),
    ("custom_emulation_plan",    "Custom emulation plan builder.", "INFO", "0.0"),
    ("scenario_engagement_design","Scenario-based engagement design.", "INFO", "0.0"),
    ("rt_scope_roe_doc",         "Engagement scope + Rules of Engagement document.", "INFO", "0.0"),
    ("rt_operating_procedure",   "Red Team Operating Procedure.", "INFO", "0.0"),
    ("pre_engagement_modeling",  "Pre-engagement threat modeling.", "INFO", "0.0"),
    ("post_engagement_report",   "Post-engagement reporting template.", "INFO", "0.0"),
    ("manual_scenario_design",   "Manual creative scenario design.", "INFO", "0.0"),
    ("manual_threat_actor_select","Manual threat-actor selection.", "INFO", "0.0"),

    # §2 Atomic Red Team Tests (14)
    ("invoke_atomic_windows",    "invoke-atomicredteam (Windows).", "MEDIUM", "5.0"),
    ("atomic_red_team_linux",    "Atomic Red Team Linux.", "MEDIUM", "5.0"),
    ("atomic_macos_tests",       "macOS atomic tests.", "MEDIUM", "5.0"),
    ("per_technique_yaml_auto",  "Per-technique YAML automation.", "INFO", "0.0"),
    ("atomic_t1059",             "T1059 Command and Scripting Interpreter.", "MEDIUM", "5.5"),
    ("atomic_t1055",             "T1055 Process Injection.", "HIGH", "7.0"),
    ("atomic_t1003",             "T1003 OS Credential Dumping.", "HIGH", "8.0"),
    ("atomic_t1078",             "T1078 Valid Accounts.", "MEDIUM", "5.5"),
    ("atomic_t1547",             "T1547 Boot/Logon Autostart.", "MEDIUM", "5.5"),
    ("atomic_t1110",             "T1110 Brute Force.", "MEDIUM", "5.5"),
    ("atomic_t1190",             "T1190 Exploit Public-Facing App.", "HIGH", "7.5"),
    ("atomic_t1566",             "T1566 Phishing.", "MEDIUM", "5.5"),
    ("atomic_t1486_ransom_sim",  "T1486 Data Encrypted for Impact (ransomware sim).", "HIGH", "8.0"),
    ("custom_atomic_runner",     "Custom atomic-test runner.", "INFO", "0.0"),

    # §3 MITRE Caldera Operations (10)
    ("caldera_server_setup",     "Caldera server setup.", "INFO", "0.0"),
    ("caldera_agent_deploy",     "Caldera agent deployment (Sandcat, Manx, Ragdoll).", "MEDIUM", "5.0"),
    ("caldera_op_autonomous",    "Caldera operation autonomous.", "MEDIUM", "5.0"),
    ("caldera_op_manual",        "Caldera operation manual (guided).", "INFO", "0.0"),
    ("caldera_planner",          "Caldera planner (chaining abilities).", "INFO", "0.0"),
    ("caldera_profiles",         "Caldera adversary profiles.", "INFO", "0.0"),
    ("caldera_abilities_audit",  "Caldera abilities library audit.", "INFO", "0.0"),
    ("custom_ability_yaml",      "Custom ability YAML authoring.", "INFO", "0.0"),
    ("caldera_atomic_integ",     "Caldera + Atomic integration.", "INFO", "0.0"),
    ("manual_emulation_refine",  "Manual emulation refinement.", "INFO", "0.0"),

    # §4 C2 Frameworks (14)
    ("cobalt_strike_industry",   "Cobalt Strike (commercial, industry std).", "HIGH", "7.5"),
    ("sliver_c2",                "⭐ Sliver C2 (open-source, fastest growing).", "HIGH", "7.5"),
    ("havoc_framework",          "⭐ Havoc framework.", "HIGH", "7.5"),
    ("mythic_modular_python",    "⭐ Mythic (modular Python C2).", "HIGH", "7.5"),
    ("brute_ratel_c4",           "⭐ Brute Ratel C4 (premium EDR-evading).", "HIGH", "7.5"),
    ("empire_starkiller",        "Empire / Starkiller (PowerShell C2).", "HIGH", "7.0"),
    ("metasploit_legacy_c2",     "Metasploit (legacy, still used).", "MEDIUM", "5.5"),
    ("merlin_http2_http3",       "Merlin (Go, HTTP/2 + HTTP/3).", "HIGH", "7.0"),
    ("manual_c2_channel_design", "⭐ Manual C2 channel design.", "INFO", "0.0"),
    ("custom_malleable_c2",      "⭐ Custom Malleable C2 profile.", "HIGH", "7.5"),
    ("manual_domain_fronting",   "⭐ Manual Domain Fronting (CDN abuse).", "HIGH", "7.5"),
    ("manual_c2_chain",          "⭐ Manual creative C2 chain.", "INFO", "0.0"),
    ("multistage_donut_sliver",  "⭐ Multi-stage agent (Donut + Sliver).", "HIGH", "7.5"),
    ("manual_edr_aware_c2",      "Manual EDR-aware C2 selection.", "INFO", "0.0"),

    # §5 Initial Access Simulation (10)
    ("phishing_gophish_aitm",    "Phishing campaign (GoPhish + AiTM).", "HIGH", "8.0"),
    ("macro_hta_lnk_delivery",   "Macro / HTA / LNK delivery.", "HIGH", "7.5"),
    ("watering_hole_design",     "Watering-hole attack design.", "HIGH", "7.5"),
    ("trusted_vendor_compromise","Trusted-vendor compromise simulation.", "HIGH", "7.5"),
    ("supply_chain_sim",         "Supply-chain compromise sim.", "HIGH", "7.5"),
    ("hw_drop_usb_cable",        "Hardware drop (USB / cable).", "MEDIUM", "5.5"),
    ("drive_by_download",        "Drive-by download.", "HIGH", "7.0"),
    ("cloud_account_compromise", "⭐ Cloud-account compromise sim.", "HIGH", "7.5"),
    ("manual_initial_access",    "Manual creative initial access.", "INFO", "0.0"),
    ("manual_pretext_build_5",   "Manual creative pretext build.", "INFO", "0.0"),

    # §6 Detection Engineering Validation (10)
    ("sigma_rule_coverage",      "Sigma rule coverage.", "INFO", "0.0"),
    ("splunk_spl_detection",     "Splunk SPL detection coverage.", "INFO", "0.0"),
    ("sentinel_kql_detection",   "Microsoft Sentinel KQL detection.", "INFO", "0.0"),
    ("falcon_detection_coverage","CrowdStrike Falcon detection coverage.", "INFO", "0.0"),
    ("s1_star_rule",             "SentinelOne STAR rule coverage.", "INFO", "0.0"),
    ("elastic_siem_detection",   "Elastic SIEM detection coverage.", "INFO", "0.0"),
    ("yara_rule_coverage",       "YARA rule coverage.", "INFO", "0.0"),
    ("detection_as_code",        "Detection-as-code (Panther, Anvilogic).", "INFO", "0.0"),
    ("manual_detection_gap",     "Manual detection gap analysis.", "INFO", "0.0"),
    ("manual_evasion_to_detect", "Manual evasion → detection improvement.", "INFO", "0.0"),

    # §7 Purple Teaming Workflow (8)
    ("joint_red_blue_exercise",  "Joint red-blue exercise design.", "INFO", "0.0"),
    ("siem_event_correlation",   "SIEM event correlation review.", "INFO", "0.0"),
    ("edr_alert_tuning",         "EDR alert tuning.", "INFO", "0.0"),
    ("attack_navigator_heatmap", "Detection coverage heat-map (ATT&CK Navigator).", "INFO", "0.0"),
    ("mttd_measurement",         "Mean-time-to-detect (MTTD) measurement.", "INFO", "0.0"),
    ("mttr_measurement",         "Mean-time-to-respond (MTTR) measurement.", "INFO", "0.0"),
    ("manual_lessons_learned",   "Manual lessons-learned.", "INFO", "0.0"),
    ("manual_remediation_roadmap","Manual remediation roadmap.", "INFO", "0.0"),

    # §8 Threat Actor TTP Emulation (12) ⭐
    ("apt28_fancy_bear",         "⭐ APT28 (Fancy Bear) emulation.", "HIGH", "7.5"),
    ("apt29_cozy_bear",          "⭐ APT29 (Cozy Bear) emulation.", "HIGH", "7.5"),
    ("lazarus_group",            "⭐ Lazarus Group emulation.", "HIGH", "7.5"),
    ("fin7_fin8",                "⭐ FIN7 / FIN8 emulation.", "HIGH", "7.5"),
    ("conti_lockbit_ransomware", "⭐ Conti / LockBit ransomware emulation.", "HIGH", "8.0"),
    ("volt_typhoon_china_apt",   "⭐ Volt Typhoon / Chinese APT emulation.", "HIGH", "7.5"),
    ("cl0p_blackcat",            "⭐ Cl0p / BlackCat emulation.", "HIGH", "8.0"),
    ("akira_ransomware",         "⭐ Akira ransomware emulation.", "HIGH", "8.0"),
    ("scattered_spider_unc3944", "⭐ Scattered Spider (UNC3944) emulation.", "HIGH", "8.0"),
    ("manual_custom_actor_profile","⭐ Manual custom-actor profile build.", "INFO", "0.0"),
    ("manual_threat_intel_driven","⭐ Manual creative threat-intel-driven emulation.", "INFO", "0.0"),
    ("manual_tiber_cbest",       "⭐ Manual TIBER-EU / CBEST engagement.", "INFO", "0.0"),
]


def _make_handler(slug, title, sev, cvss):
    def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
        return _adv(slug, req.target, title, sev=sev, cvss=cvss)
    _h.__name__ = slug
    return _h


for slug, title, sev, cvss in TECHNIQUES:
    router.add_api_route(f"/api/red_team/{slug}", _make_handler(slug, title, sev, cvss),
                          methods=["POST"])


def register(app):
    app.include_router(router)
