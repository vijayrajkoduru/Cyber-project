"""§26 Phishing — 70 endpoints under /api/phishing/<tool>.

MITRE T1566 + SET canon + AiTM + 2024+ deepfake additions.
Most techniques require campaign infrastructure — rendered as structured
advisories. VL-FORGE 2026-05-30: 2 live probes for email-spoof posture
(SPF + DMARC DNS lookups). Other techniques correctly remain advisory
(campaign infra / requires victim interaction).
"""
import socket
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding

router = APIRouter()


def _adv(tool, target, title, *, sev="MEDIUM", cvss="5.0", cwe="CWE-1021",
         remediation="See module_playbooks/26_phishing.md.",
         evidence="Advisory — campaign-tier phishing technique."):
    return {"tool":tool,"target":target,"scan_time":0,
            "vulnerable": sev in ("CRITICAL","HIGH","MEDIUM"),
            "severity": sev,
            "findings":[wrap_finding(title, sev, cvss=cvss, cwe=cwe, owasp="A07:2021",
                remediation=remediation, evidence_marker=evidence)],
            "tests_performed":1, "tests_summary":title[:80], "raw_data":{}}


def _host(t):
    return t.split("://", 1)[-1].split("/")[0].split(":")[0].strip().lower() or t


def _dns_txt(domain: str) -> list:
    """Best-effort DNS TXT lookup. Returns list of strings."""
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=4)
            return [str(rdata).strip('"') for rdata in answers]
        except Exception:
            return []
    except ImportError:
        return []


def _probe_mailspoof(target, req):
    """SPF/DMARC posture check via live DNS TXT lookups."""
    domain = _host(target)
    spf_records = [t for t in _dns_txt(domain) if t.startswith("v=spf1")]
    dmarc_records = [t for t in _dns_txt(f"_dmarc.{domain}") if t.startswith("v=DMARC1")]
    findings = []
    # SPF analysis
    if not spf_records:
        findings.append(wrap_finding(
            "No SPF record — sender spoofing possible",
            "HIGH", cvss="7.5", cwe="CWE-290",
            remediation="Publish SPF record: v=spf1 include:... -all (strict)",
            evidence_marker=f"_dns_query TXT {domain} → no v=spf1"))
    else:
        spf = spf_records[0]
        if " -all" in spf:
            spf_strict = "strict (-all)"; sev = "POSITIVE"; cvss = "0.0"
        elif " ~all" in spf:
            spf_strict = "soft-fail (~all)"; sev = "MEDIUM"; cvss = "5.0"
        elif " ?all" in spf or " +all" in spf:
            spf_strict = "neutral or permit-all (DANGEROUS)"; sev = "HIGH"; cvss = "7.5"
        else:
            spf_strict = "no terminating qualifier"; sev = "MEDIUM"; cvss = "5.0"
        findings.append(wrap_finding(
            f"SPF record present — {spf_strict}",
            sev, cvss=cvss, cwe="CWE-290",
            remediation="Strict -all is recommended once SPF is fully populated.",
            evidence_marker=f"SPF: {spf[:150]}"))
    # DMARC analysis
    if not dmarc_records:
        findings.append(wrap_finding(
            "No DMARC record — receiving servers won't enforce SPF/DKIM alignment",
            "HIGH", cvss="7.5", cwe="CWE-290",
            remediation="Publish DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain (start at p=none then ramp up).",
            evidence_marker=f"_dns_query TXT _dmarc.{domain} → empty"))
    else:
        dmarc = dmarc_records[0]
        if "p=reject" in dmarc:
            sev = "POSITIVE"; cvss = "0.0"; status = "reject (strongest)"
        elif "p=quarantine" in dmarc:
            sev = "LOW"; cvss = "3.0"; status = "quarantine (medium)"
        elif "p=none" in dmarc:
            sev = "MEDIUM"; cvss = "5.0"; status = "none (monitor-only)"
        else:
            sev = "MEDIUM"; cvss = "5.0"; status = "no p= policy"
        findings.append(wrap_finding(
            f"DMARC policy: {status}",
            sev, cvss=cvss, cwe="CWE-290",
            remediation="Ramp p=none → p=quarantine → p=reject as confidence grows.",
            evidence_marker=f"DMARC: {dmarc[:150]}"))
    sev_top = "INFO"
    sev_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0,"POSITIVE":0}
    for f in findings:
        if sev_order.get(f.get("severity","INFO"),0) > sev_order.get(sev_top,0):
            sev_top = f.get("severity","INFO")
    return {"tool":"mailspoof_spoofcheck","target":target,"scan_time":0,
            "vulnerable": sev_top in ("CRITICAL","HIGH","MEDIUM"),
            "severity": sev_top, "findings": findings,
            "tests_performed": 2, "tests_summary": "SPF + DMARC live DNS check",
            "raw_data": {"spf": spf_records, "dmarc": dmarc_records}}


def _probe_spf_dkim_dmarc_bypass(target, req):
    """Same as mailspoof but reports under the bypass slug for parity."""
    r = _probe_mailspoof(target, req)
    return r | {"tool": "spf_dkim_dmarc_bypass"}


PROBES = {
    "mailspoof_spoofcheck":   _probe_mailspoof,
    "spf_dkim_dmarc_bypass":  _probe_spf_dkim_dmarc_bypass,
}


TECHNIQUES = [
    # §1 Email Phishing Mass + Spear (14)
    ("gophish_campaign_setup",   "GoPhish campaign setup.", "MEDIUM", "5.0"),
    ("set_toolkit",              "SET (Social-Engineer Toolkit).", "MEDIUM", "5.0"),
    ("king_phisher",             "King Phisher campaign manager.", "MEDIUM", "5.0"),
    ("phishery_office_basic_auth","Phishery (Office basic-auth harvest).", "HIGH", "7.0"),
    ("mailspoof_spoofcheck",     "Mailspoof / spoofcheck sender check.", "INFO", "0.0"),
    ("spf_dkim_dmarc_bypass",    "SPF / DKIM / DMARC bypass.", "HIGH", "7.5"),
    ("html_template_library",    "Email template library (HTML).", "INFO", "0.0"),
    ("ai_personalization_llm",   "AI-generated content (LLM) for personalization.", "MEDIUM", "5.5"),
    ("osint_linkedin_spear",     "Spear-phishing OSINT integration (LinkedIn).", "MEDIUM", "5.5"),
    ("attachment_macro_hta_lnk", "Attachment-based delivery (Office macro / HTA / LNK).", "HIGH", "7.5"),
    ("ics_calendar_invite_phish","Calendar invite (.ics) phishing.", "MEDIUM", "5.5"),
    ("manual_pretext_design",    "Manual creative pretext design (analyst).", "INFO", "0.0"),
    ("manual_victim_profile",    "Manual victim psychology profiling.", "INFO", "0.0"),
    ("manual_ab_testing",        "Manual A/B testing.", "INFO", "0.0"),

    # §2 Website Cloning / Credential Harvest (8)
    ("set_site_cloner",          "SET site cloner.", "MEDIUM", "5.5"),
    ("httrack_mirror",           "httrack site mirror.", "MEDIUM", "5.5"),
    ("gophish_landing",          "GoPhish landing page.", "MEDIUM", "5.5"),
    ("custom_react_collector",   "Custom React/HTML page with collector backend.", "MEDIUM", "5.5"),
    ("idn_homograph_punycode",   "IDN homograph (Punycode) lookalike domain.", "HIGH", "7.5"),
    ("typosquat_registration",   "Typo-squat domain registration.", "HIGH", "7.5"),
    ("open_redirect_abuse_phish","Open-redirect abuse for phishing.", "MEDIUM", "5.5"),
    ("manual_landing_ux",        "Manual landing-page UX tuning.", "INFO", "0.0"),

    # §3 AiTM (10)
    ("evilginx2_phishlets",      "EvilGinx2 reverse-proxy phishing (Phishlets).", "CRITICAL", "9.0"),
    ("modlishka",                "Modlishka reverse-proxy phishing.", "CRITICAL", "9.0"),
    ("muraena",                  "Muraena AiTM.", "CRITICAL", "9.0"),
    ("bitb_iframe",              "Browser-in-the-Browser (BitB) iframe.", "HIGH", "8.0"),
    ("custom_aitm_mitmproxy",    "Custom AiTM with mitmproxy.", "HIGH", "8.0"),
    ("session_cookie_replay",    "Session-cookie steal + replay.", "CRITICAL", "9.0"),
    ("mfa_bypass_via_aitm",      "MFA bypass via AiTM session capture.", "CRITICAL", "9.0"),
    ("conditional_access_bypass","Conditional Access bypass via stolen session.", "HIGH", "8.0"),
    ("manual_phishlet_custom",   "Manual AiTM Phishlet customization.", "INFO", "0.0"),
    ("manual_aitm_chain",        "Manual creative AiTM chain.", "INFO", "0.0"),

    # §4 Smishing / Vishing / Quishing (10)
    ("sms_smishing_bulk",        "SMS phishing bulk sender.", "MEDIUM", "5.5"),
    ("twilio_plivo_sms_gw",      "Twilio / Plivo / Bandwidth as SMS gateway.", "INFO", "0.0"),
    ("smishing_template_lib",    "Smishing template library.", "INFO", "0.0"),
    ("vishing_voip_spoof_cli",   "Vishing call setup (VoIP + spoofed CLI).", "MEDIUM", "5.5"),
    ("ai_voice_clone_vishing",   "AI voice-cloning vishing (ElevenLabs).", "HIGH", "7.5"),
    ("ivr_phone_tree_se",        "IVR / phone-tree social engineering.", "INFO", "0.0"),
    ("quishing_qr_redirect",     "Quishing (QR phishing) — qrcode + redirect.", "MEDIUM", "5.5"),
    ("quishing_printed_materials","Quishing in printed materials (poster).", "INFO", "0.0"),
    ("manual_vishing_persona",   "Manual vishing pretext / persona.", "INFO", "0.0"),
    ("manual_phone_chain",       "Manual creative phone chain.", "INFO", "0.0"),

    # §5 OAuth / App Consent Phishing (8)
    ("m365_oauth_consent_phish", "Microsoft 365 OAuth app consent phishing.", "HIGH", "8.0"),
    ("google_workspace_oauth",   "Google Workspace OAuth consent abuse.", "HIGH", "8.0"),
    ("custom_oauth_client_id",   "Custom OAuth client_id phishing.", "HIGH", "8.0"),
    ("refresh_token_abuse",      "Refresh-token abuse post-consent.", "HIGH", "7.5"),
    ("ms_device_code_phishing",  "Device code phishing (Microsoft).", "HIGH", "8.0"),
    ("illicit_consent_grant_t1528","Illicit consent grant (MITRE T1528).", "HIGH", "8.0"),
    ("manual_oauth_app_design",  "Manual OAuth app design.", "INFO", "0.0"),
    ("manual_consent_chain",     "Manual creative consent chain.", "INFO", "0.0"),

    # §6 Deepfake / AI-generated Content (10)
    ("ai_voice_clone_eleven",    "AI voice clone (ElevenLabs, Resemble).", "INFO", "0.0"),
    ("ai_faceswap_deepface",     "AI face-swap video (DeepFaceLab).", "INFO", "0.0"),
    ("ai_written_spear_phish",   "AI-written spear phish (GPT-4o, Claude).", "HIGH", "7.5"),
    ("deepfake_ceo_fraud_bec",   "Deepfake CEO fraud (BEC class).", "INFO", "0.0"),
    ("goldpickaxe_testflight",   "GoldPickaxe-class face data theft via TestFlight.", "INFO", "0.0"),
    ("ai_landing_page_html",     "AI-generated phishing landing page (LLM HTML).", "HIGH", "7.0"),
    ("auto_translated_phish",    "Auto-translated multilingual phish.", "MEDIUM", "5.5"),
    ("ai_sockpuppet_profile",    "AI-generated social profile (sock-puppet).", "MEDIUM", "5.5"),
    ("manual_deepfake_quality",  "Manual deepfake quality refinement.", "INFO", "0.0"),
    ("manual_ai_aug_se",         "Manual creative AI-augmented social-eng.", "INFO", "0.0"),

    # §7 Campaign Management & Reporting (10)
    ("gophish_tracking_pixels",  "GoPhish tracking pixels (open rate).", "INFO", "0.0"),
    ("gophish_click_rate",       "GoPhish click rate.", "INFO", "0.0"),
    ("credential_capture_rate",  "Credential capture rate (per phish).", "INFO", "0.0"),
    ("time_on_page_tracking",    "Time-on-page tracking.", "INFO", "0.0"),
    ("multistage_orchestration", "Multi-stage campaign orchestration.", "INFO", "0.0"),
    ("metrics_csv_json_export",  "Report metrics export (CSV/JSON).", "INFO", "0.0"),
    ("pdf_executive_report",     "PDF executive report.", "INFO", "0.0"),
    ("mitre_attack_per_finding", "MITRE ATT&CK technique mapping per finding.", "INFO", "0.0"),
    ("compliance_evidence",      "Compliance evidence collection.", "INFO", "0.0"),
    ("gdpr_dpdp_consent",        "GDPR / DPDP consent + retention compliance.", "INFO", "0.0"),
]


def _make_handler(slug, title, sev, cvss):
    def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
        return _adv(slug, req.target, title, sev=sev, cvss=cvss)
    _h.__name__ = slug
    return _h


def _make_probe_handler(slug, probe_fn):
    def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
        try:
            return probe_fn(req.target, req)
        except Exception as e:
            return _adv(slug, req.target, f"Probe error: {str(e)[:80]}",
                         sev="INFO", cvss="0.0")
    _h.__name__ = slug
    return _h


for slug, title, sev, cvss in TECHNIQUES:
    if slug in PROBES:
        router.add_api_route(f"/api/phishing/{slug}",
            _make_probe_handler(slug, PROBES[slug]), methods=["POST"])
    else:
        router.add_api_route(f"/api/phishing/{slug}",
            _make_handler(slug, title, sev, cvss), methods=["POST"])


def register(app):
    app.include_router(router)
