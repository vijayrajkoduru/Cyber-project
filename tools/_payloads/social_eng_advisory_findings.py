"""social_eng_advisory - findings rules.

ALL findings are INFO with the [ADVISORY-BY-DESIGN] marker. These are the
phishing-playbook techniques (module_playbooks/26_phishing.md) that a SaaS
scanner cannot measure by inspecting the customer's public surface, because
they require attacker infrastructure, sending a lure to a human, a
post-compromise foothold, or creative/manual work.

ZERO-FALSE-POSITIVE / VA-not-PT rule: every rule here returns severity INFO.
None of them ever passes the playbook's planned attack severity through as a
finding severity. This is the honest boundary of external assessment, NOT a
forge gap and NOT a scaffold.
"""

_CWE_DESIGN = "CWE-1395"   # advisory-by-design marker (matches _pack_common)


def _advisory(title: str, evidence: str, remediation: str) -> dict:
    return {
        "name": f"[ADVISORY-BY-DESIGN] {title}",
        "severity": "INFO",
        "cvss": "0.0",
        "cwe": _CWE_DESIGN,
        "owasp": "N/A",
        "evidence": (
            "Advisory-by-design (NOT a forge gap): this technique cannot be "
            "assessed from an external SaaS scanner because it requires "
            "out-of-scope execution. " + evidence
        ),
        "remediation": remediation,
    }


def rule_email_delivery(s):
    if not s.get("advisory_emit"):
        return None
    return _advisory(
        "§1 mass/spear email delivery (GoPhish / SET / King Phisher / "
        "Phishery / attachment + .ics lures, AI-personalized content)",
        evidence=(
            "Actually SENDING a phishing email - and the GoPhish / "
            "Social-Engineer-Toolkit / King Phisher / Phishery infrastructure "
            "that does it - requires a sending IP, a collector backend, and a "
            "spoof domain the customer controls. VulnusLab does not send mail "
            "on a customer's behalf (that would also count against our own "
            "SPF/DMARC posture). The module instead AUDITS the defensive "
            "surface (spf_dkim_dmarc_audit, mta_sts_tls_audit) and GENERATES "
            "inert email templates (phishing_template_generate) for the "
            "customer's own authorized simulation tooling."
        ),
        remediation=(
            "Run the sending side on your own authorized simulation platform "
            "(GoPhish / KnowBe4 / Cofense). Defensively: deploy DMARC "
            "p=reject + DKIM + SPF -all (see the spf_dkim_dmarc_audit "
            "finding), strip risky attachments at the gateway (HTA/LNK/macro "
            "Office), and run recurring user-awareness training. MITRE ATT&CK "
            "T1566.001/.002."
        ),
    )


def rule_aitm(s):
    if not s.get("advisory_emit"):
        return None
    return _advisory(
        "§3 Adversary-in-the-Middle reverse-proxy phishing (EvilGinx2 / "
        "Modlishka / Muraena, session-cookie steal + replay, MFA / "
        "Conditional-Access bypass)",
        evidence=(
            "An AiTM attack runs a live reverse proxy in front of the real "
            "login page to relay credentials and steal the post-MFA session "
            "cookie. Standing up EvilGinx2/Modlishka/Muraena with a phishlet "
            "and a TLS cert for a spoof domain, then replaying a captured "
            "session, is attacker tradecraft against a victim - it cannot be "
            "performed by inspecting the customer's public surface, and "
            "VulnusLab never replays sessions or chains a captured token into "
            "another scanner."
        ),
        remediation=(
            "Defend against AiTM (which DEFEATS TOTP/push MFA): adopt "
            "phishing-resistant, origin-bound MFA (FIDO2 / passkeys / "
            "Windows Hello) so a relayed credential cannot complete sign-in; "
            "enable token-protection / continuous-access-evaluation and bind "
            "sessions to a compliant device + network in Conditional Access; "
            "shorten session lifetimes. The bitb_frameability_check and "
            "ct_log_lookalike_scan probes cover the externally-observable "
            "precursors. MITRE ATT&CK T1557 / T1606."
        ),
    )


def rule_smish_vish_quish(s):
    if not s.get("advisory_emit"):
        return None
    return _advisory(
        "§4 smishing / vishing / quishing delivery (Twilio/Plivo SMS gateway, "
        "VoIP + spoofed CLI, AI voice-clone calls, QR-code lures)",
        evidence=(
            "Sending SMS, placing spoofed-caller-ID voice calls, cloning a "
            "voice with ElevenLabs-class tooling, or printing a malicious QR "
            "all require an outbound telecom/voice channel and a target phone "
            "number list. These are delivery actions against humans on a "
            "side channel that has no relationship to the customer's web/DNS/"
            "mail surface, so a SaaS scanner cannot probe them. (Where a "
            "quishing/short URL is supplied, the open_redirect_probe can "
            "still check a redirect endpoint for off-site abuse.)"
        ),
        remediation=(
            "Defensively: enroll your numbers in STIR/SHAKEN call-"
            "authentication, train staff that IT/helpdesk will never ask for "
            "an OTP or password by phone/SMS, treat QR codes in email and "
            "print with the same scrutiny as links, and add a verification "
            "callback procedure for any 'urgent' financial request. MITRE "
            "ATT&CK T1566.002 (smishing) / social-engineering."
        ),
    )


def rule_oauth_consent_deploy(s):
    if not s.get("advisory_emit"):
        return None
    return _advisory(
        "§5 OAuth illicit-consent-grant / refresh-token abuse DELIVERY (the "
        "live consent lure + malicious app registration)",
        evidence=(
            "The oauth_tenant_exposure probe already enumerates the PUBLIC "
            "M365 OAuth surface (tenant, device-code endpoint, federation). "
            "The remaining step - registering a malicious multi-tenant app "
            "and delivering a consent lure so a victim clicks 'Accept', then "
            "abusing the refresh token - is an action against a victim and is "
            "advisory-by-design here. VulnusLab does not register apps, "
            "request tokens, or send consent lures."
        ),
        remediation=(
            "See the oauth_tenant_exposure finding for the concrete hardening "
            "(block user consent, require admin-consent workflow, restrict "
            "app registration, audit existing OAuth grants, block device-code "
            "flow via Conditional Access). MITRE ATT&CK T1528."
        ),
    )


def rule_deepfake(s):
    if not s.get("advisory_emit"):
        return None
    return _advisory(
        "§6 deepfake / AI-generated media (voice clone, face-swap video, "
        "deepfake CEO/BEC fraud, GoldPickaxe-class face-data theft, "
        "sock-puppet social profiles)",
        evidence=(
            "Producing a cloned voice, a face-swap video, or a synthetic "
            "social-media persona is content-creation tradecraft. It targets "
            "human trust, leaves no measurable trace on the customer's "
            "public infrastructure, and using it would be PT/red-team "
            "execution - so a VA scanner cannot probe it."
        ),
        remediation=(
            "Defend with PROCESS, not detection: enforce an out-of-band "
            "call-back + dual-authorization for any payment / wire / gift-card "
            "/ credential-reset request regardless of how convincing the "
            "voice or video is; establish challenge phrases for high-value "
            "approvals; train finance/HR/exec-assistant staff specifically on "
            "deepfake CEO-fraud (BEC) scenarios. MITRE ATT&CK T1656 "
            "(Impersonation)."
        ),
    )


def rule_campaign_mgmt(s):
    if not s.get("advisory_emit"):
        return None
    return _advisory(
        "§7 campaign management & metrics (GoPhish open/click/credential "
        "rates, multi-stage orchestration, per-finding ATT&CK mapping in the "
        "operator console)",
        evidence=(
            "Open-rate / click-rate / credential-capture tracking only exists "
            "once a campaign is actually RUNNING on the customer's own "
            "simulation platform - there is nothing on the customer's public "
            "surface for a scanner to measure. VulnusLab's role is the "
            "defensive audit + inert artifact generation, not running the "
            "operator's campaign console."
        ),
        remediation=(
            "Run campaign tracking inside your authorized simulation platform "
            "(GoPhish / KnowBe4 / Cofense). Feed click results into "
            "just-in-time micro-training rather than punitive action, rotate "
            "templates every cycle, and report click + reporter rates to "
            "leadership against the Verizon DBIR baseline. NIST SP 800-50r1."
        ),
    )


SOCIAL_ENG_ADVISORY_FINDING_RULES = [
    rule_email_delivery,
    rule_aitm,
    rule_smish_vish_quish,
    rule_oauth_consent_deploy,
    rule_deepfake,
    rule_campaign_mgmt,
]
