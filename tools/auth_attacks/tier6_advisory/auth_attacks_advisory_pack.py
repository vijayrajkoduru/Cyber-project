"""auth_attacks_advisory_pack - honest advisory-by-design coverage.

One scanner that enumerates every auth_attacks playbook technique which
CANNOT be detected from an external SaaS scanner, each as an
[ADVISORY-BY-DESIGN] INFO finding (vulnerable:false). This guarantees the
report reflects the full 7-section catalogue without ever passing a
playbook's PLANNED severity through as a real finding severity.

Covered (all INFO, never graded):
  §1 Pass-the-Hash / Pass-the-Ticket / Pass-the-Cert / Pass-the-Cookie /
     Pass-the-Token / Overpass-the-Hash  -> need stolen creds + LAN/host.
  §2 EvilGinx2 / Modlishka AiTM, BitB, MFA fatigue / push bombing,
     SMS-OTP SIM swap / intercept, device-code phishing -> human-targeted,
     out-of-band, social-engineering execution.
  §6 Kerberoasting, AS-REP roasting, unconstrained/constrained delegation,
     RBCD shadow creds, diamond/golden/silver tickets -> on-prem AD, needs
     a domain foothold.
  §4 SAML golden ticket (ADFS cert theft) -> post-compromise of the IdP host.

This scanner performs NO network I/O and NEVER chains into another scanner.
It is pure, deterministic INFO output.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()


class AuthAttacksAdvisoryPackRequest(ScanRequest):
    options: Optional[dict] = None


# (key, title, why-not-SaaS-probeable, cwe)
_ADVISORY_TECHNIQUES = [
    # --- §1 Pass-the-X ---
    ("pth_impacket",
     "Pass-the-Hash (impacket / crackmapexec / evil-winrm)",
     "Requires a previously-captured NTLM hash and SMB/WinRM LAN reachability to a domain host.",
     "CWE-294"),
    ("ptt_kerberos",
     "Pass-the-Ticket (Rubeus ptt / mimikatz)",
     "Requires an injected Kerberos TGT/TGS on a domain-joined host - a post-compromise action.",
     "CWE-294"),
    ("overpass_the_hash",
     "Overpass-the-Hash (Rubeus asktgt + ptt)",
     "Requires the user's NT hash and on-host execution to request a TGT.",
     "CWE-294"),
    ("pass_the_cert",
     "Pass-the-Cert (certificate-based auth abuse)",
     "Requires a stolen client/auth certificate and AD CS / PKINIT reachability.",
     "CWE-294"),
    ("pass_the_cookie",
     "Pass-the-Cookie (stolen browser session cookie)",
     "Requires post-compromise theft of a victim's browser session cookie from their endpoint.",
     "CWE-539"),
    ("pass_the_token",
     "Pass-the-Token (stolen cloud OIDC refresh/access token)",
     "Requires a token already exfiltrated from a victim device; replay is out-of-band.",
     "CWE-539"),
    # --- §2 MFA bypass via phishing / out-of-band ---
    ("aitm_evilginx",
     "Adversary-in-the-Middle phishing (EvilGinx2 / Modlishka) - session-cookie theft",
     "Requires standing up a reverse-proxy phishing site and a human clicking it - social "
     "engineering, not a target-side probe.",
     "CWE-1021"),
    ("bitb_phishing",
     "Browser-in-the-Browser (BitB) fake-SSO popup",
     "A client-side phishing UI trick delivered to victims; no server-side condition to probe.",
     "CWE-1021"),
    ("mfa_fatigue",
     "MFA fatigue / push bombing",
     "Generating real push prompts to a live user is an active DoS / harassment of the account "
     "owner - VulnusLab does not flood. Out of scope for safe VA.",
     "CWE-307"),
    ("sms_otp_sim_swap",
     "SMS-OTP SIM swap / interception",
     "Requires carrier-side SIM porting or device SMS-read permission - external to the app.",
     "CWE-287"),
    ("device_code_phishing",
     "OAuth device-code phishing",
     "Requires luring a victim to enter a device code; the abuse happens in the victim's "
     "browser, not on the target surface.",
     "CWE-1021"),
    # --- §6 Kerberos / on-prem AD ---
    ("kerberoasting",
     "Kerberoasting (GetUserSPNs) + AS-REP roasting (GetNPUsers)",
     "Requires an authenticated domain context and direct Kerberos (88/tcp) reachability to a "
     "Domain Controller on the internal network.",
     "CWE-294"),
    ("delegation_abuse",
     "Unconstrained / constrained delegation + RBCD (S4U, shadow credentials)",
     "Requires domain credentials and the ability to modify AD objects - an on-prem, "
     "authenticated operation.",
     "CWE-266"),
    ("golden_silver_ticket",
     "Golden / Silver / Diamond / Sapphire ticket forgery",
     "Requires the krbtgt or a service account hash already extracted from a compromised DC.",
     "CWE-294"),
    # --- §4 SAML golden ticket ---
    ("saml_golden_ticket",
     "SAML Golden Ticket (ADFS token-signing cert theft)",
     "Requires post-compromise extraction of the ADFS token-signing private key from the IdP "
     "host.",
     "CWE-347"),
]


async def gather(ctx: ScanContext):
    # Pure advisory enumeration - no network, no chaining.
    ctx.state["advisory_count"] = len(_ADVISORY_TECHNIQUES)
    ctx.state["advisory_techniques"] = [t[0] for t in _ADVISORY_TECHNIQUES]
    ctx.source("advisory-by-design enumeration")


def _make_advisory_rule(key, title, reason, cwe):
    def _rule(s):
        return {
            "name": f"[ADVISORY-BY-DESIGN] {title}",
            "severity": "INFO",
            "cvss": "0.0",
            "cwe": cwe,
            "owasp": "A07:2021",
            "evidence": (
                f"This technique cannot be detected from an external SaaS scanner. {reason} "
                "It is reported as advisory-by-design (NOT a forge gap and NOT a confirmed "
                "vulnerability on this target)."
            ),
            "remediation": (
                "Validate this control via an authenticated internal assessment / red-team "
                "engagement per playbook 17_auth_attacks.md. Detection-only SaaS scanning "
                "intentionally does not execute it."
            ),
        }
    return _rule


AUTH_ATTACKS_ADVISORY_PACK_FINDING_RULES = [
    _make_advisory_rule(k, t, r, c) for (k, t, r, c) in _ADVISORY_TECHNIQUES
]


INTEL_FIELDS = [
    ("Advisory techniques", "advisory_techniques"),
    ("Advisory count",      "advisory_count"),
]


@router.post("/api/auth_attacks/auth_attacks_advisory_pack")
async def auth_attacks_advisory_pack(req: AuthAttacksAdvisoryPackRequest,
                                     _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="auth_attacks_advisory_pack",
        gather_func=_gather_with_options,
        finding_rules=AUTH_ATTACKS_ADVISORY_PACK_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
