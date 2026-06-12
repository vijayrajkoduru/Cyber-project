"""clientside_advisory_surface - honest advisory-by-design coverage of the
payload-craft / red-team-infrastructure / post-compromise techniques in
module_playbooks/09_client_side.md that CANNOT be probed from an external
SaaS VA scan.

The client-side playbook spans 7 sections / 72 techniques. The DOM/JS/
header surface (CSP, DOM-XSS sinks, postMessage, prototype pollution,
CORS, clickjacking, cross-origin isolation, Permissions-Policy, SRI,
Service Worker, open redirect) IS live-probeable and is implemented as
real graded scanners in tier1_dom / tier2_js. The remaining techniques —

  §1 BeEF browser-hook hosting + hook modules (webcam/clipboard/etc.)
  §2 Office macro / Excel-4.0 / OLE / DDE / OneNote / ISO payload craft
  §3 HTA payload generation + mshta execution chains
  §4 LNK / .url shortcut abuse + Mark-of-the-Web bypass
  §5 browser 0-day / CVE / sandbox-escape / drive-by exploitation
  §6 phishing infrastructure: GoPhish / SET / EvilGinx2 / Modlishka /
     BitB / AiTM MFA bypass / quishing / IDN homograph
  §7 manual passkey phishing + modern sandbox-escape research

— require operator-side payload delivery, a victim to execute the
payload, red-team infrastructure you stand up, on-host execution, or
active exploitation. None can be safely or honestly detected by sending
HTTP to the customer's target. Per the module's HARD RULES (VA not PT,
zero false positives, no weaponised payloads), these are emitted as INFO
[ADVISORY-BY-DESIGN] findings — never as graded severities.

This scanner runs no network exploitation. It optionally does ONE benign
HTTP GET to record the target is reachable, then emits the advisory
catalogue. It always returns INFO-only.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()


class ClientSideAdvisoryRequest(ScanRequest):
    options: Optional[dict] = None


# (technique title, why-advisory reason, cwe) — every entry is INFO-only.
_ADVISORY_TECHNIQUES: list[tuple[str, str, str]] = [
    # §1 Browser Hooks / BeEF
    ("BeEF browser-hook hosting + hook modules (clipboard/webcam/mic, "
     "tabnabbing, social-eng modules)",
     "Requires standing up a BeEF server and landing the hook JS in a "
     "victim browser (typically via an XSS the analyst already found). "
     "It is offensive infrastructure + victim execution, not a condition "
     "detectable on the customer's server.",
     "CWE-1395"),
    ("Custom JS keylogger / session-replay browser hook",
     "Requires injecting and running attacker JS in a victim session — "
     "active exploitation + victim interaction, not a server-side "
     "detectable state.",
     "CWE-1395"),

    # §2 Office / Document macros
    ("Office VBA macro / Excel-4.0 (XLM) / VBA-stomping payload generation "
     "(macro_pack, EvilClippy)",
     "Generates a weaponised document and relies on a user enabling "
     "macros — payload craft + user execution. Nothing about it is "
     "observable by scanning the target host.",
     "CWE-1395"),
    ("Remote template injection / DDE / OLE / OneNote / PDF-JS / ISO-IMG "
     "container payload delivery",
     "Builds a malicious document or container and delivers it to a user. "
     "Payload-delivery + user-execution, outside the scope of external "
     "host VA.",
     "CWE-1395"),
    ("Outlook custom-form persistence + macro evasion",
     "Requires authenticated mailbox access and on-host Outlook "
     "manipulation — post-compromise persistence, not externally "
     "probeable.",
     "CWE-1395"),

    # §3 HTA
    ("HTA payload generation + mshta.exe execution chains (HTA->PowerShell "
     "stager, AMSI bypass)",
     "Builds an .hta and relies on a Windows victim launching mshta. "
     "Payload craft + Windows host execution; no remote signal exists on "
     "the customer's web target.",
     "CWE-1395"),

    # §4 LNK / shortcut abuse
    ("LNK / .url shortcut abuse (icon spoofing, PowerShell stager, "
     "archive smuggling, .vbs/.js chain)",
     "Crafts a malicious shortcut delivered to a user. Payload craft + "
     "user execution on a Windows endpoint.",
     "CWE-1395"),
    ("Mark-of-the-Web (MotW) bypass",
     "An on-endpoint file-attribute technique that defeats SmartScreen — "
     "it concerns how a downloaded file behaves on the victim host, not a "
     "condition on the customer's server.",
     "CWE-1395"),

    # §5 Browser-side exploits
    ("Browser 0-day / CVE exploitation (Chrome/Firefox/Edge/Safari), "
     "UXSS, sandbox escape, renderer chain",
     "Active exploitation of a browser engine against a victim — weaponised "
     "and engagement-scoped. VA detects missing browser-hardening headers "
     "(covered by the live header scanners) but never fires real exploits.",
     "CWE-1395"),
    ("Drive-by download / watering-hole attack design",
     "Requires the analyst to host malicious content and lure victims — "
     "offensive infrastructure + victim execution.",
     "CWE-1395"),
    ("Browser plugin / extension CVE + PDF-reader CVE delivery",
     "Targets software installed on the victim endpoint; not a state "
     "observable on the customer's web server.",
     "CWE-1395"),

    # §6 Social-engineering payload delivery
    ("Phishing infrastructure: GoPhish / SET / site-clone / URL-shortener "
     "obfuscation",
     "Stands up phishing infrastructure and sends lures to humans — "
     "out-of-band offensive operation, not a target-host condition.",
     "CWE-1395"),
    ("Reverse-proxy MITM phishing + AiTM MFA bypass (EvilGinx2, Modlishka)",
     "Requires the analyst to run a reverse-proxy phishing server and a "
     "victim to authenticate through it. Offensive infra + victim "
     "interaction; nothing to scan on the customer side.",
     "CWE-1395"),
    ("Browser-in-the-Browser (BitB) + Punycode IDN homograph + quishing "
     "(QR phishing) + .ics calendar injection",
     "Lure-craft techniques delivered to users via email/QR/calendar — "
     "social engineering, not a server-detectable vulnerability.",
     "CWE-1395"),
    ("Passwordless / Passkey phishing",
     "Requires a live AiTM relay and a victim completing a WebAuthn "
     "ceremony through it — victim interaction + offensive infrastructure.",
     "CWE-1395"),

    # §7 Modern browser surface (analyst/manual parts)
    ("Chrome Manifest-v3 extension abuse + extension privilege escalation",
     "Requires a malicious extension installed in the victim browser and "
     "on-device evaluation — endpoint-side, not externally probeable.",
     "CWE-1395"),
    ("WebRTC local-IP leak",
     "A property of the victim's browser/network stack observed at runtime "
     "in the victim session (via hosted JS), not a state on the customer's "
     "server. The live header scanners cover the server-side controls.",
     "CWE-1395"),
    ("Storage Access API abuse + manual modern sandbox-escape research",
     "Requires interactive in-browser evaluation / exploit research against "
     "a victim session — manual, engagement-scoped, not a remote VA signal.",
     "CWE-1395"),
]


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.source("no-target")
        # Still emit the advisory catalogue even without a reachable target.
        ctx.state["advisory_techniques"] = _ADVISORY_TECHNIQUES
        ctx.state["advisory_reachable"] = None
        ctx.source("advisory-catalogue")
        return

    probe_url = target
    if not probe_url.startswith(("http://", "https://")):
        probe_url = "https://" + probe_url

    reachable = None
    try:
        import httpx
        opts = ctx.state.get("_options") or {}
        ua = opts.get("user_agent") or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
            "Safari/537.36"
        )
        async with httpx.AsyncClient(
            verify=False, timeout=15, follow_redirects=True,
            headers={"User-Agent": ua},
        ) as client:
            r = await client.get(probe_url)
            reachable = r.status_code
    except Exception:
        # Reachability is purely informational; advisory output is unchanged.
        reachable = None

    ctx.state["advisory_target"] = probe_url
    ctx.state["advisory_reachable_status"] = reachable
    ctx.state["advisory_techniques"] = _ADVISORY_TECHNIQUES
    ctx.state["advisory_count"] = len(_ADVISORY_TECHNIQUES)
    ctx.source("advisory-by-design catalogue")


# ── findings rules: ALWAYS INFO, one finding per advisory technique ─────

def _make_rule(idx: int, title: str, reason: str, cwe: str):
    def _rule(s):
        techs = s.get("advisory_techniques") or []
        if idx >= len(techs):
            return None
        return {
            "name": f"[ADVISORY-BY-DESIGN] {title}",
            "severity": "INFO",
            "cvss": "0.0",
            "cwe": cwe,
            "owasp": "N/A",
            "evidence": (
                "Endpoint is advisory-by-design (NOT a forge gap). This "
                "client-side technique cannot be safely or honestly detected "
                f"from an external SaaS VA scan: {reason} See "
                "module_playbooks/09_client_side.md for the manual / "
                "red-team procedure."
            ),
            "remediation": (
                "Covered by user-awareness training, EDR/email-gateway "
                "controls, browser hardening, and MFA phishing-resistance "
                "(passkeys). Execute this technique only under an authorised "
                "red-team engagement using the referenced tooling."
            ),
        }
    return _rule


CLIENTSIDE_ADVISORY_SURFACE_FINDING_RULES = [
    _make_rule(i, t, reason, cwe)
    for i, (t, reason, cwe) in enumerate(_ADVISORY_TECHNIQUES)
]


INTEL_FIELDS = [
    ("Target",                       "advisory_target"),
    ("Reachable (HTTP status)",      "advisory_reachable_status"),
    ("Advisory-by-design techniques", "advisory_count"),
]


@router.post("/api/client_side/clientside_advisory_surface")
async def client_side_clientside_advisory_surface(req: ClientSideAdvisoryRequest,
                                                  _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="clientside_advisory_surface",
        gather_func=_gather_with_options,
        finding_rules=CLIENTSIDE_ADVISORY_SURFACE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
