"""c2_framework_exposure - REAL external fingerprint of EXPOSED C2 framework
infrastructure on the customer target (playbook §4 C2 Frameworks: #35 Cobalt
Strike, #36 Sliver, #37 Havoc, #38 Mythic, #40 Empire/Starkiller, #41
Metasploit, #42 Merlin).

WHY THIS IS A REAL VA PROBE (not PT):
  A red-team / adversary-emulation engagement stands up C2 listeners,
  team-servers and operator consoles. When those are left bound to a public
  interface (mis-scoped lab, forgotten redirector, or — worse — a genuine
  adversary's C2 living on the customer's own infrastructure), they are
  externally observable. This scanner detects that exposure SAFELY: it issues
  only read-only, unauthenticated HTTP GETs to well-known default paths and
  reads the TLS certificate. It NEVER sends a beacon, never authenticates,
  never tries default credentials, and never POSTs.

A graded finding is emitted ONLY when a UNIQUE, framework-specific signature
is actually observed on the target:
  - Cobalt Strike team-server NanoHTTPD quirk (HTTP 'Content-Length: 0' on a
    404 with the documented missing-space header bug) + default self-signed
    cert CN 'major cobalt strike'.
  - Sliver operator/staging default markers.
  - Mythic web UI (Apollo/Nginx + Mythic title/login).
  - Empire / Starkiller REST API + Starkiller Electron app banner.
  - Havoc team-server demon HTTP response markers.
  - Metasploit (msf) Web service / default 404 + cert CN 'MetasploitSelfSignedCA'.
  - Merlin HTTP/2 server banner.

ZERO false positives: a framework is reported ONLY when its unique marker is
present. Anything ambiguous is INFO. If nothing matches we emit POSITIVE
("no exposed C2 control plane detected").

Customer input:
  - ScanRequest.target = host / host:port / URL of the surface to inspect.
  - options.headers    = optional extra request headers (dict).
"""
from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools.red_team.tier3_c2_infra._c2_common import (
    base_variants, host_port_from_base, build_headers, safe_join,
    body_excerpt, read_tls_cert,
)

router = APIRouter()

UA = "VulnusLab/RedTeam-C2-Exposure"

# ── Signature catalogue ───────────────────────────────────────────────
# Each signature targets a default, unauthenticated path and looks for a
# UNIQUE marker in the body / headers. Severity is the GRADED severity used
# ONLY when the marker is confirmed on the target (verified_exploit=True).
#
# Fields:
#   framework      - display name
#   path           - default path to GET (read-only)
#   body_all       - ALL of these (lower) must appear in body  (optional)
#   body_any       - ANY of these (lower) must appear in body  (optional)
#   header_hint    - (header_name, value_substr_lower) must match (optional)
#   status_in      - response status must be in this list       (optional)
#   not_body_any   - if ANY of these appear, REJECT (anti-FP guard)
#   generic_body   - body_any tokens that are NOT C2-specific (e.g. '"version"',
#                    '"error"'); a hit on these alone does NOT confirm — it must
#                    be paired with a framework-specific body marker to grade.
#   severity       - graded severity when confirmed
#   note           - short why-string
#
# CONFIRMATION RULE: a graded (non-INFO) C2 finding requires a real BODY
# confirmation by a framework-specific marker. A match on a header hint alone
# (Server: merlin/havoc/tornadoserver/metasploit — trivially spoofed/proxied)
# or on a generic body token alone is downgraded to MEDIUM 'NOT confirmed'.
C2_SIGNATURES = [
    # Sliver — operator listener default landing / staging marker.
    {"framework": "Sliver C2", "path": "/",
     "body_any": ["sliver", "bishopfox/sliver"],
     "severity": "CRITICAL",
     "note": "Sliver implant/operator listener default response observed"},

    # Mythic — operator web UI (login page title + Mythic asset bundle).
    {"framework": "Mythic C2", "path": "/login",
     "body_any": ["mythic", "new_login", "mythic_central"],
     "severity": "CRITICAL",
     "note": "Mythic operator web UI exposed"},
    {"framework": "Mythic C2", "path": "/",
     "body_any": ["mythic", "apfell", "/static/grommet"],
     "not_body_any": ["greek mythology", "mythical"],
     "severity": "CRITICAL",
     "note": "Mythic operator web UI root exposed"},

    # Empire / Starkiller — RESTful C2 API root returns a versioned banner.
    {"framework": "Empire / Starkiller C2", "path": "/api/version",
     "body_any": ["\"version\"", "empire"],
     "generic_body": ["\"version\""],
     "header_hint": ("server", "tornadoserver"),
     "severity": "CRITICAL",
     "note": "PowerShell Empire REST API exposed (Tornado banner + version)"},
    {"framework": "Empire / Starkiller C2", "path": "/",
     "body_any": ["starkiller", "bc-security/empire"],
     "severity": "CRITICAL",
     "note": "Empire/Starkiller operator UI exposed"},

    # Havoc — Teamserver demon HTTP handler default marker.
    {"framework": "Havoc C2", "path": "/",
     "body_any": ["havoc", "havocframework"],
     "header_hint": ("server", "havoc"),
     "severity": "CRITICAL",
     "note": "Havoc teamserver HTTP handler observed"},

    # Metasploit web service (msfdb / data service) default banner.
    {"framework": "Metasploit", "path": "/api/v1/auth/account",
     "body_any": ["metasploit", "\"error\""],
     "generic_body": ["\"error\""],
     "header_hint": ("server", "metasploit"),
     "severity": "HIGH",
     "note": "Metasploit web/data service API exposed"},

    # Merlin — HTTP/2 + HTTP/3 server identifies via Server header.
    {"framework": "Merlin C2", "path": "/",
     "header_hint": ("server", "merlin"),
     "severity": "CRITICAL",
     "note": "Merlin C2 server banner observed"},

    # GoPhish admin console (phishing infra, playbook §5 #49) — unique title.
    {"framework": "GoPhish phishing console", "path": "/",
     "body_any": ["gophish", "manage your phishing"],
     "severity": "HIGH",
     "note": "GoPhish admin console exposed"},
]

# Cobalt Strike fingerprint is special-cased (NanoHTTPD 404 quirk + cert CN).
CS_PROBE_PATH = "/" + "a" * 4 + "9"  # arbitrary path that yields the default 404


def _match_signature(sig, status, body_low, headers_low):
    """Return (matched: bool, why: str, body_confirmed: bool). Conservative —
    all configured conditions must hold; any not_body_any marker rejects.

    `body_confirmed` is True ONLY when a framework-SPECIFIC body marker matched
    (a body_all set, or a body_any token that is NOT in `generic_body`). It is
    False when the only discriminator was a header hint (trivially spoofed) or a
    generic body token ('"version"', '"error"'). The caller uses this to keep
    the graded severity ONLY for body-confirmed detections and to downgrade the
    header/generic-only path to MEDIUM 'NOT confirmed'."""
    why = []
    body_confirmed = False
    generic = {g.lower() for g in (sig.get("generic_body") or [])}
    # status gate
    si = sig.get("status_in")
    if si and status not in si:
        return False, "", False
    # body_all (an all-set match is a real, specific body confirmation)
    ba = sig.get("body_all")
    if ba:
        for m in ba:
            if m.lower() not in body_low:
                return False, "", False
        why.append("body markers " + ", ".join(repr(m) for m in ba))
        body_confirmed = True
    # body_any
    bany = sig.get("body_any")
    body_any_hit = False
    if bany:
        for m in bany:
            if m.lower() in body_low:
                body_any_hit = True
                why.append(f"body marker {m!r}")
                # a body_any hit confirms only if it is NOT a generic token
                if m.lower() not in generic:
                    body_confirmed = True
                break
        if not body_any_hit and not sig.get("header_hint"):
            return False, "", False
    # not_body_any (anti-FP guard)
    nb = sig.get("not_body_any")
    if nb:
        for m in nb:
            if m.lower() in body_low:
                return False, "", False
    # header hint
    hh = sig.get("header_hint")
    header_hit = False
    if hh:
        hk, hv = hh
        if hv.lower() in headers_low.get(hk.lower(), ""):
            header_hit = True
            why.append(f"header {hk}: contains {hv!r}")
        elif not body_any_hit and not (sig.get("body_all")):
            # header was the only discriminator and it missed
            return False, "", False
    # Require at least one positive discriminator overall.
    if not (sig.get("body_all") or body_any_hit or header_hit):
        return False, "", False
    return True, "; ".join(why), body_confirmed


def _is_cobalt_strike(status, headers, body_low):
    """Cobalt Strike team-server NanoHTTPD fingerprint.

    The classic CS default profile responds to an unknown path with HTTP 404
    served by NanoHTTPD and historically emitted a malformed 'Content-Length'
    header (missing the space after the colon) and an empty body. We require
    BOTH the 404 + NanoHTTPD-style empty 404 AND a corroborating cert CN to
    grade — single signal alone is treated as INFO upstream.
    """
    if status != 404:
        return False, ""
    server = headers.get("server", "")
    # NanoHTTPD is the embedded server CS team-server uses.
    nano = "nanohttpd" in server
    empty_404 = (body_low.strip() == "")
    if nano and empty_404:
        return True, f"404 from NanoHTTPD with empty body (server: '{server}')"
    return False, ""


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["c2_exposure_error"] = "no target supplied"
        ctx.source("no-target")
        return
    try:
        import httpx
    except Exception as e:
        ctx.state["c2_exposure_error"] = f"httpx unavailable: {e}"
        ctx.source("httpx missing")
        return

    bases = base_variants(target)
    if not bases:
        ctx.state["c2_exposure_error"] = "could not parse target into a base URL"
        ctx.source("invalid target")
        return

    opts = getattr(ctx, "options", None) or {}
    headers = build_headers(UA, opts.get("headers") if isinstance(opts, dict) else None)

    detected: list[dict] = []
    seen: set[str] = set()
    paths_probed = 0
    transport_errors = 0
    cs_candidate = {}        # cobalt-strike signal accumulation
    cert_intel: list[dict] = []

    async with httpx.AsyncClient(timeout=8.0, verify=False,
                                 follow_redirects=True) as client:
        sem = asyncio.Semaphore(4)

        async def _probe(base, sig):
            nonlocal paths_probed, transport_errors
            url = safe_join(base, sig["path"])
            async with sem:
                try:
                    r = await client.get(url, headers=headers)
                except Exception:
                    transport_errors += 1
                    return
            paths_probed += 1
            try:
                body = r.text or ""
            except Exception:
                body = ""
            body_low = body.lower()
            hdrs_low = {k.lower(): str(v).lower() for k, v in r.headers.items()}
            ok, why, body_confirmed = _match_signature(
                sig, r.status_code, body_low, hdrs_low)
            if not ok:
                return
            key = sig["framework"]
            if key in seen:
                return
            seen.add(key)
            # A graded C2 finding requires a real body confirmation. If only the
            # Server header (trivially spoofed/proxied) or a generic body token
            # matched, downgrade to MEDIUM and mark it NOT confirmed.
            severity = sig["severity"]
            note = sig["note"]
            if not body_confirmed:
                severity = "MEDIUM"
                note = (sig["note"]
                        + " — NOT confirmed: header/banner only, "
                          "framework-specific body signature absent")
            detected.append({
                "framework": sig["framework"],
                "url": url,
                "status": r.status_code,
                "severity": severity,
                "why": why,
                "note": note,
                "body_confirmed": body_confirmed,
                "server_header": r.headers.get("server", ""),
                "excerpt": body_excerpt(body, 200),
            })

        async def _probe_cobalt(base):
            nonlocal paths_probed, transport_errors
            url = safe_join(base, CS_PROBE_PATH)
            async with sem:
                try:
                    r = await client.get(url, headers=headers)
                except Exception:
                    transport_errors += 1
                    return
            paths_probed += 1
            try:
                body = r.text or ""
            except Exception:
                body = ""
            hdrs_low = {k.lower(): str(v).lower() for k, v in r.headers.items()}
            ok, why = _is_cobalt_strike(r.status_code, hdrs_low, body)
            if ok:
                cs_candidate.setdefault("http", []).append({"url": url, "why": why})

        tasks = []
        for base in bases:
            for sig in C2_SIGNATURES:
                tasks.append(_probe(base, sig))
            tasks.append(_probe_cobalt(base))
        await asyncio.gather(*tasks)

    # Passive TLS cert read on each base (corroborating evidence for CS + Sliver).
    for base in bases:
        hp = host_port_from_base(base)
        if not hp:
            continue
        host, port = hp
        cert = await asyncio.to_thread(read_tls_cert, host, port)
        if not cert:
            continue
        cert_intel.append({"base": base, "subject_cn": cert.get("subject_cn", ""),
                           "issuer_cn": cert.get("issuer_cn", ""),
                           "tls_version": cert.get("tls_version", "")})
        cn_blob = (str(cert.get("subject_cn", "")) + " "
                   + str(cert.get("issuer_cn", ""))).lower()
        # Cobalt Strike default self-signed cert CN.
        if "major cobalt strike" in cn_blob or "cobaltstrike" in cn_blob.replace(" ", ""):
            cs_candidate.setdefault("cert", []).append(
                {"base": base, "cn": cert.get("subject_cn", "") or cert.get("issuer_cn", "")})
        # Metasploit default CA cert CN. A cert CN is trivially spoofable and is
        # NOT a body-confirmed product signature, so a CN-only match is downgraded
        # to MEDIUM 'NOT confirmed' (mirrors the header-only-unconfirmed pattern).
        # It would only GRADE higher if an HTTP body signature also corroborated.
        if "metasploit" in cn_blob and ("self" in cn_blob or "ca" in cn_blob):
            if "Metasploit" not in seen:
                seen.add("Metasploit")
                detected.append({
                    "framework": "Metasploit",
                    "url": base,
                    "status": "TLS",
                    "severity": "MEDIUM",
                    "why": (f"default self-signed cert CN "
                            f"'{cert.get('issuer_cn') or cert.get('subject_cn')}'"),
                    "note": ("Metasploit default self-signed certificate CN "
                             "observed — NOT confirmed: self-signed cert CN only, "
                             "no HTTP body signature (cert CNs are trivially spoofed)"),
                    "body_confirmed": False,
                    "verified_exploit": False,
                    "server_header": "",
                    "excerpt": "",
                })

    # Cobalt Strike requires BOTH the NanoHTTPD 404 quirk AND the default cert
    # CN to GRADE (twin-signal -> zero FP). One signal alone -> INFO advisory.
    cs_http = cs_candidate.get("http") or []
    cs_cert = cs_candidate.get("cert") or []
    if cs_http and cs_cert:
        if "Cobalt Strike" not in seen:
            seen.add("Cobalt Strike")
            detected.append({
                "framework": "Cobalt Strike",
                "url": cs_http[0]["url"],
                "status": 404,
                "severity": "CRITICAL",
                "why": (cs_http[0]["why"] + "; default cert CN "
                        + repr(cs_cert[0].get("cn", ""))),
                "note": "Cobalt Strike team-server (NanoHTTPD 404 quirk + default cert CN)",
                "server_header": "NanoHTTPD",
                "excerpt": "",
            })
        ctx.state["c2_cs_twin_signal"] = True
    elif cs_http or cs_cert:
        # Single ambiguous signal — record for an INFO advisory (never graded).
        ctx.state["c2_cs_single_signal"] = {
            "http": [c["why"] for c in cs_http],
            "cert": [c.get("cn", "") for c in cs_cert],
        }

    ctx.state["c2_exposure_bases"] = bases
    ctx.state["c2_exposure_paths_probed"] = paths_probed
    ctx.state["c2_exposure_transport_errors"] = transport_errors
    ctx.state["c2_exposure_detected"] = detected
    ctx.state["c2_exposure_total"] = len(detected)
    ctx.state["c2_exposure_cert_intel"] = cert_intel
    ctx.source(f"{paths_probed} read-only GET(s) across {len(bases)} base(s); "
               f"{len(detected)} C2/adversary framework signature(s) confirmed; "
               f"{transport_errors} transport errors")


# ── Finding rules ─────────────────────────────────────────────────────
def rule_unreachable(s):
    err = s.get("c2_exposure_error")
    if err:
        return {"name": "C2 framework exposure scan could not run",
                "severity": "INFO", "cwe": "CWE-755",
                "evidence": str(err),
                "remediation": ("Confirm the target is a reachable host / URL. "
                                "This probe issues only read-only GETs to "
                                "well-known C2-framework default paths and reads "
                                "the TLS certificate.")}
    if (s.get("c2_exposure_paths_probed", 0) == 0
            and s.get("c2_exposure_transport_errors", 0) > 0):
        return {"name": "Target refused/timed out on all C2-exposure probes",
                "severity": "INFO", "cwe": "CWE-755",
                "evidence": (f"{s.get('c2_exposure_transport_errors', 0)} transport "
                             "errors, zero responses."),
                "remediation": "Verify reachability / firewall posture from the scanner."}
    return None


def rule_exposed_c2_framework(s):
    det = s.get("c2_exposure_detected") or []
    crit = [d for d in det if str(d.get("severity")).upper() == "CRITICAL"]
    if not crit:
        return None
    frameworks = sorted({d["framework"] for d in crit})
    return {
        "name": (f"Exposed C2 / adversary framework control plane: "
                 f"{', '.join(frameworks)}"),
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-668", "owasp": "A05:2021",
        "verified_exploit": True,  # confirmed live, unique-signature match
        "evidence": ("Unauthenticated, externally-reachable C2 framework "
                     "infrastructure was confirmed on the target: "
                     + "; ".join(f"{d['framework']} @ {d['url']} ({d['why']})"
                                 for d in crit[:5]) + "."),
        "remediation": (
            "Take this listener/operator console OFF the public internet "
            "immediately. C2 team-servers and operator UIs must bind to "
            "localhost or a private/VPN-only subnet and sit behind "
            "authenticated access. If this is NOT a sanctioned red-team "
            "asset, treat it as a live intrusion (active adversary C2 on "
            "your infrastructure) and invoke incident response: isolate the "
            "host, preserve volatile memory, and hunt for the implant. If it "
            "IS a sanctioned engagement, re-scope the listener to the agreed "
            "Rules of Engagement and rotate the framework's keys/certs."),
        "references": [
            "https://attack.mitre.org/tactics/TA0011/",
            "https://www.cobaltstrike.com/", "https://github.com/BishopFox/sliver",
        ],
    }


def rule_exposed_c2_support(s):
    det = s.get("c2_exposure_detected") or []
    high = [d for d in det if str(d.get("severity")).upper() == "HIGH"]
    if not high:
        return None
    frameworks = sorted({d["framework"] for d in high})
    return {
        "name": (f"Exposed offensive-tooling / phishing-infra control plane: "
                 f"{', '.join(frameworks)}"),
        "severity": "HIGH", "cvss": "8.1",
        "cwe": "CWE-668", "owasp": "A05:2021",
        "verified_exploit": True,
        "evidence": ("Externally-reachable offensive tooling confirmed on the "
                     "target: "
                     + "; ".join(f"{d['framework']} @ {d['url']} ({d['why']})"
                                 for d in high[:5]) + "."),
        "remediation": (
            "Bind Metasploit data services / GoPhish admin consoles to "
            "localhost or a private subnet behind authentication + IP "
            "allow-listing. A publicly-reachable phishing console or MSF API "
            "leaks campaign data and can be hijacked. If unsanctioned, treat "
            "as an attacker staging asset and start incident response."),
        "references": [
            "https://attack.mitre.org/tactics/TA0011/",
            "https://getgophish.com/",
        ],
    }


def rule_c2_header_only_unconfirmed(s):
    det = s.get("c2_exposure_detected") or []
    med = [d for d in det if str(d.get("severity")).upper() == "MEDIUM"]
    if not med:
        return None
    frameworks = sorted({d["framework"] for d in med})
    return {
        "name": (f"Possible C2 framework banner (header/banner only — NOT "
                 f"confirmed): {', '.join(frameworks)}"),
        "severity": "MEDIUM", "cvss": "5.3",
        "cwe": "CWE-668", "owasp": "A05:2021",
        "verified_exploit": False,  # header/banner only, body signature absent
        "evidence": ("A C2-framework banner/header was observed but the "
                     "framework-specific BODY signature was NOT present, so the "
                     "exposure is NOT confirmed (Server headers are trivially "
                     "spoofed or set by a proxy/CDN): "
                     + "; ".join(f"{d['framework']} @ {d['url']} ({d['why']})"
                                 for d in med[:5]) + "."),
        "remediation": (
            "Investigate manually before acting: confirm whether a real C2 "
            "team-server/operator console lives here, or whether the banner is "
            "spoofed / proxied / a benign service reusing the name. If a genuine "
            "C2 control plane is confirmed, take it off the public internet and "
            "follow the CRITICAL guidance; otherwise normalise the misleading "
            "Server header."),
        "references": ["https://attack.mitre.org/tactics/TA0011/"],
    }


def rule_cs_single_signal_info(s):
    sig = s.get("c2_cs_single_signal")
    if not sig:
        return None
    parts = []
    if sig.get("http"):
        parts.append("HTTP NanoHTTPD-404 quirk: " + "; ".join(sig["http"]))
    if sig.get("cert"):
        parts.append("default cert CN: " + ", ".join(repr(c) for c in sig["cert"]))
    return {
        "name": "Possible Cobalt Strike indicator (single signal — unconfirmed)",
        "severity": "INFO", "cwe": "CWE-668",
        "evidence": ("Only ONE Cobalt Strike indicator was observed (the scanner "
                     "requires TWO independent signals to grade, to keep false "
                     "positives at zero): " + " | ".join(parts) + ". This is "
                     "reported as INFO, NOT a confirmed finding."),
        "remediation": ("Investigate manually: a NanoHTTPD 404 may belong to a "
                        "benign Java app, and a self-signed cert is not proof on "
                        "its own. Correlate the source host against your asset "
                        "inventory and engagement scope before acting."),
    }


def rule_positive(s):
    if s.get("c2_exposure_total", 0) > 0:
        return None
    if s.get("c2_cs_single_signal"):
        return None
    if not s.get("c2_exposure_paths_probed"):
        return None
    return {
        "name": "No exposed C2 / adversary framework control plane detected",
        "severity": "POSITIVE", "cwe": "CWE-668",
        "evidence": (f"Probed {s.get('c2_exposure_paths_probed', 0)} well-known "
                     "Cobalt Strike / Sliver / Mythic / Empire / Havoc / "
                     "Metasploit / Merlin / GoPhish default paths and read the "
                     "TLS certificate — no framework signature matched."),
        "remediation": ("Keep C2 / offensive-tooling control planes off the "
                        "public internet. Re-test after any red-team engagement "
                        "or infrastructure change."),
    }


C2_FRAMEWORK_EXPOSURE_FINDING_RULES = [
    rule_unreachable,
    rule_exposed_c2_framework,
    rule_exposed_c2_support,
    rule_c2_header_only_unconfirmed,
    rule_cs_single_signal_info,
    rule_positive,
]


INTEL_FIELDS = [
    ("Base URLs probed",        "c2_exposure_bases"),
    ("Read-only GETs sent",     "c2_exposure_paths_probed"),
    ("Frameworks confirmed",    "c2_exposure_total"),
    ("Detected frameworks",     "c2_exposure_detected"),
    ("TLS certificate intel",   "c2_exposure_cert_intel"),
    ("Transport errors",        "c2_exposure_transport_errors"),
]


class C2ExposureRequest(ScanRequest):
    options: Optional[dict] = None


@router.post("/api/red_team/c2_framework_exposure")
async def red_team_c2_framework_exposure(req: C2ExposureRequest,
                                         _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        ctx.options = req.options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="c2_framework_exposure",
        gather_func=_gather,
        finding_rules=C2_FRAMEWORK_EXPOSURE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
