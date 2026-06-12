"""detection_tooling_exposure - REAL external detection of EXPOSED blue-team
/ detection-engineering consoles + red-team payload-staging surfaces on the
customer target (playbook §6 Detection-Engineering Validation #59-#66, §7
Purple-Teaming #70-#72, §5 Initial-Access staging surfaces).

WHY THIS IS A REAL VA PROBE:
  The red_team module's detection-engineering goal is to validate that the
  blue-team stack works. A foundational prerequisite is that the detection
  stack itself is NOT publicly exposed: a Splunk/Kibana/Elastic/Wazuh/Graylog
  console, a CALDERA operator UI, or an ATT&CK Navigator instance reachable on
  the open internet is a serious exposure (it leaks detections, telemetry, and
  is itself an attack surface). Likewise an exposed payload-staging/HTTP-file
  server is an initial-access tell.

This scanner issues ONLY read-only, unauthenticated HTTP GETs to well-known
default product paths and matches UNIQUE product markers. It never logs in,
never tries default credentials, never POSTs. A graded finding is emitted
ONLY when a unique product login/banner is actually observed. Anything
ambiguous is INFO. If nothing matches we emit POSITIVE.

Customer input:
  - ScanRequest.target = host / host:port / URL to inspect.
  - options.headers    = optional extra request headers (dict).
"""
from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools.red_team.tier3_c2_infra._c2_common import (
    base_variants, build_headers, safe_join, body_excerpt,
)

router = APIRouter()

UA = "VulnusLab/RedTeam-Detection-Exposure"

# Each signature: GET a default path, confirm a UNIQUE product marker.
# category: "detection" (SIEM/EDR console) | "redteam_infra" (operator/staging)
# severity is the GRADED severity used ONLY when the marker is confirmed.
DETECTION_SIGNATURES = [
    # ── SIEM / log platforms ──
    {"product": "Splunk Web", "path": "/en-US/account/login",
     "body_any": ["splunk", "splunkd", "/static/@"], "severity": "HIGH",
     "category": "detection",
     "note": "Splunk Web login page exposed"},
    {"product": "Kibana", "path": "/app/kibana",
     "body_any": ["kibana", "kbn-injected-metadata", "kbn-name"],
     "severity": "HIGH", "category": "detection",
     "note": "Kibana UI exposed"},
    {"product": "Kibana (status)", "path": "/api/status",
     "body_any": ["\"name\":\"kibana\"", "\"kibana\"", "nucleus"],
     "header_hint": ("kbn-name", "kibana"),
     "require_body_for_grade": True,  # kbn-name header alone is trivially spoofed
     "severity": "HIGH", "category": "detection",
     "note": "Kibana status API exposed"},
    {"product": "Elasticsearch", "path": "/",
     "body_all": ["\"cluster_name\"", "\"lucene_version\""],
     "severity": "CRITICAL", "category": "detection",
     "note": "Elasticsearch cluster info exposed without auth"},
    {"product": "Grafana", "path": "/login",
     "body_any": ["grafana", "[[.appsuburl]]", "grafana-app"],
     "severity": "MEDIUM", "category": "detection",
     "note": "Grafana login exposed"},
    {"product": "Graylog", "path": "/api/system/cluster/nodes",
     "body_any": ["graylog", "\"node_id\""], "severity": "HIGH",
     "category": "detection",
     "note": "Graylog API/console exposed"},
    {"product": "Wazuh", "path": "/app/wazuh",
     "body_any": ["wazuh"], "severity": "HIGH", "category": "detection",
     "note": "Wazuh (XDR/SIEM) console exposed"},
    {"product": "TheHive / Cortex", "path": "/index.html",
     "body_any": ["thehive", "cortex-analyzer", "thehive-project"],
     "severity": "HIGH", "category": "detection",
     "note": "TheHive / Cortex SOC platform exposed"},
    {"product": "Velociraptor (DFIR)", "path": "/app/index.html",
     "body_any": ["velociraptor"], "severity": "HIGH",
     "category": "detection",
     "note": "Velociraptor DFIR/EDR console exposed"},

    # ── Red-team operator / orchestration surfaces ──
    {"product": "MITRE CALDERA", "path": "/",
     "body_any": ["caldera", "mitre caldera", "/gui/img/caldera"],
     "severity": "CRITICAL", "category": "redteam_infra",
     "note": "MITRE CALDERA operator UI exposed"},
    {"product": "MITRE CALDERA (login)", "path": "/login",
     "body_any": ["caldera"], "severity": "CRITICAL",
     "category": "redteam_infra",
     "note": "MITRE CALDERA login page exposed"},
    {"product": "ATT&CK Navigator", "path": "/",
     "body_any": ["attack-navigator", "att&ck navigator", "nav-app"],
     "severity": "LOW", "category": "redteam_infra",
     "note": "ATT&CK Navigator instance exposed"},
    {"product": "Prelude Operator / Build", "path": "/",
     "body_any": ["prelude operator", "prelude-uuid"], "severity": "HIGH",
     "category": "redteam_infra",
     "note": "Prelude operator/orchestration surface exposed"},
]


def _match(sig, status, body_low, headers_low):
    """Return (matched: bool, why: str, body_confirmed: bool).

    `body_confirmed` is True when a body marker (body_all set or any body_any
    token) actually matched in the response body. The caller uses it for
    signatures flagged `require_body_for_grade`: a match on the header hint
    alone (e.g. Kibana's kbn-name header, trivially spoofed) must NOT keep the
    graded severity — it is downgraded to MEDIUM 'not confirmed'."""
    why = []
    body_confirmed = False
    si = sig.get("status_in")
    if si and status not in si:
        return False, "", False
    ba = sig.get("body_all")
    if ba:
        for m in ba:
            if m.lower() not in body_low:
                return False, "", False
        why.append("body markers " + ", ".join(repr(m) for m in ba))
        body_confirmed = True
    bany = sig.get("body_any")
    body_hit = False
    if bany:
        for m in bany:
            if m.lower() in body_low:
                body_hit = True
                body_confirmed = True
                why.append(f"body marker {m!r}")
                break
    hh = sig.get("header_hint")
    header_hit = False
    if hh:
        hk, hv = hh
        if hv.lower() in headers_low.get(hk.lower(), ""):
            header_hit = True
            why.append(f"header {hk}: contains {hv!r}")
    nb = sig.get("not_body_any")
    if nb:
        for m in nb:
            if m.lower() in body_low:
                return False, "", False
    if not (sig.get("body_all") or body_hit or header_hit):
        return False, "", False
    return True, "; ".join(why), body_confirmed


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["det_exposure_error"] = "no target supplied"
        ctx.source("no-target")
        return
    try:
        import httpx
    except Exception as e:
        ctx.state["det_exposure_error"] = f"httpx unavailable: {e}"
        ctx.source("httpx missing")
        return

    bases = base_variants(target)
    if not bases:
        ctx.state["det_exposure_error"] = "could not parse target into a base URL"
        ctx.source("invalid target")
        return

    opts = getattr(ctx, "options", None) or {}
    headers = build_headers(UA, opts.get("headers") if isinstance(opts, dict) else None)

    detected: list[dict] = []
    seen: set[str] = set()
    paths_probed = 0
    transport_errors = 0

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
            ok, why, body_confirmed = _match(
                sig, r.status_code, body_low, hdrs_low)
            if not ok:
                return
            key = sig["product"]
            if key in seen:
                return
            seen.add(key)
            # Signatures flagged require_body_for_grade must NOT keep the graded
            # severity on a header-only match (the header is trivially spoofed).
            # Downgrade to MEDIUM and mark it NOT confirmed.
            severity = sig["severity"]
            note = sig["note"]
            if sig.get("require_body_for_grade") and not body_confirmed:
                severity = "MEDIUM"
                note = (sig["note"]
                        + " — NOT confirmed: header only, product body "
                          "signature absent")
            detected.append({
                "product": sig["product"],
                "url": url,
                "status": r.status_code,
                "severity": severity,
                "category": sig["category"],
                "why": why,
                "note": note,
                "body_confirmed": body_confirmed,
                "server_header": r.headers.get("server", ""),
                "excerpt": body_excerpt(body, 200),
            })

        tasks = []
        for base in bases:
            for sig in DETECTION_SIGNATURES:
                tasks.append(_probe(base, sig))
        await asyncio.gather(*tasks)

    ctx.state["det_exposure_bases"] = bases
    ctx.state["det_exposure_paths_probed"] = paths_probed
    ctx.state["det_exposure_transport_errors"] = transport_errors
    ctx.state["det_exposure_detected"] = detected
    ctx.state["det_exposure_total"] = len(detected)
    ctx.source(f"{paths_probed} read-only GET(s) across {len(bases)} base(s); "
               f"{len(detected)} detection/red-team console signature(s) "
               f"confirmed; {transport_errors} transport errors")


def _grade_block(det, want_sev):
    items = [d for d in det if str(d.get("severity")).upper() == want_sev]
    return items


def rule_unreachable(s):
    err = s.get("det_exposure_error")
    if err:
        return {"name": "Detection-tooling exposure scan could not run",
                "severity": "INFO", "cwe": "CWE-755",
                "evidence": str(err),
                "remediation": ("Confirm the target is a reachable host / URL. "
                                "This probe issues only read-only GETs to "
                                "well-known SIEM/EDR/red-team-console default "
                                "paths.")}
    if (s.get("det_exposure_paths_probed", 0) == 0
            and s.get("det_exposure_transport_errors", 0) > 0):
        return {"name": "Target refused/timed out on all detection-exposure probes",
                "severity": "INFO", "cwe": "CWE-755",
                "evidence": (f"{s.get('det_exposure_transport_errors', 0)} transport "
                             "errors, zero responses."),
                "remediation": "Verify reachability / firewall posture from the scanner."}
    return None


def _mk_graded_rule(sev_label, finding_sev, cvss, title_prefix, remediation):
    def _rule(s):
        det = s.get("det_exposure_detected") or []
        block = _grade_block(det, sev_label)
        if not block:
            return None
        products = sorted({d["product"] for d in block})
        return {
            "name": f"{title_prefix}: {', '.join(products)}",
            "severity": finding_sev, "cvss": cvss,
            "cwe": "CWE-668", "owasp": "A05:2021",
            "verified_exploit": True,  # confirmed unique-signature live match
            "evidence": ("Externally-reachable console confirmed on the target: "
                         + "; ".join(f"{d['product']} @ {d['url']} ({d['why']})"
                                     for d in block[:6]) + "."),
            "remediation": remediation,
            "references": [
                "https://attack.mitre.org/tactics/TA0011/",
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            ],
        }
    _rule.__name__ = f"rule_detection_exposure_{sev_label.lower()}"
    return _rule


rule_exposure_critical = _mk_graded_rule(
    "CRITICAL", "CRITICAL", "9.1",
    "Exposed detection/red-team control plane (unauthenticated data leak)",
    ("Take this console OFF the public internet now. An exposed Elasticsearch "
     "cluster leaks ALL indexed telemetry without auth; an exposed CALDERA UI "
     "is a remote-code-execution orchestrator. Bind to localhost / a private "
     "subnet, require authentication + TLS, and add IP allow-listing. If this "
     "is not a sanctioned asset, treat as an intrusion and start incident "
     "response."))

rule_exposure_high = _mk_graded_rule(
    "HIGH", "HIGH", "7.5",
    "Exposed detection/red-team console",
    ("Place this SIEM/EDR/operator console behind authenticated access on a "
     "private network or VPN. A public Splunk/Kibana/Graylog/Wazuh login leaks "
     "your detection logic and is a prime credential-stuffing / 0-day target. "
     "Enforce MFA and IP allow-listing."))

rule_exposure_medium = _mk_graded_rule(
    "MEDIUM", "MEDIUM", "5.3",
    "Exposed monitoring/dashboard console",
    ("Restrict this dashboard (e.g. Grafana) to authenticated users on a "
     "private network. Disable anonymous access and enforce SSO/MFA."))

rule_exposure_low = _mk_graded_rule(
    "LOW", "LOW", "3.1",
    "Exposed red-team support tool",
    ("An ATT&CK Navigator (or similar planning tool) is reachable externally. "
     "Move it behind authentication so engagement coverage maps are not public."))


def rule_positive(s):
    if s.get("det_exposure_total", 0) > 0:
        return None
    if not s.get("det_exposure_paths_probed"):
        return None
    return {
        "name": "No exposed detection / red-team console detected",
        "severity": "POSITIVE", "cwe": "CWE-668",
        "evidence": (f"Probed {s.get('det_exposure_paths_probed', 0)} well-known "
                     "Splunk / Kibana / Elasticsearch / Grafana / Graylog / "
                     "Wazuh / CALDERA / Navigator default paths — none responded "
                     "with a product signature."),
        "remediation": ("Keep detection and red-team orchestration consoles off "
                        "the public internet. Re-test after infrastructure "
                        "changes."),
    }


DETECTION_TOOLING_EXPOSURE_FINDING_RULES = [
    rule_unreachable,
    rule_exposure_critical,
    rule_exposure_high,
    rule_exposure_medium,
    rule_exposure_low,
    rule_positive,
]


INTEL_FIELDS = [
    ("Base URLs probed",      "det_exposure_bases"),
    ("Read-only GETs sent",   "det_exposure_paths_probed"),
    ("Consoles confirmed",    "det_exposure_total"),
    ("Detected consoles",     "det_exposure_detected"),
    ("Transport errors",      "det_exposure_transport_errors"),
]


class DetectionExposureRequest(ScanRequest):
    options: Optional[dict] = None


@router.post("/api/red_team/detection_tooling_exposure")
async def red_team_detection_tooling_exposure(req: DetectionExposureRequest,
                                              _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        ctx.options = req.options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="detection_tooling_exposure",
        gather_func=_gather,
        finding_rules=DETECTION_TOOLING_EXPOSURE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
