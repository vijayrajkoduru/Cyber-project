"""Shared helper for advisory-pack modules built from module_playbooks/.

Each pack module imports `make_advisory_router(module_name, techniques)`
and registers it. Eliminates ~30 lines of boilerplate per module.

═══════════════════════════════════════════════════════════════
VL FRAMEWORK PASSES — inheritance map for modules using this helper:

  VL-TURBO inherited via tools/_framework/scanner.py + orchestrator.py:
    - 60s wall-clock cap per endpoint (VL_TURBO_SCANNER_TIMEOUT env)
    - Tier-aware semaphore concurrency (VL_TURBO_TIER_CONCURRENCY=12)
    - 24h result cache (VL_TURBO_CACHE_TTL=86400)
    - Per-module run_all uses run_module_streaming() with NDJSON +
      Cloudflare-safe 15s heartbeats + max-concurrency cap of 16.

  VL-PRIME inherited via endpoints/recon_prime.py:
    - Rate-limiter exempts internal IPs (127.0.0.1, 172.x, 10.x, 192.168.x)
      so /run_all fan-out doesn't 429-storm. All new modules' orchestrators
      pass through this same logic via run_module_streaming.
    - JWT bearer forwarding through fan-out preserves user identity.

  VL-FORGE advisory-only by default:
    - Modules built with make_advisory_router ship structured findings
      (severity / CVSS / CWE / OWASP / remediation / evidence) but NOT
      live probes. Real probing requires per-technique implementation
      (see tools/recon/tier*/ for the canonical pattern).
    - Modules whose techniques are post-compromise / require physical or
      privileged access (AD, AV-Evasion, Post-Exploit, Container/K8s,
      Phishing, Red-Team, Wireless, Firmware, IoT-OT) are CORRECTLY
      advisory-only — they can't be live-probed from external SaaS.
    - Externally-probeable modules to upgrade next: Network, Cloud,
      APISec, AI-LLM (when LLM endpoint provided).

  VL-FLOW inherited via src/App.js:ModuleAutoPanel:
    - Generic React panel loads /api/<module>/run_all/tiers + streams
      /api/<module>/run_all NDJSON + renders Recon-style tile grid.
    - All 26 modules using make_advisory_router get the same UI.
    - Per-module PDF report integration is per-module work (not inherited).
═══════════════════════════════════════════════════════════════
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding


def _adv_response(tool: str, target: str, title: str, sev: str, cvss: str,
                   cwe: str = "CWE-1395", remediation: str = "",
                   evidence: str = "") -> dict:
    """General-purpose response shaper. Used by real probes for error /
    fallback responses where the caller has chosen an honest severity.
    Do NOT use for scaffold endpoints — see _scaffold_response."""
    return {
        "tool": tool, "target": target, "scan_time": 0,
        "vulnerable": sev in ("CRITICAL", "HIGH", "MEDIUM"),
        "severity": sev,
        "findings": [wrap_finding(
            title, sev, cvss=cvss, cwe=cwe, owasp="A05:2021",
            remediation=remediation or "See corresponding module_playbooks/*.md technique entry.",
            evidence_marker=evidence or "Advisory — see playbook + EDR/NSM detection guidance."
        )],
        "tests_performed": 1, "tests_summary": title[:80], "raw_data": {}
    }


def _advisory_by_design_response(tool: str, target: str, title: str,
                                   reason: str = "",
                                   cwe: str = "CWE-1395") -> dict:
    """Response for techniques that CANNOT be live-probed from a SaaS
    scanner by design (require on-host eBPF, physical proximity,
    engagement-scope authorization, etc.). Always INFO severity with
    clear ADVISORY-BY-DESIGN marker so customer sees the technique
    is intentionally informational, not a forge gap."""
    return {
        "tool": tool, "target": target, "scan_time": 0,
        "vulnerable": False, "severity": "INFO",
        "findings": [wrap_finding(
            f"[ADVISORY-BY-DESIGN] {title}",
            "INFO", cvss="0.0", cwe=cwe, owasp="N/A",
            remediation=(
                f"This technique cannot be SaaS-probed and is intentionally "
                f"advisory. {reason or 'Requires on-host deployment, physical access, or engagement-scope authorization.'} "
                "Use the playbook reference for manual / red-team execution."
            ),
            evidence_marker=(
                "Endpoint is advisory-by-design (NOT a forge gap). No live "
                "scan possible from external SaaS. See playbook for manual "
                "procedure."
            )
        )],
        "tests_performed": 0,
        "tests_summary": f"[advisory-by-design] {title[:60]}",
        "_skipped": True,
        "skipped_reason": "advisory-by-design (SaaS cannot reach this surface)",
        "raw_data": {"advisory_by_design": True},
    }


def _scaffold_response(tool: str, target: str, title: str,
                        planned_sev: str, planned_cvss: str,
                        cwe: str = "CWE-1395", remediation: str = "") -> dict:
    """Scaffold endpoint response — technique not yet implemented as a live
    probe. ALWAYS emits INFO severity with a clear [NOT IMPLEMENTED] marker
    so reports cannot show fabricated CRITICAL/HIGH findings. The originally
    planned severity is preserved in raw_data for implementation tracking."""
    return {
        "tool": tool, "target": target, "scan_time": 0,
        "vulnerable": False,
        "severity": "INFO",
        "findings": [wrap_finding(
            f"[NOT IMPLEMENTED] {title}",
            "INFO", cvss="0.0", cwe=cwe, owasp="N/A",
            remediation=(
                f"This check is not yet forged into a live probe — no scan "
                f"was performed against {target}. Once implemented, expected "
                f"severity: {planned_sev} (CVSS {planned_cvss}). "
                f"{remediation or 'See module_playbooks/*.md for technique reference.'}"
            ).strip(),
            evidence_marker=(
                "No live scan executed — endpoint is a scaffold pending "
                "implementation. Do not treat as a real finding."
            )
        )],
        "tests_performed": 0,
        "tests_summary": f"[scaffold] {title[:60]}",
        "raw_data": {
            "scaffold": True,
            "planned_severity": planned_sev,
            "planned_cvss": planned_cvss,
        },
    }


def make_advisory_router(module_name: str, techniques: list,
                          playbook_ref: str = "",
                          probes: dict | None = None) -> APIRouter:
    """Build an APIRouter registering one POST endpoint per technique.

    techniques: list of (slug, title, sev, cvss[, cwe[, remediation]]) tuples.
    probes:     optional {slug: probe_fn(target, req) -> dict} mapping.
                If a probe is defined for a slug, the endpoint calls it
                instead of returning the static advisory. probe_fn should
                return a full response dict (use _adv_response() shape).

    This lets modules ship as advisories by default and upgrade individual
    techniques to live probes incrementally without rewriting the pack.
    """
    router = APIRouter()
    probes = probes or {}

    def _make_advisory(slug, title, sev, cvss, cwe, remed):
        # Scaffold endpoint: no live probe wired up. Always returns INFO with
        # a [NOT IMPLEMENTED] marker — never fake CRITICAL/HIGH.
        def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
            return _scaffold_response(slug, req.target, title,
                                       planned_sev=sev, planned_cvss=cvss,
                                       cwe=cwe, remediation=remed)
        _h.__name__ = slug
        return _h

    def _make_probe(slug, probe_fn):
        def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
            try:
                return probe_fn(req.target, req)
            except Exception as e:
                # Real probe attempted but failed — honest INFO with PROBE ERROR.
                return _adv_response(slug, req.target,
                    f"[PROBE ERROR] {str(e)[:120]}",
                    "INFO", "0.0", cwe="N/A",
                    remediation="Verify target reachability and retry.",
                    evidence=f"Live probe raised exception: {str(e)[:200]}")
        _h.__name__ = slug
        return _h

    for t in techniques:
        slug = t[0]; title = t[1]; sev = t[2]; cvss = t[3]
        cwe = t[4] if len(t) > 4 else "CWE-1395"
        remed = t[5] if len(t) > 5 else playbook_ref
        if slug in probes:
            handler = _make_probe(slug, probes[slug])
        else:
            handler = _make_advisory(slug, title, sev, cvss, cwe, remed)
        router.add_api_route(
            f"/api/{module_name}/{slug}",
            handler,
            methods=["POST"],
        )

    return router
