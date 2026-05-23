"""Shared helpers for the 19 Vuln-module scanners.

Underscore-prefixed so main.py's autoloader skips it.

What this fixes (after the Forge audit):
  Every vuln scanner had its own bespoke response handling. Customer PDFs
  showed "0 findings" for clean tests instead of green "PASS — no SQLi
  detected" affirmations like the Recon module does. Some scanners didn't
  guard against unreachable targets either.

Two helpers:
  precheck_target(base, req)
      Returns None if base URL is reachable. Otherwise returns a tuple
      (skipped_reason_string, http_status) you can plumb into a
      standard_response with skipped_reason=...

  vuln_response(tool, target, findings, tested, what_checked, ...)
      Drop-in replacement for standard_response() in vuln scanners.
      Automatically appends a POSITIVE finding when:
        - findings is empty AND
        - tested >= 1 AND
        - no skipped_reason set
      Result: clean scans render as green PASS cards in the PDF instead
      of blank/empty placeholders.
"""
from typing import Optional

from tools._shared import safe_get, wrap_finding, standard_response


def precheck_target(base: str, req, *, active_probes: bool = True) -> Optional[str]:
    """Quick reachability check. Returns None if reachable, else a string
    describing why we couldn't scan.

    Used by every vuln scanner BEFORE expensive probing — if the target's
    not reachable at all, we save the customer 30-60s of timeouts and
    surface a clear diagnostic instead.

    `active_probes=True` (default) signals the scanner WILL inject payloads
    (sqli/xss/lfi/cmd_injection/ssrf/xxe/etc.). When the target sits behind
    a WAF/CDN that hard-blocks injection attempts (Cloudflare challenge page,
    Akamai 403, Imperva 406, Fastly 403), every payload is silently dropped.
    Probing 40 payloads × 8 URLs against a blocked endpoint wastes 2-3 min
    per scanner — multiply by 10 active scanners and the orchestrator stalls
    for 20+ minutes. Pass active_probes=False from read-only scanners
    (headers/cookies/ssl/cms) so they're not skipped on WAF-fronted targets.
    """
    try:
        r = safe_get(base.rstrip("/") + "/", req=req,
                     allow_redirects=True, timeout=8)
    except Exception as e:
        return f"target unreachable: {type(e).__name__}: {str(e)[:80]}"
    if r is None:
        return ("target unreachable — connection refused, timeout, or "
                "DNS failure. Verify URL and that the host is online.")
    if r.status_code >= 500:
        return (f"target returned HTTP {r.status_code} on initial probe — "
                "server-side error, not a scan-able state.")

    # WAF-EARLY-EXIT-V1 — detect Cloudflare/Akamai/Imperva/Fastly/Sucuri/F5
    # actively blocking via challenge page or 403/406/429. Read response
    # headers (case-insensitive) for known WAF fingerprints.
    if active_probes:
        h = {k.lower(): str(v) for k, v in (r.headers or {}).items()}
        cf_ray   = h.get("cf-ray") or h.get("cf-cache-status")
        server   = (h.get("server") or "").lower()
        x_amzn   = h.get("x-amzn-trace-id")
        x_sucuri = h.get("x-sucuri-id")
        x_iinfo  = h.get("x-iinfo")          # Imperva Incapsula
        x_f5     = h.get("x-cnection") or h.get("x-f5-ltm-id")
        body_low = (r.text or "")[:4000].lower()

        waf = None
        if cf_ray:
            waf = "Cloudflare"
        elif "akamai" in server or "akamaighost" in server:
            waf = "Akamai"
        elif x_iinfo or "incap_ses" in body_low or "imperva" in body_low:
            waf = "Imperva/Incapsula"
        elif x_sucuri or "sucuri" in server:
            waf = "Sucuri"
        elif x_f5 or "big-ip" in server:
            waf = "F5 Big-IP"
        elif "fastly" in server or h.get("fastly-debug-digest"):
            waf = "Fastly"
        elif x_amzn and "awselb" in server:
            waf = "AWS WAF"

        # WAF detected + response was a challenge / block page → skip active probes.
        # Heuristic: status >= 403 OR body contains challenge markers OR
        # response < 800 bytes (typical CF interstitial is tiny).
        challenge_markers = (
            "checking your browser", "cf-challenge", "ray id:",
            "request unsuccessful", "access denied", "you have been blocked",
            "incident id", "reference #", "/_incapsula_resource",
        )
        is_challenge = (
            r.status_code in (403, 406, 429, 503) or
            any(m in body_low for m in challenge_markers)
        )
        if waf and is_challenge:
            return (f"Active probes skipped — {waf} WAF returned HTTP "
                    f"{r.status_code} on initial probe (challenge / block "
                    "page). Probing this target through the WAF would "
                    "produce zero confirmed findings while consuming "
                    "scan budget. To scan effectively: connect to origin "
                    "directly (bypass the WAF), or whitelist this scanner's "
                    "IP at the WAF.")
    return None


def vuln_response(
    *,
    tool: str,
    target: str,
    findings: list,
    tested: int,
    what_checked: str = "",
    skipped_reason: Optional[str] = None,
    raw_data: Optional[dict] = None,
    tests_summary: Optional[str] = None,
    severity_when_clean: str = "POSITIVE",
) -> dict:
    """Standard vuln-scanner response with auto POSITIVE emission.

    Use this in place of standard_response() in vuln scanners. When the
    scan ran cleanly with zero real findings, appends a "PASS" finding so
    the PDF renders a green confirmation card.

    Args:
      tool:           scanner name (e.g. "sqli")
      target:         scan target
      findings:       list of wrap_finding() dicts
      tested:         how many tests were performed
      what_checked:   short description for the POSITIVE message
                      (e.g. "URL parameters for time-based SQL injection")
      skipped_reason: if set, returns a skipped response (no POSITIVE)
      raw_data:       per-tool intel dict (passed through to standard_response)
      tests_summary:  custom summary line; auto-built if not provided
      severity_when_clean: defaults to POSITIVE; some tools may want INFO
    """
    if skipped_reason:
        return standard_response(
            tool=tool, target=target, findings=[],
            tests_performed=max(tested, 1),
            tests_summary=f"{tool}: {skipped_reason}",
            skipped_reason=skipped_reason,
            raw_data=raw_data,
        )

    # POSITIVE emission — only when we genuinely ran tests and found nothing
    real_findings = [f for f in (findings or [])
                      if (f.get("severity") or "").upper() in
                      ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
    if tested >= 1 and not real_findings:
        clean_msg = (f"No vulnerabilities detected by {tool} — "
                     f"target appears clean for {what_checked or 'this check'}.")
        findings = (findings or []) + [wrap_finding(
            clean_msg, severity_when_clean,
            evidence_marker=f"{tool} ran {tested} test(s) against {target}; "
                            f"no real findings emitted."
        )]

    summary = tests_summary or (
        f"{tool}: {tested} test(s) performed; "
        f"{len(real_findings)} real finding(s) emitted.")

    return standard_response(
        tool=tool, target=target, findings=findings,
        tests_performed=max(tested, 1),
        tests_summary=summary,
        raw_data=raw_data,
    )
