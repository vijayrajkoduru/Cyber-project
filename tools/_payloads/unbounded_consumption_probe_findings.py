"""unbounded_consumption_probe - findings rules (OWASP LLM10:2025 mapping).

Advisory-toned only. True cost/availability impact of unbounded consumption
depends on account/billing context the scanner cannot see, so the "no limits
observed" finding is conservative LOW + SUSPECTED, never HIGH/CRITICAL. The
probe sends only a FEW single bounded requests (no flooding, no concurrency).
"""


def rule_positive(s):
    """Endpoint actively capped / limited / refused the oversized probes."""
    if s.get("uncon_error"):
        return None
    if not s.get("uncon_attempted"):
        return None
    limited = s.get("uncon_limited_signals") or []
    if not limited:
        return None
    # A POSITIVE requires that we saw a real limiting signal AND did NOT see an
    # unbounded (very large, uncapped) response.
    if s.get("uncon_unbounded_observed"):
        return None
    return {"name": "LLM endpoint enforces input/output limits (resilient to "
                    "unbounded consumption)",
            "severity": "POSITIVE",
            "evidence": ("Across "
                         f"{s.get('uncon_attempted', 0)} bounded probe(s) the "
                         "endpoint capped, truncated, refused, or rate-limited "
                         "oversized input/output. Observed limiting signals: "
                         + ", ".join(limited[:6])
                         + (f" (+{len(limited)-6} more)"
                            if len(limited) > 6 else "")
                         + f". Largest response observed: "
                         f"{s.get('uncon_max_response_chars', 0)} chars in "
                         f"{s.get('uncon_max_elapsed', 0)}s."),
            "remediation": ("Keep enforcing maximum input length, maximum output "
                            "tokens, per-user/IP rate limits, request timeouts, "
                            "and billing/cost alerts. Re-test after any model or "
                            "gateway change."),
            "cwe": "CWE-770", "owasp": "LLM10:2025"}


def rule_unreachable(s):
    """Probe could not run (no/invalid target, missing dep, transport error)."""
    if s.get("uncon_error"):
        return {"name": "Unbounded-consumption probe could not run",
                "severity": "INFO",
                "evidence": str(s["uncon_error"]),
                "remediation": ("Confirm the endpoint URL (full http(s):// POST "
                                "URL), reachability from the scanner, and any "
                                "auth headers (auth_bearer / options.headers). "
                                "The probe sends only a few small bounded "
                                "requests with a strict client timeout."),
                "cwe": "CWE-755"}
    if (s.get("uncon_attempted", 0) == 0
            and s.get("uncon_transport_errors", 0) > 0):
        return {"name": "LLM endpoint refused or timed out on all probes",
                "severity": "INFO",
                "evidence": (f"{s.get('uncon_transport_errors', 0)} transport "
                             "error(s) / timeout(s), zero completed responses."),
                "remediation": ("Check auth headers (auth_bearer / "
                                "options.headers), endpoint URL, and that the "
                                "endpoint accepts a benign JSON POST."),
                "cwe": "CWE-755"}
    return None


def rule_no_limits(s):
    """No apparent input/output cap, refusal, or rate-limit signal — advisory.

    SUSPECTED / LOW only: actual cost or availability impact requires account /
    billing context this read-only probe cannot determine. Evidence is the
    observed (large) response sizes and times with no observed cap.
    """
    if s.get("uncon_error"):
        return None
    if not s.get("uncon_attempted"):
        return None
    # Only fire when we actually saw an unbounded-looking response AND saw no
    # limiting signal at all — keeps this zero-FP / conservative.
    if not s.get("uncon_unbounded_observed"):
        return None
    if s.get("uncon_limited_signals"):
        return None
    samples = s.get("uncon_probe_summaries") or []
    sample_txt = "; ".join(
        f"{p.get('label', '?')}: {p.get('response_chars', 0)} chars in "
        f"{p.get('elapsed', 0)}s (HTTP {p.get('http_status', '?')})"
        for p in samples[:3])
    return {"name": "No input/output limits observed on LLM endpoint "
                    "(unbounded consumption / cost-DoS exposure)",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-770", "owasp": "LLM10:2025",
            "verified_exploit": False,
            "confidence": "SUSPECTED",
            "evidence": ("Oversized/long-output bounded probes returned very "
                         "large responses with no observed input-size cap, "
                         "output truncation, refusal, or rate-limit signal. "
                         f"Largest: {s.get('uncon_max_response_chars', 0)} "
                         f"chars in {s.get('uncon_max_elapsed', 0)}s. "
                         + (f"Probes: {sample_txt}. " if sample_txt else "")
                         + "SUSPECTED: real cost/availability impact depends on "
                         "account, billing, and gateway context this read-only "
                         "probe cannot observe — it sent only a few single "
                         "bounded requests, NOT a load/DoS test."),
            "remediation": ("Enforce a maximum input length and maximum output "
                            "tokens per request; apply per-user and per-IP rate "
                            "limits and usage quotas; set strict request "
                            "timeouts; and configure billing/cost alerts and "
                            "budget caps so a malicious or runaway client cannot "
                            "drive unbounded token spend or degrade availability "
                            "(OWASP LLM10:2025 Unbounded Consumption).")}


UNBOUNDED_CONSUMPTION_PROBE_FINDING_RULES = [
    rule_positive,
    rule_unreachable,
    rule_no_limits,
]
