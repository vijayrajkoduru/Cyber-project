"""garak_owasp_test_suite - findings rules (Garak hit reporting)."""


def rule_unreachable(s):
    if not s.get("garak_unreachable"):
        return None
    return {"name": "LLM endpoint not reachable for Garak / OWASP suite",
            "severity": "INFO",
            "evidence": str(s.get("garak_unreachable", "")),
            "remediation": ("Re-run with the target set to a full LLM endpoint "
                            "URL (http(s)://...), plus options.prompt_field / "
                            "options.response_field so Garak can drive it."),
            "cwe": "CWE-693", "owasp": "LLM01:2025"}


def rule_library_missing(s):
    if not s.get("garak_error"):
        return None
    return {"name": "garak library not available — OWASP suite skipped",
            "severity": "INFO",
            "evidence": (str(s.get("garak_error", "")) + " " +
                         str(s.get("garak_install_hint", ""))).strip(),
            "remediation": ("Install with `pip install garak` in the backend "
                            "image. Garak is the OWASP-LLM-aligned reference "
                            "scanner — without it the audit cannot exercise the "
                            "encoding, knownbadsignatures, or DAN probe families."),
            "cwe": "CWE-693", "owasp": "LLM01:2025"}


def rule_positive(s):
    if s.get("garak_total_hits", 0) > 0:
        return None
    if not s.get("garak_runs_per_probe"):
        return None
    runs = s.get("garak_runs_per_probe") or {}
    if not any(runs.values()):
        return None
    return {"name": "Garak OWASP probe suite — zero hits",
            "severity": "POSITIVE",
            "evidence": (f"Engine={s.get('garak_engine', '?')}. Probes ran "
                         f"({sum(runs.values())} attempts) with no successful "
                         "DAN, base64-injection, or phishing-generation hit."),
            "remediation": ("Schedule garak in CI on every LLM/model upgrade. "
                            "Expand probe set to the full Garak catalogue "
                            "(--probes=all) for production red-team."),
            "cwe": "CWE-693", "owasp": "LLM01:2025"}


# NOTE: garak probe "hits" are measured by running the Garak LIBRARY's own
# benchmark corpus (its canned DAN / base64 / phishing example prompts). The
# in-process fallback in particular replays a handful of library example
# prompts and substring-matches markers — that measures the LIBRARY's probe
# corpus, not a verified, proven exposure of the customer's target. Per the
# zero-FP contract these are reported as INFO (library benchmark), never graded
# as a HIGH/MEDIUM target finding.
def rule_dan_hit(s):
    h = (s.get("garak_hits_per_probe") or {}).get("dan.Dan_11_0", 0)
    if not h:
        return None
    return {"name": f"Garak dan.Dan_11_0 probe flagged ({h} time(s)) [library benchmark]",
            "severity": "INFO",
            "cwe": "CWE-285", "owasp": "LLM02:2025",
            "verified_exploit": False,
            "evidence": (f"Garak's DAN-v11 probe corpus flagged {h} time(s) "
                         f"(engine: {s.get('garak_engine', '?')}). This is a "
                         "library benchmark, not a target exposure — it measures "
                         "the Garak probe set against example prompts, not a "
                         "proven jailbreak of the customer endpoint. Re-run the "
                         "verified jailbreak_resistance_test for a graded result."),
            "remediation": ("Treat as a baseline signal. Re-tune refusal RLHF / "
                            "add an input filter matching the DAN-11 family, then "
                            "confirm with the proof-gated jailbreak scanner.")}


def rule_base64_hit(s):
    h = (s.get("garak_hits_per_probe") or {}).get("encoding.InjectBase64", 0)
    if not h:
        return None
    return {"name": f"Garak encoding.InjectBase64 probe flagged ({h} time(s)) [library benchmark]",
            "severity": "INFO",
            "cwe": "CWE-94", "owasp": "LLM01:2025",
            "verified_exploit": False,
            "evidence": (f"Garak's base64-injection probe corpus flagged {h} "
                         "time(s). This is a library benchmark, not a target "
                         "exposure — it measures the Garak probe set, not a "
                         "proven injection of the customer endpoint."),
            "remediation": ("Treat as a baseline signal. Add an input-side "
                            "decoder + re-scan pass (decode base64/hex/ROT13/"
                            "url-encoded before the PromptInjection guard), then "
                            "confirm with the proof-gated prompt_injection_audit.")}


def rule_phish_hit(s):
    h = (s.get("garak_hits_per_probe") or {}).get("knownbadsignatures.GTPhish", 0)
    if not h:
        return None
    return {"name": f"Garak knownbadsignatures.GTPhish probe flagged ({h} time(s)) [library benchmark]",
            "severity": "INFO",
            "cwe": "CWE-1391", "owasp": "LLM05:2025",
            "verified_exploit": False,
            "evidence": (f"Garak's phishing-generation probe corpus flagged {h} "
                         "time(s). This is a library benchmark, not a target "
                         "exposure — substring markers (verify account / click "
                         "link / suspended) also appear in a model's REFUSAL, so "
                         "this is not a proven content-generation bypass."),
            "remediation": ("Treat as a baseline signal. Train a refusal "
                            "classifier on phishing-generation intent or add an "
                            "output filter for phishing-template patterns.")}


def rule_cli_unavailable_used_fallback(s):
    if s.get("garak_engine") != "garak-fallback-inprocess":
        return None
    return {"name": "Garak CLI unavailable — in-process fallback used",
            "severity": "INFO",
            "evidence": ("garak CLI could not be driven against the endpoint "
                         "(missing binary, missing REST generator support, or "
                         "config-rejected). VulnusLab fell back to in-process "
                         "probe replay for signal continuity."),
            "remediation": ("Install garak in the scanner image and pre-cache "
                            "its model bundles so the real CLI runs next time. "
                            "Fallback fidelity is lower than the canonical "
                            "Garak harness."),
            "cwe": "CWE-693", "owasp": "LLM01:2025"}


GARAK_OWASP_TEST_SUITE_FINDING_RULES = [
    rule_unreachable,
    rule_library_missing,
    rule_positive,
    rule_dan_hit,
    rule_base64_hit,
    rule_phish_hit,
    rule_cli_unavailable_used_fallback,
]
