"""xss_dom_sinks_audit - findings rules.

Severity model:
  CRITICAL - confirmed source → sink dataflow inside the same JS asset
             (within ~400 chars / one function body of each other). A
             reflected/stored attacker-controlled value can reach the
             sink — DOM-XSS is likely live.
  LOW      - dangerous sink present but NO co-occurring taint source.
             A sink existing is not a proven exploit (no source→sink
             dataflow demonstrated) — it is a code-review pointer, not a
             confirmed DOM-XSS. Downgraded from HIGH to suppress
             false-positives on sites that use innerHTML/document.write
             with only static/trusted values.
  INFO     - fetch failed / no JS / dependency missing
  POSITIVE - JS analysed, zero sinks found
"""


def rule_confirmed_flows(s):
    flows = s.get("xss_dom_confirmed_flows") or []
    if not flows:
        return None
    # Aggregate sink+source combos for the headline
    sinks_seen = sorted({f.get("sink_id", "?") for f in flows})
    sources_seen: set = set()
    for f in flows:
        for src in f.get("sources") or []:
            sources_seen.add(src)
    src_list = sorted(sources_seen)
    return {
        "name": (f"Confirmed DOM-XSS dataflow — {s.get('xss_dom_flows_total', 0)} "
                  f"sink/source co-occurrence(s)"),
        "severity": "CRITICAL",
        "cvss": "8.8",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "evidence": (
            f"{len(flows)} source→sink flow(s) detected within "
            f"~400-char proximity in the page's JavaScript. "
            f"Sinks: {', '.join(sinks_seen[:5])}. "
            f"Sources: {', '.join(src_list[:5])}. "
            f"Sample snippet: {(flows[0].get('snippet') or '')[:180]}"
        ),
        "remediation": (
            "Sanitize every value read from document.location / .URL / "
            "window.name / postMessage data BEFORE it reaches innerHTML, "
            "document.write, eval, or setTimeout(string). Use the "
            "browser's Trusted Types API (TT) — Chrome supports a "
            "`Content-Security-Policy: require-trusted-types-for 'script'` "
            "header that fail-closes ANY untrusted assignment to these "
            "sinks at runtime. As a stopgap, wrap with DOMPurify.sanitize() "
            "for innerHTML and encodeURIComponent() for href/src. "
            "Reference: https://web.dev/articles/trusted-types"
        ),
    }


def rule_high_sinks_no_source(s):
    flows = s.get("xss_dom_confirmed_flows") or []
    if flows:
        return None
    total = s.get("xss_dom_sinks_total", 0)
    if total < 1:
        return None
    per_file = s.get("xss_dom_per_file") or []
    sample = ""
    for f in per_file:
        smp = f.get("sample_sink")
        if smp and smp.get("snippet"):
            sample = smp.get("snippet")[:160]
            break
    return {
        "name": f"Dangerous DOM sinks present ({total}) but no taint source / dataflow confirmed",
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "verified_exploit": False,
        "evidence": (
            f"{total} occurrence(s) of innerHTML / document.write / eval / "
            f"setTimeout(string) detected across "
            f"{s.get('xss_dom_assets_total', 0)} JS asset(s). NO attacker-"
            f"controllable taint source (document.location / .URL / "
            f"window.name / postMessage data / storage) was found within "
            f"~400 chars of any sink, so no source→sink dataflow is proven. "
            f"A sink existing is not itself an exploit — this is a "
            f"code-review pointer, not a confirmed DOM-XSS. It could still "
            f"be reachable via a longer code path / framework binding and "
            f"warrants manual review. "
            f"Sample sink: {sample or '(none)'}"
        ),
        "remediation": (
            "Audit each flagged sink manually. Replace innerHTML with "
            "textContent where the value is text-only, switch to "
            ".createElement+.appendChild for structural HTML, and remove "
            "any string-form setTimeout/setInterval / eval entirely. "
            "Deploy Trusted Types to fail-close at the browser level."
        ),
    }


def rule_fetch_failed(s):
    err = s.get("xss_dom_error")
    if not err:
        return None
    return {
        "name": "DOM-XSS sink audit could not fetch / parse target",
        "severity": "INFO",
        "evidence": str(err)[:300],
        "remediation": ("Confirm URL reachability + that BeautifulSoup4 + "
                        "httpx are installed in the scanner image."),
        "cwe": "CWE-1006",
    }


def rule_no_js(s):
    if s.get("xss_dom_error"):
        return None
    if (s.get("xss_dom_inline_count", 0)
            or s.get("xss_dom_external_count", 0)):
        return None
    return {
        "name": "Target page has no JavaScript — DOM-XSS surface = 0",
        "severity": "INFO",
        "evidence": ("No inline <script> blocks and no external script URLs "
                     "were found in the rendered HTML."),
        "remediation": ("No action — confirm this is intentional (static "
                        "landing page). Re-run on the authenticated app "
                        "route(s) where the real JS lives."),
        "cwe": "N/A",
    }


def rule_positive(s):
    if s.get("xss_dom_error"):
        return None
    if not (s.get("xss_dom_inline_count", 0) or s.get("xss_dom_external_count", 0)):
        return None
    if s.get("xss_dom_sinks_total", 0):
        return None
    if s.get("xss_dom_flows_total", 0):
        return None
    return {
        "name": "No dangerous DOM sinks detected in analysed JavaScript",
        "severity": "POSITIVE",
        "evidence": (f"{s.get('xss_dom_assets_total', 0)} JS asset(s) "
                     "scanned — no innerHTML/document.write/eval/"
                     "setTimeout(string) occurrences (after framework "
                     "fingerprint filtering)."),
        "remediation": (
            "Maintain current safe-DOM coding standards. Re-run after each "
            "front-end deploy; a single .innerHTML= line in a feature "
            "branch can open a DOM-XSS hole."
        ),
        "cwe": "CWE-79",
        "owasp": "A03:2021",
    }


XSS_DOM_SINKS_AUDIT_FINDING_RULES = [
    rule_confirmed_flows,
    rule_high_sinks_no_source,
    rule_fetch_failed,
    rule_no_js,
    rule_positive,
]
