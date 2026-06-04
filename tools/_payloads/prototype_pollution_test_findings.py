"""prototype_pollution_test - findings rules.

Severity model:
  CRITICAL - persistent pollution (marker survives into a clean follow-up
             GET → server-side Object.prototype contamination, likely
             cross-request and cross-session)
  HIGH     - reflected marker (server echoed our pollution key into the
             same response → likely sink, possibly client-only)
  MEDIUM   - stack-trace / lodash/Hoek error leaked under our payload
             (vulnerable code path exists; pollution probably works)
  INFO     - probe failed (httpx missing, target unreachable)
  POSITIVE - 0 hits across all probes
"""


def rule_persistent(s):
    p = s.get("proto_pollution_persistent") or []
    if not p:
        return None
    techs = sorted({h.get("technique", "?") for h in p})
    return {
        "name": (f"Server-side prototype pollution — "
                  f"{len(p)} payload(s) persisted across requests"),
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-1321",
        "owasp": "A03:2021",
        "evidence": (
            f"{len(p)} pollution payload(s) left a marker that REAPPEARED "
            f"in a follow-up clean GET (different cookie, no payload). "
            f"This is the signature of server-side Object.prototype "
            f"contamination — the runtime is now mutated and EVERY "
            f"subsequent request from EVERY user inherits the polluted "
            f"keys. Techniques: {', '.join(techs[:4])}. "
            f"Sample URL: {p[0].get('url', '?')}"
        ),
        "remediation": (
            "Patch the server immediately:\n"
            "  1. Restart the Node process to clear the polluted Object.prototype.\n"
            "  2. Audit every merge/extend/set/assign call — replace lodash "
            "_.merge / _.set / _.defaultsDeep with the post-4.17.12 "
            "patched versions and add the option { 'allowProtoProperties': "
            "false } where supported.\n"
            "  3. Add `Object.freeze(Object.prototype)` at process startup "
            "as a belt-and-suspenders defense.\n"
            "  4. Reject any JSON body whose top-level keys include "
            "`__proto__`, `constructor`, or `prototype` at the API gateway. "
            "Express middleware: `app.use(require('object.fromentries-sanitize'))`.\n"
            "Reference: https://github.com/HoLyVieR/prototype-pollution-nsec18"
        ),
    }


def rule_reflected(s):
    hits = s.get("proto_pollution_hits") or []
    refl = [h for h in hits
            if h.get("new_in_polluted") and not h.get("new_in_followup")]
    if not refl:
        return None
    techs = sorted({h.get("technique", "?") for h in refl})
    return {
        "name": (f"Prototype pollution marker reflected — "
                  f"{len(refl)} payload(s) echoed back"),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-1321",
        "owasp": "A03:2021",
        "evidence": (
            f"{len(refl)} pollution payload(s) produced markers that "
            f"appeared in the response but did NOT survive the follow-up "
            f"GET. This indicates a client-side sink that mirrors "
            f"polluted state into the rendered page — exploitable via "
            f"DOM-XSS or open-redirect chains. "
            f"Techniques: {', '.join(techs[:4])}."
        ),
        "remediation": (
            "Sanitize untrusted keys at the front-end JSON parser. "
            "Replace lodash _.merge with structured merge (Object.assign "
            "+ explicit key allowlist). Adopt JSON schema validation "
            "(AJV, Joi, Zod) at every request boundary that rejects "
            "payloads containing __proto__/constructor/prototype keys."
        ),
    }


def rule_error_hints(s):
    err = s.get("proto_pollution_error_hints") or []
    if not err:
        return None
    return {
        "name": (f"Application stack-trace / lodash error leaked under "
                  f"pollution payload ({len(err)} occurrence(s))"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-209",
        "owasp": "A05:2021",
        "evidence": (
            f"{len(err)} response(s) under prototype-pollution payloads "
            f"contained stack trace fragments — likely TypeError / "
            f"'Cannot read property of undefined' / lodash internals — "
            f"that were not present in the baseline. This is a strong "
            f"signal of a vulnerable merge/assign path."
        ),
        "remediation": (
            "Suppress stack traces in production (NODE_ENV=production), "
            "wrap the merge call in try/catch returning a 400, and run "
            "`npm audit` / `yarn audit` — most pre-4.17.12 lodash and "
            "Hoek versions are CVE'd for this exact pattern."
        ),
    }


def rule_probe_failed(s):
    err = s.get("proto_pollution_error")
    if not err:
        return None
    return {
        "name": "Prototype pollution probe could not complete",
        "severity": "INFO",
        "evidence": str(err)[:300],
        "remediation": ("Confirm httpx is installed in the runtime image "
                        "and the target URL is reachable from the scanner."),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("proto_pollution_error"):
        return None
    if s.get("proto_pollution_hits_total", 0):
        return None
    if not s.get("proto_pollution_payloads_sent"):
        return None
    return {
        "name": "No prototype pollution markers triggered",
        "severity": "POSITIVE",
        "evidence": (f"{s.get('proto_pollution_payloads_sent', 0)} payload(s) "
                     f"delivered across "
                     f"{s.get('proto_pollution_endpoints_tested', 0)} "
                     "endpoint(s); no response reflected, persisted, or "
                     "stack-traced under our pollution markers."),
        "remediation": ("Keep dependency hygiene: `npm audit` weekly + "
                        "freeze Object.prototype at process startup as "
                        "defense-in-depth. Re-test after any lodash / "
                        "Hoek / jquery-extend upgrade."),
        "cwe": "CWE-1321",
        "owasp": "A03:2021",
    }


PROTOTYPE_POLLUTION_TEST_FINDING_RULES = [
    rule_persistent,
    rule_reflected,
    rule_error_hints,
    rule_probe_failed,
    rule_positive,
]
