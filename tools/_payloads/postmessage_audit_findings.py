"""postmessage_audit - findings rules.

Severity model:
  HIGH     - one or more listeners accept any-origin (no origin check)
  MEDIUM   - origin is referenced but check pattern is ambiguous
             (e.g. `if (event.origin) { ... }` — truthy-only, no whitelist)
  INFO     - playwright/chromium not installed (return install hint)
             OR target unreachable
             OR page has zero postMessage listeners (informational only)
  POSITIVE - listeners exist AND all have proper origin checks
"""


def rule_unguarded(s):
    unguarded = s.get("postmessage_unguarded") or []
    if not unguarded:
        return None
    return {
        "name": (f"Unguarded postMessage listener(s) — "
                  f"{len(unguarded)} accept any origin"),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-346",
        "owasp": "A05:2021",
        "evidence": (
            f"{len(unguarded)} window.message listener(s) detected with "
            f"no event.origin check pattern (no '===', .indexOf, .includes, "
            f".startsWith, regex.test, or allowlist array). Any attacker "
            f"page that can open this URL in an iframe or popup window "
            f"can fire postMessage with arbitrary data, hijacking the "
            f"listener's logic (which often forwards data to innerHTML / "
            f"eval / location.href). "
            f"Sample handler: {(unguarded[0].get('snippet') or '')[:180]}"
        ),
        "remediation": (
            "Add an origin allowlist at the TOP of every postMessage "
            "handler:\n\n"
            "  window.addEventListener('message', (e) => {\n"
            "    const allow = ['https://trusted.example.com',\n"
            "                   'https://api.trusted.example.com'];\n"
            "    if (!allow.includes(e.origin)) return;\n"
            "    // ... safe to process e.data ...\n"
            "  });\n\n"
            "Never use substring/.indexOf alone — `e.origin.indexOf("
            "'evil.com')` matches 'https://goodsite.com/?ref=evil.com' as "
            "well. Reference: "
            "https://html.spec.whatwg.org/multipage/web-messaging.html"
        ),
    }


def rule_ambiguous(s):
    amb = s.get("postmessage_ambiguous") or []
    if not amb:
        return None
    return {
        "name": (f"postMessage listener(s) with ambiguous origin check "
                  f"({len(amb)} found)"),
        "severity": "MEDIUM",
        "cvss": "5.4",
        "cwe": "CWE-346",
        "owasp": "A05:2021",
        "evidence": (
            f"{len(amb)} listener(s) reference event.origin but no clear "
            f"equality / allowlist / regex check pattern was detected. "
            f"This frequently maps to truthy-only checks "
            f"(`if (e.origin) ...`) or to weak substring matches that "
            f"are bypassable. "
            f"Sample handler: {(amb[0].get('snippet') or '')[:180]}"
        ),
        "remediation": (
            "Manually review each flagged handler and confirm the origin "
            "check is a string-equality match against a closed allowlist. "
            "Convert any substring/indexOf check to `=== 'https://exact'` "
            "or `allowlist.includes(e.origin)`."
        ),
    }


def rule_no_listeners(s):
    if s.get("postmessage_error"):
        return None
    if s.get("postmessage_listeners_total", 0) > 0:
        return None
    return {
        "name": "No window.postMessage listeners detected on target page",
        "severity": "INFO",
        "evidence": ("Playwright loaded the page, executed all init scripts, "
                     "and observed zero registrations against window.message. "
                     "The page does not expose a cross-origin RPC surface."),
        "remediation": ("No action — re-run on routes that embed OAuth "
                        "popups, payment iframes, chat widgets, or any "
                        "feature that needs cross-frame messaging."),
        "cwe": "N/A",
    }


def rule_playwright_missing(s):
    err = s.get("postmessage_error") or ""
    if not err:
        return None
    if "playwright" not in err.lower() and "browser" not in err.lower():
        # different error -> use the unreachable rule
        return None
    return {
        "name": "Playwright / Chromium not installed on scanner host",
        "severity": "INFO",
        "evidence": str(err)[:300],
        "remediation": (
            "Install the Python lib with `pip install playwright`, then "
            "install the bundled browser via `playwright install chromium`. "
            "On Linux you also need: `apt install -y libnss3 libatk-bridge2.0-0 "
            "libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 "
            "libgbm1 libpango-1.0-0 libcairo2 libasound2`."
        ),
        "cwe": "CWE-1006",
    }


def rule_other_error(s):
    err = s.get("postmessage_error") or ""
    if not err:
        return None
    if "playwright" in err.lower() or "browser" in err.lower():
        return None  # already covered
    return {
        "name": "postMessage audit failed before listener enumeration",
        "severity": "INFO",
        "evidence": str(err)[:300],
        "remediation": ("Confirm the URL is reachable, doesn't immediately "
                        "redirect to a login wall, and doesn't crash "
                        "Chromium on load."),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("postmessage_error"):
        return None
    total = s.get("postmessage_listeners_total", 0)
    if total <= 0:
        return None
    if s.get("postmessage_unguarded") or s.get("postmessage_ambiguous"):
        return None
    return {
        "name": "postMessage listeners all enforce origin checks",
        "severity": "POSITIVE",
        "evidence": (f"{total} listener(s) detected; each one matched "
                     "an origin-check pattern (== / indexOf / includes / "
                     "regex / allowlist array)."),
        "remediation": ("Maintain current allowlist hygiene. When you add "
                        "a new trusted parent frame, add its EXACT origin "
                        "(scheme + host + port) — wildcards re-open the "
                        "exact problem you're guarding against."),
        "cwe": "CWE-346",
        "owasp": "A05:2021",
    }


POSTMESSAGE_AUDIT_FINDING_RULES = [
    rule_unguarded,
    rule_ambiguous,
    rule_no_listeners,
    rule_playwright_missing,
    rule_other_error,
    rule_positive,
]
