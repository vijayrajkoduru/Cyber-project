"""session_predict_audit - finding rules (VL-METHOD aware).

Web-app session cookie predictability audit. Reads state populated by
the SessionPredictAudit 7-stage scanner:

  - methodology_findings   : list of weak/missing-flag/fixation findings
  - target_base / login_url
  - fingerprint            : framework, cookies-list, status, server
  - primary_session_cookie : name of the cookie we focused on
  - session_samples_count  : how many fresh sessions we captured
  - avg_entropy / min_entropy / max_entropy
  - skipped_reason         : pre_flight skip reason (if any)
  - chain_next             : downstream session-attack handoffs

Severity model:
  CONFIRMED sequential session ID          -> CRITICAL CVSS 8.1 CWE-330
  CONFIRMED low-entropy session            -> HIGH     CVSS 7.5 CWE-330
  CONFIRMED session fixation               -> HIGH     CVSS 7.5 CWE-384
  CONFIRMED short session ID               -> MEDIUM   CVSS 6.5 CWE-340
  CONFIRMED missing Secure                 -> MEDIUM   CVSS 5.3 CWE-319
  CONFIRMED missing HttpOnly               -> MEDIUM   CVSS 5.3 CWE-1004
  CONFIRMED missing SameSite               -> LOW      CVSS 4.3 CWE-352
  SUSPECTED any                            -> LOW      CVSS 3.7
  Clean posture (0 findings + ent >= 4.5)  -> POSITIVE
  No session cookies detected              -> INFO
  Target unreachable / input missing       -> INFO
"""


INTEL_FIELDS = [
    ("Target",                       "target_base"),
    ("Framework Fingerprint",        "fingerprint"),
    ("Primary session cookie",       "primary_session_cookie"),
    ("Samples captured",             "session_samples_count"),
    ("Avg entropy (bits/char)",      "avg_entropy"),
    ("Min entropy",                  "min_entropy"),
    ("Max entropy",                  "max_entropy"),
    ("Stage timings (ms)",           "stage_timings"),
    ("Stage errors",                 "stage_errors"),
    ("Chain ID",                     "chain_id"),
]


# ── helper: group methodology_findings by privilege class ──────────


def _findings_by_privilege(s):
    """Group methodology_findings into severity buckets used by rules.

      confirmed_low_entropy
      confirmed_sequential
      confirmed_short_token
      confirmed_fixation
      confirmed_missing_secure
      confirmed_missing_httponly
      confirmed_missing_samesite
      suspected
    """
    buckets = {
        "confirmed_low_entropy":      [],
        "confirmed_sequential":       [],
        "confirmed_short_token":      [],
        "confirmed_fixation":         [],
        "confirmed_missing_secure":   [],
        "confirmed_missing_httponly": [],
        "confirmed_missing_samesite": [],
        "suspected":                  [],
    }
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        kind = f.get("kind", "")
        if conf != "CONFIRMED":
            buckets["suspected"].append(f)
            continue
        if kind == "low_entropy_session":
            buckets["confirmed_low_entropy"].append(f)
        elif kind == "sequential_session_id":
            buckets["confirmed_sequential"].append(f)
        elif kind == "short_session_id":
            buckets["confirmed_short_token"].append(f)
        elif kind == "session_fixation":
            buckets["confirmed_fixation"].append(f)
        elif kind == "missing_secure_flag":
            buckets["confirmed_missing_secure"].append(f)
        elif kind == "missing_httponly_flag":
            buckets["confirmed_missing_httponly"].append(f)
        elif kind == "missing_samesite_flag":
            buckets["confirmed_missing_samesite"].append(f)
        else:
            buckets["suspected"].append(f)
    return buckets


# ── INFO / POSITIVE rules: environmental / clean states ────────────


def rule_target_unreachable(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "target http not reachable" not in reason:
        return None
    return {
        "name": "Target HTTP endpoint unreachable - session cookie audit skipped",
        "severity": "INFO",
        "evidence": (
            s.get("skipped_reason") or
            "Pre-flight HTTP probe to target/login_url returned no "
            "valid response (timeout or connection refused). The "
            "session predictability audit cannot proceed without a "
            "reachable web endpoint."),
        "remediation": (
            "Verify the target URL is correct and the web server is "
            "running. If the application is behind a WAF that blocks "
            "scanner user-agents, allow-list the scan source. Re-run "
            "once the endpoint is reachable."),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "requires target url" not in reason:
        return None
    return {
        "name": "Session predictability audit skipped - target URL missing",
        "severity": "INFO",
        "evidence": (
            "Scanner requires a base URL to capture session cookies "
            "from. Supply via the request body 'target' field "
            "(e.g. https://app.example.com). Optionally also supply "
            "options.login_url to point at a specific path that issues "
            "a session cookie (default '/')."),
        "remediation": (
            "Provide a target URL and re-run. For applications where "
            "the session cookie is only issued after authentication, "
            "set options.login_url to a path that issues Set-Cookie "
            "anonymously (login page, landing page, etc)."),
        "cwe": "CWE-1006",
    }


def rule_no_session_cookie_detected(s):
    # Only fire if pre_flight succeeded but no cookies were captured.
    if s.get("skipped_reason"):
        return None
    fp = s.get("fingerprint") or {}
    cookies = fp.get("cookies") or []
    if cookies:
        return None
    if not s.get("primary_session_cookie"):
        return {
            "name": "No session cookie detected on target",
            "severity": "INFO",
            "evidence": (
                "Target did not set any session cookie. Application "
                "may use Authorization header / JWT / no auth. The "
                "session predictability audit only inspects HTTP "
                "Set-Cookie headers; bearer-token / JWT-based auth "
                "should be tested separately via the jwt_audit and "
                "oauth_audit scanners."),
            "remediation": (
                "If this app is stateless and uses bearer tokens, run "
                "tools/password/tier5_web/jwt_audit instead. If a "
                "session cookie SHOULD have been issued, check whether "
                "the login_url path is correct (default '/' may not "
                "trigger session creation - try '/login' or '/auth')."),
            "cwe": "CWE-1006",
        }
    return None


def rule_clean_session_posture(s):
    """POSITIVE: 0 findings AND avg_entropy >= 4.5 AND all 3 flags
    present on the primary cookie. Means the app meets the modern
    cookie-security baseline."""
    if s.get("skipped_reason"):
        return None
    if int(s.get("methodology_total") or 0) > 0:
        return None
    avg_ent = float(s.get("avg_entropy") or 0.0)
    if avg_ent < 4.5:
        return None
    fp = s.get("fingerprint") or {}
    primary = (s.get("primary_session_cookie") or "").lower()
    if not primary:
        return None
    primary_cookie = None
    for c in (fp.get("cookies") or []):
        if (c.get("name") or "").lower() == primary:
            primary_cookie = c
            break
    if not primary_cookie:
        return None
    if not (primary_cookie.get("secure")
            and primary_cookie.get("http_only")
            and primary_cookie.get("same_site")):
        return None
    return {
        "name": "Session cookies follow modern security baseline",
        "severity": "POSITIVE",
        "evidence": (
            f"Primary session cookie '{primary_cookie.get('name','?')}' "
            f"on {s.get('target_base','target')} meets all modern "
            f"web-session security requirements: average Shannon "
            f"entropy = {avg_ent:.2f} bits/char (>= 4.5 threshold) "
            f"across {s.get('session_samples_count','?')} captured "
            f"samples, Secure flag set, HttpOnly flag set, "
            f"SameSite={primary_cookie.get('same_site','?')} enforced. "
            f"No sequential patterns, no embedded timestamps, no "
            f"session fixation. Framework: "
            f"{fp.get('framework','unknown')}."),
        "remediation": (
            "Continue enforcing this baseline. When upgrading the "
            "session backend, retain: cryptographically random 128+ "
            "bit session IDs, Secure flag (HTTPS-only), HttpOnly "
            "(no JS access), SameSite=Lax or Strict (CSRF resistance), "
            "session rotation on login and privilege change."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


# ── CONFIRMED finding rules (grouped by severity) ──────────────────


def rule_confirmed_sequential_session_id(s):
    b = _findings_by_privilege(s)
    seq = b["confirmed_sequential"]
    if not seq:
        return None
    patterns = sorted({f.get("pattern", "?") for f in seq})
    cookie_names = sorted({f.get("cookie_name", "?") for f in seq})
    return {
        "name": (f"CRITICAL: Sequential session ID pattern detected on "
                 f"{', '.join(cookie_names)}"),
        "severity": "CRITICAL", "cvss": "8.1",
        "cwe": "CWE-330", "owasp": "A07:2021",
        "evidence": (
            f"Captured session cookies follow a predictable sequence: "
            f"{', '.join(patterns)}. Across "
            f"{s.get('session_samples_count', '?')} fresh sessions the "
            f"pattern reproduces consistently. An attacker can guess "
            f"valid future session IDs without ever brute-forcing - "
            f"e.g. for monotonic tails, fetching a single fresh cookie "
            f"reveals the next N session IDs by simple increment. "
            f"Verification method: entropy_resampling_persisted "
            f"(pattern held on a second 10-sample capture)."),
        "remediation": (
            "1. Replace the predictable session ID generator with a "
            "cryptographically secure random source (Python "
            "secrets.token_urlsafe(32), Java SecureRandom, .NET "
            "RandomNumberGenerator). 2. Session IDs must be at least "
            "128 bits of randomness, encoded as 22+ char URL-safe "
            "base64 or 32+ char hex. 3. Never embed timestamps, user "
            "IDs, or counters in session IDs - even encrypted, they "
            "leak structural information. 4. Rotate the session ID "
            "on login, privilege change, and password change. "
            "5. After deploying the fix, force-expire all existing "
            "sessions (they were predictable too)."),
    }


def rule_confirmed_low_entropy(s):
    b = _findings_by_privilege(s)
    low = b["confirmed_low_entropy"]
    if not low:
        return None
    avg_ent = float(s.get("avg_entropy") or 0.0)
    return {
        "name": (f"HIGH: Low-entropy session cookie - avg "
                 f"{avg_ent:.2f} bits/char (< 4.0 threshold)"),
        "severity": "HIGH", "cvss": "7.5",
        "cwe": "CWE-330", "owasp": "A07:2021",
        "evidence": (
            f"Primary session cookie on "
            f"{s.get('target_base', 'target')} averages "
            f"{avg_ent:.2f} bits/char Shannon entropy across "
            f"{s.get('session_samples_count', '?')} captured samples. "
            f"That is below the 4.0 bits/char industry baseline for "
            f"session IDs (truly random base64-url hits ~5.9 bits/"
            f"char; hex hits ~4.0). Low entropy means the keyspace is "
            f"small enough for online or offline guessing attacks. "
            f"Verification method: entropy_resampling_persisted "
            f"(re-captured 10 more samples, entropy stayed low)."),
        "remediation": (
            "1. Identify the session ID generator and replace its "
            "source of randomness with a CSPRNG (secrets.token_urlsafe "
            "in Python, SecureRandom in Java, crypto.randomBytes in "
            "Node, RandomNumberGenerator in .NET). 2. Increase the "
            "encoded length to 22+ chars URL-safe base64 (128 bits) "
            "or 32+ chars hex. 3. After deploying, force-expire all "
            "existing sessions because they were issued with the weak "
            "generator. 4. Add a regression test that compares "
            "session ID entropy across N captures against a 5.5 "
            "bits/char floor."),
    }


def rule_confirmed_session_fixation(s):
    b = _findings_by_privilege(s)
    fix = b["confirmed_fixation"]
    if not fix:
        return None
    cookie_names = sorted({f.get("cookie_name", "?") for f in fix})
    return {
        "name": (f"HIGH: Session fixation vulnerability on "
                 f"{', '.join(cookie_names)}"),
        "severity": "HIGH", "cvss": "7.5",
        "cwe": "CWE-384", "owasp": "A07:2021",
        "evidence": (
            f"Server honored an attacker-chosen session cookie value "
            f"and did NOT rotate to a fresh ID on subsequent requests. "
            f"An attacker can pre-set a session cookie in the victim's "
            f"browser (via XSS-set-cookie, subdomain cookie poison, "
            f"reflected response splitting), wait for the victim to "
            f"log in, then hijack the now-authenticated session "
            f"because the same cookie value is still valid. "
            f"Verification method: session_fixation_retest_confirmed "
            f"(retried with a second attacker-chosen value, still "
            f"kept)."),
        "remediation": (
            "1. CRITICAL: rotate the session ID on every authentication "
            "boundary - successful login, password change, MFA "
            "completion, privilege elevation. In Java Servlet: call "
            "HttpServletRequest.changeSessionId() inside the post-login "
            "handler. In PHP: call session_regenerate_id(true). In "
            "ASP.NET: regenerate the SessionID via "
            "Session.Abandon()+new login. 2. Reject inbound cookies "
            "that don't match a server-side issued session (validate "
            "the session ID against a server-side store on every "
            "request). 3. Set Secure + HttpOnly + SameSite=Strict to "
            "limit pre-fixation attack vectors."),
    }


def rule_confirmed_short_session_id(s):
    b = _findings_by_privilege(s)
    short = b["confirmed_short_token"]
    if not short:
        return None
    cookie_names = sorted({f.get("cookie_name", "?") for f in short})
    return {
        "name": (f"MEDIUM: Session cookie too short on "
                 f"{', '.join(cookie_names)} (< 16 chars)"),
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-340", "owasp": "A07:2021",
        "evidence": (
            f"Primary session cookie length is below the 16-character "
            f"minimum required for a brute-force-resistant session "
            f"ID. Even if the underlying entropy source is strong, a "
            f"short encoded length keeps the total keyspace small "
            f"enough for distributed online guessing attacks. "
            f"Verification: entropy_resampling_persisted (re-captured "
            f"10 more sessions, length stayed below 16)."),
        "remediation": (
            "1. Configure the session backend to emit 22+ char "
            "URL-safe base64 IDs (128 bits of randomness). Most "
            "frameworks default to this already - check the "
            "configuration that overrode it. 2. Audit for legacy "
            "cookie-shortening middleware or proxy URL rewriters that "
            "truncated session IDs in transit. 3. After deploying the "
            "fix, force-expire all existing sessions issued with the "
            "shorter format."),
    }


def rule_confirmed_missing_secure(s):
    b = _findings_by_privilege(s)
    miss = b["confirmed_missing_secure"]
    if not miss:
        return None
    return {
        "name": (f"MEDIUM: Session cookie missing Secure flag on "
                 f"{miss[0].get('cookie_name','?')}"),
        "severity": "MEDIUM", "cvss": "5.3",
        "cwe": "CWE-319", "owasp": "A05:2021",
        "evidence": (
            f"Primary session cookie was Set-Cookie'd without the "
            f"Secure attribute. Browsers will therefore include this "
            f"cookie on plaintext HTTP requests, allowing any on-path "
            f"attacker (open Wi-Fi, captive portal, ARP spoofing) to "
            f"steal the session token. Even if the application is "
            f"HTTPS-only, a single mistakenly-redirected HTTP request "
            f"leaks the cookie. Verification method: "
            f"set_cookie_header_inspection."),
        "remediation": (
            "1. Add Secure to every session-cookie Set-Cookie header. "
            "Java Servlet: response.addCookie(c) where c.setSecure"
            "(true). PHP: ini_set('session.cookie_secure', '1'). "
            "Node Express: app.use(session({ cookie: { secure: true } "
            "})). ASP.NET: <httpCookies requireSSL=\"true\"/>. "
            "2. Combine with HSTS (Strict-Transport-Security) to "
            "force browsers to refuse plain HTTP entirely. 3. Test by "
            "issuing a plaintext HTTP request - the cookie must not "
            "be sent."),
    }


def rule_confirmed_missing_httponly(s):
    b = _findings_by_privilege(s)
    miss = b["confirmed_missing_httponly"]
    if not miss:
        return None
    return {
        "name": (f"MEDIUM: Session cookie missing HttpOnly flag on "
                 f"{miss[0].get('cookie_name','?')}"),
        "severity": "MEDIUM", "cvss": "5.3",
        "cwe": "CWE-1004", "owasp": "A05:2021",
        "evidence": (
            f"Primary session cookie was Set-Cookie'd without the "
            f"HttpOnly attribute. Browsers will therefore allow "
            f"document.cookie to read its value from JavaScript, "
            f"meaning any XSS vulnerability in the application (now "
            f"or in the future) immediately escalates to full session "
            f"theft. HttpOnly is the cheapest XSS-mitigation control "
            f"available. Verification method: "
            f"set_cookie_header_inspection."),
        "remediation": (
            "1. Add HttpOnly to every session-cookie Set-Cookie "
            "header. Java Servlet: c.setHttpOnly(true). PHP: "
            "ini_set('session.cookie_httponly', '1'). Node Express: "
            "app.use(session({ cookie: { httpOnly: true } })). "
            "ASP.NET: <httpCookies httpOnlyCookies=\"true\"/>. "
            "2. If the SPA legitimately needs the session value in JS "
            "(it almost never does), migrate to a Authorization-header "
            "bearer token pattern instead - keeping the session in JS "
            "is an XSS-vulnerability amplifier."),
    }


def rule_confirmed_missing_samesite(s):
    b = _findings_by_privilege(s)
    miss = b["confirmed_missing_samesite"]
    if not miss:
        return None
    return {
        "name": (f"LOW: Session cookie missing SameSite attribute on "
                 f"{miss[0].get('cookie_name','?')}"),
        "severity": "LOW", "cvss": "4.3",
        "cwe": "CWE-352", "owasp": "A01:2021",
        "evidence": (
            f"Primary session cookie was Set-Cookie'd without an "
            f"explicit SameSite attribute. Modern browsers default to "
            f"SameSite=Lax for unset cookies, but: (a) older browser "
            f"versions still default to None (CSRF-susceptible), "
            f"(b) explicit SameSite=Lax or Strict is required by some "
            f"compliance baselines (PCI-DSS 4.0, NIST 800-63B), "
            f"(c) some browsers behave inconsistently with the "
            f"implicit-default. Verification method: "
            f"set_cookie_header_inspection."),
        "remediation": (
            "1. Add SameSite=Lax (default safe choice) or SameSite="
            "Strict (highest protection, may break legitimate "
            "cross-site links) to every session-cookie Set-Cookie "
            "header. 2. If the app needs cross-site embedding (OAuth, "
            "iframe SSO), use SameSite=None and pair it with Secure "
            "(SameSite=None without Secure is rejected by Chrome). "
            "3. Test CSRF resistance by submitting a cross-origin POST "
            "with credentials - the session cookie must not be sent."),
    }


def rule_suspected_weak_session(s):
    b = _findings_by_privilege(s)
    suspected = b["suspected"]
    if not suspected:
        return None
    kinds = sorted({f.get("kind", "?") for f in suspected})
    return {
        "name": (f"SUSPECTED weak session indicator - "
                 f"{len(suspected)} finding(s) need manual verification"),
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-330", "owasp": "A07:2021",
        "evidence": (
            f"The scanner flagged {len(suspected)} potential session "
            f"weakness indicator(s) ({', '.join(kinds)}) but the "
            f"resampling verification step could not reproduce them. "
            f"Possible causes: rate-limiter throttled the resampler, "
            f"server returned different cookies for different paths, "
            f"or the original detection was a statistical coincidence "
            f"on a small sample."),
        "remediation": (
            "Re-run the scan with options.sample_count=100 and "
            "options.always_deep=True to gather a larger sample "
            "set. If the same finding reappears under the larger "
            "sample, treat at the appropriate CONFIRMED severity. "
            "Manual verification with Burp Suite Sequencer is also "
            "recommended for borderline entropy findings."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": (
            "Confirmed session weaknesses enable downstream exploit "
            "scanners: " + ", ".join(chain_next) + ". For session "
            "fixation, post_exploit_session_takeover validates "
            "post-login privilege via the fixed cookie. For low-"
            "entropy / sequential IDs, post_exploit_session_brute "
            "demonstrates keyspace-reduction by enumerating valid "
            "neighboring session IDs."),
        "remediation": (
            "Re-run with chain_id propagation to automatically follow "
            "up with: " + ", ".join(chain_next) + ". The VL-METHOD "
            "chaining engine spawns these with the captured session "
            "context via the cross-scanner pipeline."),
        "cwe": "CWE-1006",
    }


SESSION_PREDICT_AUDIT_FINDING_RULES = [
    rule_target_unreachable,
    rule_input_missing,
    rule_no_session_cookie_detected,
    rule_clean_session_posture,
    rule_confirmed_low_entropy,
    rule_confirmed_session_fixation,
    rule_confirmed_sequential_session_id,
    rule_confirmed_short_session_id,
    rule_confirmed_missing_secure,
    rule_confirmed_missing_httponly,
    rule_confirmed_missing_samesite,
    rule_suspected_weak_session,
    rule_chain_handoff,
]
