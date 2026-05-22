"""Parameter Discovery — findings rules library."""

_SENSITIVE_PARAM_NAMES = {
    "token", "key", "secret", "password", "passwd", "pwd",
    "api_key", "apikey", "access_token", "refresh_token",
    "session", "sessionid", "auth", "authorization",
    "private", "credential", "csrf", "csrf_token",
    "user_id", "uid", "userid",  # IDOR candidates
    "redirect", "redirect_url", "url", "next", "return_to",  # open-redirect
    "callback", "jsonp",  # JSONP injection
    "debug", "test", "admin",
}


def rule_params_found(s):
    n = len(s.get("params") or [])
    if n == 0: return None
    return {"name": f"{n} unique parameter(s) discovered",
            "severity": "INFO",
            "evidence": f"Across forms / URL query strings / JS literals"}


def rule_sensitive_params(s):
    sp = s.get("sensitive_params") or []
    if not sp: return None
    return {"name": f"Sensitive parameter names exposed ({len(sp)})",
            "severity": "HIGH",
            "cwe": "CWE-598",
            "evidence": f"Found: {', '.join(sp[:8])}",
            "remediation": "Parameters named token/key/secret/password etc. should NEVER appear in URL query strings — they get logged in proxy logs, browser history, Wayback. Move to POST body or HTTP headers. If any contain real credentials, ROTATE."}


def rule_idor_candidate_params(s):
    idor = [p for p in (s.get("sensitive_params") or [])
             if p in ("user_id", "uid", "userid", "id", "account_id")]
    if not idor: return None
    return {"name": f"IDOR-candidate parameters ({len(idor)})",
            "severity": "MEDIUM",
            "cwe": "CWE-639",
            "evidence": f"Numeric identifiers: {', '.join(idor)}",
            "remediation": "Numeric user/account IDs in URLs are IDOR attack vectors. Test: change ID, check if you can see other users' data. Use UUIDs + server-side authorization checks."}


def rule_redirect_params(s):
    r = [p for p in (s.get("sensitive_params") or [])
          if p in ("redirect", "redirect_url", "url", "next", "return_to", "returnUrl")]
    if not r: return None
    return {"name": f"Open-redirect candidate parameters ({len(r)})",
            "severity": "MEDIUM",
            "cwe": "CWE-601",
            "evidence": f"Found: {', '.join(r)}",
            "remediation": "Redirect parameters allow phishing if not validated. Maintain a server-side allowlist of valid redirect targets."}


def rule_forms_count(s):
    n = s.get("forms_count") or 0
    if n == 0: return None
    return {"name": f"{n} form(s) analyzed for parameters",
            "severity": "INFO",
            "evidence": f"Total HTML forms with extractable inputs"}


PARAMS_FINDING_RULES = [
    rule_params_found, rule_sensitive_params, rule_idor_candidate_params,
    rule_redirect_params, rule_forms_count,
]


def is_sensitive_param(name):
    return name.lower() in _SENSITIVE_PARAM_NAMES
