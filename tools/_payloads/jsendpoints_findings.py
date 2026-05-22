"""JS Endpoint Extractor — findings rules library."""
import re

# Sensitive endpoint patterns
_SENSITIVE_PATTERNS = [
    (r"/admin", "admin endpoint"),
    (r"/internal", "internal endpoint"),
    (r"/debug", "debug endpoint"),
    (r"/staging|/dev/|/test/", "non-prod endpoint"),
    (r"/api/.*/(users|admin|config|secret|key)", "sensitive API path"),
    (r"/(import|export)/", "import/export endpoint"),
    (r"\.env|\.bak|/config\.", "config-like endpoint"),
]

# Hardcoded secret patterns
_SECRET_PATTERNS = [
    (r"(?i)api[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]", "API key"),
    (r"(?i)secret\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]", "secret"),
    (r"(?i)bearer\s+([A-Za-z0-9_\-\.]{30,})", "Bearer token"),
    (r"(?i)password\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]", "hardcoded password"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (r"ya29\.[0-9A-Za-z\-_]+", "Google OAuth token"),
    (r"ghp_[a-zA-Z0-9]{30,}", "GitHub personal access token"),
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI / Stripe-style secret key"),
]


def rule_endpoints_found(s):
    n = len(s.get("endpoints") or [])
    if n == 0: return None
    return {"name": f"{n} API endpoint(s) extracted from JS",
            "severity": "INFO",
            "evidence": f"Found across {s.get('js_files_scanned', 0)} JS file(s)"}


def rule_sensitive_endpoints(s):
    se = s.get("sensitive_endpoints") or []
    if not se: return None
    return {"name": f"Sensitive endpoints leaked in JS bundle ({len(se)})",
            "severity": "HIGH",
            "cwe": "CWE-540",
            "evidence": "; ".join(f"{e['path']} ({e['why']})" for e in se[:5]),
            "remediation": "JS bundles are public — anything an attacker can read in DevTools is part of your attack surface. Hide /admin / /internal / /debug from frontend JS; require server-side auth for them."}


def rule_secrets_in_js(s):
    secs = s.get("secrets_found") or []
    if not secs: return None
    return {"name": f"Hardcoded secrets in JS ({len(secs)})",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
            "evidence": "; ".join(f"{x['kind']} in {x['file']}" for x in secs[:3]),
            "remediation": "ROTATE EXPOSED SECRETS IMMEDIATELY — treat as compromised. JS bundles are public; cached + indexed. Move secrets to backend env vars; use short-lived signed tokens for client-side auth."}


def rule_source_maps_exposed(s):
    sm = s.get("source_maps_found") or []
    if not sm: return None
    return {"name": f"Source maps exposed ({len(sm)})",
            "severity": "MEDIUM",
            "cwe": "CWE-540",
            "evidence": f"Accessible: {', '.join(sm[:3])}",
            "remediation": "Source maps reveal original source code (pre-minification). Configure CI/CD to NOT publish .map files to production. Or restrict via WAF."}


def rule_js_files_count(s):
    n = s.get("js_files_scanned") or 0
    if n == 0: return None
    return {"name": f"{n} JS file(s) scanned for endpoints",
            "severity": "INFO",
            "evidence": f"Bundled JavaScript analyzed for fetch/axios/XHR patterns"}


JS_ENDPOINTS_FINDING_RULES = [
    rule_endpoints_found, rule_sensitive_endpoints, rule_secrets_in_js,
    rule_source_maps_exposed, rule_js_files_count,
]


def classify_endpoint(path):
    """Return ('why' string) if endpoint is sensitive, else None."""
    for pat, why in _SENSITIVE_PATTERNS:
        if re.search(pat, path):
            return why
    return None


def scan_for_secrets(js_text, filename):
    """Run secret patterns against JS text. Returns list of matches."""
    found = []
    for pat, kind in _SECRET_PATTERNS:
        for m in re.finditer(pat, js_text):
            found.append({"kind": kind, "file": filename,
                          "value": m.group(0)[:40] + "..."})
            if len(found) >= 10: break
        if len(found) >= 10: break
    return found
