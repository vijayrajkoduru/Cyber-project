"""POST-FORM-INJECT-V1 — shared POST-form helpers for the injection scanners.

Underscore-prefixed so main.py's autoloader skips it.

The SPA crawler records every POST <form> it renders into scan_state
(`forms` list) as a structured entry:

    {"action": abs URL the form submits to,
     "method": "post",
     "page":   URL of the page the form was rendered on (CSRF re-fetch),
     "fields": [{"name", "type", "value"}, ...]   # every named control
     "submit": {"name": value} | {},               # first submit button only
     "csrf_fields": ["user_token", ...],           # hidden anti-CSRF tokens
     "text_fields": [...], "extra": {...},         # legacy shape (stored_xss)
     "sensitive": "" | reason}                      # never inject when set

Lab seeds in tools/_spa_state.py use only the legacy shape
(action/text_fields/extra); `normalized_post_forms` accepts both.

Every injection scanner uses the same contract:
  * inject ONE field at a time, every other field keeps its default value;
  * when the form carries a CSRF token, re-fetch the form page right before
    each submission and use the fresh hidden values (tokens are per-request
    on DVWA high/impossible, Django, Rails, ...);
  * submit via tools._shared.safe_post (auth cookie + underscore-Host fix).

Safety: forms that log in/out, change passwords, reset/delete data or change
the app's security level are marked `sensitive` and never injected — e.g.
injecting into DVWA's security.php select silently flips the session to
"impossible" and every later scanner goes blind.
"""
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from tools._shared import safe_get, safe_post

# Field types a payload may be injected into. hidden/submit/checkbox/radio/
# file/password are kept at defaults (password: never touch credentials).
INJECTABLE_TYPES = {"text", "search", "textarea", "email", "url", "tel",
                    "number", "select", ""}

_CSRF_RE = re.compile(
    r"(csrf|xsrf|token|nonce|authenticity|requestverification|__viewstate|"
    r"__eventvalidation|_wpnonce)", re.I)

# Action/page paths and submit labels that indicate a state-destroying or
# session-altering form. Matched against path + submit name/value.
_SENSITIVE_PATH_RE = re.compile(
    r"(log-?in|log-?out|sign-?in|sign-?out|logoff|setup|install|reset|"
    r"delete|remove|destroy|security(_level)?[._/-]|security\.php|"
    r"password|passwd|change-?pass|unsubscribe|deactivate|"
    r"captcha)", re.I)
_SENSITIVE_SUBMIT_RE = re.compile(
    r"(delete|remove|reset|clear|drop|logout|log out|sign out|destroy|"
    r"create.*database|seclev)", re.I)
_SENSITIVE_FIELD_RE = re.compile(r"^(seclev|security|security_level|"
                                 r"create_db|password_new|password_conf)$", re.I)


def is_csrf_field(name: str, ftype: str) -> bool:
    return ftype == "hidden" and bool(_CSRF_RE.search(name or ""))


def classify_sensitive(action: str, page: str, fields: list, submit: dict) -> str:
    """Return a reason string when the form must never be injected, else ''."""
    try:
        path = urlparse(action).path + " " + urlparse(page or "").path
    except Exception:
        path = action or ""
    if any(f.get("type") == "password" for f in fields):
        return "credential form (password input)"
    if _SENSITIVE_PATH_RE.search(path):
        return f"sensitive path ({path.strip()})"
    for k, v in (submit or {}).items():
        if _SENSITIVE_SUBMIT_RE.search(f"{k} {v}"):
            return f"destructive submit button ({k}={v})"
    for f in fields:
        if _SENSITIVE_FIELD_RE.match(f.get("name") or ""):
            return f"session/state field ({f.get('name')})"
    return ""


# ─────────────────────────────────────────────────────────────────────
# HTML form parsing (used for CSRF re-fetch)
# ─────────────────────────────────────────────────────────────────────

class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._cur = None
        self._select = None
        self._textarea = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method") or "get").lower(),
                         "fields": []}
            self.forms.append(self._cur)
            return
        if self._cur is None:
            return
        if tag == "input" and a.get("name"):
            t = (a.get("type") or "text").lower()
            if t in ("checkbox", "radio") and "checked" not in a:
                return
            self._cur["fields"].append({"name": a["name"], "type": t,
                                        "value": a.get("value", "")})
        elif tag == "button" and a.get("name"):
            self._cur["fields"].append({"name": a["name"],
                                        "type": (a.get("type") or "submit").lower(),
                                        "value": a.get("value", "")})
        elif tag == "textarea" and a.get("name"):
            self._textarea = {"name": a["name"], "type": "textarea", "value": ""}
            self._cur["fields"].append(self._textarea)
        elif tag == "select" and a.get("name"):
            self._select = {"name": a["name"], "type": "select", "value": None}
            self._cur["fields"].append(self._select)
        elif tag == "option" and self._select is not None:
            v = a.get("value", "")
            if self._select["value"] is None or "selected" in a:
                self._select["value"] = v

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None
        elif tag == "select":
            if self._select is not None and self._select["value"] is None:
                self._select["value"] = ""
            self._select = None
        elif tag == "textarea":
            self._textarea = None

    def handle_data(self, data):
        if self._textarea is not None:
            self._textarea["value"] += data


def parse_forms(html: str, page_url: str) -> list:
    p = _FormParser()
    try:
        p.feed(html or "")
    except Exception:
        pass
    for f in p.forms:
        f["action"] = urljoin(page_url, f["action"] or page_url)
    return p.forms


# ─────────────────────────────────────────────────────────────────────
# Normalisation of scan_state entries (crawler shape + legacy seed shape)
# ─────────────────────────────────────────────────────────────────────

def _norm_one(f: dict):
    action = f.get("action")
    if not action or str(f.get("method", "post")).lower() != "post":
        return None
    if f.get("file_field"):
        return None   # upload forms are file_upload.py's job (multipart)
    if f.get("fields"):
        fields = [dict(x) for x in f["fields"] if x.get("name")]
        submit = dict(f.get("submit") or {})
    else:
        # Legacy seed shape: text_fields + extra (extra = hidden/submit).
        fields = [{"name": n, "type": "text", "value": ""}
                  for n in (f.get("text_fields") or []) if n]
        submit = {}
        for k, v in (f.get("extra") or {}).items():
            if not submit and re.search(
                    r"submit|btn|button|go|send|lookup|change|sign|upload", k, re.I):
                submit[k] = v
                continue
            fields.append({"name": k, "type": "hidden", "value": v})
    page = f.get("page") or action
    sensitive = f.get("sensitive")
    if sensitive is None:
        sensitive = classify_sensitive(action, page, fields, submit)
    csrf = list(f.get("csrf_fields") or
                [x["name"] for x in fields if is_csrf_field(x["name"], x.get("type", ""))])
    inj = [x["name"] for x in fields
           if x.get("type", "text") in INJECTABLE_TYPES and x["name"] not in csrf]
    return {"action": action, "page": page, "fields": fields, "submit": submit,
            "csrf_fields": csrf, "injectable": inj, "sensitive": sensitive or ""}


def normalized_post_forms(spa: dict, limit: int = 8) -> list:
    """POST forms from scan_state, normalised, de-duplicated by
    (action path, field names) — the crawler records IP-based actions while
    lab seeds use the hostname, so the same form would otherwise be tested
    twice. Crawler entries come first in scan_state and therefore win.
    Sensitive forms and forms with nothing injectable are dropped."""
    out, seen = [], set()
    for f in spa.get("forms") or []:
        try:
            n = _norm_one(f)
        except Exception:
            n = None
        if not n or n["sensitive"] or not n["injectable"]:
            continue
        key = (urlparse(n["action"]).path.rstrip("/") or "/",
               frozenset(n["injectable"]))
        # Also collapse a seed whose injectable set is a subset of a crawled form.
        if any(k[0] == key[0] and key[1] <= k[1] for k in seen):
            continue
        seen.add(key)
        out.append(n)
        if len(out) >= limit:
            break
    return out


def _filler(ftype: str, name: str) -> str:
    t, n = (ftype or "").lower(), (name or "").lower()
    if t == "email" or "mail" in n:
        return "vl@example.com"
    if t == "url":
        return "http://example.com"
    if t in ("number", "tel"):
        return "1"
    return "1"


def default_data(form: dict) -> dict:
    """Every field at its default value (empty text → benign filler), plus
    the single submit button a browser would send."""
    data = {}
    for f in form["fields"]:
        if f.get("type") in ("submit", "button", "image", "reset", "file"):
            continue
        v = f.get("value")
        if (v is None or v == "") and f.get("type", "text") in INJECTABLE_TYPES:
            v = _filler(f.get("type"), f["name"])
        data[f["name"]] = v if v is not None else ""
    data.update(form.get("submit") or {})
    return data


def refresh_hidden(form: dict, req, data: dict) -> dict:
    """If the form has CSRF tokens, re-fetch its page and overwrite the
    hidden values with fresh ones. Returns the (possibly updated) data."""
    if not form.get("csrf_fields"):
        return data
    r = safe_get(form["page"], req=req, allow_redirects=True, timeout=10, retries=0)
    if r is None or not r.text:
        return data
    want_path = urlparse(form["action"]).path.rstrip("/")
    names = {f["name"] for f in form["fields"]}
    best = None
    for pf in parse_forms(r.text, form["page"]):
        if pf["method"] != "post":
            continue
        pnames = {f["name"] for f in pf["fields"]}
        score = len(pnames & names) + (5 if urlparse(pf["action"]).path.rstrip("/") == want_path else 0)
        if best is None or score > best[0]:
            best = (score, pf)
    if best is None or best[0] == 0:
        return data
    out = dict(data)
    for f in best[1]["fields"]:
        if f["type"] == "hidden" and f["name"] in form["csrf_fields"]:
            out[f["name"]] = f["value"]
    return out


def build_data(form: dict, req, field: str = None, value: str = None) -> dict:
    """Defaults + fresh CSRF tokens, with `field` set to `value` (if given)."""
    data = refresh_hidden(form, req, default_data(form))
    if field is not None:
        data[field] = value
    return data


def submit(form: dict, req, field: str = None, value: str = None, *,
           timeout: int = 12, retries: int = 0):
    """Submit the form once with one field injected. Returns the response
    (or None). Token re-fetch happens BEFORE the timed POST so callers that
    measure only this call's POST should use build_data + post_data."""
    return post_data(form, build_data(form, req, field, value), req,
                     timeout=timeout, retries=retries)


def post_data(form: dict, data: dict, req, *, timeout: int = 12, retries: int = 0):
    return safe_post(form["action"], data=data, req=req, allow_redirects=True,
                     timeout=timeout, retries=retries)
