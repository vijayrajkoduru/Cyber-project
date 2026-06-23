"""oauth_redirect_audit - OAuth redirect_uri validation bypass (playbook §3 #23).

Customer supplies the OAuth /authorize URL of their app. The probe sends
the same authorize request multiple times with mutated redirect_uri
values and inspects the Location: header / HTML body to see which the
authorization server actually accepts.

Mutations tested:
  - subdomain takeover (xN.evil.com appended)
  - open-redirect chain (/oauth/callback?next=//evil.com)
  - path traversal (/callback/../../../evil)
  - localhost @-userinfo bypass (127.0.0.1:8000@evil.com)
  - HTTP downgrade (http:// for an https:// app)
  - scheme confusion (javascript:, data:)
  - port confusion (:80 vs :8080)

Customer input via ScanRequest.options:
  - target                      = identifier for the app (string)
  - options.oauth_authorize_url = the /authorize endpoint with all params except redirect_uri
  - options.client_id           = OAuth client_id (required)
  - options.original_redirect   = the original redirect_uri the app expects (required)
  - options.response_type       = OAuth response_type, default 'code'
  - options.state               = optional state value

An "accepted" mutation means the AS returned 302 with a Location to a
host the customer doesn't own - i.e. real account takeover potential.
"""
from __future__ import annotations
import asyncio
from typing import Optional
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.oauth_redirect_audit_findings import OAUTH_REDIRECT_AUDIT_FINDING_RULES
from tools._payloads.auth_attacks._loader import load_json

router = APIRouter()

DEFAULT_TIMEOUT = 15

# VL-CORE: AI-curated OAuth parameter-pollution pool owned by this module.
# Used to (a) extend the redirect_uri mutation surface with single-value
# attacker URIs templated against the customer's registered URI, and (b)
# surface the broader scope/state/response_type pollution techniques as intel.
# The detection verdict (302 -> attacker host, no OAuth error) is unchanged.
_OAUTH_PARAM_POLLUTION = load_json("oauth_param_pollution", fallback=[])


class OauthRedirectAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _build_mutations(original: str) -> list[tuple[str, str]]:
    """Return [(attack_name, mutated_uri), ...]."""
    try:
        parsed = urlparse(original)
    except Exception:
        parsed = None
    host = parsed.hostname if parsed else "victim.example"
    scheme = parsed.scheme if parsed else "https"
    path = parsed.path if parsed else "/"

    out = [
        ("subdomain_takeover_evil_tld",
            f"{scheme}://{host}.evil.com{path or '/'}"),
        ("subdomain_attacker_owned",
            f"{scheme}://evil.com.{host}{path or '/'}"),
        ("open_redirect_chain",
            f"{original}?next=https://evil.com" if "?" not in original else f"{original}&next=https://evil.com"),
        ("path_traversal_dotdot",
            f"{scheme}://{host}/oauth/callback/../../../evil"),
        ("userinfo_at_bypass",
            f"{scheme}://{host}@evil.com/cb"),
        ("localhost_at_bypass",
            f"{scheme}://127.0.0.1:8000@evil.com/cb"),
        ("http_downgrade",
            f"http://{host}{path or '/'}" if scheme == "https" else original),
        ("scheme_confusion_js",
            f"javascript:alert(document.domain)"),
        ("scheme_confusion_data",
            f"data:text/html,<h1>evil</h1>"),
        ("trailing_dot_bypass",
            f"{scheme}://{host}./{path.lstrip('/')}" if parsed else original),
        ("port_confusion_8080",
            f"{scheme}://{host}:8080{path or '/'}"),
        ("query_fragment_smuggle",
            f"{original}#@evil.com/" if "#" not in original else original),
    ]

    # VL-CORE extension: append single-value redirect_uri attacker URIs from the
    # curated pollution pool, templated against the customer's registered URI.
    # Duplicate-param ('&redirect_uri=' inside the mutation) entries are skipped
    # here because _send_authorize uses a dict (one value per key); those are
    # surfaced as intel instead. Backslash entries are skipped (urlencode would
    # mangle them under the dict path).
    orig_host = host or "victim.example"
    seen = {m for _, m in out}
    for p in _OAUTH_PARAM_POLLUTION:
        if not isinstance(p, dict) or p.get("param") != "redirect_uri":
            continue
        mut = p.get("mutation") or ""
        if "&redirect_uri=" in mut or "\\" in mut:
            continue
        if not mut.startswith("redirect_uri="):
            continue
        val = (mut[len("redirect_uri="):]
               .replace("{ORIGINAL_HOST}", orig_host)
               .replace("{ORIGINAL}", original))
        if not val or val in seen:
            continue
        seen.add(val)
        out.append((p.get("id") or "pool_redirect_uri", val))
    return out


def _is_attacker_host(redirect_url: str, original: str) -> bool:
    """Returns True if the AS bounced the user to a host they shouldn't be at."""
    if not redirect_url:
        return False
    try:
        rp = urlparse(redirect_url)
        op = urlparse(original)
    except Exception:
        return False
    if not rp.hostname:
        return False
    # Same host = safe (the AS sanitized the param back to the registered URI)
    if rp.hostname.lower() == (op.hostname or "").lower():
        return False
    # Attacker tells: 'evil', 'attacker', or anything not under the original domain.
    suspicious_substrings = ("evil", "attacker", "burpcollab", "interactsh")
    if any(s in rp.hostname.lower() for s in suspicious_substrings):
        return True
    # If host CONTAINS the original as a subdomain prefix (host.evil.com) that's takeover-pattern
    orig_host = (op.hostname or "").lower()
    if orig_host and orig_host in rp.hostname.lower() and rp.hostname.lower() != orig_host:
        return True
    return False


def _location_carries_attacker_redirect(location: str, mutated_redirect: str,
                                         original: str) -> bool:
    """Hard proof the AS actually accepted the malicious redirect_uri.

    Zero-FP: acceptance is NEVER inferred from the absence of an OAuth error.
    We require POSITIVE evidence in the Location header:

      (1) the Location host is the SAME host the attacker put in the mutated
          redirect_uri (the AS bounced the flow to exactly the attacker's
          host) - the strongest signal; OR
      (2) the Location host is otherwise an attacker-controlled / off-original
          host (subdomain-takeover pattern, evil/burpcollab tells) - covers
          cases where the AS rewrites but still lands off-host.

    A Location pointing back at the original/registered host, or any non-host
    scheme (javascript:/data:), or an empty Location, is NOT acceptance.
    """
    if not location:
        return False
    try:
        lp = urlparse(location)
        mp = urlparse(mutated_redirect)
        op = urlparse(original)
    except Exception:
        return False
    loc_host = (lp.hostname or "").lower()
    if not loc_host:
        # No host in Location (e.g. javascript:/data:/relative) -> cannot prove
        # an off-host redirect was accepted.
        return False
    orig_host = (op.hostname or "").lower()
    # Location bounced back to the registered host = the AS sanitized it = safe.
    if loc_host == orig_host:
        return False
    # (1) Location host == the host the attacker injected -> definitive accept.
    mut_host = (mp.hostname or "").lower()
    if mut_host and loc_host == mut_host:
        return True
    # (2) Otherwise require the Location host to be an off-original attacker host.
    return _is_attacker_host(location, original)


async def _send_authorize(client, authorize_url: str, params: dict) -> dict:
    """Send a single /authorize request, capture Location header."""
    try:
        # Build full GET URL with mutated params
        full = (authorize_url + "&" + urlencode(params)) if "?" in authorize_url \
               else (authorize_url + "?" + urlencode(params))
        r = await client.get(full, follow_redirects=False)
        status = r.status_code
        loc = r.headers.get("location") or ""
        body_has_error = bool(
            "invalid_request" in (r.text or "")[:1000].lower() or
            "redirect_uri_mismatch" in (r.text or "")[:1000].lower() or
            "unauthorized_client" in (r.text or "")[:1000].lower()
        )
        return {
            "status":    status,
            "location":  loc[:300],
            "rejected":  body_has_error,
        }
    except Exception as e:
        return {"status": 0, "location": "", "error": str(e)[:200], "rejected": True}


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    authorize_url = (opts.get("oauth_authorize_url") or "").strip()
    client_id = (opts.get("client_id") or "").strip()
    original_redirect = (opts.get("original_redirect") or "").strip()
    response_type = (opts.get("response_type") or "code").strip()
    state = opts.get("state")

    if not authorize_url or not client_id or not original_redirect:
        ctx.state["oauth_input_missing"] = True
        ctx.source("missing oauth_authorize_url/client_id/original_redirect")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["oauth_httpx_missing"] = True
        ctx.source("httpx not installed")
        return

    mutations = _build_mutations(original_redirect)
    ctx.state["oauth_authorize_url"] = authorize_url
    ctx.state["oauth_original_redirect"] = original_redirect
    ctx.state["oauth_mutations_tried"] = len(mutations)

    base_params = {
        "client_id":     client_id,
        "response_type": response_type,
        "scope":         opts.get("scope") or "openid profile email",
    }
    if state:
        base_params["state"] = str(state)

    results = []
    accepted = []
    async with httpx.AsyncClient(verify=False, timeout=DEFAULT_TIMEOUT,
                                 follow_redirects=False) as client:
        # First send baseline to confirm reachability
        baseline_params = dict(base_params); baseline_params["redirect_uri"] = original_redirect
        baseline = await _send_authorize(client, authorize_url, baseline_params)
        ctx.state["oauth_baseline_status"] = baseline.get("status")

        # Now mutate
        for attack, mutated in mutations:
            params = dict(base_params); params["redirect_uri"] = mutated
            r = await _send_authorize(client, authorize_url, params)
            r["attack"] = attack
            r["mutated_redirect_uri"] = mutated
            # Verdict (zero-FP): acceptance requires POSITIVE proof that the
            # attacker-controlled redirect host actually appears in the
            # Location header (i.e. the flow really redirected off-host to the
            # attacker). The absence of an OAuth error string is NOT proof and
            # is used only as a guard - an explicit OAuth error still rejects.
            status = r.get("status") or 0
            location = r.get("location") or ""
            off_host_to_attacker = _location_carries_attacker_redirect(
                location, mutated, original_redirect
            )
            verdict = (
                300 <= status < 400 and          # an actual redirect happened
                off_host_to_attacker and         # ...to the attacker's host
                not r.get("rejected")            # ...and the AS did not error
            )
            r["accepted"] = verdict
            results.append(r)
            if verdict:
                accepted.append(attack)

    ctx.state["oauth_variant_results"] = results
    ctx.state["oauth_accepted_attacks"] = accepted
    ctx.state["oauth_pollution_techniques"] = [
        p.get("id") for p in _OAUTH_PARAM_POLLUTION
        if isinstance(p, dict) and p.get("param") in ("scope", "state", "response_type", "response_mode")
    ]
    ctx.source(f"OAuth /authorize -> {len(mutations)} mutations, {len(accepted)} accepted")


INTEL_FIELDS = [
    ("Authorize URL",          "oauth_authorize_url"),
    ("Original redirect_uri",  "oauth_original_redirect"),
    ("Mutations tried",        "oauth_mutations_tried"),
    ("Baseline status",        "oauth_baseline_status"),
    ("Variant results",        "oauth_variant_results"),
    ("Accepted attacks",       "oauth_accepted_attacks"),
    ("Pollution techniques",   "oauth_pollution_techniques"),
]


@router.post("/api/auth_attacks/oauth_redirect_audit")
async def auth_attacks_oauth_redirect_audit(req: OauthRedirectAuditRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="oauth_redirect_audit",
        gather_func=_gather_with_options,
        finding_rules=OAUTH_REDIRECT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
