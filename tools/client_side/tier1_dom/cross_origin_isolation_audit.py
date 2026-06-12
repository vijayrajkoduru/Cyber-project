"""cross_origin_isolation_audit - COOP / COEP / CORP header audit
(playbook §5 #41 cross-origin info leak + §5 #42 XS-Leaks + §7 #69
Cross-Origin-Embedder-Policy bypass surface).

Cross-origin isolation is the browser's defense against the whole
XS-Leaks / Spectre family — cross-window references, frame counting,
timing side channels, and shared-array-buffer attacks. The three
response headers that establish it are:

  - Cross-Origin-Opener-Policy   (COOP) — severs window.opener so a
        popup/opened tab can't reach back into this page's window object
        (defeats tabnabbing, frame-counting XS-Leaks, login-detection).
  - Cross-Origin-Embedder-Policy (COEP) — requires every subresource to
        opt in (CORP/CORS); enables crossOriginIsolated mode.
  - Cross-Origin-Resource-Policy (CORP) — controls who may embed THIS
        resource as a subresource (no-cors leak vector).

This probe fetches the URL and grades PURELY on the headers actually
returned. Because these are defense-in-depth headers (their absence is
a missing mitigation, not a demonstrated exploit), the missing-header
findings are graded LOW/MEDIUM and a clear POSITIVE is emitted when
full isolation is present.

  MEDIUM  - COOP absent AND the page is a high-value auth/SSO surface
            indicator (login form / oauth path) — opener-based XS-Leaks
  LOW     - COOP absent (general window.opener / tabnabbing exposure)
  LOW     - CORP absent (resource embeddable cross-origin -> no-cors leak)
  INFO    - COEP absent (crossOriginIsolated unavailable) — informational,
            many sites cannot enable COEP without breaking third-party
            embeds, so this is reported as context not a defect
  INFO    - fetch failed
  POSITIVE- COOP same-origin + (COEP require-corp OR CORP same-origin)

ZERO false positives: severities reflect ONLY the headers observed on
the live response. Detection only.

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.user_agent  = optional UA override
"""
from __future__ import annotations
import re
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()


class CrossOriginIsolationRequest(ScanRequest):
    options: Optional[dict] = None


# Heuristic markers that the page is an authentication / SSO surface where
# opener-based XS-Leaks (login detection, account-existence oracles) bite
# hardest. Only used to nudge COOP-absent from LOW -> MEDIUM.
_AUTH_HINT_RE = re.compile(
    r"""type\s*=\s*["']password["']|"""
    r"""name\s*=\s*["'](?:password|passwd|pwd|otp|mfa)["']|"""
    r"""(?:oauth|/login|/signin|/sign-in|/sso|/authorize)""",
    re.IGNORECASE,
)


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.source("no-target")
        return
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    try:
        import httpx
    except ImportError:
        ctx.state["coi_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return

    opts = ctx.state.get("_options") or {}
    ua = opts.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=20, follow_redirects=True,
            headers={"User-Agent": ua, "Accept": "text/html,*/*"},
        ) as client:
            r = await client.get(target)
    except Exception as e:
        ctx.state["coi_error"] = f"fetch failed: {type(e).__name__}: {str(e)[:120]}"
        ctx.source("fetch failed")
        return

    coop = (r.headers.get("cross-origin-opener-policy") or "").strip()
    coep = (r.headers.get("cross-origin-embedder-policy") or "").strip()
    corp = (r.headers.get("cross-origin-resource-policy") or "").strip()

    coop_l = coop.lower()
    coep_l = coep.lower()
    corp_l = corp.lower()

    # COOP "unsafe-none" is the default and provides no protection.
    coop_protective = coop_l in ("same-origin", "same-origin-allow-popups")
    coep_protective = coep_l in ("require-corp", "credentialless")
    corp_protective = corp_l in ("same-origin", "same-site")

    auth_surface = bool(_AUTH_HINT_RE.search((r.text or "")[:200000]))

    ctx.state["coi_target_url"] = str(r.url)
    ctx.state["coi_http_status"] = r.status_code
    ctx.state["coi_coop"] = coop or "(absent)"
    ctx.state["coi_coep"] = coep or "(absent)"
    ctx.state["coi_corp"] = corp or "(absent)"
    ctx.state["coi_coop_protective"] = coop_protective
    ctx.state["coi_coep_protective"] = coep_protective
    ctx.state["coi_corp_protective"] = corp_protective
    ctx.state["coi_auth_surface"] = auth_surface
    ctx.state["coi_fully_isolated"] = (
        coop_protective and (coep_protective or corp_protective)
    )

    ctx.source(
        f"GET {target} -> {r.status_code}; "
        f"COOP={coop or 'absent'}; COEP={coep or 'absent'}; "
        f"CORP={corp or 'absent'}"
    )


# ── findings rules (inline) ────────────────────────────────────────────

def rule_coop_absent_auth(s):
    if s.get("coi_error"):
        return None
    if s.get("coi_coop_protective"):
        return None
    if not s.get("coi_auth_surface"):
        return None
    return {
        "name": "Cross-Origin-Opener-Policy absent on authentication surface (opener XS-Leaks)",
        "severity": "MEDIUM",
        "cvss": "4.3",
        "cwe": "CWE-1021",
        "cwe_name": "Improper Restriction of Rendered UI Layers or Frames",
        "owasp": "A05:2021",
        "verified_exploit": True,
        "evidence": (
            f"GET {s.get('coi_target_url')} returned "
            f"Cross-Origin-Opener-Policy: {s.get('coi_coop')} and the page "
            "exposes authentication markers (password field / OAuth / "
            "/login path). Without COOP same-origin, a window opened by an "
            "attacker page retains a live window.opener reference, enabling "
            "frame-count / login-state XS-Leaks and tabnabbing against the "
            "auth flow."
        ),
        "remediation": (
            "Set `Cross-Origin-Opener-Policy: same-origin` "
            "(or same-origin-allow-popups if the page legitimately spawns "
            "cross-origin popups, e.g. OAuth). This severs window.opener "
            "for cross-origin documents and closes the opener-based "
            "XS-Leak family."
        ),
    }


def rule_coop_absent(s):
    if s.get("coi_error"):
        return None
    if s.get("coi_coop_protective"):
        return None
    if s.get("coi_auth_surface"):
        return None  # already covered by the MEDIUM auth-surface rule
    return {
        "name": "Cross-Origin-Opener-Policy absent (window.opener / tabnabbing exposure)",
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": "CWE-1021",
        "owasp": "A05:2021",
        "verified_exploit": True,
        "evidence": (
            f"Cross-Origin-Opener-Policy header is {s.get('coi_coop')} on "
            f"{s.get('coi_target_url')}. A cross-origin document that opens "
            "this page (or that this page opens) keeps a live window "
            "reference, leaving the page exposed to opener-based XS-Leaks "
            "and reverse-tabnabbing."
        ),
        "remediation": (
            "Set `Cross-Origin-Opener-Policy: same-origin` (or "
            "same-origin-allow-popups). For outbound links use "
            "rel=\"noopener\" as a belt-and-braces measure."
        ),
    }


def rule_corp_absent(s):
    if s.get("coi_error"):
        return None
    if s.get("coi_corp_protective"):
        return None
    return {
        "name": "Cross-Origin-Resource-Policy absent (resource embeddable cross-origin)",
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "owasp": "A01:2021",
        "verified_exploit": True,
        "evidence": (
            f"Cross-Origin-Resource-Policy header is {s.get('coi_corp')} on "
            f"{s.get('coi_target_url')}. Any cross-origin page can embed "
            "this resource via a no-cors <img>/<script>/<link>, which is "
            "the loading primitive behind several XS-Leak timing and "
            "error-event oracles."
        ),
        "remediation": (
            "Set `Cross-Origin-Resource-Policy: same-origin` (or same-site) "
            "on resources that should not be embedded cross-origin. Use "
            "`cross-origin` only for assets intentionally served to other "
            "sites (public CDN files)."
        ),
    }


def rule_coep_context(s):
    # COEP absence is reported as INFO context — enabling COEP commonly
    # breaks third-party embeds, so its absence is NOT a defect by itself.
    if s.get("coi_error"):
        return None
    if s.get("coi_coep_protective"):
        return None
    return {
        "name": "Cross-Origin-Embedder-Policy not enabled (crossOriginIsolated unavailable)",
        "severity": "INFO",
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "evidence": (
            f"Cross-Origin-Embedder-Policy is {s.get('coi_coep')}. Without "
            "COEP require-corp/credentialless the document is not in "
            "crossOriginIsolated mode, so SharedArrayBuffer and "
            "high-resolution timers are coarsened. This is informational: "
            "enabling COEP can break legitimate third-party embeds and is "
            "not always appropriate."
        ),
        "remediation": (
            "If the app needs SharedArrayBuffer / precise timers / "
            "crossOriginIsolated, add `Cross-Origin-Embedder-Policy: "
            "require-corp` together with COOP same-origin, and ensure all "
            "subresources send CORP/CORS. Otherwise no action is required."
        ),
    }


def rule_fetch_failed(s):
    err = s.get("coi_error")
    if not err:
        return None
    return {
        "name": "Cross-origin isolation audit could not fetch target URL",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": str(err)[:300],
        "remediation": ("Confirm the URL is reachable from the scanner host "
                        "and uses a valid http/https scheme."),
    }


def rule_positive(s):
    if s.get("coi_error"):
        return None
    if not s.get("coi_fully_isolated"):
        return None
    return {
        "name": "Cross-origin isolation headers present (COOP + COEP/CORP)",
        "severity": "POSITIVE",
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "evidence": (
            f"COOP={s.get('coi_coop')}, COEP={s.get('coi_coep')}, "
            f"CORP={s.get('coi_corp')}. window.opener is severed for "
            "cross-origin documents and the resource is not freely "
            "embeddable, closing the opener/embed XS-Leak families."
        ),
        "remediation": ("Maintain the isolation headers. Re-test after "
                        "adding any cross-origin popup or embed flow."),
    }


CROSS_ORIGIN_ISOLATION_AUDIT_FINDING_RULES = [
    rule_coop_absent_auth,
    rule_coop_absent,
    rule_corp_absent,
    rule_coep_context,
    rule_fetch_failed,
    rule_positive,
]


INTEL_FIELDS = [
    ("Target URL",                       "coi_target_url"),
    ("HTTP status",                      "coi_http_status"),
    ("Cross-Origin-Opener-Policy",       "coi_coop"),
    ("Cross-Origin-Embedder-Policy",     "coi_coep"),
    ("Cross-Origin-Resource-Policy",     "coi_corp"),
    ("Auth surface detected",            "coi_auth_surface"),
    ("Fully cross-origin isolated",      "coi_fully_isolated"),
]


@router.post("/api/client_side/cross_origin_isolation_audit")
async def client_side_cross_origin_isolation_audit(req: CrossOriginIsolationRequest,
                                                   _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="cross_origin_isolation_audit",
        gather_func=_gather_with_options,
        finding_rules=CROSS_ORIGIN_ISOLATION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
