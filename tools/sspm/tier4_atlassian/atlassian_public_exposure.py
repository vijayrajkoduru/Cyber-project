"""atlassian_public_exposure - UNAUTHENTICATED Atlassian Cloud (Jira /
Confluence) anonymous-access + public-page exposure audit
(playbook §5 #53 "Anonymous-access audit (public pages)" + #57 external
user/guest signal, the externally-visible slice).

Atlassian Cloud sites live at <site>.atlassian.net. Several REST endpoints
answer WITHOUT authentication when the admin has enabled anonymous access —
exactly the posture gap §5 #53 is about. We read those PUBLIC endpoints
read-only and report ONLY what they actually return:

  - GET /rest/api/3/serverInfo
        confirms the site exists + Jira Cloud deployment metadata.
  - GET /rest/api/2/project   (no auth)
        if anonymous browsing is on, Jira returns the list of projects an
        anonymous user can see — CONFIRMED public Jira projects.
  - GET /rest/api/2/search?jql=order+by+created&maxResults=1  (no auth)
        if it returns issues for an anonymous caller, issue data is public.
  - GET /wiki/rest/api/space?limit=5  (no auth)
        Confluence Cloud: anonymously-readable spaces.
  - GET /wiki/rest/api/content?limit=1  (no auth)
        anonymously-readable Confluence pages.

These are READ-ONLY GETs against Atlassian's own public REST surface. No
credential is supplied, no login attempted, no content modified, no
brute-force. Detection-only (VA), never exploitation (PT).

Severity model (graded ONLY when the endpoint actually returns data to an
anonymous caller — CONFIRMED):
  HIGH    - anonymous Confluence pages/spaces readable (content exposure)
  HIGH    - anonymous Jira issue search returns issues (issue exposure)
  MEDIUM  - anonymous Jira project list non-empty (project metadata exposure)
  INFO    - site exists but every anonymous endpoint is locked (good)
  INFO    - site does not resolve / not an Atlassian Cloud site
  INFO    - everything that needs an Atlassian Access admin token (advisory)

Customer input:
  - ScanRequest.target = the Atlassian site (e.g. "acme.atlassian.net",
    "acme", or "https://acme.atlassian.net"). Bare names get .atlassian.net.
  - options.atlassian_site = explicit override for the site host.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()

TIMEOUT = 15.0


class AtlassianPublicExposureRequest(ScanRequest):
    options: Optional[dict] = None


def _resolve_site(target: str, override: str = "") -> str:
    """Return the bare <site>.atlassian.net host (no scheme)."""
    raw = (override or target or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].strip().rstrip(".")
    if not raw:
        return ""
    if raw.endswith(".atlassian.net"):
        return raw.lower()
    if "." in raw:
        # A custom domain — keep as-is (Atlassian custom-domain sites exist).
        return raw.lower()
    return f"{raw.lower()}.atlassian.net"


async def _get(client, url: str) -> tuple[int, object]:
    try:
        r = await client.get(url, timeout=TIMEOUT,
                             headers={"Accept": "application/json",
                                      "User-Agent": "VulnusLab-SSPM/1.0"})
        try:
            body = r.json()
        except Exception:
            body = {"_text": (r.text or "")[:300]}
        return r.status_code, body
    except Exception as e:
        return 0, {"_error": f"{type(e).__name__}: {str(e)[:160]}"}


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    site = _resolve_site(ctx.host or "", opts.get("atlassian_site") or "")
    if not site:
        ctx.source("no-target")
        return

    base = f"https://{site}"
    try:
        import httpx
    except ImportError:
        ctx.state["atlassian_exposure_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    async with httpx.AsyncClient(verify=True, follow_redirects=True) as client:
        # 1. serverInfo — does the site exist?
        si_status, si_body = await _get(client, f"{base}/rest/api/3/serverInfo")
        site_exists = si_status == 200 and isinstance(si_body, dict) \
            and (si_body.get("baseUrl") or si_body.get("version"))
        if not site_exists:
            # Some Confluence-only sites 404 on Jira serverInfo. Try Confluence.
            cf_status, _ = await _get(client, f"{base}/wiki/rest/api/space?limit=1")
            site_exists = cf_status in (200, 401, 403)
            ctx.state["atlassian_site_exists_via"] = (
                "confluence" if site_exists else "none")
        else:
            ctx.state["atlassian_site_exists_via"] = "jira"

        if not site_exists:
            ctx.state["atlassian_site"] = site
            ctx.state["atlassian_site_exists"] = False
            ctx.source(f"{site}: not a reachable Atlassian Cloud site")
            return

        ctx.state["atlassian_jira_version"] = (
            si_body.get("version") if isinstance(si_body, dict) else "")

        # Track raw endpoint statuses so 401/403 ("exists & protected") is
        # NEVER confused with 200 ("anonymously readable"). Only HTTP 200 with
        # actual data is graded as an anonymous-exposure finding (zero-FP).
        endpoint_statuses = {}
        protected_endpoints = []   # answered 401/403 -> exists but locked down

        # 2. Anonymous Jira projects
        pr_status, pr_body = await _get(client, f"{base}/rest/api/2/project")
        endpoint_statuses["jira_project"] = pr_status
        if pr_status in (401, 403):
            protected_endpoints.append("jira_project")
        anon_projects = []
        if pr_status == 200 and isinstance(pr_body, list):
            for p in pr_body[:50]:
                if isinstance(p, dict):
                    anon_projects.append({
                        "key": p.get("key"), "name": p.get("name"),
                    })

        # 3. Anonymous Jira issue search
        se_status, se_body = await _get(
            client,
            f"{base}/rest/api/2/search?jql=order%20by%20created%20DESC"
            "&maxResults=1&fields=summary")
        endpoint_statuses["jira_search"] = se_status
        if se_status in (401, 403):
            protected_endpoints.append("jira_search")
        anon_issue_total = 0
        if se_status == 200 and isinstance(se_body, dict):
            try:
                anon_issue_total = int(se_body.get("total") or 0)
            except (TypeError, ValueError):
                anon_issue_total = 0

        # 4. Anonymous Confluence spaces
        sp_status, sp_body = await _get(client, f"{base}/wiki/rest/api/space?limit=10")
        endpoint_statuses["confluence_space"] = sp_status
        if sp_status in (401, 403):
            protected_endpoints.append("confluence_space")
        anon_spaces = []
        if sp_status == 200 and isinstance(sp_body, dict):
            for sp in (sp_body.get("results") or [])[:25]:
                if isinstance(sp, dict):
                    anon_spaces.append({
                        "key": sp.get("key"), "name": sp.get("name"),
                        "type": sp.get("type"),
                    })

        # 5. Anonymous Confluence content
        ct_status, ct_body = await _get(client, f"{base}/wiki/rest/api/content?limit=1")
        endpoint_statuses["confluence_content"] = ct_status
        if ct_status in (401, 403):
            protected_endpoints.append("confluence_content")
        anon_content_total = 0
        if ct_status == 200 and isinstance(ct_body, dict):
            try:
                anon_content_total = int((ct_body.get("size") or 0))
            except (TypeError, ValueError):
                anon_content_total = 0
            if not anon_content_total and (ct_body.get("results")):
                anon_content_total = len(ct_body.get("results") or [])

    ctx.state["atlassian_site"] = site
    ctx.state["atlassian_site_exists"] = True
    ctx.state["atlassian_anon_projects"] = anon_projects
    ctx.state["atlassian_anon_issue_total"] = anon_issue_total
    ctx.state["atlassian_anon_spaces"] = anon_spaces
    ctx.state["atlassian_anon_content_total"] = anon_content_total
    ctx.state["atlassian_endpoint_statuses"] = endpoint_statuses
    ctx.state["atlassian_protected_endpoints"] = sorted(set(protected_endpoints))
    ctx.state["atlassian_evaluated"] = True
    ctx.source(
        f"{site}: anon-projects={len(anon_projects)}, anon-issues={anon_issue_total}, "
        f"anon-spaces={len(anon_spaces)}, anon-content={anon_content_total}"
    )


def rule_error(s):
    if not s.get("atlassian_exposure_error"):
        return None
    return {
        "name": "Atlassian public-exposure audit could not run",
        "severity": "INFO",
        "evidence": str(s.get("atlassian_exposure_error")),
        "remediation": "Transient — re-run. No Atlassian credential is needed.",
        "cwe": "N/A", "iso27001": "A.5.23",
    }


def rule_not_atlassian(s):
    if s.get("atlassian_exposure_error"):
        return None
    if s.get("atlassian_site_exists") is not False:
        return None
    return {
        "name": "Target is not a reachable Atlassian Cloud site",
        "severity": "INFO",
        "evidence": (
            f"{s.get('atlassian_site')} did not answer Atlassian Cloud REST "
            "endpoints. The Jira/Confluence anonymous-access checks do not "
            "apply."
        ),
        "remediation": (
            "If the org uses Atlassian Cloud, pass the correct site as the "
            "target (e.g. <name>.atlassian.net) or options.atlassian_site."
        ),
        "cwe": "N/A", "iso27001": "A.5.23",
    }


def rule_anon_confluence(s):
    if not s.get("atlassian_evaluated"):
        return None
    spaces = s.get("atlassian_anon_spaces") or []
    content = s.get("atlassian_anon_content_total") or 0
    if not spaces and not content:
        return None
    keys = ", ".join([sp.get("key") or "?" for sp in spaces[:10]]) or "(content)"
    return {
        "name": f"Confluence content is anonymously readable on "
                f"{s.get('atlassian_site')}",
        "severity": "HIGH",
        "evidence": (
            f"Unauthenticated requests returned {len(spaces)} space(s) "
            f"[{keys}] and {content} content item(s). Confluence anonymous "
            "access is enabled — internal documentation may be public. "
            "CONFIRMED by an unauthenticated REST read."
        ),
        "remediation": (
            "In Confluence: Settings > Security > 'Anonymous access' — disable "
            "anonymous access to the site, and review per-space permissions so "
            "only intended spaces are public."
        ),
        "cwe": "CWE-306", "owasp": "A01:2021", "iso27001": "A.5.15",
        "verified_exploit": True,
    }


def rule_anon_jira_issues(s):
    if not s.get("atlassian_evaluated"):
        return None
    total = s.get("atlassian_anon_issue_total") or 0
    if total <= 0:
        return None
    return {
        "name": f"Jira issues are anonymously searchable on "
                f"{s.get('atlassian_site')}",
        "severity": "HIGH",
        "evidence": (
            f"An unauthenticated Jira issue search returned a non-zero total "
            f"({total} issue(s) visible to anonymous). Issue summaries / "
            "comments may expose internal data. CONFIRMED by an "
            "unauthenticated REST read."
        ),
        "remediation": (
            "In Jira: project Permission Schemes — remove 'Anyone on the web' "
            "/ anonymous from Browse Projects, and disable public access under "
            "Settings > Products > Jira if not required."
        ),
        "cwe": "CWE-306", "owasp": "A01:2021", "iso27001": "A.5.15",
        "verified_exploit": True,
    }


def rule_anon_jira_projects(s):
    if not s.get("atlassian_evaluated"):
        return None
    projects = s.get("atlassian_anon_projects") or []
    if not projects:
        return None
    # If issues already flagged HIGH, this MEDIUM still adds the project list.
    keys = ", ".join([p.get("key") or "?" for p in projects[:15]])
    return {
        "name": f"Jira project list is anonymously visible on "
                f"{s.get('atlassian_site')} ({len(projects)} project(s))",
        "severity": "MEDIUM",
        "evidence": (
            f"Unauthenticated GET /rest/api/2/project returned project "
            f"metadata: {keys}. Anonymous users can enumerate projects. "
            "CONFIRMED by an unauthenticated REST read."
        ),
        "remediation": (
            "Remove anonymous access from the Browse Projects permission in "
            "each project's permission scheme."
        ),
        "cwe": "CWE-306", "owasp": "A01:2021", "iso27001": "A.5.15",
        "verified_exploit": True,
    }


def rule_locked_down(s):
    if not s.get("atlassian_evaluated"):
        return None
    if (s.get("atlassian_anon_projects") or s.get("atlassian_anon_issue_total")
            or s.get("atlassian_anon_spaces") or s.get("atlassian_anon_content_total")):
        return None
    protected = s.get("atlassian_protected_endpoints") or []
    protected_note = (
        (f"Protected endpoints returned 401/403 (exists & authenticated-only): "
         f"{', '.join(protected)}. ") if protected else "")
    return {
        "name": f"Atlassian site {s.get('atlassian_site')} blocks anonymous "
                f"access (good)",
        "severity": "INFO",
        "evidence": (
            "The site exists but every anonymous Jira/Confluence REST endpoint "
            "we probed either required authentication or returned no data — "
            "anonymous browsing appears disabled. "
            f"{protected_note}"
            "A 401/403 means the endpoint EXISTS but is protected — it is NOT "
            "an anonymous-exposure finding and is never graded as one. "
            "Internal posture (Atlassian Access policies, group schemes, guest "
            "inventory) still needs an admin token."
        ),
        "remediation": (
            "Maintain anonymous-access disabled. For the internal posture "
            "(SSO, MFA, guest audit) use an Atlassian admin API key."
        ),
        "cwe": "N/A", "iso27001": "A.5.15",
    }


def rule_creds_gated_advisory(s):
    if not s.get("atlassian_evaluated"):
        return None
    return {
        "name": "[ADVISORY-BY-DESIGN] Atlassian internal posture needs an "
                "admin token",
        "severity": "INFO",
        "evidence": (
            "Atlassian Access policy (SSO/MFA enforcement), group permission "
            "schemes, Marketplace add-on inventory, external/guest user "
            "inventory, and secrets-in-pages scanning are ORG-ADMIN settings. "
            "They cannot be read anonymously and are NOT a forge gap — they "
            "require an Atlassian admin API key / Access admin token."
        ),
        "remediation": (
            "Provide an Atlassian admin API token (admin.atlassian.com) to "
            "grade Access policies and group schemes. See "
            "module_playbooks/29_sspm.md §5."
        ),
        "cwe": "N/A", "iso27001": "A.5.23",
    }


ATLASSIAN_PUBLIC_EXPOSURE_FINDING_RULES = [
    rule_error,
    rule_not_atlassian,
    rule_anon_confluence,
    rule_anon_jira_issues,
    rule_anon_jira_projects,
    rule_locked_down,
    rule_creds_gated_advisory,
]


INTEL_FIELDS = [
    ("Atlassian site",            "atlassian_site"),
    ("Site reachable via",        "atlassian_site_exists_via"),
    ("Jira version",              "atlassian_jira_version"),
    ("Anon-visible Jira projects","atlassian_anon_projects"),
    ("Anon Jira issue total",     "atlassian_anon_issue_total"),
    ("Anon-visible Confluence spaces", "atlassian_anon_spaces"),
    ("Anon Confluence content count",  "atlassian_anon_content_total"),
    ("Endpoint HTTP statuses",         "atlassian_endpoint_statuses"),
    ("Protected (401/403) endpoints",  "atlassian_protected_endpoints"),
]


@router.post("/api/sspm/atlassian_public_exposure")
async def sspm_atlassian_public_exposure(req: AtlassianPublicExposureRequest,
                                         _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="atlassian_public_exposure",
        gather_func=_gather_with_options,
        finding_rules=ATLASSIAN_PUBLIC_EXPOSURE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
