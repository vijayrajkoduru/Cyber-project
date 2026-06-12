"""sspm_advisory_surface - honest advisory-by-design coverage of the SSPM
playbook techniques (module_playbooks/29_sspm.md) that CANNOT be probed
from an external, unauthenticated SaaS VA scan.

The SSPM playbook spans 8 sections / 88 techniques across Microsoft 365,
Google Workspace, Salesforce, Slack/Teams/Discord, Atlassian, GitHub/GitLab,
OAuth connected-apps, and cross-SaaS DLP. The externally-visible slice —
M365 public tenant/federation discovery, Workspace email-spoofing (SPF/DKIM/
DMARC) over DNS, Atlassian anonymous-access, Slack open-signup — is
implemented as REAL graded probes in the other tiers. Everything that
remains is TENANT-INTERNAL: it requires admin credentials, an OAuth bearer,
a service-account, or an on-tenant API call.

Per the module's HARD RULES (VA not PT, ZERO false positives, no fake
graded severities), these are emitted as INFO [ADVISORY-BY-DESIGN] findings.
Each names the credential-gated probe that DOES grade it (m365_security_score,
gworkspace_admin_audit, salesforce_org_audit, slack_workspace_audit,
github_org_audit) so the customer knows exactly how to close the gap.

This scanner runs NO exploitation and NO authentication. It optionally does
ONE benign HTTP GET to record the target is reachable, then emits the
advisory catalogue. It ALWAYS returns INFO-only — it can never produce a
graded finding or a false positive.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel  # noqa: F401  (kept for interface parity)

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()


class SspmAdvisoryRequest(ScanRequest):
    options: Optional[dict] = None


# (technique title, why-advisory reason incl. the probe that grades it, cwe).
# Every entry is INFO-only by construction.
_ADVISORY_TECHNIQUES: list[tuple[str, str, str]] = [
    # ── §1 Microsoft 365 (credential-gated internals) ──
    ("M365 Conditional Access policy enumeration + MFA enforcement state "
     "(playbook §1 #3/#4)",
     "Conditional Access policies and MFA enforcement live inside the tenant. "
     "They require a Microsoft Graph token (Policy.Read.All) and are graded by "
     "the m365_security_score probe — not visible on the public surface.",
     "CWE-1390"),
    ("M365 legacy-auth (POP/IMAP/SMTP) + sign-in risk + SSPR posture "
     "(playbook §1 #5/#6/#14)",
     "Legacy-auth block, sign-in risk policy, and self-service password reset "
     "are tenant settings read via Graph with an app registration. The "
     "m365_security_score probe grades them; no anonymous signal exists.",
     "CWE-1390"),
    ("M365 SharePoint / OneDrive / Teams external-sharing + anonymous links "
     "(playbook §1 #7/#8/#9/#10/#12)",
     "External-sharing and anonymous-link settings are per-tenant SharePoint/"
     "Teams admin config. They need Graph/SharePoint admin scopes (run "
     "m365_security_score) and are not exposed publicly.",
     "CWE-1390"),
    ("M365 Exchange mailbox auto-forward DLP + Defender for O365 ATP policies "
     "(playbook §1 #11/#15)",
     "Mailbox transport rules and ATP (Safe Links/Attachments) policies are "
     "read via Exchange Online / Graph with admin consent — credential-gated, "
     "covered by m365_security_score.",
     "CWE-1390"),
    ("M365 ScubaGear CISA baseline + 365 Defender Secure Score readout "
     "(playbook §1 #1/#2)",
     "The CISA ScubaGear baseline and Secure Score require an authenticated "
     "Graph read of the tenant. The m365_security_score probe performs this "
     "with a customer-supplied app registration.",
     "CWE-1390"),

    # ── §2 Google Workspace (credential-gated internals) ──
    ("Google Workspace admin-role audit + 2-Step Verification enforcement "
     "(playbook §2 #19/#21)",
     "Admin role assignments and 2SV enforcement are read via the Admin SDK "
     "Directory API with a domain-wide-delegation service account. The "
     "gworkspace_admin_audit probe grades them; no public signal exists.",
     "CWE-1390"),
    ("Google Workspace OAuth marketplace + less-secure-app + Advanced "
     "Protection (playbook §2 #20/#22/#23)",
     "Marketplace app authorisations, legacy LSA access, and Advanced "
     "Protection enrolment are tenant settings requiring Admin SDK scopes "
     "(run gworkspace_admin_audit).",
     "CWE-1390"),
    ("Google Workspace Drive/Calendar external-sharing + context-aware access "
     "+ Vault retention (playbook §2 #24/#26/#27/#28)",
     "Drive/Calendar sharing defaults, zero-trust context-aware access, and "
     "Vault retention are admin-console settings read via authenticated Admin "
     "SDK / Drive API — credential-gated, not externally visible.",
     "CWE-1390"),
    ("ScubaGoggles CISA baseline for Google (playbook §2 #18)",
     "The CISA ScubaGoggles baseline requires an authenticated Workspace "
     "admin read. Run gworkspace_admin_audit with a delegated service account.",
     "CWE-1390"),

    # ── §3 Salesforce (credential-gated internals) ──
    ("Salesforce Security Health Check + profile/permission-set + FLS audit "
     "(playbook §3 #31/#32/#34)",
     "Health Check, Profiles, Permission Sets, and field-level security are "
     "read via the Salesforce REST/Tooling API with an OAuth bearer. The "
     "salesforce_org_audit probe grades them; nothing is anonymous.",
     "CWE-1390"),
    ("Salesforce org-wide sharing defaults + IP restrictions + session policy "
     "(playbook §3 #35/#36/#37)",
     "Org-wide defaults, login IP ranges, and session timeout are org "
     "settings read with an authenticated session — covered by "
     "salesforce_org_audit.",
     "CWE-1390"),
    ("Salesforce Connected-App OAuth scope + Apex static scan + Lightning "
     "external-access (playbook §3 #33/#38/#39)",
     "Connected-App scopes, Apex code, and Lightning component access require "
     "an authenticated Tooling/Metadata API read (run salesforce_org_audit). "
     "Apex static analysis needs the source pulled from the org.",
     "CWE-1390"),

    # ── §4 Slack / Teams / Discord (credential-gated internals) ──
    ("Slack member 2FA + channel privacy + legacy token/webhook audit "
     "(playbook §4 #43/#44/#45)",
     "Member 2FA flags, public/private channel inventory, and legacy "
     "tokens/webhooks are read via the Slack Web API with a bot/admin token. "
     "The slack_workspace_audit probe grades them.",
     "CWE-1390"),
    ("Slack OAuth-app inventory + DLP keyword scan (playbook §4 #42/#43)",
     "Installed OAuth apps and message-content DLP require an authenticated "
     "Slack token (admin.apps:read). Covered by slack_workspace_audit; no "
     "public surface exposes message content.",
     "CWE-1390"),
    ("Microsoft Teams external federation + app-permission policies "
     "(playbook §4 #46/#47)",
     "Teams external federation and app-permission policies are M365 admin "
     "settings read via Graph / Teams admin — credential-gated (run "
     "m365_security_score / Teams admin API).",
     "CWE-1390"),
    ("Discord server permission audit (playbook §4 #48)",
     "Discord role/permission posture requires a bot token with the relevant "
     "Guild intents and a Discord API read — credential-gated, not part of an "
     "external SaaS web scan.",
     "CWE-1390"),

    # ── §5 Atlassian (credential-gated internals) ──
    ("Atlassian Access policy (SSO/MFA) + group permission scheme audit "
     "(playbook §5 #51/#54)",
     "Atlassian Access authentication policies and group permission schemes "
     "are org-admin settings read with an admin API key. The public-exposure "
     "probe covers anonymous access only; these need an admin token.",
     "CWE-1390"),
    ("Atlassian Marketplace add-on + external/guest user + Confluence secrets "
     "scan (playbook §5 #52/#55/#56/#57)",
     "Installed Marketplace add-ons, guest-user inventory, and scanning "
     "page content for secrets require an authenticated admin/Confluence API "
     "read — credential-gated.",
     "CWE-1390"),

    # ── §6 GitHub / GitLab org settings (credential-gated internals) ──
    ("GitHub Action runner + workflow-log secret-leak + PAT/App permission "
     "audit (playbook §6 #61/#62/#63/#64)",
     "Self-hosted runner config, workflow-log secret scanning, and PAT/App "
     "permission inventory are read via the GitHub API with an org-admin PAT. "
     "The github_org_audit probe grades the org-level posture.",
     "CWE-1390"),
    ("GitLab group SSO + protected CI/CD variables + deploy-token audit "
     "(playbook §6 #65/#66/#67)",
     "GitLab group SSO, protected CI/CD variables, and deploy tokens are read "
     "via the GitLab API with a group-owner token — credential-gated; not "
     "exposed on the public surface.",
     "CWE-1390"),

    # ── §7 OAuth connected-apps inventory (credential-gated internals) ──
    ("Tenant-wide OAuth app inventory + risky-scope + inactive-app revocation "
     "(playbook §7 #69/#70/#71)",
     "Enumerating tenant OAuth grants (M365 + Google), scoring scopes, and "
     "finding inactive apps require Graph (Application.Read.All) / Admin SDK "
     "tokens. Covered by m365_security_score + gworkspace_admin_audit.",
     "CWE-1390"),
    ("Illicit-consent-grant + DUCKTAIL consent-malware + multi-tenant "
     "admin-consent + scope-diff (playbook §7 #72/#73/#74/#75)",
     "Illicit-consent (T1528) detection and consent-malware indicators are "
     "derived from authenticated audit-log + service-principal reads — "
     "credential-gated threat-hunting, not an external probe. Detection only; "
     "no consent grant is ever created or revoked (VA not PT).",
     "CWE-1390"),
    ("Third-party app data-access scoring (playbook §7 #76)",
     "Scoring an app's effective data access requires reading its granted "
     "scopes + assigned users from the tenant directory — authenticated.",
     "CWE-1390"),

    # ── §8 Cross-SaaS data flow & DLP (credential-gated / analyst) ──
    ("Cross-SaaS data-flow map + SaaS-to-SaaS integration audit (Zapier/Make/"
     "Workato) (playbook §8 #79/#85)",
     "Mapping data flows between M365/Salesforce/Slack and enumerating "
     "iPaaS integrations requires authenticated reads of EACH SaaS plus the "
     "integration platform — multi-credential, not an external probe.",
     "CWE-1390"),
    ("Per-SaaS DLP rule audit + outbound file-share audit + CASB "
     "classification (playbook §8 #80/#81/#84)",
     "DLP rule configuration, outbound external-share inventory, and data "
     "classification are per-SaaS admin settings (and often a CASB product) — "
     "credential-gated.",
     "CWE-1390"),
    ("External-user / guest inventory + shadow-IT app discovery "
     "(playbook §8 #82/#83)",
     "Counting guests across tenants and discovering shadow-IT apps require "
     "authenticated directory + proxy/CASB log reads — not externally "
     "observable.",
     "CWE-1390"),

    # ── Manual / analyst-judgement techniques (every section's "manual ...") ──
    ("Manual creative audits + GDPR/DPDP gap analysis (playbook §1 #16, §2 "
     "#30, §3 #40, §4 #50, §5 #58, §6 #68, §7 #77/#78, §8 #86/#87/#88)",
     "The 'manual creative' and compliance-gap techniques are analyst-driven "
     "reviews of each tenant's configuration and data-processing posture. "
     "They require human judgement against authenticated evidence and cannot "
     "be automated from an external scan.",
     "CWE-1390"),
]


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    ctx.state["sspm_advisory_techniques"] = _ADVISORY_TECHNIQUES
    ctx.state["sspm_advisory_count"] = len(_ADVISORY_TECHNIQUES)

    if not target:
        ctx.state["sspm_advisory_reachable_status"] = None
        ctx.source("advisory-by-design catalogue")
        return

    probe_url = target
    if not probe_url.startswith(("http://", "https://")):
        probe_url = "https://" + probe_url

    reachable = None
    try:
        import httpx
        async with httpx.AsyncClient(
            verify=True, timeout=12, follow_redirects=True,
            headers={"User-Agent": "VulnusLab-SSPM/1.0"},
        ) as client:
            r = await client.get(probe_url)
            reachable = r.status_code
    except Exception:
        reachable = None

    ctx.state["sspm_advisory_target"] = probe_url
    ctx.state["sspm_advisory_reachable_status"] = reachable
    ctx.source("advisory-by-design catalogue")


def _make_rule(idx: int, title: str, reason: str, cwe: str):
    def _rule(s):
        techs = s.get("sspm_advisory_techniques") or []
        if idx >= len(techs):
            return None
        return {
            "name": f"[ADVISORY-BY-DESIGN] {title}",
            "severity": "INFO",
            "cvss": "0.0",
            "cwe": cwe,
            "owasp": "N/A",
            "evidence": (
                "Endpoint is advisory-by-design (NOT a forge gap). This SSPM "
                "technique cannot be safely or honestly detected from an "
                f"external, unauthenticated SaaS VA scan: {reason} "
                "See module_playbooks/29_sspm.md for the credential-gated "
                "probe / manual procedure."
            ),
            "remediation": (
                "Supply the relevant read-only admin credential (Graph app "
                "registration, Workspace service account, Salesforce/Slack/"
                "GitHub token) to the matching credential-gated probe to grade "
                "this control. Detection only — VulnusLab never writes, "
                "revokes, or exploits any SaaS configuration."
            ),
        }
    return _rule


SSPM_ADVISORY_SURFACE_FINDING_RULES = [
    _make_rule(i, t, reason, cwe)
    for i, (t, reason, cwe) in enumerate(_ADVISORY_TECHNIQUES)
]


INTEL_FIELDS = [
    ("Target",                        "sspm_advisory_target"),
    ("Reachable (HTTP status)",       "sspm_advisory_reachable_status"),
    ("Advisory-by-design techniques", "sspm_advisory_count"),
]


@router.post("/api/sspm/sspm_advisory_surface")
async def sspm_sspm_advisory_surface(req: SspmAdvisoryRequest,
                                     _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="sspm_advisory_surface",
        gather_func=_gather_with_options,
        finding_rules=SSPM_ADVISORY_SURFACE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
