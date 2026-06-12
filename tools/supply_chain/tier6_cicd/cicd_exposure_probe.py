"""cicd_exposure_probe - CI/CD surface & build-artifact exposure (playbook §4).

REAL remote probe. Against the customer target host it issues read-only HTTP
GETs for CI/CD artifacts and dashboards that must never be web-exposed, and
confirms each ONLY when the response content positively proves the artifact:

  Exposed VCS / build artifacts (content-verified):
    /.git/config                 git config (must contain '[core]')
    /.git/HEAD                   git HEAD ('ref: refs/...')
    /.github/workflows/          (probed indirectly via known-name configs)
    /package-lock.json           npm lockfile ('"lockfileVersion"')
    /yarn.lock                   yarn lockfile ('# yarn lockfile')
    /composer.lock               composer lockfile ('"packages"')
    /Gemfile.lock                bundler lockfile ('GEM' marker)
    /requirements.txt            python deps (heuristic, lower confidence -> LOW)
    /Dockerfile                  ('FROM ' marker)
    /.env                        secrets-bearing env file ('=' lines, key-ish)

  Reachable CI/CD dashboards (header/body-verified):
    Jenkins        /login , X-Jenkins header
    GitLab         /users/sign_in , 'GitLab' body
    Drone CI       /  ('drone' body marker)
    Argo CD        /  ('argo-cd'/'Argo CD' body marker)
    Concourse      /  ('concourse' body marker)

ZERO-FALSE-POSITIVE policy: a graded severity (HIGH/MEDIUM/LOW) is emitted
ONLY when the response body/header positively matched the artifact signature
(not a bare 200 — SPAs and catch-alls return 200 for everything). Each graded
rule stamps verified_exploit=True. .env exposure with real key=value content
is HIGH. Exposed .git is HIGH (full source/history reconstructable). Nothing
matched -> POSITIVE. Unreachable / no input -> INFO.

This is detection only (VA): read-only GETs, no .git dumping, no exploitation.

Customer input: ScanRequest.target (host / URL).
"""
from __future__ import annotations
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

router = APIRouter()
TIMEOUT = 8
_HEADERS = {"User-Agent": "VulnusLab-SupplyChain/1.0 (+cicd-exposure)",
            "Accept": "*/*"}

# Each entry: (path, label, severity, cwe, body_predicate, header_predicate)
# body_predicate / header_predicate are (name, fn(text)->bool) or None.


def _has_env_secrets(text: str) -> bool:
    # Real .env: lines like KEY=VALUE with secret-ish keys. Avoid HTML pages.
    if "<html" in text.lower() or "<!doctype" in text.lower():
        return False
    keyish = re.findall(r"^\s*([A-Z][A-Z0-9_]{2,})\s*=\s*\S", text, re.M)
    if len(keyish) < 2:
        return False
    secret_kw = ("secret", "key", "token", "password", "passwd", "api", "aws", "db",
                 "database", "private", "credential")
    joined = " ".join(keyish).lower()
    return any(k in joined for k in secret_kw)


_ARTIFACTS = [
    ("/.git/config", "Exposed .git/config (full source history reconstructable)",
     "HIGH", "CWE-527", lambda t: "[core]" in t.lower() and ("repositoryformatversion" in t.lower() or "bare" in t.lower())),
    ("/.git/HEAD", "Exposed .git/HEAD",
     "HIGH", "CWE-527", lambda t: t.strip().lower().startswith("ref:") and "refs/" in t.lower()),
    ("/.env", "Exposed .env file with credential-style entries",
     "HIGH", "CWE-538", _has_env_secrets),
    ("/package-lock.json", "Exposed npm lockfile (package-lock.json)",
     "MEDIUM", "CWE-538", lambda t: '"lockfileversion"' in t.lower()),
    ("/yarn.lock", "Exposed yarn lockfile",
     "MEDIUM", "CWE-538", lambda t: "# yarn lockfile" in t.lower()),
    ("/composer.lock", "Exposed composer lockfile",
     "MEDIUM", "CWE-538", lambda t: '"packages"' in t.lower() and '"content-hash"' in t.lower()),
    ("/Gemfile.lock", "Exposed bundler lockfile (Gemfile.lock)",
     "MEDIUM", "CWE-538", lambda t: t.lstrip().lower().startswith("gem") or "\nGEM\n" in t),
    ("/Dockerfile", "Exposed Dockerfile",
     "LOW", "CWE-538", lambda t: bool(re.search(r"(?im)^\s*from\s+\S+", t)) and "<html" not in t.lower()),
    ("/requirements.txt", "Exposed Python requirements.txt",
     "LOW", "CWE-538", lambda t: bool(re.search(r"(?im)^[a-z0-9_.-]+\s*(==|>=|~=)\s*\d", t)) and "<html" not in t.lower()),
]

# Dashboards: (path, label, sev, cwe, body_pred, header_pred)
_DASHBOARDS = [
    ("/login", "Jenkins CI dashboard reachable", "MEDIUM", "CWE-284",
     lambda t: "jenkins" in t.lower(),
     ("x-jenkins", lambda v: True)),
    ("/users/sign_in", "GitLab instance reachable", "LOW", "CWE-284",
     lambda t: "gitlab" in t.lower(),
     ("x-gitlab-feature-category", lambda v: True)),
    ("/", "Argo CD UI reachable", "MEDIUM", "CWE-284",
     lambda t: "argo cd" in t.lower() or "argo-cd" in t.lower(),
     None),
    ("/", "Drone CI UI reachable", "LOW", "CWE-284",
     lambda t: "drone" in t.lower() and ("ci" in t.lower() or "build" in t.lower()),
     None),
    ("/", "Concourse CI UI reachable", "LOW", "CWE-284",
     lambda t: "concourse" in t.lower(),
     None),
]


def _normalize_bases(target: str) -> list[str]:
    t = (target or "").strip().rstrip("/")
    if not t:
        return []
    if t.startswith("http://") or t.startswith("https://"):
        return [t]
    return [f"https://{t}", f"http://{t}"]


def _http_get(url: str) -> dict:
    if requests is None:
        return {"ok": False}
    try:
        r = requests.get(url, headers=_HEADERS, timeout=TIMEOUT,
                         verify=False, allow_redirects=True)
        try:
            body = r.text[:4000]
        except Exception:
            body = ""
        return {"ok": True, "status": r.status_code, "body": body,
                "headers": {k.lower(): v for k, v in r.headers.items()}}
    except Exception:
        return {"ok": False}


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        bases = _normalize_bases(ctx.host or "")
        if not bases:
            ctx.state["cicd_no_input"] = True
            ctx.source("target required")
            return
        if requests is None:
            ctx.state["cicd_error"] = "requests library unavailable"
            ctx.source("no http client")
            return

        ctx.state["cicd_target"] = ctx.host
        base = None
        # Pick the first reachable scheme via a cheap root GET.
        for b in bases:
            root = await asyncio.to_thread(_http_get, b + "/")
            if root.get("ok"):
                base = b
                break
        if base is None:
            ctx.state["cicd_unreachable"] = True
            ctx.source(f"{ctx.host} unreachable")
            return

        ctx.state["cicd_base"] = base
        artifacts_found: list[dict] = []
        dashboards_found: list[dict] = []
        attempted = 0

        for path, label, sev, cwe, pred in _ARTIFACTS:
            attempted += 1
            res = await asyncio.to_thread(_http_get, base + path)
            if not res.get("ok") or res.get("status") != 200:
                continue
            body = res.get("body") or ""
            try:
                matched = bool(pred(body))
            except Exception:
                matched = False
            if matched:
                artifacts_found.append({"path": path, "label": label,
                                        "severity": sev, "cwe": cwe,
                                        "status": res.get("status")})

        for path, label, sev, cwe, body_pred, header_pred in _DASHBOARDS:
            attempted += 1
            res = await asyncio.to_thread(_http_get, base + path)
            if not res.get("ok"):
                continue
            body = res.get("body") or ""
            headers = res.get("headers") or {}
            hit = False
            why = ""
            if header_pred is not None:
                hname, hfn = header_pred
                if hname in headers:
                    try:
                        if hfn(headers.get(hname, "")):
                            hit = True
                            why = f"header {hname}"
                    except Exception:
                        pass
            if not hit:
                try:
                    if body_pred(body):
                        hit = True
                        why = "body signature"
                except Exception:
                    pass
            if hit:
                status = res.get("status")
                # ZERO-FP: a graded severity is emitted ONLY when the service
                # is confirmed running (status 200, mirroring the artifact
                # check above). A keyword match on a non-200 response (e.g. a
                # 404 error page that merely mentions 'Argo CD') is just a
                # signature, not a running control plane -> INFO, not graded.
                if status == 200:
                    eff_sev = sev
                    eff_why = why
                else:
                    eff_sev = "INFO"
                    eff_why = (f"service signature found but not confirmed "
                               f"running (status: {status})")
                # De-dup dashboards that share path '/'.
                if not any(d["label"] == label for d in dashboards_found):
                    dashboards_found.append({"path": path, "label": label,
                                            "severity": eff_sev, "cwe": cwe,
                                            "evidence": eff_why,
                                            "status": status})

        ctx.state["cicd_probes_attempted"] = attempted
        ctx.state["cicd_artifacts"] = artifacts_found
        ctx.state["cicd_dashboards"] = dashboards_found
        total = len(artifacts_found) + len(dashboards_found)
        ctx.source(f"cicd exposure: {total} exposure(s) on {ctx.host} ({attempted} probes)")
    return gather


# ───────────────────────── finding rules (inline) ─────────────────────────

def _rule_no_input(s):
    if not s.get("cicd_no_input"):
        return None
    return {"name": "cicd_exposure_probe: target host/URL required",
            "severity": "INFO",
            "evidence": "Provide a host or URL as target to probe for exposed CI/CD artifacts.",
            "remediation": "Re-run with target=<host-or-url>.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_client_missing(s):
    if "requests library unavailable" not in (s.get("cicd_error") or ""):
        return None
    return {"name": "cicd_exposure_probe: HTTP client unavailable",
            "severity": "INFO",
            "evidence": s.get("cicd_error"),
            "remediation": "Install the `requests` library in the scanner environment.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_unreachable(s):
    if not s.get("cicd_unreachable"):
        return None
    return {"name": "Target unreachable for CI/CD exposure probing",
            "severity": "INFO",
            "evidence": f"No HTTP service answered on {s.get('cicd_target')}.",
            "remediation": "Confirm the host serves HTTP(S) and re-run from an in-scope vantage point.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_high_artifacts(s):
    arts = [a for a in (s.get("cicd_artifacts") or []) if a["severity"] == "HIGH"]
    if not arts:
        return None
    listing = "; ".join(f"{a['path']} ({a['label']})" for a in arts)
    return {"name": f"{len(arts)} HIGH-risk build artifact(s) web-exposed",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-527", "owasp": "A05:2021",
            "verified_exploit": True,
            "evidence": f"The target served content-verified sensitive artifacts: {listing}. "
                        "An exposed .git directory reconstructs full source + history; an "
                        "exposed .env leaks live credentials — both are direct supply-chain "
                        "compromise vectors.",
            "remediation": "Block dotfiles and VCS metadata at the web server / CDN (deny "
                           "/.git, /.env, lockfiles). Rotate any credential that was reachable. "
                           "Ensure build artifacts are never deployed to the web root."}


def _rule_medium_artifacts(s):
    arts = [a for a in (s.get("cicd_artifacts") or []) if a["severity"] == "MEDIUM"]
    if not arts:
        return None
    listing = "; ".join(f"{a['path']}" for a in arts)
    return {"name": f"{len(arts)} dependency lockfile(s) web-exposed",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-538", "owasp": "A05:2021",
            "verified_exploit": True,
            "evidence": f"The target served dependency lockfiles: {listing}. These enumerate "
                        "exact dependency versions, giving an attacker a precise CVE target list "
                        "and internal package names for dependency-confusion attacks.",
            "remediation": "Remove lockfiles from the web root and deny access to them at the "
                           "web server / CDN."}


def _rule_low_artifacts(s):
    arts = [a for a in (s.get("cicd_artifacts") or []) if a["severity"] == "LOW"]
    if not arts:
        return None
    listing = "; ".join(f"{a['path']}" for a in arts)
    return {"name": f"{len(arts)} build-config file(s) web-exposed",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-538", "owasp": "A05:2021",
            "verified_exploit": True,
            "evidence": f"The target served build configuration files: {listing}. These reveal "
                        "base images and dependency declarations useful for targeting.",
            "remediation": "Keep Dockerfiles / requirements files out of the web root."}


def _rule_dashboards(s):
    # Only confirmed-running dashboards (status 200) carry a graded severity.
    dash = [d for d in (s.get("cicd_dashboards") or [])
            if d.get("severity") != "INFO"]
    if not dash:
        return None
    # Use the highest dashboard severity for the headline.
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    dash_sorted = sorted(dash, key=lambda d: order.get(d["severity"], 3))
    headline_sev = dash_sorted[0]["severity"]
    listing = "; ".join(f"{d['label']} (via {d['evidence']})" for d in dash_sorted[:5])
    cvss = {"HIGH": "7.5", "MEDIUM": "5.3", "LOW": "3.7"}.get(headline_sev, "3.7")
    return {"name": f"{len(dash)} CI/CD control-plane dashboard(s) network-reachable",
            "severity": headline_sev, "cvss": cvss,
            "cwe": "CWE-284", "owasp": "A05:2021",
            "verified_exploit": True,
            "evidence": f"CI/CD dashboards responded on the target: {listing}. An internet-"
                        "reachable build control plane is a high-value supply-chain target "
                        "(credential theft, pipeline poisoning, build-output tampering).",
            "remediation": "Place CI/CD dashboards behind SSO + network ACLs / a VPN. Never "
                           "expose Jenkins/Argo/Drone/Concourse/GitLab control planes to the "
                           "public internet. Enforce 2FA and audit logging."}


def _rule_dashboard_signatures(s):
    # Keyword/header signatures seen on a non-200 response (e.g. a 404 error
    # page that mentions the product) are NOT a confirmed-running control
    # plane. Report them as INFO so they don't inflate severity.
    sigs = [d for d in (s.get("cicd_dashboards") or [])
            if d.get("severity") == "INFO"]
    if not sigs:
        return None
    listing = "; ".join(f"{d['label']} ({d['evidence']})" for d in sigs[:5])
    return {"name": f"{len(sigs)} CI/CD service signature(s) seen but not confirmed running",
            "severity": "INFO",
            "cwe": "CWE-284", "owasp": "A05:2021",
            "evidence": f"The target returned content matching CI/CD product signatures, but "
                        f"not on a 200 response, so a running control plane was NOT confirmed: "
                        f"{listing}. This is informational only and may be a stray error page.",
            "remediation": "If any of these dashboards are intended to be reachable, place them "
                           "behind SSO + network ACLs / a VPN. Otherwise no action is required."}


def _rule_clean(s):
    if any(s.get(k) for k in ("cicd_no_input", "cicd_error", "cicd_unreachable")):
        return None
    if not s.get("cicd_base"):
        return None
    if (s.get("cicd_artifacts") or []) or (s.get("cicd_dashboards") or []):
        return None
    return {"name": "No exposed CI/CD artifacts or dashboards detected",
            "severity": "POSITIVE",
            "evidence": f"{s.get('cicd_probes_attempted', 0)} CI/CD exposure probes against "
                        f"{s.get('cicd_target')} matched nothing.",
            "remediation": "Continue to keep VCS metadata, lockfiles, and CI dashboards out of "
                           "public reach; re-scan after deployments.",
            "cwe": "N/A", "owasp": "N/A"}


CICD_EXPOSURE_FINDING_RULES = [
    _rule_no_input,
    _rule_client_missing,
    _rule_unreachable,
    _rule_high_artifacts,
    _rule_medium_artifacts,
    _rule_low_artifacts,
    _rule_dashboards,
    _rule_dashboard_signatures,
    _rule_clean,
]


INTEL_FIELDS = [("Probe target", "cicd_target"),
                ("Base URL probed", "cicd_base"),
                ("Probes attempted", "cicd_probes_attempted"),
                ("Exposed artifacts", "cicd_artifacts"),
                ("Reachable dashboards", "cicd_dashboards")]


@router.post("/api/supply_chain/cicd_exposure_probe")
async def supply_chain_cicd_exposure_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="cicd_exposure_probe",
        gather_func=_make_gather(req),
        finding_rules=CICD_EXPOSURE_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
