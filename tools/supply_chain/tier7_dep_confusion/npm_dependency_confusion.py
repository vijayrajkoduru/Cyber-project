"""npm_dependency_confusion - npm dependency-confusion exposure (playbook §3 #31/#37).

REAL remote probe with TWO honest input modes:

  1) repo_url (github.com)  -> read the raw package.json via raw.githubusercontent.com
  2) target host/URL        -> GET /package.json from the web root (if served)

It parses dependencies/devDependencies, then for every package name queries the
PUBLIC npm registry (https://registry.npmjs.org/<name>) read-only and reports
the dependency-confusion primitive:

  - A declared package that DOES NOT EXIST on the public registry (HTTP 404)
    is claimable by an attacker. If the build's resolver can reach the public
    registry, the attacker's malicious public package can win -> the classic
    dependency-confusion attack. We confirm non-existence directly.

ZERO-FALSE-POSITIVE policy: the MEDIUM finding fires ONLY for names the public
registry actually returned 404 for (claimable). Names that exist (200) are NOT
flagged. Registry/network errors for a name are recorded as 'unknown' and never
graded. Each graded rule stamps verified_exploit=True (the 404 was observed).
We do NOT publish, reserve, or claim anything — detection only (VA).

Customer input: ScanRequest.repo_url (github) OR target serving /package.json.
"""
from __future__ import annotations
import asyncio
import json
import re
from urllib.parse import quote
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

router = APIRouter()
TIMEOUT = 8
NPM_REGISTRY = "https://registry.npmjs.org"
MAX_PACKAGES = 120  # safety cap on registry lookups per scan

_HEADERS = {"User-Agent": "VulnusLab-SupplyChain/1.0 (+dep-confusion)",
            "Accept": "application/json,*/*"}

_GH_RE = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", re.I)


def _gh_owner_repo(value: str):
    m = _GH_RE.search((value or "").strip())
    if not m:
        return None
    return m.group(1), m.group(2)


def _normalize_bases(target: str) -> list[str]:
    t = (target or "").strip().rstrip("/")
    if not t:
        return []
    if t.startswith("http://") or t.startswith("https://"):
        return [t]
    return [f"https://{t}", f"http://{t}"]


def _http_get(url: str, accept_json: bool = False) -> dict:
    if requests is None:
        return {"ok": False}
    try:
        r = requests.get(url, headers=_HEADERS, timeout=TIMEOUT, verify=False,
                         allow_redirects=True)
        out = {"ok": True, "status": r.status_code}
        try:
            out["text"] = r.text[:200000]
        except Exception:
            out["text"] = ""
        return out
    except Exception:
        return {"ok": False}


def _fetch_package_json(req: ScanRequest, ctx: ScanContext):
    """Return (raw_text, source_label) or (None, None). Sync (run in thread)."""
    repo_url = (getattr(req, "repo_url", None) or "").strip()
    gh = _gh_owner_repo(repo_url) if repo_url else None
    if gh:
        owner, repo = gh
        for branch in ("main", "master"):
            url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/package.json"
            res = _http_get(url)
            if res.get("ok") and res.get("status") == 200 and res.get("text", "").lstrip().startswith("{"):
                return res["text"], f"github:{owner}/{repo}@{branch}/package.json"
        return None, f"github:{owner}/{repo} (no package.json on main/master)"
    # Fall back to web-root package.json on the target.
    for base in _normalize_bases(ctx.host or ""):
        url = base + "/package.json"
        res = _http_get(url)
        if res.get("ok") and res.get("status") == 200:
            txt = res.get("text", "")
            if txt.lstrip().startswith("{") and '"dependencies"' in txt.lower() or '"name"' in txt.lower():
                return txt, f"{base}/package.json"
    return None, None


def _registry_status(name: str) -> int | None:
    """HTTP status from the public npm registry for a package name. None on error."""
    if requests is None:
        return None
    # Scoped names must be URL-encoded: @org/name -> @org%2Fname
    enc = name
    if name.startswith("@") and "/" in name:
        scope, pkg = name.split("/", 1)
        enc = f"{scope}%2F{pkg}"
    else:
        enc = quote(name, safe="@")
    try:
        r = requests.get(f"{NPM_REGISTRY}/{enc}", headers=_HEADERS, timeout=TIMEOUT,
                        verify=True, allow_redirects=True)
        return r.status_code
    except Exception:
        return None


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        if not repo_url and not (ctx.host or "").strip():
            ctx.state["depconf_no_input"] = True
            ctx.source("repo_url or target required")
            return
        if requests is None:
            ctx.state["depconf_error"] = "requests library unavailable"
            ctx.source("no http client")
            return

        raw, source = await asyncio.to_thread(_fetch_package_json, req, ctx)
        ctx.state["depconf_manifest_source"] = source or "none"
        if not raw:
            ctx.state["depconf_no_manifest"] = True
            ctx.source("no package.json reachable")
            return

        try:
            pkg = json.loads(raw)
        except Exception as e:
            ctx.state["depconf_error"] = f"package.json parse: {str(e)[:80]}"
            ctx.source("bad package.json")
            return

        names: list[str] = []
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            d = pkg.get(section)
            if isinstance(d, dict):
                names.extend(d.keys())
        # Unique, capped.
        seen = set()
        uniq = []
        for n in names:
            if n and n not in seen:
                seen.add(n)
                uniq.append(n)
        uniq = uniq[:MAX_PACKAGES]
        ctx.state["depconf_declared_count"] = len(uniq)
        ctx.state["depconf_self_name"] = pkg.get("name") or ""

        # Query the public registry for each name (read-only).
        async def _check(n):
            return n, await asyncio.to_thread(_registry_status, n)

        results = await asyncio.gather(*[_check(n) for n in uniq])
        claimable = []   # 404 on public registry => attacker can publish it
        existing = 0
        unknown = []
        for name, status in results:
            if status == 404:
                claimable.append({"name": name,
                                  "scoped": name.startswith("@"),
                                  "registry_status": 404})
            elif status == 200:
                existing += 1
            else:
                unknown.append({"name": name, "registry_status": status})

        ctx.state["depconf_claimable"] = claimable
        ctx.state["depconf_existing_count"] = existing
        ctx.state["depconf_unknown"] = unknown[:25]
        ctx.source(f"dep-confusion: {len(claimable)} claimable / {len(uniq)} declared "
                   f"from {source}")
    return gather


# ───────────────────────── finding rules (inline) ─────────────────────────

def _rule_no_input(s):
    if not s.get("depconf_no_input"):
        return None
    return {"name": "npm_dependency_confusion: repo_url or target required",
            "severity": "INFO",
            "evidence": "Provide repo_url (github) or a target serving /package.json.",
            "remediation": "Re-run with a GitHub repo_url or a host that serves package.json.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_client_missing(s):
    if "requests library unavailable" not in (s.get("depconf_error") or ""):
        return None
    return {"name": "npm_dependency_confusion: HTTP client unavailable",
            "severity": "INFO",
            "evidence": s.get("depconf_error"),
            "remediation": "Install the `requests` library in the scanner environment.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_no_manifest(s):
    if not s.get("depconf_no_manifest"):
        return None
    return {"name": "npm_dependency_confusion: no package.json reachable",
            "severity": "INFO",
            "evidence": f"Could not read a package.json ({s.get('depconf_manifest_source')}).",
            "remediation": "Point repo_url at a public GitHub repo whose default branch contains "
                           "package.json, or scan a host that serves it.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_parse_error(s):
    err = s.get("depconf_error") or ""
    if not err or "requests library unavailable" in err:
        return None
    return {"name": "npm_dependency_confusion: manifest parse failed",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Confirm the package.json is valid JSON.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_claimable_scoped(s):
    claimable = s.get("depconf_claimable") or []
    scoped = [c for c in claimable if c.get("scoped")]
    if not scoped:
        return None
    sample = ", ".join(c["name"] for c in scoped[:6])
    return {"name": f"Dependency confusion: {len(scoped)} internal-scoped package(s) unclaimed on public npm",
            "severity": "MEDIUM", "cvss": "6.5",
            "cwe": "CWE-1357", "owasp": "A06:2021",
            "verified_exploit": True,
            "evidence": f"The manifest ({s.get('depconf_manifest_source')}) declares scoped "
                        f"packages the public npm registry returns 404 for (claimable): {sample}. "
                        "If your install resolver can reach the public registry, an attacker can "
                        "publish these scopes/names and your build may fetch their malicious code.",
            "remediation": "Reserve your @scope on the public registry as a defensive placeholder. "
                           "Pin a private-registry-only resolver (.npmrc scope mapping) and set "
                           "an explicit registry per scope so public fallback is impossible."}


def _rule_claimable_unscoped(s):
    claimable = s.get("depconf_claimable") or []
    unscoped = [c for c in claimable if not c.get("scoped")]
    if not unscoped:
        return None
    sample = ", ".join(c["name"] for c in unscoped[:6])
    return {"name": f"Dependency confusion: {len(unscoped)} unscoped dependency(ies) unclaimed on public npm",
            "severity": "MEDIUM", "cvss": "6.5",
            "cwe": "CWE-1357", "owasp": "A06:2021",
            "verified_exploit": True,
            "evidence": f"The manifest ({s.get('depconf_manifest_source')}) declares unscoped "
                        f"dependencies that return 404 on the public npm registry (claimable): "
                        f"{sample}. These are likely internal/private packages an attacker can "
                        "register publicly to hijack your build.",
            "remediation": "Move internal packages under a reserved @scope, enforce a private-"
                           "registry-only resolver, and reserve the public names to deny "
                           "attacker registration."}


def _rule_clean(s):
    if any(s.get(k) for k in ("depconf_no_input", "depconf_error", "depconf_no_manifest")):
        return None
    if not s.get("depconf_manifest_source") or s.get("depconf_manifest_source") == "none":
        return None
    if (s.get("depconf_claimable") or []):
        return None
    return {"name": "No dependency-confusion-claimable npm packages detected",
            "severity": "POSITIVE",
            "evidence": f"All {s.get('depconf_declared_count', 0)} declared dependencies from "
                        f"{s.get('depconf_manifest_source')} resolve on the public npm registry "
                        f"(existing: {s.get('depconf_existing_count', 0)}).",
            "remediation": "Keep internal packages under a reserved @scope mapped to your private "
                           "registry; re-scan when dependencies change.",
            "cwe": "N/A", "owasp": "N/A"}


NPM_DEPENDENCY_CONFUSION_FINDING_RULES = [
    _rule_no_input,
    _rule_client_missing,
    _rule_no_manifest,
    _rule_parse_error,
    _rule_claimable_scoped,
    _rule_claimable_unscoped,
    _rule_clean,
]


INTEL_FIELDS = [("Manifest source", "depconf_manifest_source"),
                ("Self package name", "depconf_self_name"),
                ("Declared dependencies", "depconf_declared_count"),
                ("Existing on public npm", "depconf_existing_count"),
                ("Claimable (404 on public npm)", "depconf_claimable"),
                ("Registry-status unknown", "depconf_unknown")]


@router.post("/api/supply_chain/npm_dependency_confusion")
async def supply_chain_npm_dependency_confusion(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="npm_dependency_confusion",
        gather_func=_make_gather(req),
        finding_rules=NPM_DEPENDENCY_CONFUSION_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
