"""npm_typosquat_scan - npm typosquat detection (playbook §3, npm sibling of #32).

Reads a project's declared npm dependencies and flags any whose name is
Damerau-edit-distance EXACTLY 1 from a popular package (curated list) but is not
itself that package. The npm-ecosystem counterpart of pypi_typosquat_scan; it
mirrors that scanner's exact zero-FP _within_one logic (single substitution OR
adjacent transposition only). A near-miss is graded MEDIUM/advisory and worded
as "possible / verify" because it can be intentional.

This does NOT touch the dependency-confusion (404/claimable) probe in
npm_dependency_confusion.py — it is a separate, complementary detection that
reuses only the same read-only package.json fetch.

Pure-Python + a curated wordlist (tools/_payloads/supply_chain/npm_top_packages.txt).
No external engine, no registry writes.

Customer input precedence (same honest modes as npm_dependency_confusion):
  1. ScanRequest.repo_url  (github.com -> raw package.json)
  2. ScanRequest.target    (host serving /package.json)
"""
from __future__ import annotations
import asyncio
import json
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.npm_typosquat_scan_findings import NPM_TYPOSQUAT_SCAN_FINDING_RULES
from tools._payloads.supply_chain._loader import load_lines

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

router = APIRouter()
TIMEOUT = 8
MAX_PACKAGES = 200  # safety cap on names compared per scan

_HEADERS = {"User-Agent": "VulnusLab-SupplyChain/1.0 (+npm-typosquat)",
            "Accept": "application/json,*/*"}

_GH_RE = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", re.I)

# Minimal fallback so the scanner still functions if the curated list is absent
# (partial deploy / dev env). The full curated pool lives in
# tools/_payloads/supply_chain/npm_top_packages.txt.
_TOP_LIST_FALLBACK = (
    "react", "react-dom", "vue", "angular", "express", "lodash", "axios",
    "moment", "chalk", "commander", "debug", "webpack", "typescript", "eslint",
    "jest", "babel-core", "uuid", "dotenv", "glob", "mocha", "request",
)


def _load_top() -> set[str]:
    # VL-CORE loader (load_lines already strips blanks/# comments); normalize to
    # lowercase (npm names are case-insensitive lowercase by registry rule).
    try:
        out = set()
        for ln in load_lines("npm_top_packages", fallback=_TOP_LIST_FALLBACK):
            ln = ln.strip().lower()
            if ln:
                out.add(ln)
        return out
    except Exception:
        return {n.lower() for n in _TOP_LIST_FALLBACK}


def _norm(name: str) -> str:
    return (name or "").strip().lower()


def _within_one(a: str, b: str) -> bool:
    """True iff a and b are one edit apart (Damerau-Levenshtein distance 1):
    a single substitution, insertion, deletion, OR adjacent transposition.

    EXACT copy of pypi_typosquat_scan._within_one — the proven zero-FP core.
    Transpositions ('reqeusts' vs 'requests') are a top typosquat pattern, so
    they must count as distance 1 even though plain Levenshtein scores them 2."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:                      # single substitution
            return True
        if (len(diffs) == 2 and diffs[1] == diffs[0] + 1   # adjacent transposition
                and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]):
            return True
        return False
    # single insertion/deletion: walk both, allow one skip
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    i = j = 0
    edited = False
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1; j += 1
        else:
            if edited:
                return False
            edited = True
            j += 1  # skip one char in the longer string
    return True


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


def _gh_owner_repo(value: str):
    m = _GH_RE.search((value or "").strip())
    if not m:
        return None
    return m.group(1), m.group(2)


def _fetch_package_json(req: ScanRequest, host: str):
    """Return (raw_text, source_label) or (None, None). Sync (run in thread).

    Same read-only fetch strategy as npm_dependency_confusion."""
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
    for base in _normalize_bases(host or ""):
        url = base + "/package.json"
        res = _http_get(url)
        if res.get("ok") and res.get("status") == 200:
            txt = res.get("text", "")
            if txt.lstrip().startswith("{") and ('"dependencies"' in txt.lower() or '"name"' in txt.lower()):
                return txt, f"{base}/package.json"
    return None, None


def _declared_names(pkg: dict) -> list[str]:
    names: list[str] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        d = pkg.get(section)
        if isinstance(d, dict):
            names.extend(d.keys())
    seen = set()
    uniq = []
    for n in names:
        nn = _norm(n)
        if nn and nn not in seen:
            seen.add(nn)
            uniq.append(nn)
    return uniq[:MAX_PACKAGES]


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        host = (ctx.host or "").strip()
        if not repo_url and not host:
            ctx.state["npmtypo_no_input"] = True
            ctx.source("repo_url or target required")
            return
        if requests is None:
            ctx.state["npmtypo_client_missing"] = True
            ctx.source("no http client")
            return

        top = _load_top()
        if not top:
            ctx.state["npmtypo_list_missing"] = True
            ctx.source("curated npm top-list missing")
            return

        raw, source = await asyncio.to_thread(_fetch_package_json, req, host)
        ctx.state["npmtypo_manifest_source"] = source or "none"
        if not raw:
            ctx.state["npmtypo_no_manifest"] = True
            ctx.source("no package.json reachable")
            return

        try:
            pkg = json.loads(raw)
        except Exception as e:
            ctx.state["npmtypo_no_manifest"] = True
            ctx.state["npmtypo_manifest_source"] = f"{source} (parse error: {str(e)[:60]})"
            ctx.source("bad package.json")
            return

        declared = _declared_names(pkg)
        ctx.state["npmtypo_declared_count"] = len(declared)
        if not declared:
            ctx.source("no declared npm dependencies")
            return

        # Candidates = declared names not in the popular list that are
        # Damerau-distance EXACTLY 1 from a popular name. (Exact popular names,
        # and names >1 edit away, are never flagged -> zero-FP class.)
        candidates = []
        for name in declared:
            if name in top:
                continue
            near = next((t for t in top if _within_one(name, t)), None)
            if near:
                candidates.append({"declared": name, "near": near})

        ctx.state["npmtypo_candidates"] = candidates
        ctx.source(f"npm-typosquat: {len(declared)} declared deps, "
                   f"{len(candidates)} near-miss candidate(s) from {source}")
    return gather


INTEL_FIELDS = [("Manifest source", "npmtypo_manifest_source"),
                ("Declared dependencies", "npmtypo_declared_count"),
                ("Typosquat candidates", "npmtypo_candidates")]


@router.post("/api/supply_chain/npm_typosquat_scan")
async def supply_chain_npm_typosquat_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="npm_typosquat_scan",
        gather_func=_make_gather(req),
        finding_rules=NPM_TYPOSQUAT_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
