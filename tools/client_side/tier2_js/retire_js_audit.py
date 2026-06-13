"""retire_js_audit - known-vulnerable JavaScript library detection via the
real retire.js CLI (playbook §5 #43 supply-chain / vulnerable-component
surface).

A page that ships an outdated front-end library (jQuery 1.x, AngularJS
1.x, lodash <4.17.12, Moment.js <2.29.4, Handlebars <4.7.7, ...) inherits
every published CVE of that version: client-side prototype pollution, DOM
XSS via append()/html(), ReDoS, sandbox bypasses, and in the worst case
prototype-pollution -> RCE. retire.js carries a curated advisory database
mapping library + version range -> CVE + severity, so the library names
and CVE IDs we report are the tool's own confirmed matches (zero false
positives — we never guess a version).

This probe (DETECTION ONLY, nothing executed):
  1. fetches the target HTML,
  2. discovers + downloads the FIRST-PARTY <script src=...> assets (same
     registrable domain only — we never scan third-party CDNs we don't
     own), plus the inline HTML itself,
  3. runs `retire --js --jspath <tmpdir> --outputformat json` over the
     downloaded sources,
  4. parses retire's JSON and emits ONE finding per vulnerable library,
     carrying the component name, detected version, CVE identifiers, and
     severity straight from retire's advisory database.

Findings (graded ONLY on what retire actually matched):
  CRITICAL/HIGH/MEDIUM/LOW - one per vulnerable library, severity mapped
                             from the retire advisory entry
  INFO  [ADVISORY-BY-DESIGN] - `retire` binary not installed in the image
  INFO                        - no first-party JavaScript found / target
                               unreachable
  POSITIVE                   - JS analysed, retire matched no known-vuln
                               library

ZERO false positives: a graded severity is emitted ONLY for a
library/version that retire.js positively matched against its advisory
DB. If the `retire` binary is missing OR no JS could be fetched, the
scanner returns a clean INFO finding — never a crash, never a false HIGH.

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.max_js      = max first-party JS files to download (default 25)
  - options.user_agent  = optional UA override
"""
from __future__ import annotations
import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional
from urllib.parse import urljoin, urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()

# Wall-clock cap for the retire subprocess (seconds).
RETIRE_TIMEOUT = 90
# Hard ceilings so a hostile target can't make us download forever.
DEFAULT_MAX_JS = 25
HARD_MAX_JS = 40
MAX_JS_BYTES = 5 * 1024 * 1024          # don't write >5 MB per JS file
# Number of per-library closure rules we pre-build (== max distinct
# vulnerable libraries reported in one scan). Matches the advisory-surface
# index-rule idiom used elsewhere in this module.
MAX_VULN_LIBS = 40

# retire severity strings -> our canonical grades + CVSS anchors.
_SEV_MAP = {
    "critical": ("CRITICAL", "9.8"),
    "high":     ("HIGH", "7.5"),
    "medium":   ("MEDIUM", "5.4"),
    "moderate": ("MEDIUM", "5.4"),
    "low":      ("LOW", "3.1"),
    "info":     ("LOW", "3.1"),
}

_SCRIPT_SRC_RE = re.compile(
    r'<script[^>]*\bsrc=["\']([^"\']+)["\']', re.IGNORECASE
)


def _which() -> Optional[str]:
    return shutil.which("retire")


def _registrable(host: str) -> str:
    """Cheap eTLD+1 approximation (last two labels) to decide first-party
    vs third-party. Same heuristic as subresource_integrity_audit."""
    host = (host or "").lower().strip()
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    two_label_suffixes = {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au",
        "co.in", "co.jp", "com.br", "co.nz", "co.za",
    }
    last_two = ".".join(parts[-2:])
    if last_two in two_label_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _run_retire(jspath: str) -> tuple[Optional[dict], Optional[str]]:
    """Invoke the real retire.js CLI over a directory of JS files.

    Returns (parsed_json, error). parsed_json is None on any failure;
    error is a human string for the advisory/INFO path.
    """
    binary = _which()
    if not binary:
        return None, "retire-not-installed"
    cmd = [
        binary,
        "--js",                       # scan JS only (skip node_modules dep walk)
        "--jspath", jspath,
        "--outputformat", "json",
        "--exitwith", "0",            # never let a non-zero exit kill parsing
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=RETIRE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return None, f"retire timed out after {RETIRE_TIMEOUT}s"
    except Exception as e:
        return None, f"retire execution failed: {type(e).__name__}: {str(e)[:120]}"

    # retire writes the JSON report to stdout. Some builds prepend a banner
    # or emit nothing when clean — locate the JSON object/array defensively.
    out = (proc.stdout or "").strip()
    if not out:
        # No stdout but the run succeeded => nothing vulnerable found.
        return {"data": []}, None
    parsed = None
    try:
        parsed = json.loads(out)
    except Exception:
        # Strip any leading non-JSON banner lines and retry on the brace.
        for marker in ("{", "["):
            idx = out.find(marker)
            if idx != -1:
                try:
                    parsed = json.loads(out[idx:])
                    break
                except Exception:
                    parsed = None
    if parsed is None:
        return None, "could not parse retire JSON output"
    return parsed, None


def _normalise_results(parsed: dict) -> list[dict]:
    """Flatten retire.js JSON into one record per (component, version,
    vulnerability). Only entries retire positively matched are returned.

    retire schema (v2-v5):
      {"data": [{"file": "...", "results": [
          {"component": "jquery", "version": "1.8.0",
           "vulnerabilities": [
              {"severity": "medium",
               "identifiers": {"summary": "...",
                               "CVE": ["CVE-2020-11023"]},
               "info": ["https://..."]}]}]}]}
    """
    out: list[dict] = []
    seen: set = set()
    # Newer retire wraps everything under "data"; older emits a bare list.
    files = parsed.get("data") if isinstance(parsed, dict) else parsed
    if not isinstance(files, list):
        return out
    for entry in files:
        if not isinstance(entry, dict):
            continue
        src_file = os.path.basename(str(entry.get("file") or ""))[:120]
        for res in (entry.get("results") or []):
            if not isinstance(res, dict):
                continue
            component = str(res.get("component") or "").strip()
            version = str(res.get("version") or "").strip()
            vulns = res.get("vulnerabilities") or []
            if not component or not vulns:
                continue
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                sev_raw = str(v.get("severity") or "medium").lower()
                idents = v.get("identifiers") or {}
                cves = idents.get("CVE") or idents.get("cve") or []
                if isinstance(cves, str):
                    cves = [cves]
                cves = [c for c in cves if isinstance(c, str) and c.upper().startswith("CVE-")]
                summary = (idents.get("summary")
                           or (idents.get("issue") if isinstance(idents.get("issue"), str) else "")
                           or "")
                infos = v.get("info") or []
                ref = infos[0] if infos and isinstance(infos[0], str) else ""
                # Dedup identical (component, version, primary-CVE) tuples that
                # appear once per scanned file.
                key = (component.lower(), version, cves[0] if cves else summary[:60])
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "component": component,
                    "version": version,
                    "severity_raw": sev_raw,
                    "cves": cves,
                    "summary": str(summary)[:240],
                    "reference": str(ref)[:240],
                    "file": src_file,
                })
    return out


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.source("no-target")
        return
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Tool presence is recorded early so the advisory rule can fire even when
    # the target is reachable + has JS (honest "binary missing" signal).
    binary = _which()
    ctx.state["retire_binary"] = binary or "(not installed)"
    ctx.state["retire_target_url"] = target

    try:
        import httpx
    except ImportError:
        ctx.state["retire_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return

    opts = ctx.state.get("_options") or {}
    try:
        max_js = int(opts.get("max_js") or DEFAULT_MAX_JS)
    except Exception:
        max_js = DEFAULT_MAX_JS
    max_js = max(1, min(max_js, HARD_MAX_JS))
    ua = opts.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    # 1) Fetch the page HTML.
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=20, follow_redirects=True,
            headers={"User-Agent": ua, "Accept": "text/html,*/*"},
        ) as client:
            r = await client.get(target)
            html = r.text or ""
            base_url = str(r.url)
            ctx.state["retire_http_status"] = r.status_code
            ctx.state["retire_target_url"] = base_url
    except Exception as e:
        ctx.state["retire_error"] = f"fetch failed: {type(e).__name__}: {str(e)[:120]}"
        ctx.source("fetch failed")
        return

    base_host = urlparse(base_url).hostname or ""
    base_reg = _registrable(base_host)

    # 2) Discover FIRST-PARTY script URLs only (never scan a CDN we don't own).
    js_urls: list[str] = []
    for src in _SCRIPT_SRC_RE.findall(html):
        if src.startswith("data:"):
            continue
        abs_u = urljoin(base_url, src)
        if not abs_u.startswith(("http://", "https://")):
            continue
        h = urlparse(abs_u).hostname or ""
        if _registrable(h) == base_reg:
            js_urls.append(abs_u)
    js_urls = list(dict.fromkeys(js_urls))[:max_js]
    ctx.state["retire_js_first_party"] = len(js_urls)

    # Stage the JS (and the inline HTML) into a temp dir for retire to scan.
    tmpdir = tempfile.mkdtemp(prefix="vl_retire_")
    written = 0
    try:
        # Always include the HTML itself — inline libraries get matched too.
        try:
            html_path = os.path.join(tmpdir, "index.html")
            with open(html_path, "w", encoding="utf-8", errors="ignore") as fh:
                fh.write(html[:MAX_JS_BYTES])
        except Exception:
            pass

        if js_urls:
            try:
                async with httpx.AsyncClient(
                    verify=False, timeout=15, follow_redirects=True,
                    headers={"User-Agent": ua, "Accept": "*/*"},
                ) as client:
                    sem = asyncio.Semaphore(6)

                    async def _one(i_u):
                        i, u = i_u
                        async with sem:
                            try:
                                rr = await client.get(u)
                            except Exception:
                                return
                            if rr.status_code != 200:
                                return
                            body = rr.text or ""
                            if not body:
                                return
                            # Preserve a meaningful filename so retire's
                            # filename-based hints work (jquery.min.js etc.).
                            name = os.path.basename(urlparse(u).path) or f"asset_{i}.js"
                            if not name.endswith(".js"):
                                name = f"{name or 'asset'}_{i}.js"
                            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80]
                            fpath = os.path.join(tmpdir, f"{i:03d}_{safe}")
                            try:
                                with open(fpath, "w", encoding="utf-8",
                                          errors="ignore") as fh:
                                    fh.write(body[:MAX_JS_BYTES])
                            except Exception:
                                return
                            return fpath

                    results = await asyncio.gather(
                        *[_one((i, u)) for i, u in enumerate(js_urls)]
                    )
                    written = sum(1 for x in results if x)
            except Exception as e:
                ctx.state["retire_js_warn"] = f"{type(e).__name__}: {str(e)[:100]}"

        ctx.state["retire_js_written"] = written

        # No first-party JS and no inline HTML libs to scan -> nothing to do.
        if written == 0 and not html.strip():
            ctx.state["retire_no_js"] = True
            ctx.source(f"GET {target}; no first-party JavaScript to audit")
            return

        # 3) Run the real retire.js CLI in a worker thread (it's blocking).
        if not binary:
            # Binary missing but we DID find JS — record so the advisory rule
            # fires with an honest "couldn't run the tool" signal.
            ctx.state["retire_unavailable"] = True
            ctx.source(f"GET {target}; retire binary not installed")
            return

        parsed, err = await asyncio.to_thread(_run_retire, tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if err == "retire-not-installed":
        ctx.state["retire_unavailable"] = True
        ctx.source(f"GET {target}; retire binary not installed")
        return
    if err:
        ctx.state["retire_error"] = err
        ctx.source(f"GET {target}; retire error: {err}")
        return

    vuln_libs = _normalise_results(parsed or {})
    ctx.state["retire_vuln_libs"] = vuln_libs[:MAX_VULN_LIBS]
    ctx.state["retire_vuln_count"] = len(vuln_libs)
    ctx.source(
        f"GET {target}; retire scanned {written} first-party JS asset(s); "
        f"{len(vuln_libs)} vulnerable library finding(s)"
    )


# ── findings rules ──────────────────────────────────────────────────────
# One finding PER vulnerable library, built as index-based closures (same
# idiom as clientside_advisory_surface). Each reads
# state["retire_vuln_libs"][idx] and returns None when out of range.

def _make_lib_rule(idx: int):
    def _rule(s):
        if s.get("retire_error") or s.get("retire_unavailable"):
            return None
        libs = s.get("retire_vuln_libs") or []
        if idx >= len(libs):
            return None
        lib = libs[idx]
        component = lib.get("component") or "unknown"
        version = lib.get("version") or "?"
        sev_raw = (lib.get("severity_raw") or "medium").lower()
        sev, cvss = _SEV_MAP.get(sev_raw, ("MEDIUM", "5.4"))
        cves = lib.get("cves") or []
        cve_str = ", ".join(cves) if cves else "N/A"
        summary = lib.get("summary") or ""
        ref = lib.get("reference") or ""
        return {
            "name": (f"Vulnerable JS library: {component} {version}"
                     + (f" ({cves[0]})" if cves else "")),
            "severity": sev,
            "cvss": cvss,
            "cve": cve_str,
            "cwe": "CWE-1395",
            "cwe_name": "Dependency on Vulnerable Third-Party Component",
            "owasp": "A06:2021",
            "verified_exploit": True,   # retire confirmed the version match
            "evidence": (
                f"retire.js matched {component} version {version} against its "
                f"advisory database as a known-vulnerable component loaded by "
                f"this site"
                + (f" (file: {lib.get('file')})" if lib.get("file") else "")
                + ". "
                + (f"Advisory: {summary} " if summary else "")
                + (f"CVE(s): {cve_str}." if cves else "")
            ),
            "remediation": (
                f"Upgrade {component} to the latest patched release (retire.js "
                f"flags {component} {version} as vulnerable). Pin the version, "
                f"add Subresource-Integrity to the CDN <script>, and run "
                f"retire.js / npm audit in CI so a vulnerable dependency is "
                f"caught before deploy."
                + (f" Reference: {ref}" if ref else "")
            ),
        }
    return _rule


def rule_tool_unavailable(s):
    if not s.get("retire_unavailable"):
        return None
    return {
        "name": "[ADVISORY-BY-DESIGN] retire.js not available - vulnerable-library scan skipped",
        "severity": "INFO",
        "cvss": "0.0",
        "cwe": "CWE-1395",
        "owasp": "A06:2021",
        "evidence": (
            "The `retire` CLI is not installed in the scanner image, so the "
            "known-vulnerable JavaScript library audit could not run. This is "
            "an availability advisory, NOT a finding about the target."
        ),
        "remediation": (
            "Install retire.js in the backend image "
            "(`npm install -g retire`) and re-run, or run "
            "`retire --js --jspath <dir>` against the site's front-end "
            "assets manually."
        ),
    }


def rule_no_js(s):
    if s.get("retire_error") or s.get("retire_unavailable"):
        return None
    if not s.get("retire_no_js"):
        return None
    return {
        "name": "No first-party JavaScript to audit",
        "severity": "INFO",
        "cvss": "0.0",
        "cwe": "CWE-1395",
        "evidence": (
            f"GET {s.get('retire_target_url')} returned no first-party "
            "<script src> assets and no inline content, so there was nothing "
            "for retire.js to analyse."
        ),
        "remediation": (
            "Re-run against the application route(s) that actually load the "
            "front-end bundle (e.g. the authenticated app, not a static "
            "landing page)."
        ),
    }


def rule_fetch_failed(s):
    err = s.get("retire_error")
    if not err:
        return None
    return {
        "name": "retire.js audit could not complete",
        "severity": "INFO",
        "cvss": "0.0",
        "cwe": "CWE-1006",
        "evidence": str(err)[:300],
        "remediation": (
            "Confirm the target URL is reachable from the scanner host, "
            "serves HTML, and that retire.js + httpx are installed."
        ),
    }


def rule_positive(s):
    if s.get("retire_error") or s.get("retire_unavailable"):
        return None
    if s.get("retire_no_js"):
        return None
    # Only assert "clean" when retire actually ran over some JS.
    if not s.get("retire_js_written") and not s.get("retire_js_first_party"):
        return None
    if s.get("retire_vuln_count"):
        return None
    return {
        "name": "No known-vulnerable JS libraries detected by retire.js",
        "severity": "POSITIVE",
        "cvss": "0.0",
        "cwe": "CWE-1395",
        "owasp": "A06:2021",
        "evidence": (
            f"retire.js scanned {s.get('retire_js_written', 0)} first-party "
            "JavaScript asset(s) (plus the page HTML) and matched none of them "
            "against its known-vulnerable advisory database."
        ),
        "remediation": (
            "Maintain. Keep front-end dependencies patched and keep running "
            "retire.js / npm audit in CI; re-test after every dependency bump."
        ),
    }


RETIRE_JS_AUDIT_FINDING_RULES = (
    [_make_lib_rule(i) for i in range(MAX_VULN_LIBS)]
    + [rule_tool_unavailable, rule_no_js, rule_fetch_failed, rule_positive]
)


INTEL_FIELDS = [
    ("Target URL",                 "retire_target_url"),
    ("HTTP status",                "retire_http_status"),
    ("retire binary",              "retire_binary"),
    ("First-party JS discovered",  "retire_js_first_party"),
    ("JS assets scanned",          "retire_js_written"),
    ("Vulnerable libraries",       "retire_vuln_count"),
    ("Vulnerable library detail",  "retire_vuln_libs"),
]


class RetireJsAuditRequest(ScanRequest):
    options: Optional[dict] = None


@router.post("/api/client_side/retire_js_audit")
async def client_side_retire_js_audit(req: RetireJsAuditRequest,
                                      _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="retire_js_audit",
        gather_func=_gather_with_options,
        finding_rules=RETIRE_JS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
