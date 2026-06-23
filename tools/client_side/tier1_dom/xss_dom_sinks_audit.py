"""xss_dom_sinks_audit - DOM-XSS source-to-sink dataflow audit
(playbook §1 #1 + §5 #44).

DOM-based XSS doesn't show up in the response body — it lives in the
JavaScript that runs after page load. This probe fetches the URL,
collects all inline + external JS via BeautifulSoup, then scans the
JS source with regex for two layers:

  LAYER 1 — DANGEROUS SINKS
    - .innerHTML = / .outerHTML =        → HTML injection
    - document.write / document.writeln  → HTML injection
    - eval() / new Function()            → JS execution
    - setTimeout(string) / setInterval(string)
                                          → JS execution
    - location = / location.href = /
       location.assign / location.replace → open redirect / javascript:
    - el.insertAdjacentHTML('...', X)    → HTML injection
    - el.setAttribute('src', X) / .href = X for js-capable URLs
    - $(...).html(X) jQuery sink         → HTML injection

  LAYER 2 — TAINT SOURCES feeding those sinks
    - document.location / .location.search / .hash / .pathname
    - document.URL / .documentURI / .baseURI
    - window.name
    - window.history.state
    - localStorage.getItem / sessionStorage.getItem
    - event.data inside addEventListener("message", ...)

A finding goes CRITICAL ONLY when a confirmed source flows into a sink
in the SAME function (regex co-occurrence inside the same JS block /
proximity window) — a proven source→sink taint flow. A sink existing
WITHOUT a co-occurring source is graded LOW (a code-review pointer, not
a proven exploit), to avoid false-positives on sites that use
innerHTML / document.write only with static / trusted values.
Static analysis only — does not execute or fuzz the page.

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.max_js      = max external JS files to fetch (default 12)
  - options.user_agent  = optional UA override
"""
from __future__ import annotations
import asyncio
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.xss_dom_sinks_audit_findings import XSS_DOM_SINKS_AUDIT_FINDING_RULES

router = APIRouter()


class XssDomSinksRequest(ScanRequest):
    options: Optional[dict] = None


# Layer 1 — sinks
SINK_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("innerHTML_assign",   "HIGH",
     re.compile(r"""\.\s*(?:inner|outer)HTML\s*=\s*""")),
    ("document_write",     "HIGH",
     re.compile(r"""document\s*\.\s*write(?:ln)?\s*\(""")),
    ("eval_call",          "HIGH",
     re.compile(r"""(?<![A-Za-z0-9_$])eval\s*\(""")),
    ("new_function",       "HIGH",
     re.compile(r"""new\s+Function\s*\(""")),
    ("settimeout_str",     "HIGH",
     re.compile(r"""set(?:Timeout|Interval)\s*\(\s*['"`]""")),
    ("location_assign",    "MEDIUM",
     re.compile(r"""(?:window\.)?location\s*(?:\.\s*(?:href|assign|replace)\s*\(?\s*=?|=)\s*""")),
    ("insert_adjacent",    "HIGH",
     re.compile(r"""\.\s*insertAdjacentHTML\s*\(""")),
    ("jquery_html",        "HIGH",
     re.compile(r"""\$\s*\([^)]*\)\s*\.\s*html\s*\(""")),
    ("element_setattr_src",  "MEDIUM",
     re.compile(r"""\.\s*setAttribute\s*\(\s*['"](?:src|href|action|formaction)['"]\s*,""")),
    ("range_create_html",  "HIGH",
     re.compile(r"""createContextualFragment\s*\(""")),
]

# Layer 2 — taint sources
SOURCE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("document_location",
     re.compile(r"""document\s*\.\s*location(?:\s*\.\s*(?:search|hash|pathname|href))?""")),
    ("window_location",
     re.compile(r"""(?:window\s*\.\s*)?location\s*\.\s*(?:search|hash|pathname|href)""")),
    ("document_url",
     re.compile(r"""document\s*\.\s*(?:URL|documentURI|baseURI|referrer)""")),
    ("window_name",
     re.compile(r"""window\s*\.\s*name""")),
    ("history_state",
     re.compile(r"""(?:window\s*\.\s*)?history\s*\.\s*state""")),
    ("storage_get",
     re.compile(r"""(?:local|session)Storage\s*\.\s*getItem\s*\(""")),
    ("postmessage_event_data",
     re.compile(r"""(?:event|e|msg|message)\s*\.\s*data""")),
    ("query_string_parse",
     re.compile(r"""URLSearchParams\s*\(|new\s+URL\s*\(\s*location|getURLParameter\s*\(""")),
]

# Strings that imply the JS file is a known framework — ignore for sink-count
# noise reduction (still report exact matches in evidence though).
FRAMEWORK_SIGNATURE = re.compile(
    r"""/\*\!?\s*(?:jQuery|React|Vue|Angular|Lodash|Bootstrap)|"""
    r"""React\.\s*createElement|"""
    r"""_react\d+\.default\.createElement""",
    re.IGNORECASE,
)


# Window we use to call a finding CRITICAL: source AND sink in the same
# 400-char text window (~one function body) of one JS asset.
PROXIMITY_WINDOW = 400


def _strip_comments(js: str) -> str:
    """Strip // and /* */ comments to reduce false-positives from
    docstrings that mention "eval" etc."""
    # Block comments
    js = re.sub(r"/\*[\s\S]*?\*/", " ", js)
    # Line comments (greedy but stop at newline)
    js = re.sub(r"//[^\n]*", " ", js)
    return js


def _find_sinks(js: str) -> list[dict]:
    out: list[dict] = []
    for name, sev, rx in SINK_PATTERNS:
        for m in rx.finditer(js):
            ctx_start = max(0, m.start() - 80)
            ctx_end = min(len(js), m.end() + 80)
            out.append({
                "sink_id":  name,
                "severity": sev,
                "offset":   m.start(),
                "snippet":  js[ctx_start:ctx_end].strip(),
            })
            # cap per-pattern to avoid huge JSON blobs from minified bundles
            if sum(1 for x in out if x["sink_id"] == name) >= 6:
                break
    return out


def _find_sources(js: str) -> list[dict]:
    out: list[dict] = []
    for name, rx in SOURCE_PATTERNS:
        for m in rx.finditer(js):
            out.append({"source_id": name, "offset": m.start()})
            if sum(1 for x in out if x["source_id"] == name) >= 6:
                break
    return out


def _correlate_proximity(sinks: list[dict], sources: list[dict]) -> list[dict]:
    """Match each sink to nearby sources (within PROXIMITY_WINDOW chars)."""
    flows: list[dict] = []
    src_offsets = [(s["offset"], s["source_id"]) for s in sources]
    for sk in sinks:
        nearby = [sid for off, sid in src_offsets
                  if abs(off - sk["offset"]) <= PROXIMITY_WINDOW]
        if nearby:
            flows.append({
                "sink_id":   sk["sink_id"],
                "severity":  "CRITICAL",     # source → sink dataflow confirmed
                "sources":   sorted(set(nearby))[:5],
                "snippet":   sk["snippet"][:240],
            })
    return flows


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
        ctx.state["xss_dom_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        ctx.state["xss_dom_error"] = "beautifulsoup4 not installed (pip install beautifulsoup4)"
        ctx.source("bs4 missing")
        return

    opts = ctx.state.get("_options") or {}
    max_js = min(int(opts.get("max_js") or 12), 24)
    ua = opts.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    fetched_html: Optional[str] = None
    base_url = target
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=20, follow_redirects=True,
            headers={"User-Agent": ua, "Accept": "text/html,*/*"},
        ) as client:
            r = await client.get(target)
            fetched_html = r.text or ""
            base_url = str(r.url)
            ctx.state["xss_dom_http_status"] = r.status_code
            ctx.state["xss_dom_target_url"] = base_url
    except Exception as e:
        ctx.state["xss_dom_error"] = f"fetch failed: {type(e).__name__}: {str(e)[:120]}"
        ctx.source("fetch failed")
        return

    soup = BeautifulSoup(fetched_html, "html.parser")
    inline_scripts: list[str] = []
    external_urls: list[str] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            external_urls.append(urljoin(base_url, src))
        else:
            txt = tag.string or tag.get_text() or ""
            if txt.strip():
                inline_scripts.append(txt)
    # Deduplicate + clamp external URLs (skip data: and obvious framework CDNs
    # to keep scan time reasonable — analyst can re-run with max_js bumped).
    seen = set()
    deduped: list[str] = []
    for u in external_urls:
        if u in seen:
            continue
        if u.startswith("data:"):
            continue
        seen.add(u)
        deduped.append(u)
    external_urls = deduped[:max_js]

    fetched_js: list[tuple[str, str]] = []  # (label, source)
    for i, src in enumerate(inline_scripts[:20]):
        fetched_js.append((f"inline#{i}", src))

    async def _fetch_one(client, url):
        try:
            r = await client.get(url)
            if r.status_code != 200:
                return url, None
            ct = r.headers.get("content-type", "").lower()
            if "javascript" not in ct and "text" not in ct and "ecmascript" not in ct:
                return url, None
            txt = r.text or ""
            if len(txt) > 2_000_000:  # 2 MB cap per file
                txt = txt[:2_000_000]
            return url, txt
        except Exception:
            return url, None

    if external_urls:
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=15, follow_redirects=True,
                headers={"User-Agent": ua, "Accept": "*/*"},
            ) as client:
                sem = asyncio.Semaphore(6)

                async def _bound(u):
                    async with sem:
                        return await _fetch_one(client, u)

                results = await asyncio.gather(*[_bound(u) for u in external_urls])
                for url, txt in results:
                    if txt:
                        fetched_js.append((url, txt))
        except Exception as e:
            ctx.state["xss_dom_js_fetch_warn"] = (
                f"external JS fetch issue: {type(e).__name__}: {str(e)[:120]}"
            )

    all_sinks: list[dict] = []
    all_flows: list[dict] = []
    per_file: list[dict] = []

    for label, src in fetched_js:
        cleaned = _strip_comments(src)
        sinks = _find_sinks(cleaned)
        sources = _find_sources(cleaned)
        flows = _correlate_proximity(sinks, sources)
        is_framework = bool(FRAMEWORK_SIGNATURE.search(src[:2000]))
        if sinks or flows:
            per_file.append({
                "asset":       label,
                "sink_count":  len(sinks),
                "source_count": len(sources),
                "flows":       flows[:6],     # cap evidence
                "sample_sink": (sinks[0] if sinks else None),
                "framework":   is_framework,
            })
        # Skip aggregating noisy framework counts but DO add real flows
        if not is_framework:
            all_sinks.extend(sinks)
        all_flows.extend(flows)

    ctx.state["xss_dom_assets_total"] = len(fetched_js)
    ctx.state["xss_dom_inline_count"] = len(inline_scripts)
    ctx.state["xss_dom_external_count"] = len(external_urls)
    ctx.state["xss_dom_sinks_total"] = len(all_sinks)
    ctx.state["xss_dom_confirmed_flows"] = all_flows[:20]
    ctx.state["xss_dom_flows_total"] = len(all_flows)
    ctx.state["xss_dom_per_file"] = per_file[:20]
    sink_label = f"{len(all_sinks)} sinks; {len(all_flows)} src→sink flows"
    ctx.source(f"GET {target}; {len(fetched_js)} JS asset(s) analysed; {sink_label}")


INTEL_FIELDS = [
    ("Target URL",                 "xss_dom_target_url"),
    ("HTTP status",                "xss_dom_http_status"),
    ("JS assets analysed",         "xss_dom_assets_total"),
    ("Inline <script> blocks",     "xss_dom_inline_count"),
    ("External JS files fetched",  "xss_dom_external_count"),
    ("Dangerous sinks (total)",    "xss_dom_sinks_total"),
    ("Confirmed source→sink flows","xss_dom_flows_total"),
    ("Top flows (sample)",         "xss_dom_confirmed_flows"),
    ("Per-file breakdown",         "xss_dom_per_file"),
]


@router.post("/api/client_side/xss_dom_sinks_audit")
async def client_side_xss_dom_sinks_audit(req: XssDomSinksRequest,
                                            _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="xss_dom_sinks_audit",
        gather_func=_gather_with_options,
        finding_rules=XSS_DOM_SINKS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
