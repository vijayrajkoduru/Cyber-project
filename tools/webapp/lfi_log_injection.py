"""lfi_log_injection — LFI + log-injection chain detection.

Classic attack: app has LFI vuln (file= parameter takes path). Attacker
poisons web-server log with <?php system($_GET['c']);?> via User-Agent
header (logged in access.log), then LFI to /var/log/apache2/access.log
→ PHP eval = RCE.

Test: probe common log paths via LFI parameter names, check if response
contains log-line markers (IP addresses, HTTP status codes, timestamps).
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

LOG_PATHS = [
    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
    "/var/log/nginx/access.log", "/var/log/nginx/error.log",
    "/var/log/httpd/access_log", "/var/log/httpd/error_log",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/syslog", "/var/log/messages",
]
PARAMS = ["file", "page", "path", "include", "template", "view", "doc"]


@router.post("/api/webapp/scan/lfi_log_injection")
@vl_turbo()
def scan_lfi_log_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    lfi_hits = []
    tested = 0

    # First find a path with one of the suspicious params reflecting input
    for param in PARAMS:
        for log_path in LOG_PATHS:
            url = base + "/"
            r = safe_request("GET", url, params={param: log_path},
                headers={"User-Agent": "VulnusLab/1.0"},
                req=req, timeout=8, allow_redirects=False)
            if r is None: continue
            tested += 1
            body = (r.text or "")[:50000]
            # LFI success markers in log files
            indicators = [
                # access.log: "GET /... HTTP/1.1" 200 1234
                r" \"GET ",  # raw text marker
                "HTTP/1.1",
                # /proc/self/environ
                "PATH=",
                "USER=",
                # /etc/passwd
                "root:x:",
                # syslog/messages
                "kernel:",
                "systemd",
            ]
            hit_indicators = [i for i in indicators if i.lower() in body.lower()]
            if hit_indicators:
                lfi_hits.append({"param": param, "log_path": log_path,
                                   "indicators": hit_indicators[:3],
                                   "status": r.status_code})
                break  # one log_path per param

    findings = []
    if lfi_hits:
        findings.append(wrap_finding(
            f"LFI to log files CONFIRMED at {len(lfi_hits)} parameter(s)",
            "CRITICAL", cvss="9.0", cwe="CWE-22", owasp="A03:2021",
            remediation="LFI + log access = RCE chain (poison log via User-Agent "
                        "with PHP/template payload + LFI include the log). "
                        "(1) Fix LFI first: whitelist allowed include paths, "
                        "block ../ + absolute paths, normalize before resolving. "
                        "(2) Defense in depth: don't serve user input as code "
                        "(disable PHP include() of dynamic paths, use safe "
                        "templating like Twig sandbox).",
            evidence_marker=" | ".join(
                f"?{h['param']}={h['log_path']} → HTTP {h['status']}, "
                f"markers: {','.join(h['indicators'])}"
                for h in lfi_hits[:3]
            )))
    else:
        findings.append(wrap_finding(
            f"No LFI to log files detected ({tested} probes)",
            "POSITIVE", cwe="CWE-22",
            remediation="Maintain. Continue normalizing + whitelisting paths in "
                        "any file-include logic.",
            evidence_marker=f"{tested} probes × {len(PARAMS)} param names × "
                              f"{len(LOG_PATHS)} log paths"))

    return standard_response(
        tool="lfi_log_injection", target=req.target, findings=findings,
        tests_performed=tested,
        vulnerable=bool(lfi_hits),
        tests_summary=f"{tested} probes, {len(lfi_hits)} LFI confirmed",
        raw_data={"lfi_hits": lfi_hits})


def register(app):
    app.include_router(router)
