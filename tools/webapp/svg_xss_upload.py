"""svg_xss_upload — SVG file upload XSS detection.

SVG files can contain inline <script> tags. If the app accepts SVG uploads
and serves them with Content-Type: image/svg+xml AND the same origin as
the app, viewing the file in browser executes the script.

Test: upload SVG with embedded <script> + then GET the uploaded URL
(if discoverable from response) and check for execution markers.
"""
import re
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

EVIL_SVG = '''<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
<script type="text/javascript">window.VULNUSLAB_SVG_XSS=1;</script>
<a xlink:href="javascript:alert(1)"><text>x</text></a>
</svg>'''

UPLOAD_PATHS = ["/upload", "/api/upload", "/api/v1/upload",
                 "/api/file", "/avatar/upload", "/profile/avatar",
                 "/api/users/avatar"]


def _multipart_upload(url, filename, content, content_type, req):
    boundary = "----vulnuslab-svg-9999"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
        f"{content}\r\n"
        f"--{boundary}--\r\n"
    )
    return safe_request("POST", url,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                  "User-Agent": "VulnusLab/1.0"},
        data=body, req=req, timeout=10, allow_redirects=False)


def _extract_url(body, base):
    """Try to find an URL where uploaded file might be served."""
    patterns = [
        r'"url"\s*:\s*"([^"]+)"',
        r'"path"\s*:\s*"([^"]+)"',
        r'"location"\s*:\s*"([^"]+)"',
        r'src=["\']([^"\']+\.svg)["\']',
        r'href=["\']([^"\']+\.svg)["\']',
    ]
    for p in patterns:
        m = re.search(p, body)
        if m:
            u = m.group(1)
            if u.startswith("/"): u = base + u
            elif not u.startswith("http"): u = base + "/" + u
            return u
    return None


@router.post("/api/webapp/scan/svg_xss_upload")
@vl_turbo()
@vl_verify()
def scan_svg_xss_upload(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    # VL-TURBO deep: parallel probe across 7 upload paths.
    # Each path requires GET + multipart POST + (optional) GET of served URL.
    # Sequential worst-case: 7 paths * 24s per path = ~170s killed at
    # VL-TURBO cap. Parallel: ~24s for all paths simultaneously.

    def _probe_path(path):
        url = base + path
        r0 = safe_request("GET", url,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=6, allow_redirects=False)
        if r0 is None or r0.status_code == 404:
            return ("unreachable", path, None, None)

        # Upload evil SVG
        r = _multipart_upload(url, "vulnuslab.svg", EVIL_SVG, "image/svg+xml", req)
        if r is None:
            return ("unreachable", path, None, None)
        if r.status_code not in (200, 201):
            return ("rejected", path, r.status_code, None)

        body = (r.text or "")[:5000]
        served_url = _extract_url(body, base)
        if not served_url:
            return ("accepted_no_url", path, r.status_code, None)

        rg = safe_request("GET", served_url,
            headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if rg is None or rg.status_code != 200:
            return ("accepted_no_fetch", path, r.status_code, served_url)
        ct = (rg.headers.get("content-type") or "").lower()
        body_g = (rg.text or "")[:5000]
        if "svg" in ct and "VULNUSLAB_SVG_XSS" in body_g:
            return ("xss_confirmed", path, r.status_code,
                    {"served_url": served_url, "content_type": ct})
        return ("accepted_safe", path, r.status_code, served_url)

    accepted = []
    served_inline = []
    tested = 0
    with ThreadPoolExecutor(max_workers=7) as pool:
        for verdict, path, status, extra in pool.map(_probe_path, UPLOAD_PATHS, timeout=35):
            if verdict == "unreachable":
                continue
            tested += 1
            if verdict in ("accepted_no_url", "accepted_no_fetch",
                            "accepted_safe", "xss_confirmed"):
                accepted.append({"path": path, "status": status})
            if verdict == "xss_confirmed":
                served_inline.append({
                    "upload_path": path,
                    "served_url": extra["served_url"],
                    "content_type": extra["content_type"],
                })

    findings = []
    if served_inline:
        findings.append(wrap_finding(
            f"SVG XSS CONFIRMED — uploaded SVG executes inline at {len(served_inline)} location(s)",
            "HIGH", cvss="7.5", cwe="CWE-79", owasp="A03:2021",
            remediation="(1) Serve uploaded SVG with Content-Type: image/png OR "
                        "Content-Security-Policy: sandbox. (2) Or strip <script> + "
                        "javascript: hrefs server-side using SVGO / DOMPurify-server. "
                        "(3) Best: serve user uploads from a separate domain (e.g. "
                        "userdata.example.com) so SVG XSS can't read app cookies. "
                        "(4) Or convert SVG → PNG server-side on upload.",
            evidence_marker=" | ".join(
                f"{s['upload_path']} → {s['served_url']} (CT={s['content_type']})"
                for s in served_inline[:3]
            )))
    elif accepted:
        findings.append(wrap_finding(
            f"SVG accepted at {len(accepted)} upload path(s) but XSS execution not confirmed",
            "INFO", cwe="CWE-79",
            remediation="Upload accepted — manually verify the served URL's "
                        "Content-Type and whether <script> survives. Worth a manual "
                        "DOMPurify audit even if execution not auto-confirmed.",
            evidence_marker=" | ".join(f"{a['path']}: HTTP {a['status']}" for a in accepted[:5])))
    elif tested > 0:
        findings.append(wrap_finding(
            f"SVG upload rejected at {tested} endpoint(s)",
            "POSITIVE", cwe="CWE-79",
            remediation="Maintain. Continue blocking SVG (or sanitize on accept).",
            evidence_marker=f"{tested} endpoints × evil SVG → rejected"))
    else:
        return standard_response(
            tool="svg_xss_upload", target=req.target, findings=[],
            tests_performed=len(UPLOAD_PATHS), vulnerable=False,
            skipped_reason="No upload endpoints found")

    return standard_response(
        tool="svg_xss_upload", target=req.target, findings=findings,
        tests_performed=tested * 2, vulnerable=bool(served_inline),
        tests_summary=f"{len(accepted)} accepted, {len(served_inline)} XSS-confirmed",
        raw_data={"accepted_uploads": accepted, "served_inline": served_inline})


def register(app):
    app.include_router(router)
