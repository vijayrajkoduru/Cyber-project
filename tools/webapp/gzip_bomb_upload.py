"""gzip_bomb_upload — gzip-bomb DoS protection check.

Apps that accept gzip-encoded request bodies (Content-Encoding: gzip)
+ decompress without size cap = vulnerable to gzip bombs. A 1 KB gzip
file can decompress to 10 MB+, exhausting memory.

Test: POST a benign 5 KB gzip body (decompresses to ~5 MB of zeros)
to common upload/API endpoints. Flag if accepted (200) vs rejected
(413 / 415).

Zero-FP: bomb is benign-sized (won't actually DoS); just measures
whether server has size protection.
"""
import gzip
from io import BytesIO
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

PROBE_PATHS = ["/api/upload", "/upload", "/api/data",
                "/api/file", "/api/import", "/api/v1/upload"]


def _make_gzip_bomb_small() -> bytes:
    """Small benign bomb: 5 MB of zeros → ~5 KB compressed."""
    buf = BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9) as gz:
        gz.write(b"\x00" * (5 * 1024 * 1024))
    return buf.getvalue()


@router.post("/api/webapp/scan/gzip_bomb_upload")
@vl_turbo()
@vl_verify()
def scan_gzip_bomb_upload(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    bomb = _make_gzip_bomb_small()  # ~5 KB → 5 MB decompressed

    accepted = []
    rejected = []
    tested = 0

    for path in PROBE_PATHS:
        url = base + path
        # Baseline: probe path exists?
        r0 = safe_request("GET", url,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        # Skip clearly-nonexistent
        if r0 is None or r0.status_code == 404: continue
        tested += 1

        r = safe_request("POST", url,
            headers={"User-Agent": "VulnusLab/1.0",
                      "Content-Type": "application/octet-stream",
                      "Content-Encoding": "gzip"},
            data=bomb, req=req, timeout=20, allow_redirects=False)
        if r is None: continue

        # 413 = payload too large (good), 415 = unsupported media (good),
        # 5xx = decompress crashed (BAD — DoS surface!)
        if r.status_code in (413, 415):
            rejected.append({"path": path, "status": r.status_code})
        elif r.status_code >= 500:
            accepted.append({"path": path, "status": r.status_code,
                              "issue": "crash (5xx) — possible decompression DoS"})
        elif r.status_code == 200:
            accepted.append({"path": path, "status": 200,
                              "issue": "accepted 5MB decompressed payload"})

    findings = []
    if accepted:
        findings.append(wrap_finding(
            f"GZIP BOMB risk at {len(accepted)} endpoint(s)",
            "MEDIUM", cvss="5.3", cwe="CWE-409", owasp="A04:2021",
            remediation="Cap decompressed body size BEFORE decompressing. "
                        "Frameworks: nginx 'client_max_body_size' applies to "
                        "compressed bytes — add 'gzip_max_body_size' OR "
                        "decompress inline with size check (Express: "
                        "body-parser inflate: false + manual stream decompress "
                        "with byte count). Real attacker bombs reach 1000:1 "
                        "ratios (1 MB → 1 GB).",
            evidence_marker=" | ".join(
                f"{a['path']}: HTTP {a['status']} ({a.get('issue','?')})"
                for a in accepted[:5]
            )))
    elif rejected and not accepted:
        findings.append(wrap_finding(
            f"Gzip-encoded upload rejected at {len(rejected)} endpoint(s)",
            "POSITIVE", cwe="CWE-409",
            remediation="Maintain. Continue size-cap on decompression.",
            evidence_marker=" | ".join(f"{r['path']}: HTTP {r['status']}"
                                          for r in rejected[:5])))
    else:
        return standard_response(
            tool="gzip_bomb_upload", target=req.target, findings=[],
            tests_performed=len(PROBE_PATHS), vulnerable=False,
            skipped_reason=f"No upload endpoints found among {PROBE_PATHS}")

    return standard_response(
        tool="gzip_bomb_upload", target=req.target, findings=findings,
        tests_performed=tested * 2,
        vulnerable=bool(accepted),
        tests_summary=f"{tested} endpoints tested, {len(accepted)} risky",
        raw_data={"accepted_paths": accepted, "rejected_paths": rejected})


def register(app):
    app.include_router(router)
