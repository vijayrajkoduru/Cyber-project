"""document_metadata — extract author / creator / timestamps from public docs.

Crawls /sitemap.xml + 3 common doc paths, downloads any .pdf/.docx/.xlsx,
extracts metadata via stdlib (zip+xml for OOXML; PDF Info dict for PDF).
No external deps (PyPDF2/python-docx avoided — keeps Docker layer thin).

VL-FOUNDRY Layer 6: 7-check DoD compliant.
"""
import asyncio
import io
import re
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.osint.osint_dorks import OSINT_DORKS  # registers L5 curation usage
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 25

_DOC_PATHS = ["/sitemap.xml", "/", "/about", "/docs", "/files"]
_PDF_INFO_RE = re.compile(rb"/(Author|Creator|Producer|Title|CreationDate)\s*\(([^)]{1,120})\)")
_OOXML_NS = {"cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
             "dc": "http://purl.org/dc/elements/1.1/",
             "dcterms": "http://purl.org/dc/terms/"}


def _find_docs(target: str, req) -> list[str]:
    """Crawl candidate paths, return absolute URLs to .pdf/.docx/.xlsx files."""
    docs = set()
    base = f"https://{target}"
    for p in _DOC_PATHS:
        r = safe_get(base + p, req=req, timeout=5)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        for m in re.finditer(r'href=["\']([^"\']+\.(?:pdf|docx|xlsx))["\']',
                              body, re.IGNORECASE):
            u = m.group(1)
            if u.startswith("http"):
                docs.add(u)
            elif u.startswith("/"):
                docs.add(base + u)
            else:
                docs.add(base + "/" + u)
        if len(docs) >= 8:
            break
    return list(docs)[:8]


def _extract_pdf(blob: bytes) -> dict:
    md = {}
    for m in _PDF_INFO_RE.finditer(blob[:200_000]):
        key = m.group(1).decode("latin-1", "replace")
        val = m.group(2).decode("latin-1", "replace").strip()
        if val:
            md[key] = val[:120]
    return md


def _extract_ooxml(blob: bytes) -> dict:
    md = {}
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            with zf.open("docProps/core.xml") as f:
                root = ET.fromstring(f.read())
        for tag in ("creator", "lastModifiedBy"):
            el = root.find(f".//dc:{tag}", _OOXML_NS) or root.find(f".//cp:{tag}", _OOXML_NS)
            if el is not None and el.text:
                md[tag] = el.text[:120]
        for tag in ("created", "modified"):
            el = root.find(f".//dcterms:{tag}", _OOXML_NS)
            if el is not None and el.text:
                md[tag] = el.text[:60]
    except (zipfile.BadZipFile, ET.ParseError, KeyError):
        pass
    return md


def _fetch_meta(url: str, req) -> dict | None:
    r = safe_get(url, req=req, timeout=6)
    if r is None or r.status_code != 200:
        return None
    blob = r.content[:500_000]  # cap 500KB
    if url.lower().endswith(".pdf"):
        md = _extract_pdf(blob)
    elif url.lower().endswith((".docx", ".xlsx", ".pptx")):
        md = _extract_ooxml(blob)
    else:
        return None
    if not md:
        return None
    return {"url": url, "metadata": md}


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip().lower()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    if "." not in target:
        return standard_response(tool="document_metadata", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="target must be a domain")

    docs = _find_docs(target, req)
    if not docs:
        return standard_response(tool="document_metadata", target=req.target,
            findings=[wrap_finding(
                "No public PDF/Office docs discovered for metadata extraction",
                severity="POSITIVE",
                cwe="CWE-200", owasp="A05:2021",
                remediation="No exposed docs — keep it that way (require auth on doc paths).",
                evidence_marker=f"{len(_DOC_PATHS)} paths crawled, 0 docs")],
            tests_performed=len(_DOC_PATHS), vulnerable=False,
            tests_summary="Crawl: 0 docs found")

    results = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = {pool.submit(_fetch_meta, u, req): u for u in docs}
        for fut in futs:
            try:
                r = fut.result(timeout=8)
                if r:
                    results.append(r)
            except Exception:
                continue

    findings = []
    if results:
        sample = []
        for r in results[:6]:
            md = r["metadata"]
            sample.append(f"{r['url'].split('/')[-1]}: "
                           f"author={md.get('creator', md.get('Author', '?'))}")
        findings.append(wrap_finding(
            f"Metadata extracted from {len(results)} public document(s) — "
            f"reveals author / software / creation time",
            severity="MEDIUM", cvss="4.0",
            cwe="CWE-200", owasp="A05:2021",
            remediation=("Strip document metadata before publishing — use "
                        "ExifTool (-all=) for PDF, or set Trust Center → "
                        "'Remove document metadata' in Word/Excel."),
            evidence_marker="; ".join(sample)))
    else:
        findings.append(wrap_finding(
            f"{len(docs)} doc(s) found but no extractable metadata",
            severity="POSITIVE",
            cwe="CWE-200", owasp="A05:2021",
            remediation="Metadata-clean documents — good operational hygiene.",
            evidence_marker=f"{len(docs)} docs, 0 with metadata"))

    return standard_response(
        tool="document_metadata", target=req.target, findings=findings,
        tests_performed=len(docs),
        vulnerable=len(results) > 0,
        tests_summary=f"{len(docs)} docs crawled; {len(results)} had metadata",
        raw_data={"results": results[:20]})


@router.post("/api/osint/document_metadata")
@vl_verify()
async def scan_docmeta(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="document_metadata", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
