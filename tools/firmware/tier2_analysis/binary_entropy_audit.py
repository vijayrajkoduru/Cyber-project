"""binary_entropy_audit - per-chunk Shannon entropy distribution (playbook §2 #19).

Reads firmware blob in 256-byte chunks, computes Shannon entropy per chunk,
and classifies regions:
  - HIGH (>7.5 bits/byte sustained >4 KB)  => encrypted / compressed
  - LOW  (<3.0 bits/byte sustained >4 KB)  => plaintext / sparse padding
  - BALANCED otherwise                     => normal binary mixture

Reports region offsets + sizes + dominant class. If firmware is entirely
high-entropy, static analysis is blocked → INFO state advisory (visibility,
not a proven weakness). If entirely low-entropy, NO encryption at all → LOW
finding (cleartext code/secrets readable from a chip dump).

Customer input: ScanRequest.target = path to firmware blob.
"""
from __future__ import annotations
import asyncio
import math
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.binary_entropy_audit_findings import BINARY_ENTROPY_AUDIT_FINDING_RULES

router = APIRouter()
CHUNK = 256
HIGH_THR = 7.5
LOW_THR = 3.0
REGION_MIN = 4096        # 4 KB minimum to flag a region
MAX_FILE = 256 * 1024 * 1024  # 256 MB cap
MAX_REGIONS_REPORTED = 24


def _entropy(b: bytes) -> float:
    if not b: return 0.0
    counts = [0] * 256
    for x in b: counts[x] += 1
    n = len(b)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def _analyze(path: Path):
    chunks = []
    try:
        with open(path, "rb") as fh:
            while True:
                buf = fh.read(CHUNK)
                if not buf: break
                chunks.append(_entropy(buf))
                if len(chunks) * CHUNK >= MAX_FILE: break
    except OSError as e:
        return None, str(e), [], [], 0
    if not chunks:
        return [], "", [], [], 0

    high_count = sum(1 for h in chunks if h > HIGH_THR)
    low_count = sum(1 for h in chunks if h < LOW_THR)
    avg = sum(chunks) / len(chunks)

    # Find runs of sustained high / low entropy
    regions_high = []
    regions_low = []
    state = None
    start = 0
    for i, h in enumerate(chunks):
        cls = "high" if h > HIGH_THR else ("low" if h < LOW_THR else "mid")
        if cls != state:
            if state in ("high", "low"):
                length_bytes = (i - start) * CHUNK
                if length_bytes >= REGION_MIN:
                    region = {"offset": start * CHUNK, "size": length_bytes,
                              "avg_entropy": round(sum(chunks[start:i]) / max(1, i - start), 3)}
                    if state == "high": regions_high.append(region)
                    else: regions_low.append(region)
            state = cls
            start = i
    # tail
    if state in ("high", "low"):
        length_bytes = (len(chunks) - start) * CHUNK
        if length_bytes >= REGION_MIN:
            region = {"offset": start * CHUNK, "size": length_bytes,
                      "avg_entropy": round(sum(chunks[start:]) / max(1, len(chunks) - start), 3)}
            if state == "high": regions_high.append(region)
            else: regions_low.append(region)

    return chunks, "", regions_high, regions_low, avg


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["binary_entropy_audit_total"] = 0
        ctx.source("firmware file not found at target path")
        return

    chunks, err, regions_high, regions_low, avg = await asyncio.get_event_loop().run_in_executor(
        None, _analyze, Path(target)
    )
    if chunks is None:
        ctx.state["binary_entropy_audit_error"] = f"read failed: {err[:120]}"
        ctx.source("read failed")
        return
    if not chunks:
        ctx.state["binary_entropy_audit_total"] = 0
        ctx.source("empty file")
        return

    total_bytes = len(chunks) * CHUNK
    high_bytes = sum(r["size"] for r in regions_high)
    low_bytes = sum(r["size"] for r in regions_low)
    pct_high = round(100 * high_bytes / max(1, total_bytes), 2)
    pct_low = round(100 * low_bytes / max(1, total_bytes), 2)

    classification = "balanced"
    if pct_high >= 90: classification = "encrypted_or_compressed"
    elif pct_low >= 90: classification = "plaintext_no_encryption"
    elif pct_high >= 40: classification = "mostly_compressed"
    elif pct_low >= 40: classification = "mostly_plaintext"

    findings = []
    findings.append({"check": "entropy_classification",
                     "label": classification,
                     "avg_entropy": round(avg, 3),
                     "high_pct": pct_high, "low_pct": pct_low})
    if classification == "encrypted_or_compressed":
        findings.append({"check": "static_analysis_blocked",
                         "reason": "entire firmware appears encrypted or compressed"})
    if classification == "plaintext_no_encryption":
        findings.append({"check": "no_encryption_applied",
                         "reason": "no high-entropy regions — sensitive sections likely plaintext"})

    # Top regions for intel
    regions_high_sorted = sorted(regions_high, key=lambda r: -r["size"])[:MAX_REGIONS_REPORTED]
    regions_low_sorted = sorted(regions_low, key=lambda r: -r["size"])[:MAX_REGIONS_REPORTED]

    ctx.state["entropy_avg"] = round(avg, 3)
    ctx.state["entropy_high_pct"] = pct_high
    ctx.state["entropy_low_pct"] = pct_low
    ctx.state["entropy_classification"] = classification
    ctx.state["entropy_high_regions"] = regions_high_sorted
    ctx.state["entropy_low_regions"] = regions_low_sorted
    ctx.state["entropy_total_bytes"] = total_bytes
    ctx.state["binary_entropy_audit_total"] = len(findings)
    ctx.source(f"avg={round(avg, 3)} bits/byte, high={pct_high}%, low={pct_low}%, "
               f"class={classification}")


INTEL_FIELDS = [("Average entropy (bits/byte)", "entropy_avg"),
                ("High-entropy share (%)",      "entropy_high_pct"),
                ("Low-entropy share (%)",       "entropy_low_pct"),
                ("Classification",              "entropy_classification"),
                ("Top high-entropy regions",    "entropy_high_regions"),
                ("Top low-entropy regions",     "entropy_low_regions"),
                ("Total bytes analysed",        "entropy_total_bytes")]


@router.post("/api/firmware/binary_entropy_audit")
async def firmware_binary_entropy_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="binary_entropy_audit",
        gather_func=gather, finding_rules=BINARY_ENTROPY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
