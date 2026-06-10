"""radare2_strings_audit - r2 strings classification (playbook §2 #20).

Wraps `r2 -qc "iz~secret;iz~password;iz~api_key;iz~aws_;iz~private" <firmware>`
to extract strings matching credential / API key patterns. Classifies hits into
buckets (creds / API keys / URLs / IPs / private keys / cloud secrets) and
reports counts + top 5 most-suspicious strings (truncated 80 chars, masked).

Customer input: ScanRequest.target = path to firmware blob.
"""
from __future__ import annotations
import asyncio
import re
import shutil
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.radare2_strings_audit_findings import RADARE2_STRINGS_AUDIT_FINDING_RULES

router = APIRouter()
TIMEOUT = 90
MAX_HITS_PER_BUCKET = 40

# r2 command — iz lists strings in data sections, semicolon-chained `~` filters
R2_CMD = (
    "iz~secret;"      # secret_key / secrets / SECRET
    "iz~password;"    # password / passwd
    "iz~api_key;"     # api_key / API-KEY
    "iz~aws_;"        # aws_access_key etc.
    "iz~private;"     # PRIVATE KEY etc.
    "iz~token;"       # bearer / api token
)

BUCKETS = [
    ("creds",        re.compile(r"(password|passwd|pwd|credentials?)\b", re.I)),
    ("api_keys",     re.compile(r"(api[_\- ]?key|apikey|access[_\- ]?key)", re.I)),
    ("aws",          re.compile(r"(aws_|amazonaws|s3\.amazonaws|akia[a-z0-9]{16})", re.I)),
    ("github",       re.compile(r"(ghp_|gho_|ghu_|ghs_|github_pat)", re.I)),
    ("google",       re.compile(r"(aiza[a-z0-9_\-]{35}|google[_\- ]?api)", re.I)),
    ("urls",         re.compile(r"https?://[a-z0-9.\-]+", re.I)),
    ("ips",          re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
    ("private_keys", re.compile(r"begin (rsa|ec|dsa|openssh|pgp) private key", re.I)),
    ("tokens",       re.compile(r"\b(bearer|token|auth[_\- ]?token)\b", re.I)),
    ("jwt",          re.compile(r"eyj[a-z0-9\-_]{10,}\.eyj", re.I)),
]

# r2 string line format: <ord> <paddr> <vaddr> <len> <size> <section> <type> <string>
R2_STRING_LINE = re.compile(r"^\s*\d+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+\d+\s+\d+\s+\S+\s+\S+\s+(.*)$")


def _mask(s: str) -> str:
    """Mask cred-looking strings beyond first 8 chars (memory feedback)."""
    s = s.strip()[:80]
    if len(s) <= 8: return s
    return s[:8] + "*" * min(8, len(s) - 8) + ("..." if len(s) > 16 else "")


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["radare2_strings_audit_total"] = 0
        ctx.source("firmware file not found at target path")
        return
    if not shutil.which("r2") and not shutil.which("radare2"):
        ctx.state["radare2_strings_audit_error"] = "radare2 (r2) binary not installed"
        ctx.source("r2 missing")
        return

    bin_path = shutil.which("r2") or shutil.which("radare2")
    try:
        proc = await asyncio.create_subprocess_exec(
            bin_path, "-qq", "-c", R2_CMD, target,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            ctx.state["radare2_strings_audit_error"] = f"timeout after {TIMEOUT}s"
            ctx.source("timeout")
            return
    except Exception as e:
        ctx.state["radare2_strings_audit_error"] = f"subprocess: {str(e)[:120]}"
        ctx.source(f"subprocess failed: {str(e)[:80]}")
        return

    text = stdout.decode("utf-8", errors="replace")
    raw_lines = text.splitlines()

    # Extract just the string payloads
    payloads = []
    for line in raw_lines:
        m = R2_STRING_LINE.match(line)
        if m:
            s = m.group(1).strip()
            if s: payloads.append(s)
        else:
            # r2 may print plain strings as fallback
            s = line.strip()
            if s and not s.startswith("[") and 4 <= len(s) <= 400:
                payloads.append(s)

    # De-dupe preserving order
    seen = set()
    unique = []
    for p in payloads:
        if p in seen: continue
        seen.add(p); unique.append(p)
    payloads = unique[:5000]

    # Bucket
    buckets = {name: [] for name, _ in BUCKETS}
    for p in payloads:
        for name, pat in BUCKETS:
            if pat.search(p):
                if len(buckets[name]) < MAX_HITS_PER_BUCKET:
                    buckets[name].append(p)
                break

    bucket_counts = {name: len(v) for name, v in buckets.items()}
    nonempty_buckets = {k: v for k, v in buckets.items() if v}

    # Top 5 suspicious overall (priority order)
    priority = ["private_keys", "aws", "github", "google", "creds", "api_keys", "tokens", "jwt"]
    top_suspicious = []
    for cat in priority:
        for s in buckets.get(cat, []):
            top_suspicious.append({"category": cat, "value": _mask(s)})
            if len(top_suspicious) >= 5: break
        if len(top_suspicious) >= 5: break

    findings = []
    total_strings = sum(bucket_counts.values())
    if total_strings:
        findings.append({"check": "suspicious_strings_found", "total": total_strings,
                         "by_bucket": bucket_counts})
    if any(buckets[c] for c in ("aws", "github", "google", "private_keys")):
        findings.append({"check": "high_value_secrets_detected",
                         "categories": [c for c in ("aws", "github", "google", "private_keys")
                                        if buckets[c]]})

    ctx.state["r2_bucket_counts"] = bucket_counts
    ctx.state["r2_top_suspicious"] = top_suspicious
    ctx.state["r2_bucket_samples"] = {k: [_mask(s) for s in v[:5]] for k, v in nonempty_buckets.items()}
    ctx.state["r2_total_strings_matched"] = total_strings
    ctx.state["radare2_strings_audit_total"] = len(findings)
    ctx.source(f"{total_strings} matched strings, {len(nonempty_buckets)} buckets non-empty")


INTEL_FIELDS = [("Strings matched per bucket", "r2_bucket_counts"),
                ("Top 5 suspicious",           "r2_top_suspicious"),
                ("Bucket samples (masked)",    "r2_bucket_samples"),
                ("Total strings matched",      "r2_total_strings_matched")]


@router.post("/api/firmware/radare2_strings_audit")
async def firmware_radare2_strings_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="radare2_strings_audit",
        gather_func=gather, finding_rules=RADARE2_STRINGS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
