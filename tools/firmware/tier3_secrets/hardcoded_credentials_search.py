"""hardcoded_credentials_search - byte-level cred / key pattern scan (playbook §2 #20).

Reads firmware as bytes (capped 256 MB) and runs strict regex passes for:
  - AWS access keys      (AKIA + 16 base32 chars)
  - AWS secret-like      (40-char base64 in env-var assignment)
  - Google API keys      (AIza + 35 base64 chars)
  - GitHub tokens        (ghp_/gho_/ghu_/ghs_/github_pat_)
  - Slack tokens         (xox[abprs]-[0-9a-zA-Z\\-]+)
  - bcrypt hashes        ($2[abxy]$NN$...)
  - shadow hashes        ($1$, $5$, $6$, $y$)
  - JWT tokens           (eyJ... base64 dot-segment)
  - OpenSSH/RSA keys     (-----BEGIN ... PRIVATE KEY-----)
  - Telnet hardcoded pwd (passwd patterns in inittab/rcS)
  - Base64-creds         (basic auth headers)

Each finding mask actual cred beyond first 8 chars.

Zero-FP severity bands (a graded finding must be PROVEN exploitable by itself):
  - CRITICAL: confirmed live secret VALUES (aws_secret/google/github/stripe)
              and PEM PRIVATE KEY blocks. An AWS access-key ID (AKIA/ASIA) is a
              PUBLIC identifier — CRITICAL only when a paired AWS secret is found
              nearby, otherwise INFO ("key id found, confirm if active").
  - HIGH:     live bearer tokens (slack/JWT/basic-auth) + PGP private key.
  - INFO:     password / shadow / bcrypt HASHES are inventory only — not
              exploitable by themselves (must be cracked, KDF-gated).

Customer input: ScanRequest.target = path to firmware blob.
"""
from __future__ import annotations
import asyncio
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.hardcoded_credentials_search_findings import HARDCODED_CREDENTIALS_SEARCH_FINDING_RULES

router = APIRouter()
MAX_BYTES = 256 * 1024 * 1024
MAX_HITS_PER_CAT = 30

PATTERNS = [
    ("aws_access_key",   re.compile(rb"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),                  "CRITICAL"),
    ("aws_secret_like",  re.compile(rb"(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key[\"'=: ]+([A-Za-z0-9/+]{40})"), "CRITICAL"),
    ("google_api_key",   re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"),                   "CRITICAL"),
    ("github_pat",       re.compile(rb"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,255}\b"), "CRITICAL"),
    ("github_pat_new",   re.compile(rb"\bgithub_pat_[0-9A-Za-z_]{82}\b"),              "CRITICAL"),
    ("slack_token",      re.compile(rb"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b"),            "HIGH"),
    ("stripe_secret",    re.compile(rb"\bsk_live_[0-9a-zA-Z]{24,99}\b"),               "CRITICAL"),
    ("openssh_priv",     re.compile(rb"-----BEGIN (OPENSSH|RSA|DSA|EC) PRIVATE KEY-----"), "CRITICAL"),
    ("pgp_priv",         re.compile(rb"-----BEGIN PGP PRIVATE KEY BLOCK-----"),        "HIGH"),
    ("bcrypt_hash",      re.compile(rb"\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}"),           "HIGH"),
    ("shadow_hash_md5",  re.compile(rb"\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}"),   "HIGH"),
    ("shadow_hash_sha", re.compile(rb"\$[56]\$(?:rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{43,}"), "HIGH"),
    ("shadow_hash_yes",  re.compile(rb"\$y\$[A-Za-z0-9./]{6,}\$[A-Za-z0-9./]{8,}\$[A-Za-z0-9./]{20,}"), "HIGH"),
    ("jwt_token",        re.compile(rb"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "HIGH"),
    ("basic_auth_b64",   re.compile(rb"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{16,})"), "HIGH"),
    ("telnet_passwd",    re.compile(rb"(?:passwd|password)\s*[:=]\s*[\"']?([!-~]{4,32})[\"']?\s*$", re.MULTILINE), "MEDIUM"),
    ("hardcoded_root",   re.compile(rb"root:[^:]+:0:0:"),                              "MEDIUM"),
]

PATTERNS_BY_CAT = {cat: pat for cat, pat, _sev in PATTERNS}


def _mask(b: bytes) -> str:
    """Mask cred beyond first 8 chars."""
    try: s = b.decode("ascii", errors="replace")
    except Exception: s = repr(b)[:80]
    s = s.strip()[:120]
    if len(s) <= 8: return s
    return s[:8] + "*" * min(12, len(s) - 8) + ("..." if len(s) > 20 else "")


# Generic AWS-secret shape (40-char base64) — used ONLY to prove an access-key
# ID is paired with a secret nearby. An access-key ID alone is a PUBLIC
# identifier, not a secret.
_AWS_SECRET_SHAPE = re.compile(rb"\b[A-Za-z0-9/+]{40}\b")
_AWS_PAIR_WINDOW = 512  # bytes around an AKIA/ASIA hit to look for a secret


def _aws_key_has_paired_secret(data: bytes, offsets) -> bool:
    """A bare AWS access-key ID (AKIA/ASIA + 16 chars) is a public identifier.
    It is only an exploitable secret when a 40-char AWS secret value sits near
    it (same env block / config line region). Look in a small window around
    each access-key offset for an aws_secret assignment OR a stand-alone
    40-char base64 secret-shape token."""
    for off in offsets:
        lo = max(0, off - _AWS_PAIR_WINDOW)
        hi = min(len(data), off + _AWS_PAIR_WINDOW)
        window = data[lo:hi]
        # Strong signal: an explicit aws_secret_access_key assignment nearby.
        if PATTERNS_BY_CAT["aws_secret_like"].search(window):
            return True
        # Weaker signal: a 40-char secret-shape token that is NOT itself the
        # access-key ID region (access-key IDs are 20 chars).
        for sm in _AWS_SECRET_SHAPE.finditer(window):
            if sm.group(0) not in (data[off:off + 20],):
                return True
    return False


def _scan(path: Path):
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES)
    except OSError as e:
        return None, str(e)
    if not data:
        return {}, ""

    results = {}
    aws_key_offsets = []
    for cat, pat, sev in PATTERNS:
        seen = set()
        hits = []
        for m in pat.finditer(data):
            raw = m.group(0)
            key = raw[:64]
            if key in seen: continue
            seen.add(key)
            hits.append({"match": _mask(raw), "offset": m.start(), "severity": sev})
            if cat == "aws_access_key":
                aws_key_offsets.append(m.start())
            if len(hits) >= MAX_HITS_PER_CAT: break
        if hits:
            results[cat] = hits

    # Zero-FP gate: only treat an AWS access-key ID as a CRITICAL secret when a
    # paired AWS secret is found nearby; otherwise it is a public identifier.
    aws_key_paired = False
    if "aws_access_key" in results:
        aws_key_paired = _aws_key_has_paired_secret(data, aws_key_offsets)
    return {"results": results, "aws_key_paired": aws_key_paired}, ""


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["hardcoded_credentials_search_total"] = 0
        ctx.source("firmware file not found at target path")
        return

    scan, err = await asyncio.get_event_loop().run_in_executor(None, _scan, Path(target))
    if scan is None:
        ctx.state["hardcoded_credentials_search_error"] = f"read failed: {err[:120]}"
        ctx.source("read failed")
        return
    results = scan.get("results", {})
    aws_key_paired = scan.get("aws_key_paired", False)

    findings = []
    total_hits = sum(len(v) for v in results.values())

    # ── Zero-FP severity bands ──────────────────────────────────────────────
    # CRITICAL only for material that is exploitable BY ITSELF:
    #   - confirmed live API secrets (secret VALUES, not public identifiers)
    #   - PEM PRIVATE KEY blocks
    # An AWS access-key ID (AKIA/ASIA) is a PUBLIC identifier — CRITICAL only
    # when a paired AWS secret was found nearby, else INFO ("key id found,
    # confirm if active").
    critical_candidates = ["aws_secret_like", "google_api_key", "github_pat",
                           "github_pat_new", "stripe_secret", "openssh_priv"]
    critical_cats = [c for c in critical_candidates if c in results]
    aws_key_id_present = "aws_access_key" in results
    aws_key_id_info = aws_key_id_present and not aws_key_paired
    if aws_key_id_present and aws_key_paired:
        critical_cats.insert(0, "aws_access_key")

    # HIGH only for full live-token secrets that grant access by themselves:
    #   - slack token, PGP private key, JWT, basic-auth blob.
    # Password / shadow / bcrypt HASHES are NOT exploitable by themselves
    # (they must be cracked, gated by KDF strength) -> INFO inventory.
    high_candidates = ["slack_token", "pgp_priv", "jwt_token", "basic_auth_b64"]
    high_cats = [c for c in high_candidates if c in results]
    hash_candidates = ["bcrypt_hash", "shadow_hash_md5", "shadow_hash_sha",
                       "shadow_hash_yes"]
    hash_cats = [c for c in hash_candidates if c in results]

    medium_cats = [c for c in ("telnet_passwd", "hardcoded_root") if c in results]

    if critical_cats:
        findings.append({"check": "critical_secrets_found",
                         "categories": critical_cats,
                         "count": sum(len(results[c]) for c in critical_cats)})
    if high_cats:
        findings.append({"check": "high_severity_secrets",
                         "categories": high_cats,
                         "count": sum(len(results[c]) for c in high_cats)})
    if aws_key_id_info:
        findings.append({"check": "aws_access_key_id_inventory",
                         "categories": ["aws_access_key"],
                         "count": len(results.get("aws_access_key", []))})
    if hash_cats:
        findings.append({"check": "password_hash_inventory",
                         "categories": hash_cats,
                         "count": sum(len(results[c]) for c in hash_cats)})
    if medium_cats:
        findings.append({"check": "system_account_credentials",
                         "categories": medium_cats,
                         "count": sum(len(results[c]) for c in medium_cats)})

    by_cat_counts = {c: len(v) for c, v in results.items()}
    samples = {c: v[:5] for c, v in results.items()}

    ctx.state["secrets_by_category"] = by_cat_counts
    ctx.state["secrets_samples"] = samples
    ctx.state["secrets_critical_categories"] = critical_cats
    ctx.state["secrets_high_categories"] = high_cats
    ctx.state["secrets_hash_categories"] = hash_cats
    ctx.state["secrets_aws_key_id_only"] = aws_key_id_info
    ctx.state["secrets_aws_key_paired"] = bool(aws_key_id_present and aws_key_paired)
    ctx.state["secrets_total_hits"] = total_hits
    ctx.state["hardcoded_credentials_search_total"] = len(findings)
    ctx.source(f"{total_hits} secrets across {len(results)} categories, "
               f"{len(critical_cats)} critical, {len(hash_cats)} hash-inventory")


INTEL_FIELDS = [("Secrets per category",      "secrets_by_category"),
                ("Critical categories",       "secrets_critical_categories"),
                ("Samples (masked)",          "secrets_samples"),
                ("Total secret hits",         "secrets_total_hits")]


@router.post("/api/firmware/hardcoded_credentials_search")
async def firmware_hardcoded_credentials_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="hardcoded_credentials_search",
        gather_func=gather, finding_rules=HARDCODED_CREDENTIALS_SEARCH_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
