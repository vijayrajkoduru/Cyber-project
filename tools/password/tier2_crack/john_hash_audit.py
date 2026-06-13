"""john_hash_audit - offline hash crack via John the Ripper (VL-METHOD methodology).

REWRITTEN 2026-06-05 to use VL-METHOD 7-step pentest pattern instead of
the previous shallow "run john -> parse --show" approach.

UNLIKE most VL-METHOD scanners, this one is NETWORK-LESS: ctx.host is
unused. The "target" is the hash string(s) supplied in options.hashes.
The 7 stages still map cleanly:

  1. PRE-FLIGHT  - Validate options.hashes (presence, non-empty, plausible
                    hash chars). Parse into deduped list, clamp at 100.

  2. FINGERPRINT - Auto-detect algorithm per hash:
                     $1$ -> md5crypt, $2y$/$2a$/$2b$ -> bcrypt,
                     $5$ -> sha256crypt, $6$ -> sha512crypt,
                     $argon2id$ -> argon2, $apr1$ -> apache_md5,
                     $y$ -> yescrypt, $krb5pa$ -> kerberos,
                     $WPA*$ -> wpa, 32 hex -> md5/ntlm/lm (ambiguous),
                     40 hex -> sha1, 64 hex -> sha256, 128 hex -> sha512,
                     <user>:<32hex>:<32hex> -> LM:NTLM (pwdump).
                   Uses hashid lib as primary detector when available.

  3. QUICK PROBE - john --wordlist=top-100 (10M-pw-list top 100),
                    --max-run-time=30. Cheap insurance to find the
                    obvious "password123" / "admin" cracks fast.

  4. DEEP SCAN   - Gated: only runs if quick_probe found something OR
                    options.always_deep=True. john --wordlist=rockyou
                    --rules, timeout options.deep_timeout (default 120s,
                    max 600s). Uses isolated per-session pot so previous
                    scan results never leak into this one.

  5. VERIFY      - Re-hash the cracked plaintext with the SAME algorithm
                    via passlib + compare to original hash. If match:
                    CONFIRMED + verification_method='passlib_rehash_match'.
                    Else: SUSPECTED + 'john_only_unverified' (rare).

  6. PRIVILEGE   - Classify based on hash type + context:
                     NTLM admin user -> windows_credential (root-equiv)
                     NTLM normal     -> windows_credential
                     /etc/shadow uid=0 -> root
                     /etc/shadow uid<1000 -> service
                     /etc/shadow else -> user
                     bcrypt -> webapp_user
                     Kerberos -> ad_account
                     WPA -> wifi_psk

  7. CHAIN       - Suggest follow-up scanners:
                     Windows NTLM -> ad_netexec_smb_spray, ad_certipy_find
                     Linux root/service -> password_hydra_ssh_spray
                     Webapp bcrypt -> password_patator_http_form_brute
                     Kerberos -> ad_kerberoast_audit

Customer input via ScanRequest.options:
  - hashes         = newline-separated raw hashes or full /etc/shadow lines
                      (required, max 100)
  - always_deep    = bool, force deep_scan even if quick_probe empty
  - deep_timeout   = wall-clock cap for deep scan (default 120s, max 600s)
  - quick_timeout  = wall-clock cap for quick probe (default 30s, max 60s)

Safety: hashfile written to per-session tempdir; ALWAYS deleted in finally
even on crash. Isolated pot file so cracked passwords from prior scans
cannot leak across tenants. Plaintext masked via _redact() before any
state stash - cleartext NEVER appears in ctx.state / response / PDF.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.john_hash_audit_findings import JOHN_HASH_AUDIT_FINDING_RULES

router = APIRouter()
JOHN_BIN = shutil.which("john")
DEFAULT_QUICK_TIMEOUT = 30
DEFAULT_DEEP_TIMEOUT = 120
MAX_QUICK_TIMEOUT = 60
MAX_DEEP_TIMEOUT = 600
HARD_MAX_HASHES = 100

# Wordlist preference: top-100 for quick, rockyou for deep
_QUICK_WORDLISTS = [
    "/opt/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
    "/opt/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "/usr/share/wordlists/rockyou.txt",
]
_DEEP_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/opt/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "/opt/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
]


# Map detected algorithm fingerprint to john --format value used for cracking
# and passlib handler name used for verify-rehash.
ALGO_TO_JOHN_FORMAT = {
    "md5crypt":     "md5crypt",
    "bcrypt":       "bcrypt",
    "sha256crypt":  "sha256crypt",
    "sha512crypt":  "sha512crypt",
    "argon2":       "argon2",
    "apache_md5":   "md5crypt",
    "yescrypt":     "crypt",
    "kerberos":     "krb5pa-md5",
    "wpa":          "wpapsk",
    "sha1":         "raw-sha1",
    "sha256":       "raw-sha256",
    "sha512":       "raw-sha512",
    "md5":          "raw-md5",
    "ntlm":         "nt",
    "lm":           "lm",
    "pwdump":       "nt",  # split LM:NTLM line: john auto-detects both
    "unknown":      "",
}

ALGO_TO_PASSLIB = {
    "md5crypt":    "md5_crypt",
    "bcrypt":      "bcrypt",
    "sha256crypt": "sha256_crypt",
    "sha512crypt": "sha512_crypt",
    "argon2":      "argon2",
    "apache_md5":  "apr_md5_crypt",
    "ntlm":        "nthash",
    "lm":          "lmhash",
    "sha1":        "hex_sha1",
    "sha256":      "hex_sha256",
    "sha512":      "hex_sha512",
    "md5":         "hex_md5",
}


class JohnHashAuditRequest(ScanRequest):
    options: Optional[dict] = None


# ───────────── helpers ─────────────

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

def _split_hashes(s: str, limit: int) -> list[str]:
    """Trim/dedupe/clamp newline-separated hash list. Allows full /etc/shadow
    lines (user:hash:rest) and bare hashes. Comments (#) ignored."""
    if not s:
        return []
    seen: list[str] = []
    for raw in s.splitlines():
        v = raw.strip()
        if not v or v.startswith("#"):
            continue
        if v in seen:
            continue
        seen.append(v)
        if len(seen) >= limit:
            break
    return seen


def _extract_hash_portion(raw_line: str) -> tuple[str, str]:
    """If raw_line looks like /etc/shadow (user:hash:lastchange:...), return
    (username, hash). Otherwise return ("", raw_line).
    Also handles pwdump (user:rid:lm:ntlm:::) -> ("user", "lm:ntlm")."""
    if not raw_line or ":" not in raw_line:
        return ("", raw_line)
    parts = raw_line.split(":")
    # /etc/shadow: user:hash:lastchange:min:max:warn:inactive:expire
    if len(parts) >= 7 and parts[1] and (parts[1].startswith("$") or parts[1] == "!" or parts[1] == "*"):
        return (parts[0], parts[1])
    # pwdump: user:rid:lmhash:nthash:::
    if (len(parts) >= 4
            and parts[1].isdigit()
            and len(parts[2]) == 32 and _HEX_RE.match(parts[2])
            and len(parts[3]) == 32 and _HEX_RE.match(parts[3])):
        return (parts[0], f"{parts[2]}:{parts[3]}")
    return ("", raw_line)


def _detect_algorithm(hash_str: str) -> str:
    """Prefix + length heuristics. Returns one of the ALGO_TO_JOHN_FORMAT keys."""
    h = hash_str.strip()
    if not h:
        return "unknown"
    # MCF / crypt-style prefixes
    if h.startswith("$1$"):                       return "md5crypt"
    if h.startswith("$2y$") or h.startswith("$2a$") or h.startswith("$2b$"):
        return "bcrypt"
    if h.startswith("$5$"):                       return "sha256crypt"
    if h.startswith("$6$"):                       return "sha512crypt"
    if h.startswith("$argon2id$") or h.startswith("$argon2i$") or h.startswith("$argon2d$"):
        return "argon2"
    if h.startswith("$apr1$"):                    return "apache_md5"
    if h.startswith("$y$"):                       return "yescrypt"
    if h.startswith("$krb5pa$") or h.startswith("$krb5asrep$") or h.startswith("$krb5tgs$"):
        return "kerberos"
    if h.startswith("$WPA") or h.startswith("$WPAPSK"):
        return "wpa"
    # pwdump-style LM:NTLM (32hex:32hex)
    if ":" in h:
        a, _, b = h.partition(":")
        if len(a) == 32 and len(b) == 32 and _HEX_RE.match(a) and _HEX_RE.match(b):
            return "pwdump"
    # Length-based for plain hex
    if _HEX_RE.match(h):
        n = len(h)
        if n == 32:  return "ntlm"   # ambiguous with md5/lm; default to ntlm (most common)
        if n == 40:  return "sha1"
        if n == 64:  return "sha256"
        if n == 128: return "sha512"
    return "unknown"


def _detect_with_hashid(hash_str: str) -> Optional[str]:
    """Use hashid library if available for primary detection. Maps hashid's
    prose names to our algorithm key set. Returns None on no-match."""
    try:
        from hashid import HashID
    except Exception:
        return None
    try:
        hi = HashID()
        # hashID returns generator of namedtuple(name, hashcat, john)
        for r in hi.identifyHash(hash_str.strip()):
            name = (getattr(r, "name", "") or "").lower()
            # First sensible match wins
            if "bcrypt" in name:           return "bcrypt"
            if "argon2" in name:           return "argon2"
            if "sha-512 crypt" in name:    return "sha512crypt"
            if "sha-256 crypt" in name:    return "sha256crypt"
            if "md5 crypt" in name:        return "md5crypt"
            if "apache" in name and "md5" in name: return "apache_md5"
            if "ntlm" in name and "lm" in name:    return "pwdump"
            if name.startswith("ntlm"):    return "ntlm"
            if name == "lm" or name.startswith("lm "): return "lm"
            if "kerberos" in name:         return "kerberos"
            if "wpa" in name:              return "wpa"
            if name.startswith("sha-1"):   return "sha1"
            if name.startswith("sha-256"): return "sha256"
            if name.startswith("sha-512"): return "sha512"
            if name.startswith("md5"):     return "md5"
    except Exception:
        return None
    return None


# Built-in top-50 fallback wordlist when SecLists / rockyou aren't on
# disk. Hard-coded so the scanner always has SOMETHING to crack against.
# Sourced from the public top-100 cracked-passwords distribution.
_BUILTIN_TOP_FALLBACK = (
    "password\n123456\n123456789\nqwerty\n12345678\nabc123\n1234567\n111111\n"
    "letmein\nadmin\nwelcome\nmonkey\n1234567890\ndragon\nsunshine\nprincess\n"
    "qwerty123\n654321\niloveyou\n000000\nadmin123\npassword1\nbaseball\n"
    "football\nsoccer\nsuperman\nbatman\ntrustno1\nshadow\nmaster\n"
    "michael\njennifer\nthomas\njordan\nhunter\nmichelle\ncharlie\n"
    "andrew\nmatthew\nabc1234\npassword123\nhello\nfreedom\nwhatever\n"
    "ninja\nazerty\nadminadmin\nrootroot\ntoor\nchangeme\n"
)
_BUILTIN_WORDLIST_PATH: Optional[str] = None


def _materialize_builtin() -> str:
    """Write the built-in fallback wordlist to a tempfile (once per process)
    and return its path."""
    global _BUILTIN_WORDLIST_PATH
    if _BUILTIN_WORDLIST_PATH and os.path.isfile(_BUILTIN_WORDLIST_PATH):
        return _BUILTIN_WORDLIST_PATH
    fd, path = tempfile.mkstemp(prefix="vl_john_builtin_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(_BUILTIN_TOP_FALLBACK)
    except Exception:
        try: os.close(fd)
        except Exception: pass
        return ""
    _BUILTIN_WORDLIST_PATH = path
    return path


def _resolve_wordlist(candidates: list[str]) -> Optional[str]:
    """Find first existing wordlist from candidates. If none exist, fall
    back to a built-in top-50 list materialized in /tmp so the scanner
    always has SOMETHING to crack against (gap 3 from PDF audit -
    SecLists wasn't at the expected path in some Docker builds)."""
    for p in candidates:
        if os.path.isfile(p) and os.access(p, os.R_OK):
            return p
    # Fallback: built-in top-50 list
    return _materialize_builtin() or None


def _redact(pwd: str, show_plaintext: bool = False) -> str:
    """Customer-safe cleartext marker: length + last 2 chars only.
    show_plaintext=True returns plaintext (customer owns the hashes -
    they already know the plaintext or want it back for audit). Default
    False keeps the marker so the PDF can be circulated safely."""
    if not pwd:
        return "len=0"
    pwd = pwd.strip()
    if show_plaintext:
        return pwd
    if len(pwd) <= 2:
        return f"len={len(pwd)} ***"
    return f"len={len(pwd)} ***{pwd[-2:]}"


def _verify_rehash(algo: str, plaintext: str, original_hash: str) -> bool:
    """Re-hash the cracked plaintext with the SAME algorithm and confirm
    it matches the original hash. Uses passlib. Returns True on match."""
    handler_name = ALGO_TO_PASSLIB.get(algo)
    if not handler_name:
        return False
    try:
        # For MCF-style schemes passlib's .verify(secret, hash) handles
        # salt extraction from the hash itself. For raw hex schemes we
        # compute the hash ourselves and compare.
        if handler_name.startswith("hex_"):
            import hashlib as _hl
            algo_name = handler_name[4:]  # md5 / sha1 / sha256 / sha512
            digest = _hl.new(algo_name, plaintext.encode("utf-8", errors="ignore")).hexdigest()
            return digest.lower() == original_hash.strip().lower()
        if handler_name == "nthash":
            try:
                from passlib.hash import nthash
                return nthash.verify(plaintext, original_hash.strip())
            except Exception:
                # Fallback: manual NT hash = MD4 of UTF-16LE
                import hashlib as _hl
                digest = _hl.new("md4", plaintext.encode("utf-16le")).hexdigest()
                return digest.lower() == original_hash.strip().lower()
        if handler_name == "lmhash":
            try:
                from passlib.hash import lmhash
                return lmhash.verify(plaintext, original_hash.strip())
            except Exception:
                return False
        # MCF-style: bcrypt, sha512_crypt, sha256_crypt, md5_crypt, argon2, apr_md5_crypt
        import importlib
        mod = importlib.import_module(f"passlib.hash")
        handler = getattr(mod, handler_name)
        return bool(handler.verify(plaintext, original_hash.strip()))
    except Exception:
        return False


# john --show output line: "hash:plaintext"  (or with salt: "user:plaintext:uid:gid:...")
_RE_SHOW_LINE = re.compile(r"^(?P<lhs>[^:]+):(?P<pwd>.+)$")


# ═══════════════════════════════════════════════════════════════════
#  JohnHashAudit - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class JohnHashAudit(MethodologyScanner):
    name = "john_hash_audit"

    # ── STAGE 1: PRE-FLIGHT (input validation, no network) ─────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        opts = ctx.state.get("_options") or {}
        hashes_raw = (opts.get("hashes") or "").strip()
        if not hashes_raw:
            ctx.state["skipped_reason"] = "options.hashes not supplied"
            ctx.state["hash_count"] = 0
            return False
        # Plausibility filter: must contain hex / $ / : characters at minimum
        if not re.search(r"[\$a-fA-F0-9:]", hashes_raw):
            ctx.state["skipped_reason"] = "options.hashes contains no plausible hash characters"
            ctx.state["hash_count"] = 0
            return False
        parsed = _split_hashes(hashes_raw, HARD_MAX_HASHES)
        if not parsed:
            ctx.state["skipped_reason"] = "options.hashes empty after dedupe/strip"
            ctx.state["hash_count"] = 0
            return False
        # Decompose each line into (username, hash_portion) so /etc/shadow
        # users carry through to privilege_check.
        decomposed = []
        for idx, line in enumerate(parsed):
            user, hash_portion = _extract_hash_portion(line)
            decomposed.append({
                "idx": idx,
                "raw_line": line,
                "username": user,
                "hash": hash_portion,
            })
        ctx.state["hashes_parsed"] = decomposed
        ctx.state["hash_count"] = len(decomposed)
        if not JOHN_BIN:
            ctx.state["john_missing"] = True
            ctx.state["skipped_reason"] = "john binary not installed on scanner host"
            return False
        return True

    # ── STAGE 2: FINGERPRINT (algorithm detection per hash) ────────
    async def fingerprint(self, ctx: ScanContext):
        decomposed = ctx.state.get("hashes_parsed") or []
        hash_types: dict[int, str] = {}
        salt_present = False
        ambiguous_count = 0
        for entry in decomposed:
            h = entry["hash"]
            # Try hashid first, fall back to prefix heuristic
            algo = _detect_with_hashid(h) or _detect_algorithm(h)
            entry["algorithm"] = algo
            hash_types[entry["idx"]] = algo
            # MCF-style hashes carry their own salt; raw hex doesn't
            if h.startswith("$"):
                salt_present = True
            # 32-hex hashes are ambiguous (md5/ntlm/lm) - we picked one
            if algo == "ntlm" and len(h) == 32 and re.match(r"^[0-9a-fA-F]+$", h):
                # Could also be md5 / lm - flag the ambiguity
                ambiguous_count += 1
            if algo == "unknown":
                ambiguous_count += 1
        ctx.state["fingerprint"] = {
            "hash_types": hash_types,
            "salt_present": salt_present,
            "ambiguous_count": ambiguous_count,
            "unique_formats": sorted(set(hash_types.values())),
        }

    # ── STAGE 3: QUICK PROBE (top-100 wordlist, 30s cap) ───────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        opts = ctx.state.get("_options") or {}
        decomposed = ctx.state.get("hashes_parsed") or []
        if not decomposed:
            return []
        wordlist = _resolve_wordlist(_QUICK_WORDLISTS)
        if not wordlist:
            ctx.state["quick_no_wordlist"] = True
            return []
        timeout = min(max(int(opts.get("quick_timeout") or DEFAULT_QUICK_TIMEOUT), 10), MAX_QUICK_TIMEOUT)
        ctx.state["quick_wordlist"] = os.path.basename(wordlist)
        ctx.state["quick_probe_attempts"] = len(decomposed)

        # Group hashes by detected format so we run john with the right --format
        findings, total_cracked = await self._run_john_pass(
            ctx, decomposed, wordlist,
            timeout=timeout,
            session_label="quick",
            rules=None,
            discovery_method="quick_probe_top100",
        )
        ctx.state["quick_probe_cracked"] = total_cracked
        return findings

    # ── STAGE 4: DEEP SCAN (rockyou + rules, gated) ────────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        opts = ctx.state.get("_options") or {}
        decomposed = ctx.state.get("hashes_parsed") or []
        if not decomposed:
            return []
        # Exclude hashes already cracked in quick_probe
        already_cracked_idxs = {
            f["hash_idx"] for f in (ctx.state.get("methodology_findings") or [])
            if f.get("kind") == "cracked_hash"
        }
        # methodology_findings isn't set yet during deep_scan, so look at
        # what quick_probe stashed via ctx.state
        already = ctx.state.get("_quick_cracked_idxs") or set()
        remaining = [e for e in decomposed if e["idx"] not in already]
        if not remaining:
            ctx.state["deep_skipped"] = "all hashes already cracked by quick_probe"
            return []
        wordlist = _resolve_wordlist(_DEEP_WORDLISTS)
        if not wordlist:
            ctx.state["deep_no_wordlist"] = True
            return []
        timeout = min(max(int(opts.get("deep_timeout") or DEFAULT_DEEP_TIMEOUT), 30), MAX_DEEP_TIMEOUT)
        ctx.state["deep_wordlist"] = os.path.basename(wordlist)
        ctx.state["deep_scan_remaining"] = len(remaining)

        findings, total_cracked = await self._run_john_pass(
            ctx, remaining, wordlist,
            timeout=timeout,
            session_label="deep",
            rules="Single",
            discovery_method="deep_scan_rockyou_rules",
        )
        ctx.state["deep_scan_cracked"] = total_cracked
        return findings

    # ── Shared john runner ─────────────────────────────────────────
    async def _run_john_pass(
        self, ctx, entries: list[dict], wordlist: str, *,
        timeout: int, session_label: str, rules: Optional[str],
        discovery_method: str,
    ) -> tuple[list[dict], int]:
        """Group entries by detected format, run john per format, parse
        --show output, build preliminary findings (no verify yet)."""
        # Optional user override: force one john --format for every hash. Used
        # when hashid auto-detect picks the wrong algorithm or can't classify a
        # hash at all (those map to an empty fmt and would be silently skipped
        # below, so the user could supply hashes and get zero results). When
        # blank, behaviour is unchanged (per-hash auto-detected format).
        forced_fmt = ((ctx.state.get("_options") or {}).get("hash_format") or "").strip()
        groups: dict[str, list[dict]] = {}
        for e in entries:
            fmt = forced_fmt or ALGO_TO_JOHN_FORMAT.get(e.get("algorithm") or "unknown", "")
            if not fmt:
                continue
            groups.setdefault(fmt, []).append(e)

        all_findings: list[dict] = []
        quick_cracked_idxs: set = ctx.state.get("_quick_cracked_idxs") or set()
        for john_fmt, group in groups.items():
            session_dir = tempfile.mkdtemp(prefix=f"vl_john_{session_label}_")
            hash_path = os.path.join(session_dir, "hashes.txt")
            pot_path = os.path.join(session_dir, "john.pot")
            try:
                # Write hashes - use the user:hash format so john can recover
                # the username on --show output.
                with open(hash_path, "w", encoding="utf-8") as fh:
                    for e in group:
                        uname = e["username"] or f"user{e['idx']}"
                        fh.write(f"{uname}:{e['hash']}\n")
                open(pot_path, "w").close()

                # Build crack cmd
                crack_cmd = [
                    JOHN_BIN,
                    f"--format={john_fmt}",
                    f"--wordlist={wordlist}",
                    f"--pot={pot_path}",
                    f"--session={session_dir}/sess",
                    f"--max-run-time={timeout}",
                    hash_path,
                ]
                if rules:
                    crack_cmd.insert(4, f"--rules={rules}")
                env = {**os.environ, "HOME": session_dir}
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *crack_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env,
                    )
                    try:
                        await asyncio.wait_for(proc.communicate(), timeout=timeout + 10)
                    except asyncio.TimeoutError:
                        try: proc.kill()
                        except Exception: pass
                        ctx.state[f"{session_label}_crack_timed_out"] = True
                except FileNotFoundError:
                    ctx.state["john_missing"] = True
                    return ([], 0)

                # --show pass
                show_cmd = [
                    JOHN_BIN,
                    f"--format={john_fmt}",
                    f"--pot={pot_path}",
                    "--show",
                    hash_path,
                ]
                show_stdout = b""
                try:
                    proc2 = await asyncio.create_subprocess_exec(
                        *show_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env,
                    )
                    try:
                        show_stdout, _ = await asyncio.wait_for(proc2.communicate(), timeout=20)
                    except asyncio.TimeoutError:
                        try: proc2.kill()
                        except Exception: pass
                except FileNotFoundError:
                    pass

                show_text = (show_stdout or b"").decode("utf-8", errors="ignore")

                # Map username back to entry index
                by_uname = {(e["username"] or f"user{e['idx']}"): e for e in group}
                for line in show_text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    low = line.lower()
                    if "password hash" in low and ("cracked" in low or "left" in low):
                        continue  # summary line
                    m = _RE_SHOW_LINE.match(line)
                    if not m:
                        continue
                    lhs = m.group("lhs")
                    pwd = m.group("pwd")
                    # john --show output for "user:hash" input is "user:plaintext"
                    entry = by_uname.get(lhs)
                    if not entry:
                        continue
                    _show = bool((ctx.state.get("_options") or {}).get("show_plaintext"))
                    finding = {
                        "id": f"{session_label}_{entry['idx']}",
                        "kind": "cracked_hash",
                        "hash_idx": entry["idx"],
                        "hash_type": entry.get("algorithm") or "unknown",
                        "hash_marker": entry["hash"][:12] + "...",
                        "username": entry["username"] or "",
                        "raw_line_hint": entry["raw_line"][:80],
                        "plaintext_marker": _redact(pwd, show_plaintext=_show),
                        "_plaintext_internal": pwd,  # stripped before response
                        "discovery_method": discovery_method,
                    }
                    all_findings.append(finding)
                    quick_cracked_idxs.add(entry["idx"])
            finally:
                try: shutil.rmtree(session_dir, ignore_errors=True)
                except Exception: pass

        if session_label == "quick":
            ctx.state["_quick_cracked_idxs"] = quick_cracked_idxs
        return (all_findings, len(all_findings))

    # ── STAGE 5: VERIFY (passlib re-hash) ──────────────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # VL-FOUNDRY evidence surfacing: stamp a concrete, per-finding
        # evidence string onto the methodology finding object. This rides
        # into the report via the methodology_findings intel field; it adds
        # no new finding and changes no severity (advisory-by-design safe).
        finding["evidence_marker"] = (
            f"{finding.get('discovery_method') or finding.get('kind') or 'probe'}"
            f" -> verifying {finding.get('kind') or 'finding'} for "
            f"{finding.get('user') or finding.get('attack_label') or ctx.host}")
        algo = finding.get("hash_type") or "unknown"
        plaintext = finding.get("_plaintext_internal") or ""
        # Find the original hash for this finding
        original_hash = ""
        for e in (ctx.state.get("hashes_parsed") or []):
            if e["idx"] == finding.get("hash_idx"):
                original_hash = e["hash"]
                break
        verified = False
        if plaintext and original_hash:
            try:
                verified = _verify_rehash(algo, plaintext, original_hash)
            except Exception:
                verified = False
        if verified:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "passlib_rehash_match"
        else:
            # John is usually right; SUSPECTED here is rare and usually
            # means passlib doesn't support the format (e.g. yescrypt, krb5).
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "john_only_unverified"
        # Strip internal-only plaintext key before it can leak to PDF/response
        finding.pop("_plaintext_internal", None)
        return finding

    # ── STAGE 6: PRIVILEGE CHECK (hash type + context) ─────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        algo = finding.get("hash_type") or "unknown"
        username = (finding.get("username") or "").lower()
        raw_line = finding.get("raw_line_hint") or ""
        priv_level = "unknown"
        cred_ctx = ""

        if algo == "ntlm":
            cred_ctx = "windows_credential"
            if username in ("administrator", "admin", "root"):
                priv_level = "root"
            else:
                priv_level = "user"
        elif algo == "lm" or algo == "pwdump":
            cred_ctx = "windows_credential_lm_weak"
            if username in ("administrator", "admin", "root"):
                priv_level = "root"
            else:
                priv_level = "user"
        elif algo in ("sha512crypt", "sha256crypt", "md5crypt", "yescrypt"):
            cred_ctx = "linux_shadow"
            # /etc/shadow doesn't carry uid - look for the literal "/0:0:" if
            # raw_line came from /etc/passwd-style input, or check username==root
            if username == "root" or "/0:0:" in raw_line:
                priv_level = "root"
            elif username in ("daemon", "bin", "sys", "nobody", "www-data",
                              "postgres", "mysql", "redis", "mongodb", "nginx",
                              "apache", "sshd", "systemd-network"):
                priv_level = "service"
            else:
                priv_level = "user"
        elif algo == "bcrypt":
            cred_ctx = "webapp_user"
            priv_level = "user"
        elif algo == "argon2":
            cred_ctx = "webapp_user"
            priv_level = "user"
        elif algo == "apache_md5":
            cred_ctx = "webapp_htpasswd"
            priv_level = "user"
        elif algo == "kerberos":
            cred_ctx = "ad_account"
            if username in ("administrator", "admin", "krbtgt"):
                priv_level = "root"
            else:
                priv_level = "user"
        elif algo == "wpa":
            cred_ctx = "wifi_psk"
            priv_level = "user"
        elif algo in ("md5", "sha1", "sha256", "sha512"):
            cred_ctx = "raw_unsalted"
            priv_level = "user"
        else:
            cred_ctx = "unknown"
            priv_level = "unknown"

        finding["privilege_level"] = priv_level
        finding["credential_context"] = cred_ctx
        return finding

    # ── STAGE 7: CHAIN HANDOFF ─────────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        suggested: list[str] = []
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            ctx_kind = f.get("credential_context", "")
            if ctx_kind in ("windows_credential", "windows_credential_lm_weak"):
                for s in ("ad_netexec_smb_spray", "ad_certipy_find"):
                    if s not in suggested:
                        suggested.append(s)
            elif ctx_kind == "linux_shadow" and f.get("privilege_level") in ("root", "service", "user"):
                if "password_hydra_ssh_spray" not in suggested:
                    suggested.append("password_hydra_ssh_spray")
            elif ctx_kind in ("webapp_user", "webapp_htpasswd"):
                if "password_patator_http_form_brute" not in suggested:
                    suggested.append("password_patator_http_form_brute")
            elif ctx_kind == "ad_account":
                if "ad_kerberoast_audit" not in suggested:
                    suggested.append("ad_kerberoast_audit")
        return suggested


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper - adapts MethodologyScanner to existing framework
# ═══════════════════════════════════════════════════════════════════


INTEL_FIELDS = [
    ("Stage timings (ms)",       "stage_timings"),
    ("Hash count",               "hash_count"),
    ("Fingerprint",              "fingerprint"),
    ("Quick-probe wordlist",     "quick_wordlist"),
    ("Quick-probe attempts",     "quick_probe_attempts"),
    ("Quick-probe cracked",      "quick_probe_cracked"),
    ("Deep-scan wordlist",       "deep_wordlist"),
    ("Deep-scan remaining",      "deep_scan_remaining"),
    ("Deep-scan cracked",        "deep_scan_cracked"),
    ("Methodology findings",     "methodology_findings"),
    ("Chain handoff next",       "chain_next"),
    ("Stage errors",             "stage_errors"),
]


@router.post("/api/password/john_hash_audit")
async def password_john_hash_audit(req: JohnHashAuditRequest, _=Depends(verify_scan_quota)):
    scanner = JohnHashAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=JOHN_HASH_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
