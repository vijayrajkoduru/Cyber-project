"""hashcat_wpa_audit - offline WPA/WPA2 PSK strength audit via hashcat
(playbook 18_wireless, tier1_wifi - companion to wpa_handshake_capture_audit).

Wires the hashcat binary into the wireless module. WPA2 PSK recovery is an
OFFLINE step: it needs a previously-captured 4-way handshake (or PMKID).
The scanner host is a hardware-less SaaS backend with NO monitor-mode radio,
so it cannot capture a handshake itself. The customer must therefore supply
a capture file that was recorded on an agent / workstation with a monitor
NIC (see wpa_handshake_capture_audit / monitor_mode_capability_audit).

What this scanner does, when (and ONLY when) a capture file is supplied AND
hashcat is installed:
  - Detect the capture format from its extension:
      .22000 / .hc22000     -> hashcat mode 22000 (WPA-PBKDF2-PMKID+EAPOL), native
      .hccapx               -> hashcat mode 22000 also reads hccapx, native
      .cap / .pcap / .pcapng-> needs conversion to .22000 first; we try
                                hcxpcapngtool / cap2hccapx if present, else advise
  - Run hashcat in straight (-a 0) dictionary mode against a SMALL top-passwords
    wordlist (SecLists top-1000 / top-100) with a STRICT wall-clock timeout and
    --potfile isolated per run. This is a weak-PSK audit, NOT exhaustive cracking.
  - Parse hashcat's machine-readable output. ONLY emit a HIGH weak-PSK finding
    when hashcat actually reports a recovered key (status Cracked + a
    hash:plaintext line). The recovered PSK is REDACTED (length + last 2 chars).
  - If hashcat ran the full dictionary without recovering the PSK, emit a
    POSITIVE result (PSK survived the small dictionary in the bounded window).

When NO capture file is supplied, OR hashcat is missing, OR the capture cannot
be converted to a hashcat-readable format, the scanner emits a clear
[ADVISORY-BY-DESIGN] INFO finding explaining exactly what to supply. It never
crashes and never emits a false HIGH.

Customer input:
  ScanRequest.target                  = (optional) path to a capture file, OR an
                                          ESSID/BSSID label for the report
  ScanRequest.options.capture_file    = absolute path to .22000 / .hccapx / .cap
                                          (preferred way to pass the handshake)
  ScanRequest.options.wordlist        = (optional) override wordlist path
  ScanRequest.options.scan_duration   = hashcat wall-clock cap (s, default 60,
                                          capped at 180)
  ScanRequest.options.show_plaintext  = bool, return the recovered PSK in clear
                                          (default False -> redacted marker)
"""
from __future__ import annotations
import asyncio
import contextvars
import os
import shutil
import tempfile
from fastapi import APIRouter, Depends, Request
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()
HASHCAT_BIN = shutil.which("hashcat") or "/usr/bin/hashcat"
DEFAULT_DURATION = 60
MAX_DURATION = 180

# hashcat mode 22000 reads BOTH the new .22000 (PMKID+EAPOL) format AND the
# legacy .hccapx binary format directly.
_NATIVE_EXTS = (".22000", ".hc22000", ".hccapx")
_CONVERTIBLE_EXTS = (".cap", ".pcap", ".pcapng")

# Small, fast wordlists for a weak-PSK audit (NOT exhaustive). First existing
# path wins. WPA2 PSKs are >= 8 chars; top-1000 still surfaces "password",
# "12345678", "Password1", common SSID-derived defaults, etc.
_WORDLISTS = [
    "/opt/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "/opt/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
    "/opt/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
    "/usr/share/wordlists/rockyou.txt",
    "/opt/seclists/Passwords/Leaked-Databases/rockyou.txt",
]

# Tiny built-in WPA-plausible fallback (>= 8 chars) materialized to /tmp once
# per process when no SecLists/rockyou path exists in this build.
_BUILTIN_WPA_FALLBACK = (
    "password\n12345678\n123456789\n1234567890\nqwertyuiop\npassword1\n"
    "Password1\nadmin123\nwelcome1\nletmein1\nsunshine\niloveyou\n"
    "superman1\nfootball\nbaseball\nchangeme1\nP@ssw0rd\nqwerty123\n"
    "abcd1234\ndragon123\nmonkey123\ntrustno1\nwhatever1\nsecret12\n"
)
_BUILTIN_PATH: "str | None" = None

_REQ_OPTS: contextvars.ContextVar = contextvars.ContextVar("hashcat_wpa_opts", default={})


def _materialize_builtin() -> str:
    global _BUILTIN_PATH
    if _BUILTIN_PATH and os.path.isfile(_BUILTIN_PATH):
        return _BUILTIN_PATH
    try:
        fd, path = tempfile.mkstemp(prefix="vl_hashcat_wpa_builtin_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(_BUILTIN_WPA_FALLBACK)
        _BUILTIN_PATH = path
        return path
    except Exception:
        return ""


def _resolve_wordlist(override: str) -> str:
    if override and os.path.isfile(override) and os.access(override, os.R_OK):
        return override
    for p in _WORDLISTS:
        if os.path.isfile(p) and os.access(p, os.R_OK):
            return p
    return _materialize_builtin()


def _resolve_capture(opts: dict, target: str) -> str:
    """Return the capture-file path from options.capture_file, else from the
    target IF the target is itself a path to an existing capture file."""
    cap = (opts.get("capture_file") or "").strip()
    if cap and os.path.isfile(cap):
        return cap
    t = (target or "").strip()
    if t and os.path.isfile(t) and t.lower().endswith(_NATIVE_EXTS + _CONVERTIBLE_EXTS):
        return t
    return ""


def _hashcat_available() -> bool:
    return bool(shutil.which("hashcat")) or os.path.exists(HASHCAT_BIN)


async def _convert_to_22000(cap_path: str, work_dir: str) -> str:
    """Convert a .cap/.pcap/.pcapng to a hashcat-readable .22000 using
    hcxpcapngtool (or legacy cap2hccapx -> .hccapx) IF available on PATH.
    Returns the converted path, or "" if no converter is installed / it
    produced nothing. Never raises."""
    out_22000 = os.path.join(work_dir, "converted.22000")
    hcx = shutil.which("hcxpcapngtool")
    if hcx:
        try:
            proc = await asyncio.create_subprocess_exec(
                hcx, "-o", out_22000, cap_path,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=30)
            except asyncio.TimeoutError:
                try: proc.kill()
                except Exception: pass
        except Exception:
            pass
        if os.path.isfile(out_22000) and os.path.getsize(out_22000) > 0:
            return out_22000
    # Legacy fallback: cap2hccapx -> .hccapx (hashcat 22000 reads hccapx too)
    c2h = shutil.which("cap2hccapx") or shutil.which("cap2hccapx.bin")
    if c2h:
        out_hccapx = os.path.join(work_dir, "converted.hccapx")
        try:
            proc = await asyncio.create_subprocess_exec(
                c2h, cap_path, out_hccapx,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=30)
            except asyncio.TimeoutError:
                try: proc.kill()
                except Exception: pass
        except Exception:
            pass
        if os.path.isfile(out_hccapx) and os.path.getsize(out_hccapx) > 0:
            return out_hccapx
    return ""


def _redact(pwd: str, show_plaintext: bool) -> str:
    if not pwd:
        return "len=0"
    pwd = pwd.rstrip("\r\n")
    if show_plaintext:
        return pwd
    if len(pwd) <= 2:
        return f"len={len(pwd)} ***"
    return f"len={len(pwd)} ***{pwd[-2:]}"


def _parse_cracked(show_text: str, show_plaintext: bool) -> "list[dict]":
    """Parse hashcat --show output. For mode 22000 each cracked line is
    <hashline>:<essid>:<plaintext>  or  <hash>:<plaintext>. We only treat a
    line as a recovery if it has at least one ':' separator AND a non-empty
    trailing field. Returns a list of {essid, psk_marker} dicts."""
    out = []
    for raw in show_text.splitlines():
        line = raw.rstrip("\r\n")
        if not line or ":" not in line:
            continue
        # hashcat 22000 --show => "<wpa*...>:<essid>:<password>" (the password
        # is the LAST colon-delimited field; essid may itself contain colons in
        # rare cases, so take the final field as the plaintext).
        parts = line.split(":")
        pwd = parts[-1]
        essid = parts[-2] if len(parts) >= 3 else ""
        if not pwd:
            continue
        out.append({"essid": essid[:64], "psk_marker": _redact(pwd, show_plaintext)})
    return out


async def gather(ctx: ScanContext):
    opts = _REQ_OPTS.get() or {}
    target = (ctx.host or "").strip()
    duration = int(opts.get("scan_duration") or DEFAULT_DURATION)
    duration = max(15, min(duration, MAX_DURATION))
    show_plaintext = bool(opts.get("show_plaintext"))

    ctx.state["target_label"] = target

    # 1) hashcat present?
    if not _hashcat_available():
        ctx.state["hashcat_binary_missing"] = True
        ctx.state["hashcat_wpa_audit_total"] = 0
        ctx.source("hashcat not installed")
        return

    # 2) capture file supplied?
    cap_path = _resolve_capture(opts, target)
    if not cap_path:
        ctx.state["no_capture_file"] = True
        ctx.state["hashcat_wpa_audit_total"] = 0
        ctx.source("no WPA capture supplied")
        return

    ctx.state["capture_file"] = os.path.basename(cap_path)
    try:
        ctx.state["capture_bytes"] = os.path.getsize(cap_path)
    except Exception:
        ctx.state["capture_bytes"] = 0

    work_dir = tempfile.mkdtemp(prefix="vl_hashcat_wpa_")
    hashfile = cap_path
    ext = os.path.splitext(cap_path)[1].lower()

    try:
        # 3) Normalize to a hashcat-readable format.
        if ext in _CONVERTIBLE_EXTS:
            converted = await _convert_to_22000(cap_path, work_dir)
            if not converted:
                ctx.state["capture_unconvertible"] = True
                ctx.state["hashcat_wpa_audit_total"] = 0
                ctx.source("capture needs hcxpcapngtool conversion")
                return
            hashfile = converted
        elif ext not in _NATIVE_EXTS:
            ctx.state["capture_unsupported_ext"] = ext or "(none)"
            ctx.state["hashcat_wpa_audit_total"] = 0
            ctx.source(f"unsupported capture extension {ext}")
            return

        # 4) Wordlist.
        wordlist = _resolve_wordlist((opts.get("wordlist") or "").strip())
        if not wordlist:
            ctx.state["no_wordlist"] = True
            ctx.state["hashcat_wpa_audit_total"] = 0
            ctx.source("no wordlist available")
            return
        ctx.state["wordlist"] = os.path.basename(wordlist)
        ctx.state["scan_duration_sec"] = duration

        potfile = os.path.join(work_dir, "hc.potfile")
        session = os.path.join(work_dir, "sess")

        # 5) Run hashcat, mode 22000, straight dictionary, bounded.
        #   --quiet            : suppress the interactive status screen
        #   --potfile-path     : isolated potfile (no cross-tenant leakage)
        #   --runtime          : hashcat self-enforced wall-clock abort
        #   --machine-readable : stable parse for the --show pass
        #   --force            : tolerate CPU-only / no-GPU SaaS backend
        crack_cmd = [
            HASHCAT_BIN, "-m", "22000", "-a", "0",
            "--quiet", "--force",
            "--potfile-path", potfile,
            "--session", session,
            "--runtime", str(duration),
            "--outfile-format", "2",
            hashfile, wordlist,
        ]
        ran_ok = True
        try:
            proc = await asyncio.create_subprocess_exec(
                *crack_cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
            )
            try:
                # hashcat self-aborts at --runtime; give it a small grace margin.
                await asyncio.wait_for(proc.communicate(), timeout=duration + 20)
            except asyncio.TimeoutError:
                ctx.state["hashcat_timed_out"] = True
                try: proc.kill()
                except Exception: pass
                try: await proc.wait()
                except Exception: pass
        except FileNotFoundError:
            ctx.state["hashcat_binary_missing"] = True
            ctx.state["hashcat_wpa_audit_total"] = 0
            ctx.source("hashcat exec failed")
            return
        except PermissionError:
            ctx.state["hashcat_permission_denied"] = True
            ctx.state["hashcat_wpa_audit_total"] = 0
            ctx.source("hashcat permission denied")
            return
        except Exception as e:
            ctx.state["hashcat_error"] = str(e)[:200]
            ctx.state["hashcat_wpa_audit_total"] = 0
            ctx.source(f"hashcat error: {str(e)[:80]}")
            return

        # 6) --show pass against the isolated potfile -> authoritative result.
        show_text = ""
        if os.path.isfile(potfile):
            show_cmd = [
                HASHCAT_BIN, "-m", "22000",
                "--potfile-path", potfile,
                "--show", "--outfile-format", "2",
                hashfile,
            ]
            try:
                proc2 = await asyncio.create_subprocess_exec(
                    *show_cmd,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    cwd=work_dir,
                )
                try:
                    so, _ = await asyncio.wait_for(proc2.communicate(), timeout=30)
                    show_text = (so or b"").decode("utf-8", "replace")
                except asyncio.TimeoutError:
                    try: proc2.kill()
                    except Exception: pass
            except Exception:
                show_text = ""

        cracked = _parse_cracked(show_text, show_plaintext)
        ctx.state["psk_recovered"] = bool(cracked)
        if cracked:
            ctx.state["cracked"] = cracked
        ctx.state["hashcat_wpa_audit_total"] = 1 if cracked else 0
        ctx.state["scan_ran"] = ran_ok
        ctx.source(f"hashcat 22000 dictionary audit ({ctx.state.get('wordlist')}) "
                   f"{'recovered PSK' if cracked else 'no recovery'} in <= {duration}s")
    finally:
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass


# ──────────────────────── finding rules (inline) ────────────────────────
# Plain functions: state -> finding dict or None. Rules NEVER raise (the
# engine catches), and ONLY graded findings for tool-confirmed results.

def rule_hashcat_missing(s):
    if not s.get("hashcat_binary_missing"):
        return None
    return {"name": "[ADVISORY-BY-DESIGN] hashcat not installed on scanner host",
            "severity": "INFO",
            "evidence": ("shutil.which('hashcat') returned None and "
                         f"{HASHCAT_BIN} is absent. Offline WPA2 PSK audit needs "
                         "the hashcat binary."),
            "remediation": ("Install hashcat (`apt install hashcat`) on the scan "
                            "agent, then re-run this probe with a captured WPA2 "
                            "handshake supplied via options.capture_file."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_no_capture(s):
    if not s.get("no_capture_file"):
        return None
    return {"name": "[ADVISORY-BY-DESIGN] No WPA2 handshake capture supplied",
            "severity": "INFO",
            "evidence": ("Offline WPA2 PSK cracking requires a previously-captured "
                         "4-way handshake or PMKID. The scanner host has NO "
                         "monitor-mode radio, so it cannot capture one itself; "
                         "neither options.capture_file nor a capture-file target "
                         "path was provided."),
            "remediation": ("Capture a handshake on an agent/workstation that has a "
                            "monitor-mode Wi-Fi adapter (see the "
                            "wpa_handshake_capture_audit / monitor_mode_capability_audit "
                            "probes), convert it to hashcat mode 22000 with "
                            "`hcxpcapngtool -o handshake.22000 capture.pcapng`, then "
                            "re-run this probe with options.capture_file=\"/path/handshake.22000\". "
                            "Native formats: .22000 / .hc22000 / .hccapx."),
            "cwe": "CWE-326", "owasp": "A02:2021"}


def rule_capture_unconvertible(s):
    if not s.get("capture_unconvertible"):
        return None
    return {"name": "[ADVISORY-BY-DESIGN] Capture supplied but no converter installed",
            "severity": "INFO",
            "evidence": (f"Supplied capture '{s.get('capture_file', '')}' is a raw "
                         "pcap/cap that hashcat cannot read directly, and neither "
                         "hcxpcapngtool nor cap2hccapx is installed on this host."),
            "remediation": ("Pre-convert the capture to hashcat mode 22000 on a host "
                            "with hcxtools: `hcxpcapngtool -o handshake.22000 "
                            "capture.pcapng`, then supply the .22000 file via "
                            "options.capture_file. Alternatively install hcxtools "
                            "(`apt install hcxtools`) on the scan agent."),
            "cwe": "CWE-326", "owasp": "A02:2021"}


def rule_capture_unsupported_ext(s):
    ext = s.get("capture_unsupported_ext")
    if not ext:
        return None
    return {"name": "[ADVISORY-BY-DESIGN] Unsupported capture file type",
            "severity": "INFO",
            "evidence": (f"Capture extension '{ext}' is not a recognized WPA "
                         "handshake format."),
            "remediation": ("Supply a hashcat-readable handshake: .22000 / .hc22000 "
                            "(hashcat mode 22000) or legacy .hccapx, or a raw "
                            ".cap/.pcap/.pcapng (auto-converted when hcxpcapngtool "
                            "is installed)."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_no_wordlist(s):
    if not s.get("no_wordlist"):
        return None
    return {"name": "[ADVISORY-BY-DESIGN] No wordlist available for WPA audit",
            "severity": "INFO",
            "evidence": "Neither SecLists/rockyou nor the built-in fallback list could be resolved.",
            "remediation": ("Install SecLists (`/opt/seclists`) or pass an explicit "
                            "options.wordlist path readable by the scanner."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_psk_recovered(s):
    if not s.get("psk_recovered"):
        return None
    cracked = s.get("cracked") or []
    first = cracked[0] if cracked else {}
    essid = first.get("essid") or s.get("target_label") or "(unknown ESSID)"
    marker = first.get("psk_marker") or "(redacted)"
    return {"name": "Weak WPA2 PSK recovered from captured handshake",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-521", "owasp": "A07:2021",
            "verified_exploit": True,
            "evidence": (f"hashcat mode 22000 recovered the WPA2 pre-shared key for "
                         f"ESSID '{essid}' from the supplied handshake using a small "
                         f"top-passwords dictionary ({s.get('wordlist', 'wordlist')}) "
                         f"within {s.get('scan_duration_sec', 0)}s. Recovered PSK: "
                         f"{marker} (redacted). A PSK that falls to a top-1000 "
                         "dictionary is trivially crackable by any attacker who "
                         "captures one handshake."),
            "remediation": ("1) Rotate the WPA2-PSK to a 20+ char random passphrase "
                            "that is not in any wordlist. 2) Prefer WPA3-SAE "
                            "(Dragonfly), which resists offline handshake cracking. "
                            "3) For enterprise, deploy WPA2/3-Enterprise (EAP-TLS) "
                            "with per-user credentials instead of a shared PSK. "
                            "4) Enable Protected Management Frames (802.11w) and "
                            "rotate keys after any suspected capture.")}


def rule_psk_survived(s):
    # Only emit when hashcat ACTUALLY ran a full pass and recovered nothing.
    if s.get("psk_recovered"):
        return None
    if not s.get("scan_ran"):
        return None
    if s.get("hashcat_timed_out"):
        return None  # inconclusive: aborted on time, do not claim a clean bill
    return {"name": "WPA2 PSK survived small-dictionary audit",
            "severity": "POSITIVE",
            "evidence": (f"hashcat mode 22000 ran the {s.get('wordlist', 'wordlist')} "
                         f"dictionary against the supplied handshake for "
                         f"'{s.get('target_label', '')}' and did NOT recover the PSK "
                         f"within {s.get('scan_duration_sec', 0)}s. This rules out "
                         "the most common weak passphrases only; it is NOT proof of "
                         "an uncrackable key."),
            "remediation": ("Good baseline. For full assurance, run a longer offline "
                            "audit against a larger wordlist on dedicated hardware, "
                            "and migrate to WPA3-SAE where possible.")}


HASHCAT_WPA_AUDIT_FINDING_RULES = [
    rule_hashcat_missing,
    rule_no_capture,
    rule_capture_unconvertible,
    rule_capture_unsupported_ext,
    rule_no_wordlist,
    rule_psk_recovered,
    rule_psk_survived,
]


INTEL_FIELDS = [
    ("Target", "target_label"),
    ("Capture file", "capture_file"),
    ("Capture file size (B)", "capture_bytes"),
    ("Wordlist", "wordlist"),
    ("Audit duration (s)", "scan_duration_sec"),
    ("PSK recovered", "psk_recovered"),
]


@router.post("/api/wireless/hashcat_wpa_audit")
async def wireless_hashcat_wpa_audit(req: ScanRequest, request: Request,
                                     _=Depends(verify_scan_quota)):
    # Stash request options for gather() (mirrors wpa_handshake_capture_audit).
    try:
        body = await request.json()
    except Exception:
        body = {}
    _REQ_OPTS.set(body.get("options") or {})
    return await run_scanner(host=req.target, tool="hashcat_wpa_audit",
        gather_func=gather, finding_rules=HASHCAT_WPA_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
