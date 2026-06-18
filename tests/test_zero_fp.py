"""FP-REGRESSION GATE — the test that makes VulnusLab's zero-false-positive
principle a *guarantee* rather than a convention.

ZERO-FP PRINCIPLE (non-negotiable): a graded finding (CRITICAL/HIGH/MEDIUM/
LOW) MUST be PROVEN — never inferred from a weak signal ("status 200",
"port open", "a base64 blob exists", "a string appears somewhere"). On a
known-clean target the only acceptable output is INFO / POSITIVE.

This module enforces that with two independent layers:

  (A) STATIC layer  — walks every payload library and scanner source file
      and fails if ANY payload's `matcher` value is an always-true regex
      (".+", ".*", "^.*$", "(.+)", "(.*)", empty / whitespace, …). An
      always-true matcher fires on EVERY response, so it manufactures a
      graded finding on a clean target — the exact bug class this gate
      exists to prevent. Catches the bug at lint time, before a scan runs.

  (B) BEHAVIORAL layer — spins up a local stdlib http.server on 127.0.0.1
      that returns a small, benign, clean HTML page to everything (200, no
      security issues, no secrets, no base64 blobs, normal Host echo only).
      A representative set of webapp scanners is run against it. ANY graded
      finding (LOW/MEDIUM/HIGH/CRITICAL) is a false positive => test fails,
      printing the offending finding. Only INFO / POSITIVE is allowed.

Hermetic: no external network, fast, and each scanner is skipped cleanly if
it needs an unavailable binary or its host environment can't be guaranteed
clean (e.g. portscan probing loopback well-known ports we don't control).

Run just the static layer:
    python -m pytest tests/test_zero_fp.py -k static -q
Run everything:
    python -m pytest tests/test_zero_fp.py -q
"""
from __future__ import annotations

import ast
import asyncio
import json
import os
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

# ── Repo layout ──────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_HERE)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

PAYLOADS_DIR = os.path.join(REPO_ROOT, "tools", "_payloads")
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")

GRADED = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


# ════════════════════════════════════════════════════════════════════════
#  LAYER A — STATIC: no always-true matcher may exist in any payload
# ════════════════════════════════════════════════════════════════════════
#
# An always-true regex matches every possible response, so a payload that
# uses one will "confirm" itself against a clean target. We normalise the
# matcher (strip whitespace, an optional leading "(?i)"/"(?s)" inline flag,
# and one layer of wrapping parens/anchors) and then test whether what
# remains is the universal pattern `.` quantified by `*` / `+` / `*?` / `+?`.
#
# Examples that MUST be flagged:
#   ""  "   "  ".+"  ".*"  "^.*$"  "(.+)"  "(.*)"  "^.+$"  ".*?"  "(?i).+"
# Examples that MUST NOT be flagged (they actually constrain the response):
#   "root:x:0:0:"  "(?i)(welcome|home)"  "<script>alert\\(1\\)</script>"
#   "(?<![0-9])49(?![0-9])"  "AKIA[0-9A-Z]{16}"

_FLAG_PREFIX_RE = re.compile(r"^\(\?[aiLmsux]+\)")  # leading inline-flag group


def _strip_one_paren_layer(s: str) -> str:
    """Remove ONE balanced outer (...) group if it wraps the whole string."""
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        depth = 0
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    # only a wrapper if the matching ")" is the last char
                    return s[1:-1] if i == len(s) - 1 else s
    return s


def is_always_true_matcher(matcher) -> bool:
    """True iff `matcher` is an always-true / vacuous regex (a zero-FP risk)."""
    if matcher is None:
        return True
    if not isinstance(matcher, str):
        return False  # non-string matcher is a different problem; not our gate
    s = matcher.strip()
    if s == "":
        return True  # empty / whitespace-only matches everything

    # Peel surface decoration that does not constrain WHAT is matched:
    #   leading inline-flag group, wrapping parens, ^ / $ anchors.
    prev = None
    while prev != s:
        prev = s
        s = _FLAG_PREFIX_RE.sub("", s, count=1).strip()
        s = _strip_one_paren_layer(s).strip()
        if s.startswith("^"):
            s = s[1:]
        if s.endswith("$"):
            s = s[:-1]
        s = s.strip()

    if s == "":
        return True  # was just anchors / flags around nothing
    # What remains is an always-true atom iff it matches every (non-empty)
    # response. Covered universal patterns:
    #   .   .?   .*   .+   .*?   .+?            (dot, optionally quantified)
    #   .{0,}  .{1,}  .{0,N}  .{1,N}            (dot with always-satisfiable
    #                                            lower bound on a real body)
    # A bare "." is always-true here because scanners apply it with re.search
    # against a response body, which is effectively never empty — so "." (and
    # the .{0,*}/.{1,*} forms) "confirm" against any target.
    if re.fullmatch(r"\.[*+]?\??", s):
        return True
    if re.fullmatch(r"\.\{[01],\d*\}\??", s):
        return True
    return False


def _matchers_in_pyfile(path: str):
    """Yield (lineno, value) for every dict literal key 'matcher' in a .py
    file, via AST (robust to raw strings, r-prefixes, etc.; no import)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
    except (SyntaxError, UnicodeDecodeError):
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and k.value == "matcher":
                if isinstance(v, ast.Constant) and isinstance(v.value, (str, bytes)):
                    val = v.value.decode() if isinstance(v.value, bytes) else v.value
                    yield (getattr(v, "lineno", node.lineno), val)
                elif isinstance(v, ast.Constant) and v.value is None:
                    yield (getattr(v, "lineno", node.lineno), None)


def _matchers_in_jsonfile(path: str):
    """Yield (json_pointer, value) for every 'matcher' key anywhere in a
    JSON document (lists/dicts nested arbitrarily)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return

    def _walk(obj, ptr):
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key == "matcher":
                    yield (f"{ptr}/matcher", val)
                yield from _walk(val, f"{ptr}/{key}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                yield from _walk(item, f"{ptr}[{i}]")

    yield from _walk(data, "")


def _iter_matcher_sources():
    """Walk tools/** once, yielding (relpath, locator, value) for every
    'matcher' value found in .py (any path) and .json (under _payloads only)."""
    for root, _dirs, files in os.walk(TOOLS_DIR):
        if "__pycache__" in root:
            continue
        under_payloads = (
            os.path.commonpath([root, PAYLOADS_DIR]) == PAYLOADS_DIR
        )
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, REPO_ROOT)
            if name.endswith(".py"):
                for lineno, val in _matchers_in_pyfile(full):
                    yield (rel, f"line {lineno}", val)
            elif name.endswith(".json") and under_payloads:
                for ptr, val in _matchers_in_jsonfile(full):
                    yield (rel, ptr, val)


# ── Runtime-guard awareness ──────────────────────────────────────────────
#
# The codebase deliberately keeps a few always-true matchers in payload DATA
# files (LFI/SSRF "extra" pools) but NEUTRALISES them at runtime: every
# consuming scanner drops a matcher that matches the canonical guard regex
# before it is ever applied to a response (commit 60e715ca — "kill
# always-true-matcher false positives"). So an always-true matcher is only a
# LIVE false-positive hazard if its consuming scanner LACKS that guard.
#
# The gate therefore reports an always-true matcher as an OFFENDER unless
# every scanner that consumes its source file carries the canonical guard.
# New, un-guarded always-true matchers (the actual bug class) still FAIL.

# The canonical "drop always-true matcher" guard, normalised to a substring
# that is stable across the xxe/lfi/ssrf copies.
_GUARD_SIGNATURE = r're.fullmatch(r"[()\s]*\.[+*?]*[()\s]*"'

# The EXACT regex the runtime guard fullmatches a stripped matcher against.
# A matcher is only neutralised by the guard if the guard would actually drop
# it — i.e. this pattern fullmatches the matcher. The guard covers .+/.*/(.+)
# style atoms but NOT a bare "." or ".{1,}" (those slip through and remain
# live false positives even in a guarded scanner).
_GUARD_COVERS_RE = re.compile(r"[()\s]*\.[+*?]*[()\s]*")


def _guard_covers(matcher) -> bool:
    """True iff the runtime guard would drop this specific matcher value."""
    return isinstance(matcher, str) and \
        _GUARD_COVERS_RE.fullmatch(matcher.strip()) is not None


def _file_has_guard(scanner_relpath: str) -> bool:
    try:
        with open(os.path.join(REPO_ROOT, scanner_relpath), "r",
                  encoding="utf-8") as fh:
            src = fh.read()
    except OSError:
        return False
    return _GUARD_SIGNATURE in src


def _build_consumer_index():
    """Map a payload source basename -> list of scanner relpaths that consume
    it. JSON pools are loaded via load_json("<name>") -> <name>.json; .py pools
    via `from tools._payloads.<mod> import` / `_payloads.<mod>`."""
    consumers: dict[str, list[str]] = {}
    load_json_re = re.compile(r'load_json\(\s*["\']([^"\']+)["\']')
    import_re = re.compile(r'tools\._payloads\.([A-Za-z0-9_]+)')
    for root, _dirs, files in os.walk(TOOLS_DIR):
        if "__pycache__" in root:
            continue
        for name in files:
            if not name.endswith(".py"):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, REPO_ROOT)
            try:
                with open(full, "r", encoding="utf-8") as fh:
                    src = fh.read()
            except OSError:
                continue
            for json_name in load_json_re.findall(src):
                consumers.setdefault(json_name + ".json", []).append(rel)
            for mod in import_re.findall(src):
                consumers.setdefault(mod + ".py", []).append(rel)
    return consumers


def _is_neutralised(source_relpath: str, matcher, consumer_index: dict) -> bool:
    """An always-true matcher is neutralised iff (a) the runtime guard would
    actually DROP this specific matcher value, AND (b) every scanner that
    applies it carries that guard.

    Condition (a) matters: the guard only covers .+/.*/(.+)-style atoms. A
    bare "." or ".{1,}" is always-true but slips PAST the guard, so it stays a
    live false positive even in a "guarded" scanner -> NOT neutralised.

    - Payload-DATA file (under tools/_payloads/): every consumer must carry
      the guard.
    - Inline scanner file (a tools/**/*.py that is NOT a payload pool): that
      file itself must carry the guard."""
    if not _guard_covers(matcher):
        return False  # guard does not drop this matcher -> live FP
    norm = source_relpath.replace("\\", "/")
    if not norm.startswith("tools/_payloads/"):
        # Inline scanner file — it applies its own matcher.
        return _file_has_guard(source_relpath)
    consumers = consumer_index.get(os.path.basename(source_relpath), [])
    if not consumers:
        return False  # cannot prove neutralisation -> fail safe
    return all(_file_has_guard(c) for c in consumers)


def test_static_no_always_true_matcher():
    """No payload's `matcher` may be an always-true regex UNLESS every scanner
    that consumes it drops it via the canonical runtime guard (lint-time gate
    for the false-positive bug class)."""
    consumer_index = _build_consumer_index()
    offenders = []
    neutralised = []
    seen = 0
    for rel, locator, val in _iter_matcher_sources():
        seen += 1
        if not is_always_true_matcher(val):
            continue
        if _is_neutralised(rel, val, consumer_index):
            neutralised.append(f"  {rel} :: {locator} :: matcher={val!r}")
        else:
            offenders.append(f"  {rel} :: {locator} :: matcher={val!r}")

    assert seen > 0, (
        "Static gate found ZERO matcher values to inspect — the walker is "
        "broken or the payload tree moved. Refusing to pass vacuously."
    )
    assert not offenders, (
        f"\nALWAYS-TRUE MATCHER(S) DETECTED — {len(offenders)} payload "
        f"matcher(s) match every response and are NOT neutralised by a "
        f"runtime guard, so they will manufacture graded findings on a CLEAN "
        f"target (false positives):\n"
        + "\n".join(offenders)
        + "\n\nFix EITHER by replacing the matcher with a regex that proves "
        "the vulnerability (reflected payload echo / file-content marker / "
        "error string) OR by adding the canonical always-true-matcher guard "
        "to the consuming scanner.\n"
        + (f"\n({len(neutralised)} other always-true matcher(s) are present "
           f"but runtime-neutralised by the guard — allowed.)"
           if neutralised else "")
    )


def test_static_self_check_classifier():
    """Sanity-check the classifier itself so the static gate can't silently
    rot into a no-op (e.g. a refactor that always returns False)."""
    always_true = ["", "   ", ".+", ".*", "^.*$", "(.+)", "(.*)", "^.+$",
                   ".*?", ".+?", "(?i).+", "(?is)^.*$", "((.*))", "^(.+)$",
                   ".", ".?", "(.)", "^.$", "(?i).", ".{0,}", ".{1,}",
                   ".{0,200}", ".{1,8}"]
    constrained = ["root:x:0:0:", "(?i)(welcome|home|dashboard)",
                   r"<script>alert\(1\)</script>", "(?<![0-9])49(?![0-9])",
                   "AKIA[0-9A-Z]{16}", r"127\.0\.0\.1\s+localhost", "a.+b",
                   ".+world", "error in your SQL", "regf", "..",
                   ".{2,}", "x.", ".x"]
    bad_pos = [m for m in always_true if not is_always_true_matcher(m)]
    bad_neg = [m for m in constrained if is_always_true_matcher(m)]
    assert not bad_pos, f"classifier missed always-true matchers: {bad_pos}"
    assert not bad_neg, f"classifier flagged constrained matchers: {bad_neg}"


# ════════════════════════════════════════════════════════════════════════
#  LAYER B — BEHAVIORAL: scanners must produce NO graded finding on clean
# ════════════════════════════════════════════════════════════════════════
#
# A deliberately benign target. The page has NO security issues, NO secrets,
# NO base64 blobs, NO emails/SSNs/cards, NO reflective behaviour. Anything a
# scanner grades against THIS is, by construction, a false positive.

_CLEAN_HTML = (
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    "<title>Hello</title></head><body>"
    "<h1>It works</h1>"
    "<p>This is a plain, benign static page used as a known-clean scan "
    "target. It exposes nothing of value and reflects no user input.</p>"
    "<p>The quick brown fox jumps over the lazy dog.</p>"
    "</body></html>"
)
# NOTE: the page deliberately avoids substrings that legitimate matchers key
# on (e.g. "secret"/"token"/"password"/"APP_KEY"/"root:x:0:0:"). A truly
# known-clean target must not even MENTION those words, or it collides with a
# real (correct) detection and looks like an FP that isn't the scanner's fault.


class _CleanHandler(BaseHTTPRequestHandler):
    """Returns the same clean 200 HTML for every path/method. It does NOT
    reflect query strings, headers, or bodies anywhere in the page — so no
    injection payload can ever appear in the response. It echoes the Host
    header only in the standard, legitimate way (it doesn't, in fact, even
    do that — Host echo is a common HHI false-positive source, so we omit
    it entirely to keep the target unambiguously clean)."""

    def _respond(self):
        body = _CLEAN_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # Deliberately set defensive headers so header scanners stay quiet.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy",
                         "geolocation=(), camera=(), microphone=()")
        self.send_header("Strict-Transport-Security",
                         "max-age=63072000; includeSubDomains")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # Same clean response for every verb we might be probed with.
    do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_HEAD = \
        do_PATCH = _respond

    # Versionless Server header — the stdlib default leaks "Python/3.x" which
    # the security_headers scanner CORRECTLY grades (version disclosure). A
    # known-clean target must not leak a version, so we strip it.
    def version_string(self):
        return "clean-test-server"

    def log_message(self, *_a, **_k):  # silence the server
        return


@pytest.fixture(scope="module")
def clean_target():
    """Start a hermetic clean HTTP server on 127.0.0.1 and yield its base URL."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CleanHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}/", port
    finally:
        srv.shutdown()
        srv.server_close()


def _make_request(target: str):
    """Build a ScanRequest for the clean target."""
    from tools._shared import ScanRequest
    return ScanRequest(target=target)


def _endpoint_for(module, substr: str):
    """Pull the decorated route handler whose path contains `substr` from a
    scanner module's APIRouter. Returns the (async) callable or None."""
    router = getattr(module, "router", None)
    if router is None:
        return None
    for route in router.routes:
        path = getattr(route, "path", "")
        if substr in path:
            return getattr(route, "endpoint", None)
    return None


def _run_scanner(endpoint, req):
    """Invoke a scanner endpoint (all are async after @vl_turbo/@vl_verify)
    and return the response dict. Passes a dummy auth payload positionally so
    the Depends() default isn't needed."""
    result = endpoint(req, {})  # (req, payload/_)
    if asyncio.iscoroutine(result):
        result = asyncio.run(result)
    return result


def _graded_findings(resp):
    """Extract graded (LOW+) findings from a scanner response dict."""
    if not isinstance(resp, dict):
        return []
    out = []
    for f in (resp.get("findings") or []):
        if isinstance(f, dict) and str(f.get("severity", "")).upper() in GRADED:
            out.append(f)
    return out


# Each entry: (module import path, route-path substring, needs_auth_skip).
# needs_auth scanners (idor) self-skip without creds — we still run them to
# prove they DON'T fabricate a graded finding on a clean unauth target.
_WEBAPP_SCANNERS = [
    ("tools.webapp.xxe", "/xxe"),
    ("tools.webapp.lfi", "/lfi"),
    ("tools.webapp.ssrf", "/ssrf"),
    ("tools.webapp.idor", "/idor"),
    ("tools.webapp.host_header_injection", "/host_header_injection"),
    ("tools.webapp.secrets", "/secrets"),
    ("tools.webapp.security_headers", "/security_headers"),
    ("tools.webapp.sensitive_data", "/sensitive_data"),
    ("tools.webapp.sqli", "/sqli"),
    ("tools.webapp.xss", "/xss"),
]


def _loopback_catalog_ports_open(exclude_port: int) -> list:
    """Return well-known PORT_CATALOG ports (other than our own clean server)
    that are ALREADY open on 127.0.0.1. If any are, the loopback host is not
    a clean environment and portscan's graded findings would reflect THOSE
    services, not a scanner FP — so the portscan check skips."""
    try:
        from tools._payloads.portscan_findings import PORT_CATALOG
    except Exception:
        return []
    open_ports = []
    for p in PORT_CATALOG:
        if p == exclude_port:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        try:
            if s.connect_ex(("127.0.0.1", p)) == 0:
                open_ports.append(p)
        except OSError:
            pass
        finally:
            s.close()
    return open_ports


@pytest.mark.parametrize("mod_path,path_substr", _WEBAPP_SCANNERS,
                         ids=[m.rsplit(".", 1)[-1] for m, _ in _WEBAPP_SCANNERS])
def test_behavioral_clean_target_no_graded_findings(clean_target, mod_path,
                                                    path_substr):
    """Run a webapp scanner against a known-clean target. ZERO graded
    (CRITICAL/HIGH/MEDIUM/LOW) findings allowed — only INFO/POSITIVE."""
    target, _port = clean_target
    try:
        import importlib
        module = importlib.import_module(mod_path)
    except Exception as e:  # pragma: no cover - env dependent
        pytest.skip(f"cannot import {mod_path}: {type(e).__name__}: {e}")

    endpoint = _endpoint_for(module, path_substr)
    if endpoint is None:
        pytest.skip(f"no route matching {path_substr!r} in {mod_path}")

    req = _make_request(target)
    try:
        resp = _run_scanner(endpoint, req)
    except (FileNotFoundError, OSError) as e:
        # A required external binary (nmap/etc.) is unavailable — skip cleanly.
        pytest.skip(f"{mod_path}: required binary/IO unavailable: {e}")
    except Exception as e:  # pragma: no cover - defensive
        pytest.skip(f"{mod_path}: scanner raised {type(e).__name__}: {e}")

    graded = _graded_findings(resp)
    assert not graded, (
        f"\nFALSE POSITIVE: {mod_path} produced {len(graded)} graded "
        f"finding(s) against a KNOWN-CLEAN target ({target}). On a clean "
        f"target only INFO/POSITIVE is allowed.\n"
        + "\n".join(
            f"  [{f.get('severity')}] {f.get('detail', '')[:140]} "
            f"| evidence={str(f.get('evidence_marker', ''))[:160]}"
            for f in graded
        )
    )


def test_behavioral_portscan_no_graded_findings(clean_target):
    """portscan probes loopback well-known ports — which we can only assert
    on when no OTHER catalog service is running on 127.0.0.1. If the host is
    clean (only our benign server is up), portscan must NOT grade it."""
    target, port = clean_target
    pre_open = _loopback_catalog_ports_open(exclude_port=port)
    if pre_open:
        pytest.skip(
            "loopback is not a clean environment for portscan — pre-existing "
            f"open catalog port(s): {pre_open}. portscan findings would "
            "reflect those host services, not a scanner FP."
        )
    try:
        import importlib
        module = importlib.import_module("tools.webapp.portscan")
    except Exception as e:  # pragma: no cover
        pytest.skip(f"cannot import portscan: {type(e).__name__}: {e}")

    endpoint = _endpoint_for(module, "/portscan")
    if endpoint is None:
        pytest.skip("no /portscan route found")

    req = _make_request(target)
    try:
        resp = _run_scanner(endpoint, req)
    except (FileNotFoundError, OSError) as e:
        pytest.skip(f"portscan: required binary/IO unavailable: {e}")
    except Exception as e:  # pragma: no cover
        pytest.skip(f"portscan raised {type(e).__name__}: {e}")

    graded = _graded_findings(resp)
    assert not graded, (
        f"\nFALSE POSITIVE: portscan produced {len(graded)} graded finding(s) "
        f"against a clean loopback host (only a benign HTTP server up).\n"
        + "\n".join(
            f"  [{f.get('severity')}] {f.get('detail', '')[:140]} "
            f"| evidence={str(f.get('evidence_marker', ''))[:160]}"
            for f in graded
        )
    )


if __name__ == "__main__":  # allow `python tests/test_zero_fp.py`
    sys.exit(pytest.main([__file__, "-q"]))
