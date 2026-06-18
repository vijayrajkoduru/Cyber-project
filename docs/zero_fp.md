# Zero-FP Regression Gate

`tests/test_zero_fp.py` is the automated guarantee behind VulnusLab's
non-negotiable zero-false-positive principle: a graded finding
(CRITICAL/HIGH/MEDIUM/LOW) must be PROVEN, never inferred from a weak signal.
The gate has two layers:

- **Static** (`-k static`): walks `tools/_payloads/**` (`.py` + `.json`) and
  `tools/**/*.py`, failing if any payload's `matcher` value is an always-true
  regex (`.+`, `.*`, `^.*$`, `(.+)`, `(.*)`, empty/whitespace, and flag/anchor
  variants). An always-true matcher fires on every response, manufacturing a
  graded finding on a clean target. Caught at lint time.

- **Behavioral**: starts a hermetic stdlib `http.server` on `127.0.0.1` that
  serves a benign, clean HTML page (200, no secrets/base64/PII, no input
  reflection) and runs a representative set of webapp scanners (xxe, lfi,
  ssrf, idor, host_header_injection, secrets, security_headers,
  sensitive_data, sqli, xss, portscan) against it. ANY graded finding =
  a false positive = test fails. Only INFO/POSITIVE is allowed on a clean
  target. Skips cleanly when a scanner needs an unavailable binary or the
  loopback host can't be guaranteed clean (portscan).

Run: `python -m pytest tests/test_zero_fp.py -q`
(static only: `python -m pytest tests/test_zero_fp.py -k static -q`).
