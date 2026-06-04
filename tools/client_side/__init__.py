"""client_side module - Modern frontend security probes
(per module_playbooks/09_client_side.md).

7 sections / 72 techniques across BeEF hooks, document macros, HTA,
LNK, browser-side exploits, social-engineering payload delivery, and
the 2024+ modern-browser surface (Manifest v3, Service Workers,
WebUSB, etc.).

This starter goes deeper than the basic Webapp module's reflected-XSS
checks. It exercises DOM-only attack surface that only renders client-
side: CSP bypass classes, DOM-XSS source-to-sink data flow, postMessage
origin-skip abuse, prototype pollution, and CORS preflight reflection.

Customer input via ScanRequest:
  - target               = website URL (http(s)://...)
  - options              = optional dict (per-probe overrides)

Backend dependencies (image-installed):
  - httpx, beautifulsoup4, playwright (chromium browser bundled
    separately via `playwright install chromium`)

All probes degrade gracefully on missing browser / missing library /
unreachable target (return INFO with install hint instead of crashing).
"""
