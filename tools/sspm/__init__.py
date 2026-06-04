"""sspm module — SaaS Security Posture Management (playbook 29_sspm.md).

8 sections, 88 techniques. This package autoloads tier* subdirectories,
each containing real Python probes that query the customer's SaaS tenants
over their official admin APIs (Microsoft Graph, Google Admin SDK,
Salesforce REST, Slack web API, GitHub REST).

All probes are READ-ONLY (no config write, no user create/delete, no
revocation). Customer-supplied API tokens / OAuth bearers / service-account
JSONs are consumed via ScanRequest.options and never logged.

Customer input via ScanRequest:
  - target          = label for the SaaS tenant (e.g. "acme.onmicrosoft.com")
  - options         = per-probe credential dict (see each probe docstring)

Backend dependencies (image-installed):
  - msal, httpx, requests
Optional (auto-installed on first use if missing):
  - google-api-python-client (only for gworkspace_admin_audit)

Concurrency = 3. SaaS admin APIs throttle aggressively; staying low keeps
the probes well under each provider's per-tenant per-minute envelope.
"""
