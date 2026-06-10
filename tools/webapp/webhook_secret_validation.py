"""webhook_secret_validation — webhook endpoint accepts requests without HMAC sig.

Webhook receivers (GitHub, Stripe, Slack, Twilio) require HMAC signature
verification using a shared secret. Bug: receiver doesn't check the
X-Hub-Signature / X-Stripe-Signature / etc. header → attacker forges
events (fake-paid invoices, fake commit pushes, etc.).

Test: POST a benign payload to common webhook paths WITHOUT sig header,
flag if 200/201 accepted.
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

WEBHOOK_PATHS = [
    "/webhook", "/webhooks", "/api/webhook", "/api/webhooks",
    "/hooks/github", "/hooks/stripe", "/hooks/slack",
    "/api/v1/webhooks", "/webhooks/incoming",
    "/api/integrations/webhook",
    "/.well-known/webhooks",
]

# Distinctive payloads per provider
PAYLOADS = {
    "github":  {"action": "opened", "pull_request": {"id": 999, "title": "vulnuslab-test"}},
    "stripe":  {"id": "evt_vulnuslab", "object": "event",
                "type": "invoice.payment_succeeded",
                "data": {"object": {"amount_paid": 100000}}},
    "slack":   {"type": "event_callback", "event": {"type": "message", "text": "test"}},
    "generic": {"id": "vulnuslab-test", "event": "test"},
}


@router.post("/api/webapp/scan/webhook_secret_validation")
@vl_turbo()
@vl_verify()
def scan_webhook_secret_validation(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    discovered = []
    accepted_unsigned = []

    for path in WEBHOOK_PATHS:
        url = base + path
        # Try GET first to see if endpoint exists
        r0 = safe_request("GET", url,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=6, allow_redirects=False)
        if r0 is None or r0.status_code == 404: continue
        discovered.append(path)

        # POST unsigned payload — try each provider shape
        for prov, body in PAYLOADS.items():
            r = safe_request("POST", url,
                headers={"Content-Type": "application/json",
                          "User-Agent": "VulnusLab/1.0",
                          # NO signature header on purpose
                          "X-GitHub-Event": "pull_request" if prov == "github" else ""},
                data=json.dumps(body), req=req, timeout=8, allow_redirects=False)
            if r is None: continue
            # Success indicator: 200/201/202/204 without explicit "invalid signature" error
            if r.status_code in (200, 201, 202, 204):
                body_resp = (r.text or "")[:1000].lower()
                if not any(k in body_resp for k in ("invalid signature", "missing signature",
                                                      "sig", "unauthorized", "x-hub-signature")):
                    accepted_unsigned.append({"path": path, "provider": prov,
                                                "status": r.status_code})
                    break  # one per path

    findings = []
    if accepted_unsigned:
        findings.append(wrap_finding(
            f"Webhook accepts UNSIGNED payload at {len(accepted_unsigned)} endpoint(s)",
            "HIGH", cvss="7.5", cwe="CWE-345", owasp="A04:2021",
            remediation="Verify HMAC signature on every webhook request. "
                        "GitHub: X-Hub-Signature-256 (HMAC-SHA256 of body with "
                        "webhook secret). Stripe: Stripe-Signature with timestamp + "
                        "signature. Slack: X-Slack-Signature with v0=... prefix. "
                        "REJECT requests without valid signature with 401. Without "
                        "this, attacker forges fake-paid invoices, fake commit "
                        "pushes, etc.",
            evidence_marker=" | ".join(
                f"{a['path']}: {a['provider']} payload → HTTP {a['status']}"
                for a in accepted_unsigned[:3]
            )))
    elif discovered:
        findings.append(wrap_finding(
            f"Webhook endpoint(s) ({len(discovered)}) reject unsigned payload",
            "POSITIVE", cwe="CWE-345",
            remediation="Maintain HMAC validation. Rotate webhook secrets periodically.",
            evidence_marker=f"discovered: {discovered[:5]}; all reject unsigned"))
    else:
        return standard_response(
            tool="webhook_secret_validation", target=req.target,
            findings=[wrap_finding(
                "No webhook endpoints detected at common paths",
                "POSITIVE", cwe="CWE-345",
                remediation="No webhook surface from this scan.",
                evidence_marker=f"checked {len(WEBHOOK_PATHS)} paths")],
            tests_performed=len(WEBHOOK_PATHS), vulnerable=False,
            tests_summary="No webhooks")

    return standard_response(
        tool="webhook_secret_validation", target=req.target, findings=findings,
        tests_performed=len(WEBHOOK_PATHS) * (1 + len(PAYLOADS)),
        vulnerable=bool(accepted_unsigned),
        tests_summary=f"{len(discovered)} webhook paths, {len(accepted_unsigned)} accept unsigned",
        raw_data={"discovered": discovered, "accepted_unsigned": accepted_unsigned})


def register(app):
    app.include_router(router)
