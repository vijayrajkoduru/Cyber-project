# Payments + Transactional Email — Setup

The full flow is built and boots safely with **no keys** (create-order returns
503, the webhook rejects unsigned calls). To go live, set the env vars below on
the VPS `.env`, rebuild the backend, and register the webhook. No code change.

## What's built
| Piece | File |
|---|---|
| Plan catalogue (placeholder INR prices) | `tools/_payments/plans.py` |
| Razorpay REST + signature helpers | `tools/_payments/razorpay_client.py` |
| Transactional email (SendGrid / ZeptoMail / SMTP) | `tools/_payments/mailer.py` |
| Paid-user provisioning (idempotent) | `tools/_payments/provisioning.py` |
| Endpoints (config / create-order / webhook / verify) | `endpoints/payment.py` |
| Public checkout page | `landing-page/public/checkout.html` |

Plans map to the existing quota tiers in `tools/_quota.py` (`pro` = 500 scans/mo,
`team` = 5000). On a captured payment the user's `plan` + `subscription_expires_at`
are set; quota is already enforced by `tools/consent/consent_log.py`.

## Model: à la carte modules (monthly)
Customers subscribe to **individual modules** (monthly). On a captured payment
the account is set to `plan='modular'` with `subscription_expires_at = +30d` and
the purchased module ids unioned into `users.modules` (CSV). A free 7-day Trial
unlocks everything; after that, access is gated to the modules they bought.
Entitlement rules live in `tools/_payments/entitlements.py`.

> Phase status: purchase + provisioning + module-select checkout are **done**.
> Access-gating (lock unowned modules in the dashboard + enforce on the server)
> and the demo/video section are the next phases.

## 1. Set the prices
**Primary — per-module:** edit `tools/_payments/module_catalog.py` →
`MODULE_CATALOG` amounts are **placeholder monthly prices in paise (INR × 100)**.
Replace with your confirmed prices. The module ids must match the backend
`tools/<id>/` dir + the frontend catalog id.

**Legacy (optional) — plans:** `tools/_payments/plans.py` still supports
single-plan purchases if you ever want bundles.

## 2. Env vars (VPS `.env`)
```
# Razorpay
RAZORPAY_KEY_ID=rzp_test_xxx          # rzp_live_xxx for production
RAZORPAY_KEY_SECRET=xxx
RAZORPAY_WEBHOOK_SECRET=xxx           # the string you set on the webhook

# Email (pick ONE provider)
EMAIL_PROVIDER=zeptomail              # zeptomail | sendgrid | smtp
EMAIL_API_KEY=xxx                     # zeptomail/sendgrid
EMAIL_FROM=no-reply@vulnuslab.com
EMAIL_REPLY_TO=support@vulnuslab.com
# (SMTP only) EMAIL_SMTP_HOST / EMAIL_SMTP_PORT / EMAIL_SMTP_USER / EMAIL_SMTP_PASS

DASHBOARD_URL=https://app.vulnuslab.com
```

## 3. CORS (checkout page is cross-origin)
The checkout page lives on `vulnuslab.com` but calls the API on
`app.vulnuslab.com`. Add the landing origin to `CORS_ORIGINS` in `.env`:
```
CORS_ORIGINS=https://app.vulnuslab.com,https://vulnuslab.com,https://www.vulnuslab.com
```

## 4. Register the webhook in Razorpay
- URL: `https://app.vulnuslab.com/api/payment/webhook`
- Events: `payment.captured` and `order.paid`
- Secret: same value as `RAZORPAY_WEBHOOK_SECRET`

## 5. The checkout page
`checkout.html` is a **module multi-select** — it loads the catalogue from
`/api/payment/config`, the customer ticks modules, the live total updates, and
the amount is **recomputed server-side** at create-order (the client total is
never trusted). Link it as `https://vulnuslab.com/checkout.html` (optionally
pre-select with `?modules=recon,vuln`). For local test: `&api=http://localhost:8000`.

## 6. Test (test mode, no KYC needed)
1. Set the `rzp_test_*` keys + webhook secret + email vars, rebuild backend.
2. Open `vulnuslab.com/checkout.html?plan=pro_monthly`, pay with a Razorpay
   test card (e.g. `4111 1111 1111 1111`).
3. Confirm: webhook fires → user created/upgraded with `plan=pro` + expiry →
   welcome + receipt email arrives.
4. Flip to `rzp_live_*` after KYC. No code change.
