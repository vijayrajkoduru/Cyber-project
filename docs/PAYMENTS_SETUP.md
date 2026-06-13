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

## 1. Set the prices
Edit `tools/_payments/plans.py` — the `PAYMENT_PLANS` amounts are **placeholders
in paise (INR × 100)**. Replace with your confirmed INR prices.

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

## 5. Link the checkout from pricing
Point each plan's CTA at `https://vulnuslab.com/checkout.html?plan=<id>`, e.g.
`?plan=pro_monthly`, `?plan=team_annual`. (For local/test you can append
`&api=http://localhost:8000`.)

## 6. Test (test mode, no KYC needed)
1. Set the `rzp_test_*` keys + webhook secret + email vars, rebuild backend.
2. Open `vulnuslab.com/checkout.html?plan=pro_monthly`, pay with a Razorpay
   test card (e.g. `4111 1111 1111 1111`).
3. Confirm: webhook fires → user created/upgraded with `plan=pro` + expiry →
   welcome + receipt email arrives.
4. Flip to `rzp_live_*` after KYC. No code change.
