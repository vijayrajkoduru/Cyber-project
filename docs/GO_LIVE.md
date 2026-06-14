# VulnusLab — Go-Live Runbook (switch on payments + email)

The payment/provisioning/email code is complete and verified (Razorpay HMAC
signature checks, server-side pricing, idempotent provisioning, provider-agnostic
mailer). Going live is **configuration + one end-to-end test** — no code changes.

All env vars go in the VPS `.env` (NOT the repo). After editing `.env`:
`docker compose up -d backend` (env reload).

Check readiness any time in the **Ops Console** system-health card:
`Payments: LIVE/not configured · Email: configured/not configured`.

---

## 1. Razorpay (payments)

1. Razorpay Dashboard -> Settings -> API Keys -> **Generate** (use **Test Mode** first).
2. Add to `.env`:
   ```
   RAZORPAY_KEY_ID=rzp_test_xxxxxxxx        # rzp_live_... when going live
   RAZORPAY_KEY_SECRET=xxxxxxxxxxxxxxxx
   RAZORPAY_WEBHOOK_SECRET=<your-chosen-webhook-secret>
   DASHBOARD_URL=https://app.vulnuslab.com
   ```
3. Dashboard -> Settings -> **Webhooks** -> Add:
   - URL: `https://app.vulnuslab.com/api/payment/webhook`
   - Secret: the **same** value as `RAZORPAY_WEBHOOK_SECRET`
   - Active events: **`payment.captured`** and **`order.paid`** (the code only acts on these)
4. `docker compose up -d backend`. Confirm: Ops Console shows **Payments: LIVE**, and
   `GET /api/payment/config` returns `"configured": true`.

Notes: amounts are computed server-side from `module_catalog.py` (the client total is
never trusted); currency is INR (paise). Razorpay retries the webhook until it gets a
2xx — provisioning is idempotent (a `payments` row keyed by `payment_id`), so retries
are safe.

## 2. Email (credentials + receipts)

Pick ONE provider and set it in `.env`:

ZeptoMail (good for India) or SendGrid:
```
EMAIL_PROVIDER=zeptomail            # or: sendgrid
EMAIL_API_KEY=<provider api key>
EMAIL_FROM=no-reply@vulnuslab.com
EMAIL_REPLY_TO=support@vulnuslab.com
```
Or plain SMTP:
```
EMAIL_PROVIDER=smtp
EMAIL_SMTP_HOST=smtp.yourhost.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USER=...
EMAIL_SMTP_PASS=...
EMAIL_FROM=no-reply@vulnuslab.com
EMAIL_REPLY_TO=support@vulnuslab.com
```
**Deliverability:** add SPF + DKIM DNS records for `vulnuslab.com` at your provider, or
the welcome/receipt emails will land in spam. `docker compose up -d backend`, then
confirm Ops Console shows **Email: configured**. (If unset, the backend just LOGS the
email instead of sending — paid accounts are still created.)

## 3. HTTPS (must be on before taking real payments)

Cloudflare -> SSL/TLS -> set to **Full (strict)** so Cloudflare<->origin is encrypted
(not "Flexible"). Enable **Always Use HTTPS** + **HSTS**. Confirm `https://app.vulnuslab.com`
and `https://vulnuslab.com` load over TLS with no mixed-content warnings.

## 4. Deploy the marketing/landing site

The landing site (`landing-page/`) has the checkout + `terms.html`/`privacy.html`.
Deploy it to `vulnuslab.com` and confirm: pricing -> pick module(s) -> Razorpay
checkout opens -> footer links to /terms and /privacy work.

## 5. End-to-end test (do this in Razorpay TEST mode first)

1. On the pricing page, select a module and check out with a Razorpay **test card**
   (e.g. `4111 1111 1111 1111`, any future expiry/CVV).
2. Confirm in order:
   - Razorpay shows the payment captured.
   - Backend log shows the webhook hit + `provision_module_purchase` (no errors).
   - A row appears in the `payments` table and a new user in `users`
     (Ops Console -> Customers, or:
     `docker compose exec backend python -c "import sqlite3;[print(r) for r in sqlite3.connect('/app/data/users.db').execute('select username,email,plan,modules,subscription_expires_at from users')]"`).
   - The welcome email (with the temp password) + receipt arrive.
   - Log in with that username + temp password; the purchased module is unlocked;
     a module you did NOT buy is still locked (the consent gate blocks it).
3. Re-deliver the same webhook from the Razorpay dashboard -> response should be
   `{"ok": true, "duplicate": true}` (idempotency holds, no second account/charge).
4. Switch `RAZORPAY_KEY_ID/SECRET` to the `rzp_live_...` keys, repeat one small **real**
   purchase, then refund it from the Razorpay dashboard.

## 6. Rollback / safety

- To pause sales instantly: blank `RAZORPAY_KEY_ID` in `.env` + `up -d backend` —
  `create-order` returns 503 and the webhook rejects everything. No data loss.
- The platform boots fine with payments/email unset (this is the default).
