"""secrets_patterns — handcrafted dev-time. Webapp module asset.

Regex patterns for detecting leaked secrets in HTTP responses (HTML/JS/JSON).
Used by tools/webapp/secrets.py. Sources: gitleaks, trufflehog, custom curation.

Each entry: {name, regex, service, severity, cvss, remediation, [class]}.
Regex is Python-style; use re.IGNORECASE when matching.

ZERO-FP gating (read tools/webapp/secrets.py for the enforcement):
  - "class": "vendor"  (DEFAULT when key is absent) — precise prefix-anchored
    shapes (AWS AKIA, Slack xox*, Google AIza*, Stripe sk_live_, GitHub ghp_,
    private-key PEM headers, etc.). Graded as written, but the scanner still
    runs a light shape sanity-check before grading.
  - "class": "generic" — loose / high-entropy / proximity-keyword patterns that
    are KNOWN to collide with normal minified JS bundles (webpack chunk hashes,
    base64 fragments, SRI integrity hashes, source-map refs, long hex consts).
    The scanner ONLY grades these when the captured candidate clears a Shannon
    entropy floor AND survives the allowlist below; otherwise -> INFO, never
    HIGH/CRITICAL. This is what stopped the 8 fake "Cohere API Key" hits on
    Juice Shop's main.js.

Helpers exported for the scanner: SECRET_ALLOWLIST_PATTERNS, GENERIC_MIN_ENTROPY,
shannon_entropy(), looks_like_false_match().
"""
import math
import re as _re

SECRETS_PATTERNS = [
    # ── AWS ─────────────────────────────────────────────────────────────────
    {"name": "AWS Access Key ID", "regex": r"AKIA[0-9A-Z]{16}", "service": "aws",
     "severity": "CRITICAL", "cvss": "9.8",
     "remediation": "Rotate the AWS key immediately at IAM console. Audit CloudTrail for misuse."},
    {"name": "AWS Secret Access Key", "regex": r"(?i)aws_?secret_?access_?key[\"'\s:=]{1,5}[A-Za-z0-9/+=]{40}", "service": "aws",
     "class": "generic", "severity": "CRITICAL", "cvss": "9.8",
     "remediation": "Rotate immediately. Never commit secrets to source. Use IAM roles or AWS Secrets Manager."},
    {"name": "AWS Session Token", "regex": r"FQoG[A-Za-z0-9/+=]{100,}", "service": "aws",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Session tokens expire — but rotate IAM key that issued it."},
    {"name": "AWS MWS Auth Token", "regex": r"amzn\.mws\.[0-9a-f-]{36}", "service": "aws",
     "severity": "HIGH", "cvss": "7.5", "remediation": "Rotate MWS token via Seller Central."},

    # ── Google Cloud ────────────────────────────────────────────────────────
    {"name": "Google API Key", "regex": r"AIza[0-9A-Za-z\-_]{35}", "service": "gcp",
     "severity": "HIGH", "cvss": "7.5",
     "remediation": "Restrict via API key restrictions (HTTP referrer or API). Rotate at GCP console."},
    {"name": "Google OAuth Access Token", "regex": r"ya29\.[0-9A-Za-z\-_]{50,}", "service": "gcp",
     "severity": "HIGH", "cvss": "7.5", "remediation": "OAuth tokens expire ~1h. Revoke if not naturally expired."},
    {"name": "Google OAuth Refresh Token", "regex": r"1//[0-9A-Za-z\-_]{40,}", "service": "gcp",
     "severity": "CRITICAL", "cvss": "9.0", "remediation": "Revoke at https://myaccount.google.com/permissions immediately."},
    {"name": "Google Service Account JSON", "regex": r"\"type\":\s*\"service_account\".{0,500}private_key", "service": "gcp",
     "severity": "CRITICAL", "cvss": "9.8", "remediation": "Delete the service-account key in GCP IAM, rotate. Audit usage."},
    {"name": "Firebase API Key", "regex": r"AIzaSy[A-Za-z0-9_\-]{33}", "service": "firebase",
     "severity": "MEDIUM", "cvss": "5.3", "remediation": "Firebase keys are designed to be public, but restrict by domain/bundle ID."},

    # ── Azure ───────────────────────────────────────────────────────────────
    {"name": "Azure Storage Account Key", "regex": r"DefaultEndpointsProtocol=https;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9/+=]{86,}==", "service": "azure",
     "severity": "CRITICAL", "cvss": "9.8", "remediation": "Rotate the storage account access key in Azure portal."},
    {"name": "Azure SAS Token", "regex": r"sv=\d{4}-\d{2}-\d{2}&[^&]*sig=[A-Za-z0-9%]{40,}", "service": "azure",
     "severity": "HIGH", "cvss": "7.5", "remediation": "Regenerate SAS with shorter expiry. Use signed identifier when possible."},
    {"name": "Azure Connection String", "regex": r"Endpoint=sb://[^;]+;SharedAccessKey=[A-Za-z0-9/+=]+", "service": "azure",
     "severity": "CRITICAL", "cvss": "9.1", "remediation": "Rotate SharedAccessKey in Service Bus / Event Hubs."},
    {"name": "Azure AD Client Secret", "regex": r"(?i)client_secret[\"'\s:=]{1,5}[A-Za-z0-9~._\-]{34,40}", "service": "azure",
     "class": "generic", "severity": "CRITICAL", "cvss": "9.8", "remediation": "Rotate in App Registrations → Certificates & Secrets."},

    # ── GitHub / GitLab / Bitbucket ─────────────────────────────────────────
    {"name": "GitHub Personal Access Token (classic)", "regex": r"ghp_[A-Za-z0-9]{36}", "service": "github",
     "severity": "CRITICAL", "cvss": "9.8", "remediation": "Revoke at github.com/settings/tokens immediately."},
    {"name": "GitHub Fine-grained PAT", "regex": r"github_pat_[A-Za-z0-9_]{82}", "service": "github",
     "severity": "CRITICAL", "cvss": "9.8", "remediation": "Revoke and regenerate at github.com/settings/tokens?type=beta."},
    {"name": "GitHub OAuth Token", "regex": r"gho_[A-Za-z0-9]{36}", "service": "github",
     "severity": "CRITICAL", "cvss": "9.1", "remediation": "Revoke OAuth app in github.com/settings/applications."},
    {"name": "GitHub App Installation Token", "regex": r"ghs_[A-Za-z0-9]{36}", "service": "github",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Tokens expire ~1h, but rotate the App's private key."},
    {"name": "GitHub Refresh Token", "regex": r"ghr_[A-Za-z0-9]{76}", "service": "github",
     "severity": "CRITICAL", "cvss": "9.0", "remediation": "Revoke via OAuth app settings."},
    {"name": "GitLab Personal Access Token", "regex": r"glpat-[A-Za-z0-9_\-]{20}", "service": "gitlab",
     "severity": "CRITICAL", "cvss": "9.8", "remediation": "Revoke at gitlab.com/-/user_settings/personal_access_tokens."},
    {"name": "GitLab Pipeline Trigger Token", "regex": r"glptt-[A-Za-z0-9]{40}", "service": "gitlab",
     "severity": "HIGH", "cvss": "7.5", "remediation": "Revoke trigger token in CI/CD settings."},
    {"name": "GitLab Runner Token", "regex": r"GR1348941[A-Za-z0-9_\-]{20}", "service": "gitlab",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Reset runner registration token."},
    {"name": "Bitbucket App Password", "regex": r"ATBB[A-Za-z0-9]{16,}", "service": "bitbucket",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke at bitbucket.org/account/settings/app-passwords."},

    # ── Slack / Discord / Telegram ──────────────────────────────────────────
    {"name": "Slack Bot Token", "regex": r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}", "service": "slack",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Regenerate at api.slack.com/apps → OAuth & Permissions."},
    {"name": "Slack User Token", "regex": r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{32}", "service": "slack",
     "severity": "CRITICAL", "cvss": "9.0", "remediation": "Revoke immediately — user tokens have full workspace access."},
    {"name": "Slack Workflow Token", "regex": r"xoxa-[0-9]{2}-[0-9]{10,}-[A-Za-z0-9]{16,}", "service": "slack",
     "severity": "HIGH", "cvss": "7.5", "remediation": "Revoke workflow integration."},
    {"name": "Slack Webhook URL", "regex": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}", "service": "slack",
     "severity": "MEDIUM", "cvss": "5.3", "remediation": "Rotate webhook URL — anyone can post messages with it."},
    {"name": "Discord Bot Token", "regex": r"[MN][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}", "service": "discord",
     "severity": "CRITICAL", "cvss": "9.8", "remediation": "Reset at discord.com/developers/applications → Bot."},
    {"name": "Discord Webhook", "regex": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,}/[A-Za-z0-9_\-]{60,}", "service": "discord",
     "severity": "MEDIUM", "cvss": "5.3", "remediation": "Delete webhook in channel settings."},
    {"name": "Telegram Bot Token", "regex": r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}", "service": "telegram",
     "severity": "HIGH", "cvss": "7.5", "remediation": "Revoke via @BotFather /revoke command."},

    # ── Payment processors ──────────────────────────────────────────────────
    {"name": "Stripe Secret Key (live)", "regex": r"sk_live_[0-9A-Za-z]{24,99}", "service": "stripe",
     "severity": "CRITICAL", "cvss": "9.8", "remediation": "Rotate IMMEDIATELY at dashboard.stripe.com/apikeys."},
    {"name": "Stripe Secret Key (test)", "regex": r"sk_test_[0-9A-Za-z]{24,99}", "service": "stripe",
     "severity": "MEDIUM", "cvss": "5.3", "remediation": "Test keys can't move funds but still rotate."},
    {"name": "Stripe Restricted Key", "regex": r"rk_live_[0-9A-Za-z]{24,99}", "service": "stripe",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Rotate at dashboard.stripe.com/apikeys."},
    {"name": "Stripe Publishable Key", "regex": r"pk_live_[0-9A-Za-z]{24,99}", "service": "stripe",
     "severity": "LOW", "cvss": "2.0", "remediation": "Publishable keys are safe in client-side code by design."},
    {"name": "PayPal Braintree Access Token", "regex": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "service": "paypal",
     "severity": "CRITICAL", "cvss": "9.8", "remediation": "Rotate in Braintree control panel."},
    {"name": "Square Access Token", "regex": r"sq0atp-[0-9A-Za-z\-_]{22}", "service": "square",
     "severity": "CRITICAL", "cvss": "9.8", "remediation": "Revoke at squareup.com/developers/apps."},
    {"name": "Razorpay Key ID", "regex": r"rzp_(?:live|test)_[A-Za-z0-9]{14,}", "service": "razorpay",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Rotate at dashboard.razorpay.com → Settings → API Keys."},
    {"name": "PayU Merchant Key", "regex": r"(?i)payu_?merchant_?key[\"'\s:=]{1,5}[A-Za-z0-9]{6,12}", "service": "payu",
     "class": "generic", "severity": "HIGH", "cvss": "7.5", "remediation": "Rotate at info.payu.in merchant dashboard."},

    # ── Communication APIs ──────────────────────────────────────────────────
    {"name": "Twilio Account SID", "regex": r"AC[0-9a-fA-F]{32}", "service": "twilio",
     "class": "generic", "severity": "MEDIUM", "cvss": "5.3", "remediation": "SID alone is non-credential, but pair with Auth Token = full control."},
    {"name": "Twilio Auth Token", "regex": r"SK[0-9a-fA-F]{32}", "service": "twilio",
     "class": "generic", "severity": "CRITICAL", "cvss": "9.1", "remediation": "Rotate at console.twilio.com → Account → API keys."},
    {"name": "SendGrid API Key", "regex": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "service": "sendgrid",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke at app.sendgrid.com/settings/api_keys."},
    {"name": "Mailgun API Key", "regex": r"key-[0-9a-f]{32}", "service": "mailgun",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Rotate at app.mailgun.com → Sending → Domain settings."},
    {"name": "Mailgun Domain Sending Key", "regex": r"(?i)mailgun.{0,15}[\"'][A-Za-z0-9]{40,80}[\"']", "service": "mailgun",
     "class": "generic", "severity": "HIGH", "cvss": "8.1", "remediation": "Rotate domain sending key."},
    {"name": "Postmark Server Token", "regex": r"(?i)postmark.{0,15}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "service": "postmark",
     "class": "generic", "severity": "HIGH", "cvss": "7.5", "remediation": "Regenerate server token in Postmark account."},

    # ── JWT ─────────────────────────────────────────────────────────────────
    {"name": "JWT (HS/RS signed token)", "regex": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}", "service": "jwt",
     "class": "generic", "severity": "MEDIUM", "cvss": "5.5",
     "remediation": "JWT in HTML/JS source = client-side leak. Move to HttpOnly cookie. Audit if it's a high-privilege token."},

    # ── Generic API key shape ───────────────────────────────────────────────
    {"name": "Bearer token in source", "regex": r"(?i)bearer\s+[A-Za-z0-9_\-\.]{30,200}", "service": "generic",
     "class": "generic", "severity": "HIGH", "cvss": "7.0", "remediation": "Never embed Bearer tokens in HTML/JS. Use HttpOnly cookies."},
    {"name": "Generic API key param", "regex": r"(?i)(?:api[_\-]?key|apikey|access[_\-]?token)[\"'\s:=]{1,5}[A-Za-z0-9_\-]{16,80}", "service": "generic",
     "class": "generic", "severity": "MEDIUM", "cvss": "6.5", "remediation": "Audit context. Move secrets to environment variables / vault."},
    {"name": "Authorization header literal", "regex": r"(?i)authorization[\"'\s:=]{1,5}[\"']?(?:Basic|Bearer|Token)\s+[A-Za-z0-9_\-/.+=]{16,}", "service": "generic",
     "class": "generic", "severity": "HIGH", "cvss": "7.5", "remediation": "Don't ship Authorization headers in HTML/JS."},
    {"name": "x-api-key header", "regex": r"(?i)x-api-key[\"'\s:=]{1,5}[\"']?[A-Za-z0-9_\-]{16,}", "service": "generic",
     "class": "generic", "severity": "MEDIUM", "cvss": "6.0", "remediation": "Audit value source. Avoid hardcoding."},

    # ── Private keys ────────────────────────────────────────────────────────
    {"name": "RSA Private Key", "regex": r"-----BEGIN RSA PRIVATE KEY-----", "service": "private_key",
     "severity": "CRITICAL", "cvss": "10.0", "remediation": "Rotate key pair IMMEDIATELY. Assume compromise of all signed data."},
    {"name": "DSA Private Key", "regex": r"-----BEGIN DSA PRIVATE KEY-----", "service": "private_key",
     "severity": "CRITICAL", "cvss": "9.8", "remediation": "Generate new keypair and rotate everywhere."},
    {"name": "EC Private Key", "regex": r"-----BEGIN EC PRIVATE KEY-----", "service": "private_key",
     "severity": "CRITICAL", "cvss": "10.0", "remediation": "Rotate keypair. Re-sign all certs/tokens."},
    {"name": "OpenSSH Private Key", "regex": r"-----BEGIN OPENSSH PRIVATE KEY-----", "service": "private_key",
     "severity": "CRITICAL", "cvss": "10.0", "remediation": "Rotate. Remove key from authorized_keys everywhere."},
    {"name": "PGP Private Key", "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "service": "private_key",
     "severity": "CRITICAL", "cvss": "10.0", "remediation": "Revoke via PGP keyserver. Generate new keypair."},
    {"name": "Generic Private Key Block", "regex": r"-----BEGIN (?:ENCRYPTED |EC |RSA |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----", "service": "private_key",
     "severity": "CRITICAL", "cvss": "10.0", "remediation": "Rotate this key immediately."},

    # ── Database connection strings ─────────────────────────────────────────
    {"name": "MongoDB Connection URI", "regex": r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+", "service": "mongodb",
     "severity": "CRITICAL", "cvss": "9.1", "remediation": "Rotate password. Use MongoDB Atlas IP allow-list."},
    {"name": "PostgreSQL Connection URI", "regex": r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+", "service": "postgres",
     "severity": "CRITICAL", "cvss": "9.1", "remediation": "Rotate password. Use SSL-only + IP allow-list."},
    {"name": "MySQL Connection URI", "regex": r"mysql://[^:\s]+:[^@\s]+@[^/\s]+", "service": "mysql",
     "severity": "CRITICAL", "cvss": "9.1", "remediation": "Rotate password. Bind MySQL to internal IP."},
    {"name": "Redis Connection URI", "regex": r"redis://(?:[^:\s]+:)?[^@\s]+@[^/\s]+", "service": "redis",
     "severity": "HIGH", "cvss": "8.5", "remediation": "Rotate Redis AUTH password. Bind to localhost or VPN."},
    {"name": "AMQP Connection URI", "regex": r"amqps?://[^:\s]+:[^@\s]+@[^/\s]+", "service": "rabbitmq",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Rotate RabbitMQ user password."},

    # ── Crypto wallets ──────────────────────────────────────────────────────
    {"name": "BIP39 Mnemonic (12-24 words)", "regex": r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b", "service": "crypto",
     "class": "generic", "severity": "CRITICAL", "cvss": "10.0", "remediation": "Move funds to new wallet IMMEDIATELY. Mnemonic = root key for all derived addresses."},
    {"name": "Ethereum Private Key", "regex": r"\b0x[0-9a-fA-F]{64}\b", "service": "crypto",
     "class": "generic", "severity": "HIGH", "cvss": "8.0", "remediation": "If this is a private key (not a tx hash), transfer balance to new address."},

    # ── AI provider keys ────────────────────────────────────────────────────
    {"name": "OpenAI API Key", "regex": r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", "service": "openai",
     "severity": "HIGH", "cvss": "7.5", "remediation": "Revoke at platform.openai.com/api-keys."},
    {"name": "OpenAI Project Key", "regex": r"sk-proj-[A-Za-z0-9_\-]{50,}", "service": "openai",
     "severity": "HIGH", "cvss": "7.5", "remediation": "Revoke project-scoped key in OpenAI dashboard."},
    {"name": "Anthropic API Key", "regex": r"sk-ant-api03-[A-Za-z0-9_\-]{90,}", "service": "anthropic",
     "severity": "HIGH", "cvss": "7.5", "remediation": "Revoke at console.anthropic.com/settings/keys."},
    {"name": "Hugging Face Token", "regex": r"hf_[A-Za-z0-9]{34}", "service": "huggingface",
     "severity": "MEDIUM", "cvss": "5.3", "remediation": "Revoke at huggingface.co/settings/tokens."},
    # Cohere keys are bare 40-char alnum — that shape matches webpack chunk
    # hashes / base64 fragments in every minified bundle, so REQUIRE a real
    # `cohere`-adjacent context token (assignment to a cohere-named var/key)
    # before we will even consider it. Classified generic -> capped at INFO.
    {"name": "Cohere API Key", "regex": r"(?i)cohere[\"'\s_\-]{0,15}(?:api[_\-]?key|token|key)?[\"'\s:=]{1,5}[\"']?[A-Za-z0-9]{40}[\"']?", "service": "cohere",
     "class": "generic", "severity": "MEDIUM", "cvss": "5.3", "remediation": "Cohere keys are 40-char alnum; verify context. Rotate if confirmed."},
    {"name": "Replicate API Token", "regex": r"r8_[A-Za-z0-9]{32,40}", "service": "replicate",
     "severity": "MEDIUM", "cvss": "5.3", "remediation": "Revoke at replicate.com/account/api-tokens."},

    # ── CDN / hosting ───────────────────────────────────────────────────────
    {"name": "Cloudflare API Token", "regex": r"(?i)cloudflare.{0,15}[\"']?[A-Za-z0-9_-]{40}[\"']?", "service": "cloudflare",
     "class": "generic", "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke at dash.cloudflare.com/profile/api-tokens."},
    {"name": "Cloudflare Global API Key", "regex": r"(?i)cf-api-key[\"'\s:=]{1,5}[0-9a-f]{37}", "service": "cloudflare",
     "severity": "CRITICAL", "cvss": "9.8", "remediation": "Global API keys are deprecated. Roll to scoped API tokens immediately."},
    {"name": "Heroku API Key", "regex": r"(?i)heroku.{0,15}[\"']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\"']?", "service": "heroku",
     "class": "generic", "severity": "HIGH", "cvss": "8.1", "remediation": "Regenerate at dashboard.heroku.com/account → API Key."},
    {"name": "Vercel API Token", "regex": r"(?i)vercel.{0,15}[\"']?[A-Za-z0-9]{24}[\"']?", "service": "vercel",
     "class": "generic", "severity": "HIGH", "cvss": "8.1", "remediation": "Delete at vercel.com/account/tokens."},
    {"name": "Netlify API Token", "regex": r"(?i)netlify.{0,15}[\"']?[A-Za-z0-9_-]{30,}[\"']?", "service": "netlify",
     "class": "generic", "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke at app.netlify.com/user/applications."},
    {"name": "Fastly API Token", "regex": r"(?i)fastly.{0,15}[\"']?[A-Za-z0-9_-]{32}[\"']?", "service": "fastly",
     "class": "generic", "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke at manage.fastly.com/account/personal/tokens."},

    # ── High-entropy generic catches ────────────────────────────────────────
    {"name": "Generic JWT-format token (not validated)", "regex": r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "service": "jwt",
     "class": "generic", "severity": "MEDIUM", "cvss": "5.3", "remediation": "Inspect token content. Move sensitive tokens out of HTML/JS."},
    {"name": "High-entropy base64 string (64+ chars)", "regex": r"[A-Za-z0-9+/]{64,}={0,2}", "service": "generic",
     "class": "generic", "severity": "LOW", "cvss": "3.1", "remediation": "Audit context — could be cert chain, but may also be secret material."},
    {"name": "High-entropy hex string (128+ chars)", "regex": r"\b[0-9a-fA-F]{128,}\b", "service": "generic",
     "class": "generic", "severity": "LOW", "cvss": "3.1", "remediation": "Audit context — could be a session key or private key material."},
    {"name": "Base64 with secret-like prefix", "regex": r"(?i)(?:secret|password|token|key)[\"'\s:=]{1,5}[\"']?[A-Za-z0-9+/]{20,}={0,2}[\"']?", "service": "generic",
     "class": "generic", "severity": "HIGH", "cvss": "7.5", "remediation": "Treat as compromised. Rotate."},

    # ── Misc dev infra ──────────────────────────────────────────────────────
    {"name": "NPM Token", "regex": r"npm_[A-Za-z0-9]{36}", "service": "npm",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke at npmjs.com/settings/<user>/tokens."},
    {"name": "PyPI Token", "regex": r"pypi-[A-Za-z0-9_\-]{60,}", "service": "pypi",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke at pypi.org/manage/account/token/."},
    {"name": "Docker Hub Personal Access Token", "regex": r"dckr_pat_[A-Za-z0-9_\-]{27}", "service": "dockerhub",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke at hub.docker.com/settings/security."},
    {"name": "Sentry Auth Token", "regex": r"(?i)sentry.{0,15}[\"']?[a-f0-9]{64}[\"']?", "service": "sentry",
     "class": "generic", "severity": "MEDIUM", "cvss": "6.5", "remediation": "Revoke at sentry.io/settings/account/api/auth-tokens/."},
    {"name": "Datadog API Key", "regex": r"(?i)datadog.{0,15}[\"']?[a-f0-9]{32}[\"']?", "service": "datadog",
     "class": "generic", "severity": "HIGH", "cvss": "7.5", "remediation": "Revoke at app.datadoghq.com/organization-settings/api-keys."},
    {"name": "New Relic License Key", "regex": r"(?i)new[_\-]?relic.{0,15}[\"']?[a-f0-9]{40}[\"']?", "service": "newrelic",
     "class": "generic", "severity": "HIGH", "cvss": "7.5", "remediation": "Rotate at one.newrelic.com → Account settings → API keys."},
    {"name": "Pusher Channel App Key", "regex": r"(?i)pusher.{0,15}[\"']?[a-z0-9]{16,32}[\"']?", "service": "pusher",
     "class": "generic", "severity": "MEDIUM", "cvss": "5.3", "remediation": "Rotate at dashboard.pusher.com → Apps → Settings."},
    {"name": "Shopify Access Token", "regex": r"shpat_[a-fA-F0-9]{32}", "service": "shopify",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke in Shopify admin → Apps → Develop apps."},
    {"name": "Shopify Shared Secret", "regex": r"shpss_[a-fA-F0-9]{32}", "service": "shopify",
     "severity": "HIGH", "cvss": "7.5", "remediation": "Rotate shared secret in app settings."},
    {"name": "Asana Token", "regex": r"(?i)asana.{0,15}[\"']?\d/\d{16}/[a-f0-9]{32}[\"']?", "service": "asana",
     "class": "generic", "severity": "MEDIUM", "cvss": "5.3", "remediation": "Revoke at app.asana.com/0/my-apps."},
    {"name": "Atlassian / Jira API Token", "regex": r"ATATT3[A-Za-z0-9_\-]{180,}", "service": "atlassian",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke at id.atlassian.com/manage-profile/security/api-tokens."},
    {"name": "Linear API Key", "regex": r"lin_api_[A-Za-z0-9]{40}", "service": "linear",
     "severity": "HIGH", "cvss": "7.5", "remediation": "Revoke at linear.app/settings/api."},
    {"name": "Notion API Token", "regex": r"secret_[A-Za-z0-9]{43}", "service": "notion",
     "severity": "HIGH", "cvss": "7.5", "remediation": "Revoke integration at notion.so/my-integrations."},
    {"name": "Zoom API Token", "regex": r"(?i)zoom.{0,15}[\"']?eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}[\"']?", "service": "zoom",
     "class": "generic", "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke at marketplace.zoom.us."},
    {"name": "DigitalOcean Personal Access Token", "regex": r"dop_v1_[a-f0-9]{64}", "service": "digitalocean",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke at cloud.digitalocean.com/account/api/tokens."},
    {"name": "DigitalOcean OAuth", "regex": r"doo_v1_[a-f0-9]{64}", "service": "digitalocean",
     "severity": "HIGH", "cvss": "8.1", "remediation": "Revoke OAuth app authorization."},

    # ── Indian fintech (regional moat) ──────────────────────────────────────
    {"name": "PhonePe Merchant Key", "regex": r"(?i)phonepe.{0,15}[\"']?[A-Za-z0-9_\-]{20,}[\"']?", "service": "phonepe",
     "class": "generic", "severity": "HIGH", "cvss": "8.1", "remediation": "Rotate merchant key in PhonePe Business Portal."},
    {"name": "Paytm Merchant Key", "regex": r"(?i)paytm.{0,15}[\"']?[A-Za-z0-9!@#$&]{16}[\"']?", "service": "paytm",
     "class": "generic", "severity": "HIGH", "cvss": "8.1", "remediation": "Rotate at business.paytm.com → Developer Settings."},
    {"name": "Cashfree App ID", "regex": r"(?i)cashfree.{0,15}[\"']?[A-Za-z0-9]{16,32}[\"']?", "service": "cashfree",
     "class": "generic", "severity": "MEDIUM", "cvss": "6.5", "remediation": "Rotate at merchant.cashfree.com → Developers → Keys."},
    {"name": "Instamojo API Key", "regex": r"(?i)instamojo.{0,15}[\"']?[A-Za-z0-9]{40,}[\"']?", "service": "instamojo",
     "class": "generic", "severity": "HIGH", "cvss": "7.5", "remediation": "Rotate at imjo.in/integrations/api/keys."},

    # ── End — pattern catalog is intentionally over-inclusive for high recall ─
]


# ── Zero-FP support for generic / high-entropy matches ──────────────────────
#
# Minimum Shannon entropy (bits/char) a *generic-class* candidate must clear
# before it is even eligible to be graded. Random secret material on a 62-char
# alphabet sits around ~5.5–6.0 bits/char; a webpack chunk hash or a repetitive
# minified token is much lower. 3.6 is a deliberately conservative floor: it
# kills low-entropy filler without dropping genuinely random key material.
GENERIC_MIN_ENTROPY = 3.6

# Regexes for strings that LOOK like high-entropy secrets but are well-known
# benign artifacts of modern front-end builds. A generic-class candidate whose
# surrounding context (or the candidate itself) matches any of these is treated
# as a false match and is NEVER graded (downgraded to INFO at most).
SECRET_ALLOWLIST_PATTERNS = [
    # Sub-Resource Integrity hashes:  integrity="sha384-…"
    r"(?i)integrity\s*=\s*[\"']?(?:sha256|sha384|sha512)-",
    r"(?i)\b(?:sha256|sha384|sha512)-[A-Za-z0-9+/]{20,}={0,2}",
    # Source-map references / inline maps
    r"(?i)sourceMappingURL\s*=",
    r"(?i)\.js\.map\b",
    r"(?i)\.css\.map\b",
    # base64 data-URIs (fonts/images inlined into bundles)
    r"(?i)data:[a-z0-9.+/\-]+;base64,",
    # webpack / hashed asset filenames:  main.4f3a9c.js, chunk-AB12.css,
    # runtime~app.deadbeef.js, app.[contenthash].bundle.js
    r"(?i)[\w./~-]+\.[0-9a-f]{6,}\.(?:js|css|mjs|map|woff2?|png|jpe?g|gif|svg|webp)\b",
    # webpack module/chunk identifiers
    r"(?i)__webpack_require__|webpackJsonp|webpackChunk",
    # generic content-hash query/fragment cache busters: ?v=deadbeef, ?h=abc123
    r"(?i)[?&](?:v|h|hash|rev|ver)=[0-9a-f]{6,}",
]
_ALLOWLIST_COMPILED = [_re.compile(p) for p in SECRET_ALLOWLIST_PATTERNS]


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string in bits/char. 0.0 for empty input."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def looks_like_false_match(candidate: str, context: str = "") -> bool:
    """True if a generic-class candidate is a known-benign front-end artifact.

    `candidate` is the exact matched substring; `context` is the surrounding
    text (e.g. ±60 chars) so SRI / data-URI / source-map markers that sit
    *next to* the blob are caught too.
    """
    hay = candidate + "\n" + (context or "")
    for rx in _ALLOWLIST_COMPILED:
        if rx.search(hay):
            return True
    return False
