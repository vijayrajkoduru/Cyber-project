# Secret Rotation Runbook

**Why this exists:** live secrets were found in a stray `.env'''` file, and CI
history shows credentials were once committed. Anything that has touched git
history or a loose file on disk must be considered **compromised** and rotated.
Rotation is an action only you can take — at each provider — so this is the
exact checklist.

## Rotate these now (found exposed)

| Secret (env var) | Where to rotate | After rotating |
|---|---|---|
| `RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` | Razorpay Dashboard → Settings → API Keys → **Regenerate** | update `.env`, redeploy |
| `RAZORPAY_WEBHOOK_SECRET` | Razorpay → Webhooks → edit endpoint → new secret | update `.env`, redeploy |
| `ANTHROPIC_API_KEY` | console.anthropic.com → API Keys → revoke + create | update `.env`, redeploy |
| `JWT_SECRET` | generate new: `openssl rand -hex 32` | update `.env`, redeploy — **invalidates all sessions** (expected) |
| `VAULT_KEY` / `CREDENTIAL_VAULT_MASTER_KEY` | see "Vault re-key" below — **do not just replace** | |
| `EMAIL_API_KEY` (ZeptoMail) | ZeptoMail → Mail Agents → Send Mail Token → regenerate | update `.env`, redeploy |
| `GITHUB_TOKEN` | github.com → Settings → Developer settings → Tokens → revoke + new | update `.env`, redeploy |
| `PASSWORD` (admin seed) | choose a new strong value | see EVERYDAY-TODO.md §11 (reset ADMIN) |

## Steps per secret
1. Generate/regenerate at the provider; copy the **new** value.
2. On the VPS: `nano ~/Cyber-project/.env` → replace the value.
3. `cd ~/Cyber-project && docker compose restart backend` (env-only change) — or
   redeploy if other changes are pending.
4. Confirm the old credential is **revoked** at the provider (not just rotated).

## Vault re-key (special handling)
`VAULT_KEY` / `CREDENTIAL_VAULT_MASTER_KEY` encrypt stored credentials. Swapping
the key blindly makes existing vault data undecryptable. To re-key safely:
1. With the **old** key still set, export/decrypt stored secrets.
2. Set the new key, re-encrypt, and write back.
3. Verify a read works before discarding the old key.
If the vault holds nothing critical yet, simpler: clear the vault, set the new
key, re-enter secrets.

## Going forward
- Secrets are read through `tools/_core/secrets.py`; set `SECRETS_BACKEND` to a
  real manager (Vault/AWS/GCP) when ready — call sites won't change.
- `.gitignore` now covers `.env*`. CI's gitleaks step blocks any secret in the
  working tree.
- `require_secret()` refuses to start with placeholder values (e.g.
  `your_actual_key_here`), surfacing un-rotated config at boot.
