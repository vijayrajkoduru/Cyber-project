"""Full Webapp-module dev-time asset generator.

Mirrors gen_recon_assets.py and gen_vuln_assets.py. Writes to /tmp/vl_payloads/
for review before copying into tools/_payloads/.

12 CONFIGS covering the highest-ROI Webapp scanners that currently use
hardcoded inline lists:

  directory_brute_paths   — 1500 directory/file brute paths
  param_discovery_names   — 600 parameter name candidates
  crawler_seed_paths      —  200 high-value seed URLs for BFS crawl
  secrets_patterns        —  220 regex patterns for API keys / tokens
  nosqli_payloads         —  120 NoSQL injection payloads (MongoDB/CouchDB)
  ldap_injection_payloads —   80 LDAP injection payloads
  crlf_injection_payloads —   60 CRLF / header-injection payloads
  prototype_pollution_payloads — 80 prototype-pollution gadgets
  host_header_payloads    —   60 Host header injection payloads
  http_smuggling_payloads —   50 HTTP request smuggling payloads
  cache_poisoning_payloads — 60 web cache poisoning payloads
  deserialization_payloads — 60 deserialization gadgets (Java/Python/PHP/.NET)
"""
import json, os, re, sys
import anthropic

CONFIGS = {
    "directory_brute_paths": {
        "max_tokens": 28000, "var": "DIRECTORY_BRUTE_PATHS",
        "prompt": """Generate 1500 directory/file paths for a web directory-brute scanner.
Priority-ordered (highest hit-rate first).

REQUIRED coverage:
- Common admin / panel paths (/admin, /dashboard, /login, /panel) — 80
- API endpoints (/api, /v1, /v2, /graphql, /rest, /soap) — 100
- Backup files (.bak, .backup, .old, .save, .swp, ~) — 120
- Config files (.env, web.config, config.php, settings.py, application.yml) — 120
- Source-control leaks (.git/, .svn/, .hg/, .bzr/, .gitignore) — 60
- IDE/editor leaks (.idea/, .vscode/, .DS_Store, Thumbs.db) — 40
- Test/debug paths (/test, /debug, /phpinfo.php, /info.php, /server-status) — 80
- Cloud config (/.aws/credentials, /.gcp/, /.azure/) — 40
- DB exports (.sql, .sql.gz, dump.sql, backup.sql) — 60
- Log files (.log, /logs/, /var/log/, error.log) — 80
- Framework-specific (Laravel storage, Django admin, Spring actuator) — 150
- WordPress paths (/wp-admin, /wp-content/, /wp-config.php.bak) — 80
- CMS plugin paths (Joomla components, Drupal modules) — 60
- Generic webapp leaks (/install, /setup, /update.php, /readme) — 80
- API docs (/swagger, /api-docs, /openapi.json, /redoc) — 60
- Container/orchestration (/healthz, /metrics, /actuator/env) — 80
- Modern dev paths (/_next, /__vite, /.parcelrc) — 60
- Misc high-value (/console, /jenkins, /grafana, /kibana) — 100
- Sensitive directory listings (/uploads/, /backup/, /tmp/, /old/) — 50

Each item EXACTLY 4 keys:
  path (with leading /), category (snake_case),
  severity (CRITICAL|HIGH|MEDIUM|LOW),
  priority (1-10, 10=highest hit-rate)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "param_discovery_names": {
        "max_tokens": 16000, "var": "PARAM_DISCOVERY_NAMES",
        "prompt": """Generate 600 parameter name candidates for HTTP parameter discovery (Arjun-style).
Priority-ordered.

REQUIRED coverage:
- Common auth (token, auth, api_key, session, jwt, bearer) — 50
- User identifiers (id, user, user_id, uid, account_id, customer_id) — 60
- Actions (action, cmd, command, exec, do, op, function, method) — 50
- Path/file (file, path, dir, folder, url, link, src, dest) — 80
- Search (q, query, search, keyword, term, find) — 30
- Pagination (page, offset, limit, count, size, per_page) — 40
- Filters (filter, sort, order, direction, field, type) — 50
- Debug (debug, test, dev, verbose, trace, log) — 30
- Admin/internal (admin, role, permission, is_admin, superuser) — 30
- Callback/redirect (callback, redirect, return_url, next, continue) — 30
- Format (format, type, output, response_type, accept) — 20
- Date/time (date, from, to, start, end, since, until) — 40
- Geo (lat, lng, country, region, city, ip, geo) — 30
- Misc (lang, locale, theme, mode, env, host, proxy) — 60

Each item EXACTLY 3 keys:
  name (string, no spaces),
  category (snake_case),
  priority (1-10)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "crawler_seed_paths": {
        "max_tokens": 8000, "var": "CRAWLER_SEED_PATHS",
        "prompt": """Generate 200 high-value seed URLs for a webapp BFS crawler.
These are paths where APIs/admins/sensitive content commonly live, so the
crawler should probe them first before random link-following.

Mix:
- API roots (/api, /api/v1, /graphql, /rest) — 25
- Authentication (/login, /signin, /auth, /oauth) — 20
- User account (/account, /profile, /settings, /preferences) — 25
- Admin (/admin, /dashboard, /manage, /control-panel) — 25
- File operations (/upload, /download, /file, /docs) — 15
- Common entry pages (/contact, /about, /faq, /help) — 15
- Search (/search, /find, /lookup) — 10
- Sitemap (/sitemap.xml, /robots.txt, /humans.txt, /.well-known/) — 10
- Health/monitoring (/health, /status, /ping, /metrics) — 15
- Static assets dirs (/static/, /assets/, /public/, /uploads/) — 15
- Modern SPA routes (/app, /home, /dashboard.html) — 10
- E-commerce (/cart, /checkout, /products, /catalog) — 15

Each item EXACTLY 3 keys:
  path (with leading /), category (snake_case), priority (1-10)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "secrets_patterns": {
        "max_tokens": 18000, "var": "SECRETS_PATTERNS",
        "prompt": """Generate 220 regex patterns for detecting leaked secrets/credentials in JS/HTML/JSON responses.
Based on common API key formats, tokens, and credential patterns.

REQUIRED coverage:
- AWS (Access Key, Secret, Session Token) — 15
- Google Cloud (API key, OAuth, service-account) — 15
- Azure (key, connection string, SAS) — 12
- GitHub / GitLab / Bitbucket tokens — 15
- Slack / Discord / Telegram bot tokens — 15
- Stripe / PayPal / Square (API keys, webhook) — 15
- Twilio / SendGrid / Mailgun (API keys) — 12
- JWT (header.payload.signature format) — 10
- Generic API key patterns (api_key=, x-api-key:, Bearer ...) — 25
- Private keys (RSA, EC, PGP BEGIN ... END) — 10
- Database connection strings (mongodb://, postgres://, mysql://) — 12
- Crypto wallets (BTC, ETH addresses, mnemonic phrases) — 10
- Cloudflare / Fastly / Akamai (account/zone IDs) — 8
- OpenAI / Anthropic / Cohere (sk-*, ak-*) — 12
- Indian/Asian fintech (Razorpay, PayU, Cashfree, Paytm) — 12
- High-entropy generic patterns (base64 32+, hex 64+) — 22

Each item EXACTLY 6 keys:
  name (string, descriptive),
  regex (Python regex string, <120 chars),
  service (snake_case),
  severity (CRITICAL|HIGH|MEDIUM),
  cvss (numeric string like "9.1"),
  remediation (1 short sentence)

OUTPUT: ONLY JSON array. Start [ end ]. NO prose. Use single backslashes in regex (escape for JSON: \\d, \\w, etc)."""
    },

    "nosqli_payloads": {
        "max_tokens": 10000, "var": "NOSQLI_PAYLOADS",
        "prompt": """Generate 120 NoSQL injection payloads for MongoDB, CouchDB, and Cassandra.

Mix:
- MongoDB operator injection ($ne, $gt, $regex, $where) — 30
- MongoDB BLIND time-based ($where: 'sleep(...)') — 20
- MongoDB auth bypass ({"username": {"$ne": null}, "password": {"$ne": null}}) — 20
- CouchDB injection (_all_docs, _design/) — 10
- JSON body injection (operator in nested key) — 20
- URL-encoded variants — 20

Each item EXACTLY 4 keys:
  payload (string),
  context (json_body|query_string|nested),
  category (auth_bypass|extract|blind|enum),
  severity (CRITICAL|HIGH|MEDIUM)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "ldap_injection_payloads": {
        "max_tokens": 6000, "var": "LDAP_INJECTION_PAYLOADS",
        "prompt": """Generate 80 LDAP injection payloads.

Mix:
- Boolean-based filter injection ( *) ( cn=* ) — 25
- Authentication bypass ( admin)(&  ) — 20
- Blind LDAP attribute extraction (cn=a*, cn=b*) — 15
- Time-based (where supported) — 5
- LDAP search filter escapes (parens, backslashes) — 15

Each item EXACTLY 3 keys:
  payload (string),
  category (snake_case),
  severity (CRITICAL|HIGH|MEDIUM)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "crlf_injection_payloads": {
        "max_tokens": 6000, "var": "CRLF_INJECTION_PAYLOADS",
        "prompt": """Generate 60 CRLF / header-injection payloads.

Mix:
- Raw \\r\\n header injection — 20
- URL-encoded %0d%0a — 15
- Double URL-encoded — 10
- Unicode (%E5%98%8A) — 5
- Set-Cookie injection — 5
- Location: injection (open-redirect chain) — 5

Each item EXACTLY 3 keys:
  payload (string),
  category (snake_case),
  severity (HIGH|MEDIUM)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "prototype_pollution_payloads": {
        "max_tokens": 8000, "var": "PROTOTYPE_POLLUTION_PAYLOADS",
        "prompt": """Generate 80 JavaScript prototype-pollution gadgets and probe payloads.

Mix:
- JSON __proto__ injection ({"__proto__":{"polluted":true}}) — 20
- constructor.prototype injection — 15
- Nested __proto__ ({"a":{"__proto__":{"x":1}}}) — 15
- URL query-string pollution (a[__proto__][x]=1) — 15
- Lodash / jQuery / mongoose / minimist-specific gadgets — 15

Each item EXACTLY 4 keys:
  payload (string),
  context (json_body|query_string),
  library (lodash|jquery|mongoose|minimist|generic),
  severity (CRITICAL|HIGH)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "host_header_payloads": {
        "max_tokens": 6000, "var": "HOST_HEADER_PAYLOADS",
        "prompt": """Generate 60 Host header injection payloads for testing.

Mix:
- Override Host with attacker domain — 15
- Override via X-Forwarded-Host — 10
- X-Forwarded-Server / X-Host / X-Real-IP variants — 15
- Port-confusion (host:80@evil.com) — 10
- Cache-key poisoning header combos — 10

Each item EXACTLY 4 keys:
  header_name (string),
  header_value (string with attacker.example or evil.example placeholder),
  category (snake_case),
  severity (HIGH|MEDIUM)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "http_smuggling_payloads": {
        "max_tokens": 5000, "var": "HTTP_SMUGGLING_PAYLOADS",
        "prompt": """Generate 50 HTTP request smuggling payloads (CL.TE, TE.CL, TE.TE variants).

Mix:
- Content-Length + Transfer-Encoding desync (CL.TE) — 15
- TE.CL desync — 10
- TE.TE (header obfuscation) — 10
- HTTP/2 downgrade smuggling — 5
- Header line-folding tricks — 10

Each item EXACTLY 4 keys:
  name (string, descriptive),
  variant (cl_te|te_cl|te_te|h2_downgrade),
  payload (string with literal \\r\\n preserved),
  severity (CRITICAL|HIGH)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "cache_poisoning_payloads": {
        "max_tokens": 6000, "var": "CACHE_POISONING_PAYLOADS",
        "prompt": """Generate 60 web cache poisoning payloads.

Mix:
- Unkeyed header injection (X-Forwarded-Host, X-Original-URL) — 20
- Cache deception (suffix-based, /account/foo.css) — 15
- Parameter cloaking (utm_source confusion) — 10
- CDN-specific (Cloudflare, Fastly, Akamai keys) — 15

Each item EXACTLY 4 keys:
  technique (snake_case),
  payload (string),
  cache_tier (cdn|reverse_proxy|browser),
  severity (HIGH|MEDIUM)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "deserialization_payloads": {
        "max_tokens": 8000, "var": "DESERIALIZATION_PAYLOADS",
        "prompt": """Generate 60 deserialization probe markers (NOT exploit gadgets — just patterns to fingerprint vulnerable endpoints).

Mix:
- Java (ysoserial markers, ObjectInputStream patterns) — 15
- Python (pickle markers, __reduce__) — 10
- PHP (unserialize markers, O:N: patterns) — 15
- .NET (BinaryFormatter, ObjectStateFormatter __VIEWSTATE) — 10
- Ruby Marshal / Node.js node-serialize — 10

Each item EXACTLY 4 keys:
  marker (string — base64 or hex pattern that vulnerable endpoints accept),
  language (java|python|php|dotnet|ruby|node),
  context (cookie|param|body),
  severity (CRITICAL|HIGH)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },
}


def salvage(raw):
    """Multi-point salvage — walks backwards finding the longest valid JSON prefix."""
    raw = re.sub(r"^```(?:json)?\s*", "", raw.strip())
    raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw), False
    except json.JSONDecodeError:
        pass
    end_positions = [m.end() - 1 for m in re.finditer(r"\},", raw)]
    end_positions.reverse()
    for pos in end_positions:
        candidate = raw[:pos + 1] + "]"
        try:
            res = json.loads(candidate)
            if isinstance(res, list) and len(res) > 5:
                return res, True
        except json.JSONDecodeError:
            pass
    return None, False


def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else ""
    if kind not in CONFIGS:
        sys.exit(f"Usage: gen_webapp_assets.py {list(CONFIGS.keys())}")
    cfg = CONFIGS[kind]
    print(f"=== {kind} (max_tokens={cfg['max_tokens']}, streaming) ===")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY missing")

    client = anthropic.Anthropic()
    chunks, last_dot = [], 0
    with client.messages.stream(
        model="claude-sonnet-4-6",
        max_tokens=cfg["max_tokens"],
        messages=[{"role": "user", "content": cfg["prompt"]}],
    ) as stream:
        for text in stream.text_stream:
            chunks.append(text)
            total = sum(len(c) for c in chunks)
            if total // 5000 > last_dot:
                print(".", end="", flush=True); last_dot = total // 5000
        final = stream.get_final_message()
        in_tok, out_tok = final.usage.input_tokens, final.usage.output_tokens
    print()

    raw = "".join(chunks)
    items, salvaged = salvage(raw)
    if items is None:
        open(f"/tmp/{kind}_raw.txt", "w").write(raw)
        sys.exit(f"Salvage failed. Saved /tmp/{kind}_raw.txt ({len(raw)} bytes)")
    if salvaged:
        print(f"  ⚠ truncated, salvaged {len(items)} items")

    out = f"/tmp/vl_payloads/{kind}.py"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    import pprint
    with open(out, "w") as f:
        f.write(f'"""{kind} — generated dev-time by Claude. Webapp module asset.\n"""\n\n')
        f.write(f'{cfg["var"]} = ')
        f.write(pprint.pformat(items, width=120, sort_dicts=False))
        f.write("\n")
    cost = (in_tok * 3 + out_tok * 15) / 1_000_000
    print(f"  ✓ wrote {len(items)} items to {out}")
    print(f"  tokens: {in_tok} in, {out_tok} out  |  cost: ~${cost:.3f}")


if __name__ == "__main__":
    main()
