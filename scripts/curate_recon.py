"""
One-shot Claude curation for Recon module path lists.
Run ONCE, deactivate Claude API after, ship the static JSON forever.
Cost: ~$1.50-2.00 with Sonnet 4.6
"""
import os, json, time, pathlib, urllib.request, urllib.error

API_KEY = os.environ.get("ANTHROPIC_API_KEY") or open(".env").read().split("ANTHROPIC_API_KEY=")[1].split("\n")[0].strip()
OUT_DIR = pathlib.Path("tools/_payloads/recon")
OUT_DIR.mkdir(parents=True, exist_ok=True)

PROMPTS = {
    "wordpress_paths.json": (
        "Generate a JSON array of 1500 unique paths commonly found on WordPress installations. "
        "Include: /wp-admin/ paths, /wp-content/ (plugins, themes, uploads), /wp-includes/, "
        "/wp-json/ REST API endpoints (esp. /wp-json/wp/v2/users), /xmlrpc.php, "
        "backup names (wp-config.php.bak, .swp, .old, .save, ~), .htaccess/.htpasswd variants, "
        "common plugin paths (woocommerce, yoast, elementor, contact-form-7, wpforms, etc.), "
        "common theme paths, debug.log, error_log, install.php, /readme.html. "
        "OUTPUT FORMAT: pure JSON array of strings, no markdown, no leading slashes. "
        "Each path under 80 chars. Sort by exploit value (most sensitive first)."
    ),
    "laravel_paths.json": (
        "Generate a JSON array of 1000 unique paths commonly found on Laravel applications. "
        "Include: /.env variants (.env.backup, .env.local, .env.production, .env.example), "
        "/storage/logs/laravel.log + dated variants, /storage/framework/, /storage/app/public/, "
        "/telescope, /horizon, /pulse, /nova, /_ignition (Ignition debugger), "
        "/.git/config + Laravel-specific Git exposures, /vendor/composer/, "
        "/config/*.php common config files, /database/migrations/, "
        "/public/storage symlinks. OUTPUT: pure JSON array, no leading slashes, sort by exploit value."
    ),
    "express_paths.json": (
        "Generate a JSON array of 1000 unique paths for Node.js/Express applications. "
        "Include: /api/* common patterns (users, admin, login, register, products, orders), "
        "/api/v1, /api/v2 versioned, /graphql + /playground, /api-docs (Swagger), "
        "/health, /metrics, /debug, /admin, /uploads, /static, "
        "package.json + package-lock.json + .npmrc, /.env variants, "
        "Express error handler endpoints, /api/internal/*, /admin/users variants. "
        "OUTPUT: pure JSON array, no leading slashes, sort by exploit value."
    ),
    "django_paths.json": (
        "Generate a JSON array of 800 unique paths for Django applications. "
        "Include: /admin/ + /admin/login/ + Django admin user paths, /__debug__/, "
        "/static/, /media/, /accounts/login/, /accounts/password_reset/, "
        "common Django REST Framework paths (/api/, /api-auth/), "
        "/celery, common third-party app paths (allauth, oscar, wagtail, taggit), "
        "settings exposure attempts, /static/admin/, manage.py exposure, "
        "Django channels /ws/ paths, /sentry-debug/. OUTPUT: pure JSON array, sort by exploit value."
    ),
    "spring_paths.json": (
        "Generate a JSON array of 800 unique paths for Spring Boot / Java applications. "
        "Include: /actuator/* endpoints (env, heapdump, threaddump, mappings, beans, configprops, "
        "loggers, httptrace, scheduledtasks, sessions, auditevents, conditions, info, health, "
        "metrics, prometheus, gateway), /h2-console (H2 DB console), /jolokia, "
        "/swagger-ui, /v2/api-docs, /v3/api-docs, /webjars/, "
        "/error pages, /trace, common Spring Security paths, /static/, /WEB-INF/ exposures. "
        "OUTPUT: pure JSON array, no leading slashes, sort by exploit value."
    ),
    "subdomain_wordlist.json": (
        "Generate a JSON array of 1000 most-common subdomains for enterprise SaaS targets. "
        "Cover: standard (www, mail, ftp, admin, api), dev (dev, staging, qa, test, uat, sandbox, preview), "
        "infrastructure (cdn, static, assets, media, files), service (vpn, ssh, git, gitlab, jenkins, jira), "
        "monitoring (grafana, kibana, prometheus, sentry, datadog), database (db, mysql, postgres, redis, mongo), "
        "support (support, help, docs, kb, wiki), business (portal, dashboard, app, accounts, my, console), "
        "regional variants (us, eu, asia, prod, primary), legacy (old, new, beta, v1, v2). "
        "OUTPUT: pure JSON array of strings, no domain suffix (just the subdomain part)."
    ),
    "tech_fingerprints.json": (
        "Generate a JSON object mapping 30 web frameworks/CMS to their detection signatures. "
        "Frameworks: WordPress, Drupal, Joomla, Magento, Shopify, Laravel, Symfony, Rails, "
        "Django, Flask, FastAPI, Express, NextJS, NuxtJS, Angular, React, Vue, Svelte, "
        "Spring Boot, ASP.NET, .NET Core, Tomcat, Wildfly, Ghost, Strapi, KeystoneJS, "
        "Gatsby, Hugo, Jekyll, Webflow. "
        "For each: {headers: [regex patterns], cookies: [names], paths: [unique-paths], "
        "html_markers: [strings or regex], js_globals: [window vars]}. "
        "OUTPUT: pure JSON object, no markdown."
    ),
    "cloud_bucket_patterns.json": (
        "Generate a JSON array of 200 common naming patterns for cloud storage buckets "
        "(AWS S3, GCS, Azure Blob). Patterns should use {company} as placeholder. "
        "Examples: {company}-backup, {company}-prod, {company}-dev, backup-{company}, "
        "{company}-uploads, static-{company}, {company}-media-cdn, etc. "
        "Include common suffixes: -backup, -bak, -prod, -staging, -dev, -test, -uploads, -media, "
        "-images, -cdn, -static, -assets, -logs, -archive, -temp, -tmp, -old, -2024, -2025. "
        "OUTPUT: pure JSON array of pattern strings."
    ),
}

def call_claude(prompt, max_retries=2):
    """Single Claude API call, returns parsed JSON output."""
    body = json.dumps({
        "model": "claude-sonnet-4-6",
        "max_tokens": 8000,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages",
        data=body, headers={
            "Content-Type": "application/json",
            "x-api-key": API_KEY,
            "anthropic-version": "2023-06-01",
        })
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                resp = json.loads(r.read())
                text = resp["content"][0]["text"]
                # Strip any markdown fences if present
                if text.strip().startswith("```"):
                    text = text.split("```")[1]
                    if text.startswith("json"):
                        text = text[4:]
                in_tok = resp.get("usage", {}).get("input_tokens", 0)
                out_tok = resp.get("usage", {}).get("output_tokens", 0)
                cost = (in_tok * 3 + out_tok * 15) / 1_000_000
                return json.loads(text.strip()), cost
        except urllib.error.HTTPError as e:
            print(f"  HTTP {e.code}: {e.read()[:200]}")
            if attempt == max_retries - 1: raise
            time.sleep(2)
        except json.JSONDecodeError as e:
            print(f"  JSON parse failed: {e}; got: {text[:200]}")
            if attempt == max_retries - 1: raise
            time.sleep(2)

total_cost = 0.0
print(f"━━━ Curating Recon module — {len(PROMPTS)} assets ━━━\n")
for filename, prompt in PROMPTS.items():
    out_path = OUT_DIR / filename
    print(f"→ {filename} ... ", end="", flush=True)
    if out_path.exists():
        print("SKIP (already exists)")
        continue
    try:
        data, cost = call_claude(prompt)
        out_path.write_text(json.dumps(data, indent=2))
        total_cost += cost
        count = len(data) if isinstance(data, list) else len(data.keys())
        print(f"✓ {count} items · ${cost:.3f}")
    except Exception as e:
        print(f"✗ FAILED: {e}")

print(f"\n━━━ DONE · Total spent: ${total_cost:.2f} ━━━")
print(f"Files in: {OUT_DIR}")
