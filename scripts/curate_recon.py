"""Offline AI curation for Recon module."""
import os, json, time, pathlib, urllib.request, urllib.error

def load_key():
    if os.environ.get("ANTHROPIC_API_KEY"): return os.environ["ANTHROPIC_API_KEY"]
    with open(".env") as f:
        for line in f:
            if line.startswith("ANTHROPIC_API_KEY="):
                return line.split("=",1)[1].strip().strip('"').strip("'")
    raise RuntimeError("no key")

KEY = load_key()
OUT = pathlib.Path("tools/_payloads/recon"); OUT.mkdir(parents=True, exist_ok=True)

PROMPTS = {
"wordpress_paths.json": "Generate JSON array of 1500 unique paths on WordPress installs: /wp-admin/*, /wp-content/ (plugins, themes, uploads), /wp-includes/, /wp-json/wp/v2/* REST endpoints, /xmlrpc.php, backup names (wp-config.php.bak, .swp, .old, .save), .htaccess variants, common plugin paths (woocommerce, yoast, elementor, contact-form-7, wpforms), common theme paths, debug.log, error_log, install.php, readme.html. OUTPUT: pure JSON array of strings only, NO markdown fences, NO leading slashes. Each path under 80 chars. Sort by exploit value.",
"laravel_paths.json": "Generate JSON array of 1000 Laravel paths: .env variants (.env.backup, .env.local, .env.production), storage/logs/laravel.log, storage/framework/, storage/app/public/, telescope, horizon, pulse, nova, _ignition, .git/config, vendor/composer/, config/*.php, database/migrations/, public/storage. OUTPUT: pure JSON array, no leading slashes, no markdown.",
"express_paths.json": "Generate JSON array of 600 Node.js/Express paths: api/* (users, admin, login, register, products, orders), api/v1, api/v2, graphql, playground, api-docs, health, metrics, debug, admin, uploads, static, package.json, .npmrc, .env, api/internal/*. OUTPUT: pure JSON array, no leading slashes, no markdown.",
"django_paths.json": "Generate JSON array of 500 Django paths: admin/, admin/login/, __debug__/, static/, media/, accounts/login/, accounts/password_reset/, api/, api-auth/, celery, allauth, oscar, wagtail, manage.py, ws/, sentry-debug/. OUTPUT: pure JSON array, no markdown.",
"spring_paths.json": "Generate JSON array of 500 Spring Boot paths: actuator/* (env, heapdump, threaddump, mappings, beans, configprops, loggers, httptrace, sessions, info, health, metrics, prometheus), h2-console, jolokia, swagger-ui, v2/api-docs, v3/api-docs, webjars/, WEB-INF/. OUTPUT: pure JSON array, no leading slashes, no markdown.",
"subdomain_wordlist.json": "Generate JSON array of 600 common SaaS subdomains. Cover: standard (www, mail, ftp, admin, api), dev (dev, staging, qa, test, uat, sandbox), infrastructure (cdn, static, assets, media), service (vpn, ssh, git, gitlab, jenkins, jira), monitoring (grafana, kibana, prometheus, sentry, datadog), database (db, mysql, postgres, redis, mongo), support (support, help, docs, wiki), business (portal, dashboard, app, accounts, my), regional (us, eu, asia, prod), legacy (old, new, beta, v1, v2). OUTPUT: pure JSON array of subdomain strings only.",
"tech_fingerprints.json": "Generate JSON object mapping 30 frameworks to detection signatures. Frameworks: WordPress, Drupal, Joomla, Magento, Shopify, Laravel, Symfony, Rails, Django, Flask, FastAPI, Express, NextJS, NuxtJS, Angular, React, Vue, Svelte, SpringBoot, ASPNet, Tomcat, Wildfly, Ghost, Strapi, Gatsby, Hugo, Jekyll, Webflow, Wix, Squarespace. For each: {headers:[regex], cookies:[names], paths:[paths], html_markers:[strings], js_globals:[vars]}. OUTPUT: pure JSON object, no markdown.",
"cloud_bucket_patterns.json": "Generate JSON array of 200 cloud storage bucket naming patterns. Use {company} placeholder. Examples: {company}-backup, {company}-prod, backup-{company}, {company}-uploads, static-{company}. Suffixes: -backup, -bak, -prod, -staging, -dev, -test, -uploads, -media, -images, -cdn, -static, -assets, -logs, -archive, -temp, -old, -2024, -2025. OUTPUT: pure JSON array of pattern strings.",
}

def call(prompt, retries=2):
    body = json.dumps({"model":"claude-haiku-4-5-20251001","max_tokens":16000,"messages":[{"role":"user","content":prompt}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={"Content-Type":"application/json","x-api-key":KEY,"anthropic-version":"2023-06-01"})
    for a in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                resp = json.loads(r.read())
                text = resp["content"][0]["text"].strip()
                if text.startswith("```"):
                    text = text.split("```",2)[1]
                    if text.startswith("json"): text = text[4:]
                    text = text.strip()
                u = resp.get("usage",{})
                cost = (u.get("input_tokens",0)*1 + u.get("output_tokens",0)*5) / 1_000_000
                return json.loads(text), cost
        except urllib.error.HTTPError as e:
            print(f"  HTTP {e.code}: {e.read()[:200].decode('utf-8','ignore')}")
            if a == retries-1: raise
            time.sleep(30)
        except json.JSONDecodeError as e:
            print(f"  parse fail: {e}")
            if a == retries-1: raise
            time.sleep(30)

total = 0.0
print(f"\n=== Recon AI curation ({len(PROMPTS)} assets) ===\n")
for fn, p in PROMPTS.items():
    out = OUT / fn
    print(f"-> {fn} ... ", end="", flush=True)
    if out.exists():
        print("SKIP (exists)"); continue
    try:
        data, cost = call(p)
        out.write_text(json.dumps(data, indent=2))
        total += cost
        n = len(data) if isinstance(data,list) else len(data.keys())
        print(f"OK {n} items ${cost:.3f}")
        print("  ... cooling 70s to respect rate limit")
        time.sleep(70)
    except Exception as e:
        print(f"FAIL: {e}")

print(f"\n=== DONE — total ${total:.2f} ===")
print(f"Files in {OUT}/")
