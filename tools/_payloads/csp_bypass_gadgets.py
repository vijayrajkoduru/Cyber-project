"""csp_bypass_gadgets — handcrafted dev-time. Webapp module asset.

CSP bypass gadget catalog — hostnames/patterns that, if allowed by a target's
CSP, let an attacker execute arbitrary JavaScript via JSONP or similar.

Used by tools/webapp/csp_bypass.py to flag dangerous script-src entries.
Sources: csp-evaluator.withgoogle.com gadget database, Lukas Weichselbaum
research, public bug bounty writeups.
"""

CSP_BYPASS_GADGETS = [
    # ── Google JSONP endpoints (the canonical csp-bypass corpus) ────────────
    {"gadget": "ajax.googleapis.com", "csp_directive": "script-src",
     "bypass_type": "jsonp", "severity": "CRITICAL",
     "reference": "Google CDN serves JSONP via callback param — load /jsapi?callback=alert"},
    {"gadget": "www.googleapis.com", "csp_directive": "script-src",
     "bypass_type": "jsonp", "severity": "CRITICAL",
     "reference": "Google APIs JSONP: /customsearch/v1?callback=alert"},
    {"gadget": "apis.google.com", "csp_directive": "script-src",
     "bypass_type": "jsonp", "severity": "CRITICAL",
     "reference": "Google Platform Library serves JSONP-style callbacks"},
    {"gadget": "accounts.google.com", "csp_directive": "script-src",
     "bypass_type": "jsonp", "severity": "HIGH",
     "reference": "Google sign-in API JSONP endpoints"},
    {"gadget": "www.google-analytics.com", "csp_directive": "script-src",
     "bypass_type": "third_party_script", "severity": "MEDIUM",
     "reference": "Analytics script — risk via tag-manager misuse"},
    {"gadget": "www.googletagmanager.com", "csp_directive": "script-src",
     "bypass_type": "third_party_script", "severity": "HIGH",
     "reference": "GTM accepts arbitrary script via tag configuration"},
    {"gadget": "translate.googleapis.com", "csp_directive": "script-src",
     "bypass_type": "jsonp", "severity": "CRITICAL",
     "reference": "Google Translate JSONP endpoint with callback param"},
    {"gadget": "feedburner.google.com", "csp_directive": "script-src",
     "bypass_type": "jsonp", "severity": "HIGH",
     "reference": "Feedburner JSONP callback"},

    # ── AWS / CloudFront ────────────────────────────────────────────────────
    {"gadget": "*.s3.amazonaws.com", "csp_directive": "script-src",
     "bypass_type": "wildcard_s3", "severity": "CRITICAL",
     "reference": "Wildcard S3 — attacker creates bucket and serves JS"},
    {"gadget": "*.cloudfront.net", "csp_directive": "script-src",
     "bypass_type": "wildcard_cdn", "severity": "CRITICAL",
     "reference": "Wildcard CloudFront — attacker registers distribution"},
    {"gadget": "*.amazonaws.com", "csp_directive": "script-src",
     "bypass_type": "wildcard_cdn", "severity": "CRITICAL",
     "reference": "Massive wildcard — covers all AWS subdomains"},

    # ── unpkg / jsDelivr / cdnjs ────────────────────────────────────────────
    {"gadget": "unpkg.com", "csp_directive": "script-src",
     "bypass_type": "package_cdn", "severity": "CRITICAL",
     "reference": "Attacker publishes npm package and loads it via unpkg.com/<pkg>"},
    {"gadget": "cdn.jsdelivr.net", "csp_directive": "script-src",
     "bypass_type": "package_cdn", "severity": "CRITICAL",
     "reference": "Same as unpkg — npm/GitHub package CDN, attacker can publish"},
    {"gadget": "cdn.jsdelivr.net/combine", "csp_directive": "script-src",
     "bypass_type": "combiner_cdn", "severity": "CRITICAL",
     "reference": "JsDelivr's combine endpoint can concatenate arbitrary attacker files"},
    {"gadget": "cdnjs.cloudflare.com", "csp_directive": "script-src",
     "bypass_type": "package_cdn", "severity": "HIGH",
     "reference": "Curated CDN — lower risk but still loads many libs with JSONP-style entry"},

    # ── Facebook / Twitter SDK ──────────────────────────────────────────────
    {"gadget": "connect.facebook.net", "csp_directive": "script-src",
     "bypass_type": "social_sdk", "severity": "HIGH",
     "reference": "Facebook SDK exposes JSONP-like callback endpoints"},
    {"gadget": "platform.twitter.com", "csp_directive": "script-src",
     "bypass_type": "social_sdk", "severity": "HIGH",
     "reference": "Twitter widgets.js serves JSONP via /widgets/follow_button.html"},
    {"gadget": "syndication.twitter.com", "csp_directive": "script-src",
     "bypass_type": "jsonp", "severity": "HIGH",
     "reference": "Twitter syndication API JSONP"},

    # ── CDN combiners / dynamic builders ────────────────────────────────────
    {"gadget": "ajax.aspnetcdn.com", "csp_directive": "script-src",
     "bypass_type": "jsonp", "severity": "HIGH",
     "reference": "Microsoft Ajax CDN serves jquery JSONP variants"},
    {"gadget": "code.jquery.com", "csp_directive": "script-src",
     "bypass_type": "package_cdn", "severity": "MEDIUM",
     "reference": "jQuery official CDN — narrower attack surface but still risky"},
    {"gadget": "stackpath.bootstrapcdn.com", "csp_directive": "script-src",
     "bypass_type": "package_cdn", "severity": "MEDIUM",
     "reference": "Bootstrap CDN"},

    # ── Stripe / payment SDKs ───────────────────────────────────────────────
    {"gadget": "js.stripe.com", "csp_directive": "script-src",
     "bypass_type": "payment_sdk", "severity": "MEDIUM",
     "reference": "Stripe.js — narrow scope but allowed-host"},

    # ── Tag managers + analytics ────────────────────────────────────────────
    {"gadget": "tagmanager.google.com", "csp_directive": "script-src",
     "bypass_type": "tag_manager", "severity": "HIGH",
     "reference": "GTM lets authorized users inject arbitrary script"},
    {"gadget": "static.hotjar.com", "csp_directive": "script-src",
     "bypass_type": "third_party_script", "severity": "MEDIUM",
     "reference": "Hotjar tracking script"},
    {"gadget": "cdn.segment.com", "csp_directive": "script-src",
     "bypass_type": "third_party_script", "severity": "MEDIUM",
     "reference": "Segment CDP — config-driven script execution"},

    # ── Wildcard scheme bypasses ────────────────────────────────────────────
    {"gadget": "https:", "csp_directive": "script-src",
     "bypass_type": "wildcard_scheme", "severity": "CRITICAL",
     "reference": "Allows ANY https URL — equivalent to no CSP"},
    {"gadget": "http:", "csp_directive": "script-src",
     "bypass_type": "wildcard_scheme", "severity": "CRITICAL",
     "reference": "Allows any http URL"},
    {"gadget": "data:", "csp_directive": "script-src",
     "bypass_type": "data_uri", "severity": "CRITICAL",
     "reference": "data: URI in script-src = inline code execution"},
    {"gadget": "blob:", "csp_directive": "script-src",
     "bypass_type": "blob_uri", "severity": "HIGH",
     "reference": "blob: URI created from attacker data = code exec"},
    {"gadget": "filesystem:", "csp_directive": "script-src",
     "bypass_type": "filesystem_uri", "severity": "HIGH",
     "reference": "filesystem: URI — Chrome-specific bypass"},
    {"gadget": "javascript:", "csp_directive": "script-src",
     "bypass_type": "javascript_uri", "severity": "CRITICAL",
     "reference": "javascript: URI in script-src = direct exec"},

    # ── unsafe-* directives ─────────────────────────────────────────────────
    {"gadget": "'unsafe-inline'", "csp_directive": "script-src",
     "bypass_type": "unsafe_inline", "severity": "CRITICAL",
     "reference": "Allows ALL inline <script>, on* handlers — CSP effectively bypassed for XSS"},
    {"gadget": "'unsafe-eval'", "csp_directive": "script-src",
     "bypass_type": "unsafe_eval", "severity": "HIGH",
     "reference": "Allows eval()/Function() — gadget for stored XSS chains"},
    {"gadget": "'unsafe-hashes'", "csp_directive": "script-src",
     "bypass_type": "unsafe_hashes", "severity": "MEDIUM",
     "reference": "Allows hashed inline event handlers"},
    {"gadget": "*", "csp_directive": "script-src",
     "bypass_type": "wildcard", "severity": "CRITICAL",
     "reference": "Wildcard script-src — equivalent to no CSP"},
    {"gadget": "* data: blob:", "csp_directive": "script-src",
     "bypass_type": "wildcard_combo", "severity": "CRITICAL",
     "reference": "Multiple wildcards/schemes together"},
    {"gadget": "'self'", "csp_directive": "script-src",
     "bypass_type": "self_via_open_redirect", "severity": "MEDIUM",
     "reference": "'self' bypassable via open-redirect on same origin"},

    # ── strict-dynamic without integrity ────────────────────────────────────
    {"gadget": "'strict-dynamic'", "csp_directive": "script-src",
     "bypass_type": "strict_dynamic_misuse", "severity": "MEDIUM",
     "reference": "strict-dynamic without nonce/hash on initial script = bypass"},
    {"gadget": "nonce-static", "csp_directive": "script-src",
     "bypass_type": "static_nonce", "severity": "HIGH",
     "reference": "Static nonce (not regenerated per request) = predictable bypass"},

    # ── object-src / frame-src wildcards ────────────────────────────────────
    {"gadget": "*", "csp_directive": "object-src",
     "bypass_type": "wildcard_object", "severity": "HIGH",
     "reference": "object-src * — Flash/PDF gadgets can load arbitrary content"},
    {"gadget": "*", "csp_directive": "default-src",
     "bypass_type": "wildcard_default", "severity": "CRITICAL",
     "reference": "default-src * — falls through to script-src etc."},
    {"gadget": "data:", "csp_directive": "object-src",
     "bypass_type": "data_object", "severity": "HIGH",
     "reference": "object-src data: — Flash gadget execution"},

    # ── frame-ancestors weakness ────────────────────────────────────────────
    {"gadget": "*", "csp_directive": "frame-ancestors",
     "bypass_type": "no_clickjacking_protection", "severity": "MEDIUM",
     "reference": "Allows page to be framed by any site — clickjacking risk"},

    # ── Report-only mode ────────────────────────────────────────────────────
    {"gadget": "Content-Security-Policy-Report-Only", "csp_directive": "header_name",
     "bypass_type": "report_only_mode", "severity": "HIGH",
     "reference": "CSP is REPORT-ONLY — no enforcement, just monitoring"},

    # ── More CDN gadgets ────────────────────────────────────────────────────
    {"gadget": "raw.githubusercontent.com", "csp_directive": "script-src",
     "bypass_type": "user_content_cdn", "severity": "CRITICAL",
     "reference": "Attacker hosts JS in own GitHub repo, serves via raw.githubusercontent.com"},
    {"gadget": "gist.githubusercontent.com", "csp_directive": "script-src",
     "bypass_type": "user_content_cdn", "severity": "CRITICAL",
     "reference": "GitHub Gist raw content — attacker-controlled JS"},
    {"gadget": "pages.github.com", "csp_directive": "script-src",
     "bypass_type": "user_content_cdn", "severity": "CRITICAL",
     "reference": "GitHub Pages — attacker hosts site at <user>.github.io"},
    {"gadget": "*.github.io", "csp_directive": "script-src",
     "bypass_type": "wildcard_user_pages", "severity": "CRITICAL",
     "reference": "Wildcard GitHub Pages — any user can host JS"},
    {"gadget": "*.repl.co", "csp_directive": "script-src",
     "bypass_type": "wildcard_user_pages", "severity": "CRITICAL",
     "reference": "Replit — any user can serve JS"},
    {"gadget": "*.vercel.app", "csp_directive": "script-src",
     "bypass_type": "wildcard_paas", "severity": "CRITICAL",
     "reference": "Vercel — any deploy gets a subdomain, attacker can register"},
    {"gadget": "*.netlify.app", "csp_directive": "script-src",
     "bypass_type": "wildcard_paas", "severity": "CRITICAL",
     "reference": "Netlify — same wildcard issue"},
    {"gadget": "*.glitch.me", "csp_directive": "script-src",
     "bypass_type": "wildcard_paas", "severity": "CRITICAL",
     "reference": "Glitch — attacker forks a project"},
    {"gadget": "*.herokuapp.com", "csp_directive": "script-src",
     "bypass_type": "wildcard_paas", "severity": "CRITICAL",
     "reference": "Heroku free tier — attacker registers subdomain"},

    # ── Specific JSONP-supporting hosts ─────────────────────────────────────
    {"gadget": "embed.tawk.to", "csp_directive": "script-src",
     "bypass_type": "third_party_widget", "severity": "MEDIUM",
     "reference": "Chat widget — config-injected script"},
    {"gadget": "embed.zendesk.com", "csp_directive": "script-src",
     "bypass_type": "third_party_widget", "severity": "MEDIUM",
     "reference": "Zendesk widget"},
    {"gadget": "static.intercomcdn.com", "csp_directive": "script-src",
     "bypass_type": "third_party_widget", "severity": "MEDIUM",
     "reference": "Intercom messenger script"},

    # ── Older deprecated bypass techniques ──────────────────────────────────
    {"gadget": "yandex.st", "csp_directive": "script-src",
     "bypass_type": "jsonp_legacy", "severity": "HIGH",
     "reference": "Yandex CDN with JSONP (legacy projects only)"},
    {"gadget": "vk.com/js", "csp_directive": "script-src",
     "bypass_type": "social_jsonp", "severity": "MEDIUM",
     "reference": "VKontakte API JSONP"},

    # ── Cloudflare workers / scripts ────────────────────────────────────────
    {"gadget": "*.workers.dev", "csp_directive": "script-src",
     "bypass_type": "wildcard_serverless", "severity": "HIGH",
     "reference": "Cloudflare Workers — attacker deploys arbitrary handler"},

    # ── Self via path injection ─────────────────────────────────────────────
    {"gadget": "'self' /api/jsonp", "csp_directive": "script-src",
     "bypass_type": "self_jsonp_endpoint", "severity": "HIGH",
     "reference": "Site's own JSONP endpoint becomes XSS source"},
]
