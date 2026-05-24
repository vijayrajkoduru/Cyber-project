"""retire_js_signatures — handcrafted dev-time. Webapp module phase-2 asset.

JS library CVE signatures used by tools/webapp/retire_js.py. Each entry detects
a specific library version range with a CVE. Sources: Retire.js community
database, GitHub Advisory Database, Snyk public vuln DB.
"""

RETIRE_JS_SIGNATURES = [
    # ── jQuery ──────────────────────────────────────────────────────────────
    {"library": "jQuery", "detection_regex": r"jquery[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"jquery[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<3.0.0", "cve": "CVE-2015-9251",
     "severity": "MEDIUM"},  # XSS via cross-domain ajax
    {"library": "jQuery", "detection_regex": r"jquery[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"jquery[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<3.4.1", "cve": "CVE-2019-11358",
     "severity": "MEDIUM"},  # Prototype pollution via $.extend
    {"library": "jQuery", "detection_regex": r"jquery[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"jquery[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<3.5.0", "cve": "CVE-2020-11022",
     "severity": "MEDIUM"},  # XSS via HTML in append()
    {"library": "jQuery", "detection_regex": r"jquery[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"jquery[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<3.5.0", "cve": "CVE-2020-11023",
     "severity": "MEDIUM"},  # XSS via HTML in html()/append()/etc
    {"library": "jQuery", "detection_regex": r"jquery[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"jquery[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<1.9.0", "cve": "CVE-2012-6708",
     "severity": "MEDIUM"},  # Selector treated as HTML

    # jQuery UI
    {"library": "jQuery UI", "detection_regex": r"jquery[\-\.]ui[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"jquery[\-\.]ui[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<1.12.0", "cve": "CVE-2016-7103",
     "severity": "HIGH"},  # XSS via closeText
    {"library": "jQuery UI", "detection_regex": r"jquery[\-\.]ui[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"jquery[\-\.]ui[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<1.13.0", "cve": "CVE-2021-41182",
     "severity": "MEDIUM"},  # XSS in datepicker
    {"library": "jQuery UI", "detection_regex": r"jquery[\-\.]ui[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"jquery[\-\.]ui[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<1.13.0", "cve": "CVE-2021-41183",
     "severity": "MEDIUM"},  # XSS in dialog

    # jQuery Migrate
    {"library": "jQuery Migrate", "detection_regex": r"jquery[\-\.]migrate[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"jquery[\-\.]migrate[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<3.0.0", "cve": "",
     "severity": "MEDIUM"},  # Legacy code paths

    # ── AngularJS 1.x ───────────────────────────────────────────────────────
    {"library": "AngularJS", "detection_regex": r"angular[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"angular[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<1.6.9", "cve": "CVE-2018-12557",
     "severity": "HIGH"},  # XSS in regex sanitizer
    {"library": "AngularJS", "detection_regex": r"angular[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"angular[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<1.8.0", "cve": "CVE-2020-7676",
     "severity": "HIGH"},  # XSS via mergeURI sanitizer bypass
    {"library": "AngularJS", "detection_regex": r"angular[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"angular[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<1.8.0", "cve": "",
     "severity": "MEDIUM"},  # AngularJS EOL — no security support
    {"library": "AngularJS", "detection_regex": r"angular\.js[\?v=](\d+\.\d+\.\d+)",
     "version_extract_regex": r"angular\.js[\?v=](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<1.5.0", "cve": "CVE-2015-9251",
     "severity": "HIGH"},  # Sandbox bypass

    # ── Angular 2+ ──────────────────────────────────────────────────────────
    {"library": "Angular", "detection_regex": r"@angular/core[/\-]?[\@]?(\d+\.\d+\.\d+)",
     "version_extract_regex": r"@angular/core[/\-]?[\@]?(\d+\.\d+\.\d+)",
     "vulnerable_versions": "<13.0.0", "cve": "",
     "severity": "LOW"},  # Older Angular versions no longer receive patches

    # ── React ───────────────────────────────────────────────────────────────
    {"library": "React", "detection_regex": r"react[/\-]?(\d+\.\d+\.\d+)",
     "version_extract_regex": r"react[/\-]?(\d+\.\d+\.\d+)",
     "vulnerable_versions": "<16.13.1", "cve": "CVE-2020-7693",
     "severity": "MEDIUM"},  # XSS via attribute injection in createElement
    {"library": "React", "detection_regex": r"react[/\-]?(\d+\.\d+\.\d+)",
     "version_extract_regex": r"react[/\-]?(\d+\.\d+\.\d+)",
     "vulnerable_versions": "<16.4.2", "cve": "CVE-2018-6341",
     "severity": "MEDIUM"},  # XSS in server-side renderer
    {"library": "React DOM", "detection_regex": r"react-dom[/\-]?(\d+\.\d+\.\d+)",
     "version_extract_regex": r"react-dom[/\-]?(\d+\.\d+\.\d+)",
     "vulnerable_versions": "<16.4.2", "cve": "CVE-2018-6341",
     "severity": "MEDIUM"},

    # ── Vue ─────────────────────────────────────────────────────────────────
    {"library": "Vue", "detection_regex": r"vue[/\-]?(\d+\.\d+\.\d+)",
     "version_extract_regex": r"vue[/\-]?(\d+\.\d+\.\d+)",
     "vulnerable_versions": "<2.6.11", "cve": "CVE-2019-11358",
     "severity": "MEDIUM"},  # Prototype pollution via $.extend (inherited)
    {"library": "Vue Router", "detection_regex": r"vue-router[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"vue-router[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<3.5.0", "cve": "",
     "severity": "LOW"},

    # ── Lodash ──────────────────────────────────────────────────────────────
    {"library": "lodash", "detection_regex": r"lodash[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"lodash[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.17.12", "cve": "CVE-2019-10744",
     "severity": "HIGH"},  # Prototype pollution in defaultsDeep
    {"library": "lodash", "detection_regex": r"lodash[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"lodash[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.17.20", "cve": "CVE-2020-8203",
     "severity": "HIGH"},  # Prototype pollution in zipObjectDeep
    {"library": "lodash", "detection_regex": r"lodash[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"lodash[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.17.21", "cve": "CVE-2021-23337",
     "severity": "HIGH"},  # Command injection in template
    {"library": "lodash", "detection_regex": r"lodash[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"lodash[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.17.5", "cve": "CVE-2018-3721",
     "severity": "MEDIUM"},  # Prototype pollution in set/setWith

    # ── Bootstrap ───────────────────────────────────────────────────────────
    {"library": "Bootstrap", "detection_regex": r"bootstrap[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"bootstrap[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<3.4.0", "cve": "CVE-2018-14041",
     "severity": "MEDIUM"},  # XSS via data-target
    {"library": "Bootstrap", "detection_regex": r"bootstrap[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"bootstrap[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<3.4.0", "cve": "CVE-2018-14040",
     "severity": "MEDIUM"},  # XSS via collapse data-parent
    {"library": "Bootstrap", "detection_regex": r"bootstrap[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"bootstrap[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<3.4.0", "cve": "CVE-2018-14042",
     "severity": "MEDIUM"},  # XSS in tooltip data-container
    {"library": "Bootstrap", "detection_regex": r"bootstrap[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"bootstrap[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.3.1", "cve": "CVE-2019-8331",
     "severity": "MEDIUM"},  # XSS in tooltip/popover data-template

    # ── Moment.js ───────────────────────────────────────────────────────────
    {"library": "Moment.js", "detection_regex": r"moment[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"moment[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<2.29.4", "cve": "CVE-2022-31129",
     "severity": "HIGH"},  # ReDoS
    {"library": "Moment.js", "detection_regex": r"moment[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"moment[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<2.29.2", "cve": "CVE-2022-24785",
     "severity": "HIGH"},  # Path traversal in locale

    # ── Handlebars ──────────────────────────────────────────────────────────
    {"library": "Handlebars", "detection_regex": r"handlebars[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"handlebars[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.7.7", "cve": "CVE-2021-23369",
     "severity": "CRITICAL"},  # Prototype pollution → RCE
    {"library": "Handlebars", "detection_regex": r"handlebars[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"handlebars[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.7.7", "cve": "CVE-2021-23383",
     "severity": "CRITICAL"},  # Prototype pollution

    # ── Underscore ──────────────────────────────────────────────────────────
    {"library": "Underscore.js", "detection_regex": r"underscore[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"underscore[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<1.12.1", "cve": "CVE-2021-23358",
     "severity": "CRITICAL"},  # Arbitrary code execution in template

    # ── Marked / Markdown ───────────────────────────────────────────────────
    {"library": "marked", "detection_regex": r"marked[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"marked[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.0.10", "cve": "CVE-2022-21680",
     "severity": "HIGH"},  # ReDoS
    {"library": "marked", "detection_regex": r"marked[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"marked[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.0.10", "cve": "CVE-2022-21681",
     "severity": "HIGH"},  # ReDoS in blockTokenizer

    # ── DOMPurify ───────────────────────────────────────────────────────────
    {"library": "DOMPurify", "detection_regex": r"dompurify[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"dompurify[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<2.0.17", "cve": "CVE-2020-26870",
     "severity": "HIGH"},  # mXSS bypass
    {"library": "DOMPurify", "detection_regex": r"dompurify[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"dompurify[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<2.3.5", "cve": "CVE-2021-3957",
     "severity": "MEDIUM"},  # XSS via prototype pollution chain

    # ── jszip ───────────────────────────────────────────────────────────────
    {"library": "JSZip", "detection_regex": r"jszip[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"jszip[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<3.8.0", "cve": "CVE-2022-48285",
     "severity": "HIGH"},  # Path traversal during file unzipping

    # ── CKEditor ────────────────────────────────────────────────────────────
    {"library": "CKEditor 4", "detection_regex": r"ckeditor[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"ckeditor[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.19.0", "cve": "CVE-2022-24728",
     "severity": "HIGH"},  # HTML processing XSS
    {"library": "CKEditor 4", "detection_regex": r"ckeditor[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"ckeditor[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.20.0", "cve": "CVE-2022-24729",
     "severity": "HIGH"},
    {"library": "CKEditor 5", "detection_regex": r"ckeditor5[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"ckeditor5[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<35.0.0", "cve": "",
     "severity": "MEDIUM"},

    # ── TinyMCE ─────────────────────────────────────────────────────────────
    {"library": "TinyMCE", "detection_regex": r"tinymce[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"tinymce[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<5.10.0", "cve": "CVE-2022-23494",
     "severity": "HIGH"},  # XSS via paste plugin
    {"library": "TinyMCE", "detection_regex": r"tinymce[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"tinymce[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<5.6.0", "cve": "CVE-2020-12648",
     "severity": "HIGH"},  # XSS in core
    {"library": "TinyMCE", "detection_regex": r"tinymce[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"tinymce[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<5.7.1", "cve": "CVE-2021-21908",
     "severity": "HIGH"},  # XSS via media plugin

    # ── D3.js / Chart.js / misc ─────────────────────────────────────────────
    {"library": "D3.js", "detection_regex": r"d3[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"d3[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<5.10.0", "cve": "",
     "severity": "LOW"},  # XSS in svg-formatter

    # ── Older / legacy ──────────────────────────────────────────────────────
    {"library": "Mustache.js", "detection_regex": r"mustache[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"mustache[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.1.0", "cve": "CVE-2021-43138",
     "severity": "MEDIUM"},
    {"library": "EJS", "detection_regex": r"ejs[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"ejs[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<3.1.7", "cve": "CVE-2022-29078",
     "severity": "CRITICAL"},  # RCE via opts.outputFunctionName
    {"library": "swfobject", "detection_regex": r"swfobject[\.\-](\d+\.\d+(?:\.\d+)?)",
     "version_extract_regex": r"swfobject[\.\-](\d+\.\d+(?:\.\d+)?)",
     "vulnerable_versions": "<2.2", "cve": "",
     "severity": "MEDIUM"},  # Flash-era — Flash itself EOL

    # ── Build/dev artifacts ─────────────────────────────────────────────────
    {"library": "Webpack dev-mode", "detection_regex": r"webpack-dev-server",
     "version_extract_regex": r"webpack-dev-server[/\-]?(\d+\.\d+\.\d+)?",
     "vulnerable_versions": "any", "cve": "",
     "severity": "HIGH"},  # Should not be in production
    {"library": "Vite dev-mode", "detection_regex": r"vite[/\-]?dev",
     "version_extract_regex": r"vite[/\-]?(\d+\.\d+\.\d+)?",
     "vulnerable_versions": "any", "cve": "",
     "severity": "HIGH"},  # Should not be in production
    {"library": "React DevTools", "detection_regex": r"__REACT_DEVTOOLS_GLOBAL_HOOK__",
     "version_extract_regex": r"react[/\-]?(\d+\.\d+\.\d+)?",
     "vulnerable_versions": "any", "cve": "",
     "severity": "LOW"},  # Indicates dev build in production
    {"library": "Source map exposed", "detection_regex": r"//# sourceMappingURL=",
     "version_extract_regex": r"sourceMappingURL=([^\s]+)",
     "vulnerable_versions": "any", "cve": "",
     "severity": "MEDIUM"},  # Original source leak

    # ── Modern stack newer libs ─────────────────────────────────────────────
    {"library": "Next.js", "detection_regex": r"next[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"next[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<13.5.1", "cve": "CVE-2023-46298",
     "severity": "MEDIUM"},  # Missing cache HTTP headers
    {"library": "Express", "detection_regex": r"express[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"express[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<4.19.2", "cve": "CVE-2024-29041",
     "severity": "MEDIUM"},  # Open redirect via malformed URL
    {"library": "axios", "detection_regex": r"axios[/\-](\d+\.\d+\.\d+)",
     "version_extract_regex": r"axios[/\-](\d+\.\d+\.\d+)",
     "vulnerable_versions": "<1.6.0", "cve": "CVE-2023-45857",
     "severity": "HIGH"},  # CSRF token leak via Referer

    # ── Cross-cutting library detection (no version match) ──────────────────
    {"library": "Generic JS lib", "detection_regex": r"jquery|angular|react|vue|backbone|ember|underscore|lodash",
     "version_extract_regex": r"(\d+\.\d+\.\d+)",
     "vulnerable_versions": "any", "cve": "",
     "severity": "INFO"},
]
