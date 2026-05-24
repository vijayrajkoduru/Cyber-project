"""Webapp Phase-2 dev-time asset generator.

Mirrors gen_webapp_assets.py / gen_vuln_assets.py / gen_recon_assets.py.
Writes to /tmp/vl_payloads/ — review then copy into tools/_payloads/.

6 CONFIGS for the newly-wired (tier11-13) webapp scanners that still
use hardcoded inline lists:

  retire_js_signatures             — 200 JS library CVE signatures
  oauth_redirect_bypass_payloads   —  80 OAuth redirect_uri bypass payloads
  csp_bypass_gadgets               — 120 CSP bypass gadgets
  file_upload_bypass_extensions    —  80 file-upload extension/MIME bypasses
  drupal_scan_paths                — 150 Drupal-specific paths + CVE markers
  joomla_scan_paths                — 150 Joomla-specific paths + CVE markers
"""
import json, os, re, sys
import anthropic

CONFIGS = {
    "retire_js_signatures": {
        "max_tokens": 18000, "var": "RETIRE_JS_SIGNATURES",
        "prompt": """Generate 200 JavaScript library CVE signatures for a Retire.js-style scanner.
Each entry detects a specific JS lib by URL/path/content + version, and flags
if version is vulnerable.

REQUIRED coverage:
- jQuery + jQuery UI (every CVE'd version range) — 25
- Angular (1.x AND 2+, all CVE'd) — 20
- React + React-DOM (versions with XSS bypass CVEs) — 15
- Vue / Vue Router — 10
- Lodash (prototype pollution CVE range) — 12
- Bootstrap 3.x, 4.x, 5.x (CVE'd XSS in tooltip etc) — 15
- Moment.js (vulnerable versions) — 8
- Underscore.js — 5
- Handlebars (template-injection CVEs) — 8
- Marked + Markdown libs — 6
- DOMPurify (CVE-fixed versions) — 6
- jsZip — 4
- CKEditor 4.x, 5.x — 10
- TinyMCE — 10
- D3.js — 5
- Chart.js — 5
- swfobject / older Flash-era libs — 6
- AngularJS 1.x specific (Strict Contextual Escaping bypass) — 10
- Vite/Webpack dev artifacts (devmode markers) — 8
- Generic node_modules/lib path patterns — 17

Each item EXACTLY 6 keys:
  library (string),
  detection_regex (Python regex to find in HTML/JS source <80 chars),
  version_extract_regex (Python regex with one capture group for version <80 chars),
  vulnerable_versions (string range like "<3.5.0" or ">=1.0,<1.12"),
  cve (single CVE-XXXX-XXXXX or empty string for general bug),
  severity (CRITICAL|HIGH|MEDIUM)

OUTPUT: ONLY JSON array. Start [ end ]. No prose. Escape backslashes for JSON."""
    },

    "oauth_redirect_bypass_payloads": {
        "max_tokens": 6000, "var": "OAUTH_REDIRECT_BYPASS_PAYLOADS",
        "prompt": """Generate 80 OAuth/OIDC redirect_uri bypass payloads for a webapp scanner.

Mix:
- Wildcard subdomain confusion (attacker.victim.com) — 12
- Path traversal in redirect_uri — 10
- Open-redirect chains via state parameter — 8
- Fragment injection (#@attacker.com) — 10
- URL parsing inconsistencies (\\@attacker, /\\\\@attacker) — 10
- Userinfo abuse (victim.com@attacker.com) — 8
- Double-encoding bypasses — 8
- Mixed scheme (javascript:, data:) — 6
- Cross-origin postMessage abuse markers — 8

Each item EXACTLY 4 keys:
  payload (string — the redirect_uri value to test),
  bypass_category (snake_case),
  expected_behavior (1-line description),
  severity (CRITICAL|HIGH|MEDIUM)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "csp_bypass_gadgets": {
        "max_tokens": 14000, "var": "CSP_BYPASS_GADGETS",
        "prompt": """Generate 120 Content-Security-Policy bypass gadgets for a webapp scanner.

Each gadget is a hostname / pattern that, if allowed by CSP, lets an attacker
execute arbitrary JS via that source.

Mix:
- Google CDN JSONP endpoints (ajax.googleapis.com, etc.) — 15
- AWS S3 / CloudFront wildcard bypass — 10
- jsDelivr / unpkg / cdnjs combiner endpoints — 15
- Facebook/Twitter SDK JSONP bypass — 10
- Akamai / Fastly CDN-specific abuse — 10
- Wildcard scheme bypass (https:, blob:, data:) — 12
- unsafe-inline / unsafe-eval / unsafe-hashes detection — 15
- 'self' bypass via open redirect — 8
- nonce reuse / weak nonce CSPs — 10
- Strict-dynamic without integrity — 8
- Report-only mode (no enforcement) — 7

Each item EXACTLY 5 keys:
  gadget (string — the host/scheme/pattern that bypasses),
  csp_directive (script-src|default-src|object-src|frame-src),
  bypass_type (snake_case),
  severity (CRITICAL|HIGH|MEDIUM),
  reference (1-line how the bypass works)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "file_upload_bypass_extensions": {
        "max_tokens": 8000, "var": "FILE_UPLOAD_BYPASS_EXTENSIONS",
        "prompt": """Generate 80 file-upload extension/MIME-bypass entries for a webapp scanner.

Each entry attempts to evade upload validation while still being executable.

Mix:
- Double-extension (.jpg.php, .png.phtml) — 15
- Null-byte injection (.php%00.jpg) — 8
- Trailing dots/spaces (.php., .php  ) — 8
- Alt PHP exts (.phtml, .phps, .phar, .pht, .php5, .php7) — 10
- Apache .htaccess / web.config — 5
- ASP.NET (.aspx, .asax, .ashx, .config) — 8
- JSP (.jsp, .jspx, .jsw) — 6
- MIME-type spoofing (Content-Type: image/jpeg, but body is PHP) — 8
- Path traversal in filename (../../etc/cron.d/x.php) — 6
- Polyglot (GIF/PHP, GIF/JS hybrids) — 6

Each item EXACTLY 5 keys:
  filename (string — including extension/encoding),
  content_type (HTTP Content-Type header to send),
  technique (snake_case),
  severity (CRITICAL|HIGH|MEDIUM),
  remediation_hint (1-line server fix)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "drupal_scan_paths": {
        "max_tokens": 14000, "var": "DRUPAL_SCAN_PATHS",
        "prompt": """Generate 150 Drupal-specific paths + CVE markers for a Drupal vulnerability scanner.

Mix:
- Core admin paths (/user/login, /admin, /admin/config, /admin/people) — 20
- CVE-2018-7600 (Drupalgeddon2) endpoints + form_id markers — 15
- CVE-2019-6340 (REST module RCE) markers — 10
- Coder module RCE (CVE-2016-?) — 5
- Module/theme info file paths (.info / .info.yml) — 10
- CHANGELOG.txt / MAINTAINERS.txt for version detection — 10
- Drupal 6, 7, 8, 9, 10 core file paths — 25
- Common contrib module paths (views, ctools, libraries) — 20
- Drupal-specific JSON-API endpoints — 10
- Update.php / install.php / cron.php access checks — 8
- Devel module markers — 7
- Composer / vendor leakage paths — 10

Each item EXACTLY 5 keys:
  path (with leading /),
  category (snake_case),
  drupal_version_hint (string like "7" or "8+" or empty),
  cve (single CVE-XXXX-XXXXX or empty),
  severity (CRITICAL|HIGH|MEDIUM|LOW|INFO)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "joomla_scan_paths": {
        "max_tokens": 14000, "var": "JOOMLA_SCAN_PATHS",
        "prompt": """Generate 150 Joomla-specific paths + CVE markers for a Joomla vulnerability scanner.

Mix:
- Core admin paths (/administrator, /administrator/index.php) — 15
- Configuration.php / xmlrpc / install dirs — 12
- CVE-2015-8562 (RCE via UserAgent) markers — 8
- CVE-2023-23752 (Information Disclosure /api/index.php) — 8
- Joomla 1.5, 2.5, 3.x, 4.x, 5.x core file paths — 25
- Component paths (com_users, com_content, com_contact) — 25
- Module paths (mod_*) — 15
- Plugin paths (plg_*) — 15
- Manifest XML files (administrator/manifests) — 10
- README.txt / CHANGELOG / license files — 8
- Template paths (templates/protostar, /system) — 10
- Cache / tmp / logs leakage — 8
- htaccess.txt / robots.txt.dist defaults — 6

Each item EXACTLY 5 keys:
  path (with leading /),
  category (snake_case),
  joomla_version_hint (string like "3.x" or "4+" or empty),
  cve (single CVE-XXXX-XXXXX or empty),
  severity (CRITICAL|HIGH|MEDIUM|LOW|INFO)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },
}


def salvage(raw):
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
        sys.exit(f"Usage: gen_webapp_assets_v2.py {list(CONFIGS.keys())}")
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
        f.write(f'"""{kind} - generated dev-time by Claude. Webapp module phase-2 asset.\n"""\n\n')
        f.write(f'{cfg["var"]} = ')
        f.write(pprint.pformat(items, width=120, sort_dicts=False))
        f.write("\n")
    cost = (in_tok * 3 + out_tok * 15) / 1_000_000
    print(f"  ✓ wrote {len(items)} items to {out}")
    print(f"  tokens: {in_tok} in, {out_tok} out  |  cost: ~${cost:.3f}")


if __name__ == "__main__":
    main()
