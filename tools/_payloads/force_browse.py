"""force_browse payload library — generated dev-time by Claude.

Regenerate via tools/_gen/gen_payloads.py force_browse. Zero runtime cost.
"""

FORCE_BROWSE_PATHS = [
  {
    "path": "/.git/config",
    "category": "source_control",
    "severity": "HIGH"
  },
  {
    "path": "/.git/HEAD",
    "category": "source_control",
    "severity": "HIGH"
  },
  {
    "path": "/.git/index",
    "category": "source_control",
    "severity": "HIGH"
  },
  {
    "path": "/.git/logs/HEAD",
    "category": "source_control",
    "severity": "HIGH"
  },
  {
    "path": "/.git/COMMIT_EDITMSG",
    "category": "source_control",
    "severity": "MEDIUM"
  },
  {
    "path": "/.git/packed-refs",
    "category": "source_control",
    "severity": "MEDIUM"
  },
  {
    "path": "/.git/refs/heads/master",
    "category": "source_control",
    "severity": "MEDIUM"
  },
  {
    "path": "/.git/refs/heads/main",
    "category": "source_control",
    "severity": "MEDIUM"
  },
  {
    "path": "/.git/objects/info/packs",
    "category": "source_control",
    "severity": "HIGH"
  },
  {
    "path": "/.gitignore",
    "category": "source_control",
    "severity": "LOW"
  },
  {
    "path": "/.gitmodules",
    "category": "source_control",
    "severity": "LOW"
  },
  {
    "path": "/.svn/entries",
    "category": "source_control",
    "severity": "HIGH"
  },
  {
    "path": "/.svn/wc.db",
    "category": "source_control",
    "severity": "HIGH"
  },
  {
    "path": "/.svn/pristine",
    "category": "source_control",
    "severity": "MEDIUM"
  },
  {
    "path": "/.hg/store/00manifest.i",
    "category": "source_control",
    "severity": "HIGH"
  },
  {
    "path": "/.hg/hgrc",
    "category": "source_control",
    "severity": "HIGH"
  },
  {
    "path": "/.bzr/branch/branch.conf",
    "category": "source_control",
    "severity": "HIGH"
  },
  {
    "path": "/CVS/Root",
    "category": "source_control",
    "severity": "MEDIUM"
  },
  {
    "path": "/CVS/Entries",
    "category": "source_control",
    "severity": "MEDIUM"
  },
  {
    "path": "/.env",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/.env.local",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/.env.production",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/.env.staging",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/.env.development",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/.env.backup",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/.env.old",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/.env.bak",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/.env.example",
    "category": "config_exposure",
    "severity": "MEDIUM"
  },
  {
    "path": "/.env.sample",
    "category": "config_exposure",
    "severity": "MEDIUM"
  },
  {
    "path": "/wp-config.php",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/wp-config.php.bak",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/wp-config.php.old",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/wp-config.php~",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/wp-config.txt",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/wp-config.php.save",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/config.php",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/config.php.bak",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/config.php.old",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/configuration.php",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/configuration.php.bak",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/settings.php",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/settings.py",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/settings.yml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/settings.yaml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/config.yml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/config.yaml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/config.json",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/config.xml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/config.ini",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/app.config",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/web.config",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/web.config.bak",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/database.yml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/database.yaml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/db.php",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/db_config.php",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/application.properties",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/application.yml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/application-prod.yml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/application-dev.yml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/bootstrap.yml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/secrets.yml",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/secrets.json",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/secrets.yaml",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/secret.txt",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/credentials.json",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/credentials.xml",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/credentials.txt",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/passwords.txt",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/passwords.xml",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/passwd",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/private.key",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/private.pem",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/id_rsa",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/id_rsa.pub",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/server.key",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/server.pem",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/ssl.key",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/certificate.pem",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.ssh/id_rsa",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.ssh/authorized_keys",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/backup.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/backup.sql.gz",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/dump.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/db_backup.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/database.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/database.sql.gz",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/backup.tar.gz",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/backup.zip",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/backup.tar",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/site.tar.gz",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/www.tar.gz",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/web.tar.gz",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/files.tar.gz",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/backup/backup.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/backups/backup.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/old/index.php",
    "category": "backup_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/index.php.bak",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/index.php.old",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/index.php~",
    "category": "backup_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/index.html.bak",
    "category": "backup_files",
    "severity": "LOW"
  },
  {
    "path": "/admin/backup.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/wp-content/backup",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/wp-content/uploads/backup.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/error.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/access.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/debug.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/application.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/app.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/server.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/system.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/php_error.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/php-errors.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/laravel.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/storage/logs/laravel.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/logs/error.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/logs/access.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/logs/debug.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/logs/application.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/log/error.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/log/debug.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/var/log/nginx/access.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/var/log/apache2/error.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/tmp/error.log",
    "category": "log_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/admin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/admin/",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/admin/login",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/admin/index.php",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/administrator",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/administrator/index.php",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/wp-admin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/wp-admin/",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/wp-login.php",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/wp-admin/admin-ajax.php",
    "category": "admin_panel",
    "severity": "MEDIUM"
  },
  {
    "path": "/joomla/administrator",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/drupal/admin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/panel",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/panel/login",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/controlpanel",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/cpanel",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/phpmyadmin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/phpmyadmin/",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/pma",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/phpMyAdmin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/mysql",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/myadmin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/adminer.php",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/adminer",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/backend",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/backend/login",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/manager",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/management",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/sysadmin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/webadmin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/moderator",
    "category": "admin_panel",
    "severity": "MEDIUM"
  },
  {
    "path": "/superadmin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/console",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/rails/info/properties",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/rails/info/routes",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/__debug__",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/__debugbar",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/_debugbar",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/debug",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/debug/",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/debug/pprof",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/telescope",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/telescope/requests",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/horizon",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/horizon/dashboard",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/_profiler",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/_profiler/phpinfo",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/phpinfo.php",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/info.php",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/test.php",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/test.html",
    "category": "dev_debug",
    "severity": "LOW"
  },
  {
    "path": "/dev",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/development",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/staging",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/status",
    "category": "dev_debug",
    "severity": "LOW"
  },
  {
    "path": "/server-status",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/server-info",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/actuator",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/actuator/env",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/actuator/health",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/actuator/metrics",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/actuator/mappings",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/actuator/configprops",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/actuator/beans",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/actuator/httptrace",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/actuator/threaddump",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/actuator/heapdump",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/actuator/loggers",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/actuator/info",
    "category": "dev_debug",
    "severity": "LOW"
  },
  {
    "path": "/actuator/auditevents",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/actuator/scheduledtasks",
    "category": "dev_debug",
    "severity": "LOW"
  },
  {
    "path": "/api/debug",
    "category": "api_debug",
    "severity": "HIGH"
  },
  {
    "path": "/api/v1/debug",
    "category": "api_debug",
    "severity": "HIGH"
  },
  {
    "path": "/api/v2/debug",
    "category": "api_debug",
    "severity": "HIGH"
  },
  {
    "path": "/api/swagger",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/api/swagger-ui.html",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/api/swagger.json",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/api/swagger.yaml",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/swagger",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/swagger-ui",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/swagger-ui.html",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/swagger/index.html",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/swagger.json",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/swagger.yaml",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/openapi.json",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/openapi.yaml",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/v2/api-docs",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/v3/api-docs",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/graphql",
    "category": "api_debug",
    "severity": "HIGH"
  },
  {
    "path": "/graphiql",
    "category": "api_debug",
    "severity": "HIGH"
  },
  {
    "path": "/playground",
    "category": "api_debug",
    "severity": "HIGH"
  },
  {
    "path": "/api/graphql",
    "category": "api_debug",
    "severity": "HIGH"
  },
  {
    "path": "/api/v1",
    "category": "api_debug",
    "severity": "LOW"
  },
  {
    "path": "/api/v2",
    "category": "api_debug",
    "severity": "LOW"
  },
  {
    "path": "/api/users",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/api/admin",
    "category": "api_debug",
    "severity": "HIGH"
  },
  {
    "path": "/api/config",
    "category": "api_debug",
    "severity": "HIGH"
  },
  {
    "path": "/api/env",
    "category": "api_debug",
    "severity": "HIGH"
  },
  {
    "path": "/api/health",
    "category": "api_debug",
    "severity": "LOW"
  },
  {
    "path": "/api/status",
    "category": "api_debug",
    "severity": "LOW"
  },
  {
    "path": "/rest/v1/users",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/rest/v2/users",
    "category": "api_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/.idea/workspace.xml",
    "category": "ide_editor",
    "severity": "HIGH"
  },
  {
    "path": "/.idea/dataSources.xml",
    "category": "ide_editor",
    "severity": "HIGH"
  },
  {
    "path": "/.idea/dataSources.local.xml",
    "category": "ide_editor",
    "severity": "HIGH"
  },
  {
    "path": "/.idea/dbnavigator.xml",
    "category": "ide_editor",
    "severity": "HIGH"
  },
  {
    "path": "/.idea/.name",
    "category": "ide_editor",
    "severity": "LOW"
  },
  {
    "path": "/.vscode/settings.json",
    "category": "ide_editor",
    "severity": "HIGH"
  },
  {
    "path": "/.vscode/launch.json",
    "category": "ide_editor",
    "severity": "HIGH"
  },
  {
    "path": "/.vscode/extensions.json",
    "category": "ide_editor",
    "severity": "LOW"
  },
  {
    "path": "/.vscode/tasks.json",
    "category": "ide_editor",
    "severity": "LOW"
  },
  {
    "path": "/.sublime-project",
    "category": "ide_editor",
    "severity": "MEDIUM"
  },
  {
    "path": "/.sublime-workspace",
    "category": "ide_editor",
    "severity": "MEDIUM"
  },
  {
    "path": "/.project",
    "category": "ide_editor",
    "severity": "LOW"
  },
  {
    "path": "/.classpath",
    "category": "ide_editor",
    "severity": "LOW"
  },
  {
    "path": "/.settings/org.eclipse.core.resources.prefs",
    "category": "ide_editor",
    "severity": "LOW"
  },
  {
    "path": "/nbproject/project.properties",
    "category": "ide_editor",
    "severity": "MEDIUM"
  },
  {
    "path": "/nbproject/private/private.properties",
    "category": "ide_editor",
    "severity": "HIGH"
  },
  {
    "path": "/.Rhistory",
    "category": "ide_editor",
    "severity": "MEDIUM"
  },
  {
    "path": "/.Rprofile",
    "category": "ide_editor",
    "severity": "MEDIUM"
  },
  {
    "path": "/.DS_Store",
    "category": "ide_editor",
    "severity": "LOW"
  },
  {
    "path": "/Thumbs.db",
    "category": "ide_editor",
    "severity": "LOW"
  },
  {
    "path": "/.travis.yml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/.circleci/config.yml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/.github/workflows/deploy.yml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/.github/workflows/main.yml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/Jenkinsfile",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/.gitlab-ci.yml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/bitbucket-pipelines.yml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/azure-pipelines.yml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/wercker.yml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/.drone.yml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/buildspec.yml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/Makefile",
    "category": "ci_build",
    "severity": "LOW"
  },
  {
    "path": "/Dockerfile",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/docker-compose.yml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/docker-compose.yaml",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/docker-compose.prod.yml",
    "category": "ci_build",
    "severity": "HIGH"
  },
  {
    "path": "/docker-compose.override.yml",
    "category": "ci_build",
    "severity": "HIGH"
  },
  {
    "path": "/Vagrantfile",
    "category": "ci_build",
    "severity": "MEDIUM"
  },
  {
    "path": "/build/",
    "category": "ci_build",
    "severity": "LOW"
  },
  {
    "path": "/dist/",
    "category": "ci_build",
    "severity": "LOW"
  },
  {
    "path": "/target/",
    "category": "ci_build",
    "severity": "LOW"
  },
  {
    "path": "/out/",
    "category": "ci_build",
    "severity": "LOW"
  },
  {
    "path": "/release/",
    "category": "ci_build",
    "severity": "LOW"
  },
  {
    "path": "/.aws/credentials",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/.aws/config",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/aws.yml",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/aws.json",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/gcp-service-account.json",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/service-account.json",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/google-credentials.json",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/.gcloud/application_default_credentials.json",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/azure.json",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/.azure/credentials",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/terraform.tfvars",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/terraform.tfstate",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/terraform.tfstate.backup",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/.terraform/terraform.tfstate",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/pulumi.yaml",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/serverless.yml",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/cloudformation.yml",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/ansible.cfg",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/inventory",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/inventory.yml",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/tmp/",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/temp/",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/uploads/",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/upload/",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/files/",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/cache/",
    "category": "temp_upload",
    "severity": "LOW"
  },
  {
    "path": "/data/",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/storage/",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/private/",
    "category": "temp_upload",
    "severity": "HIGH"
  },
  {
    "path": "/public/uploads/",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/media/uploads/",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/assets/uploads/",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/wp-content/uploads/",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/wp-content/cache/",
    "category": "temp_upload",
    "severity": "LOW"
  },
  {
    "path": "/tmp/upload",
    "category": "temp_upload",
    "severity": "MEDIUM"
  },
  {
    "path": "/upload.php",
    "category": "temp_upload",
    "severity": "HIGH"
  },
  {
    "path": "/fileupload.php",
    "category": "temp_upload",
    "severity": "HIGH"
  },
  {
    "path": "/wp-login.php",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/wp-json/wp/v2/users",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/wp-json/wp/v2/posts",
    "category": "cms_exposed",
    "severity": "MEDIUM"
  },
  {
    "path": "/wp-content/debug.log",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/wp-content/plugins/",
    "category": "cms_exposed",
    "severity": "LOW"
  },
  {
    "path": "/wp-includes/",
    "category": "cms_exposed",
    "severity": "LOW"
  },
  {
    "path": "/xmlrpc.php",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/wp-cron.php",
    "category": "cms_exposed",
    "severity": "MEDIUM"
  },
  {
    "path": "/administrator/manifests/files/joomla.xml",
    "category": "cms_exposed",
    "severity": "MEDIUM"
  },
  {
    "path": "/joomla.xml",
    "category": "cms_exposed",
    "severity": "MEDIUM"
  },
  {
    "path": "/configuration.php",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/templates/",
    "category": "cms_exposed",
    "severity": "LOW"
  },
  {
    "path": "/components/",
    "category": "cms_exposed",
    "severity": "LOW"
  },
  {
    "path": "/modules/",
    "category": "cms_exposed",
    "severity": "LOW"
  },
  {
    "path": "/plugins/",
    "category": "cms_exposed",
    "severity": "LOW"
  },
  {
    "path": "/sites/default/settings.php",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/sites/default/files/",
    "category": "cms_exposed",
    "severity": "MEDIUM"
  },
  {
    "path": "/user/login",
    "category": "cms_exposed",
    "severity": "LOW"
  },
  {
    "path": "/user/register",
    "category": "cms_exposed",
    "severity": "LOW"
  },
  {
    "path": "/update.php",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/install.php",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/typo3/",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/typo3conf/LocalConfiguration.php",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/contao/main.php",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/magento/",
    "category": "cms_exposed",
    "severity": "MEDIUM"
  },
  {
    "path": "/app/etc/local.xml",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/app/etc/env.php",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/var/export/",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/shell/",
    "category": "cms_exposed",
    "severity": "HIGH"
  },
  {
    "path": "/composer.json",
    "category": "common_app",
    "severity": "MEDIUM"
  },
  {
    "path": "/composer.lock",
    "category": "common_app",
    "severity": "MEDIUM"
  },
  {
    "path": "/package.json",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/package-lock.json",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/yarn.lock",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/Gemfile",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/Gemfile.lock",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/requirements.txt",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/pipfile",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/Pipfile.lock",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/pom.xml",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/build.gradle",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/Cargo.toml",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/go.mod",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/go.sum",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/mix.exs",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/pubspec.yaml",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/setup.py",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/setup.cfg",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/phpunit.xml",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/phpunit.xml.dist",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/karma.conf.js",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/webpack.config.js",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/webpack.config.prod.js",
    "category": "common_app",
    "severity": "MEDIUM"
  },
  {
    "path": "/gulpfile.js",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/Gruntfile.js",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/robots.txt",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/sitemap.xml",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/crossdomain.xml",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/clientaccesspolicy.xml",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/.well-known/security.txt",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/humans.txt",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/CHANGELOG.md",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/CHANGELOG.txt",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/README.md",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/README.txt",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/LICENSE",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/VERSION",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/version.txt",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/release-notes.txt",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/INSTALL.md",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/TODO",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/TODO.md",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/SECURITY.md",
    "category": "common_app",
    "severity": "LOW"
  },
  {
    "path": "/.htaccess",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/.htpasswd",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/.htaccess.bak",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/.htpasswd.bak",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/nginx.conf",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/httpd.conf",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/apache.conf",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/lighttpd.conf",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/server.xml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/context.xml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/web.xml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/persistence.xml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/log4j.properties",
    "category": "config_exposure",
    "severity": "MEDIUM"
  },
  {
    "path": "/log4j2.xml",
    "category": "config_exposure",
    "severity": "MEDIUM"
  },
  {
    "path": "/logback.xml",
    "category": "config_exposure",
    "severity": "MEDIUM"
  },
  {
    "path": "/WEB-INF/web.xml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/WEB-INF/applicationContext.xml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/WEB-INF/classes/",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/WEB-INF/lib/",
    "category": "config_exposure",
    "severity": "MEDIUM"
  },
  {
    "path": "/WEB-INF/struts-config.xml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/WEB-INF/hibernate.cfg.xml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/META-INF/MANIFEST.MF",
    "category": "config_exposure",
    "severity": "MEDIUM"
  },
  {
    "path": "/META-INF/context.xml",
    "category": "config_exposure",
    "severity": "HIGH"
  },
  {
    "path": "/health",
    "category": "dev_debug",
    "severity": "LOW"
  },
  {
    "path": "/healthz",
    "category": "dev_debug",
    "severity": "LOW"
  },
  {
    "path": "/readyz",
    "category": "dev_debug",
    "severity": "LOW"
  },
  {
    "path": "/livez",
    "category": "dev_debug",
    "severity": "LOW"
  },
  {
    "path": "/metrics",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/prometheus",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/trace",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/tracing",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/env",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/config",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/vars",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/info",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/dump",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/heap",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/goroutine",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/block",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/cmdline",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/profile",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/symbol",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/node/debug",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/node_modules/.bin/",
    "category": "dev_debug",
    "severity": "LOW"
  },
  {
    "path": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/vendor/phpunit/phpunit/phpunit",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/vendor/composer/installed.json",
    "category": "dev_debug",
    "severity": "MEDIUM"
  },
  {
    "path": "/vendor/",
    "category": "dev_debug",
    "severity": "LOW"
  },
  {
    "path": "/flask/debug",
    "category": "dev_debug",
    "severity": "HIGH"
  },
  {
    "path": "/console/",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/rails/console",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/system/console",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/felix/console",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/jolokia",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/jolokia/list",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/jolokia/exec",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/hawtio",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/solr/admin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/solr/admin/cores",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/kibana",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/elasticsearch",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/_cat/indices",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/_cluster/health",
    "category": "admin_panel",
    "severity": "MEDIUM"
  },
  {
    "path": "/_nodes",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/mongo-express",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/redis-commander",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/rabbitmq",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/api/rabbitmq",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/management/api",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/flower",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/airflow",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/airflow/admin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/grafana",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/prometheus/targets",
    "category": "admin_panel",
    "severity": "MEDIUM"
  },
  {
    "path": "/jaeger",
    "category": "admin_panel",
    "severity": "MEDIUM"
  },
  {
    "path": "/zipkin",
    "category": "admin_panel",
    "severity": "MEDIUM"
  },
  {
    "path": "/portainer",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/registry/v2",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/v2/_catalog",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/jenkins",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/jenkins/script",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/jenkins/systemInfo",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/jmx",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/druid",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/druid/index.html",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/django-admin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/django/admin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/admin/django",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/login",
    "category": "admin_panel",
    "severity": "LOW"
  },
  {
    "path": "/signup",
    "category": "admin_panel",
    "severity": "LOW"
  },
  {
    "path": "/register",
    "category": "admin_panel",
    "severity": "LOW"
  },
  {
    "path": "/forgot-password",
    "category": "admin_panel",
    "severity": "LOW"
  },
  {
    "path": "/reset-password",
    "category": "admin_panel",
    "severity": "LOW"
  },
  {
    "path": "/user/admin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/users",
    "category": "admin_panel",
    "severity": "MEDIUM"
  },
  {
    "path": "/api/users/admin",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/api/admin/users",
    "category": "admin_panel",
    "severity": "HIGH"
  },
  {
    "path": "/sftp-config.json",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.ftpconfig",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.netrc",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.pgpass",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.my.cnf",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.mysql_history",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.bash_history",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.bash_profile",
    "category": "secret_store",
    "severity": "MEDIUM"
  },
  {
    "path": "/.bashrc",
    "category": "secret_store",
    "severity": "MEDIUM"
  },
  {
    "path": "/.profile",
    "category": "secret_store",
    "severity": "MEDIUM"
  },
  {
    "path": "/.zsh_history",
    "category": "secret_store",
    "severity": "MEDIUM"
  },
  {
    "path": "/.zshrc",
    "category": "secret_store",
    "severity": "LOW"
  },
  {
    "path": "/.npmrc",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.pypirc",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.gem/credentials",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.docker/config.json",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.kube/config",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.boto",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.s3cfg",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.passwd-s3fs",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/vault",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/vault/v1/secret",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/vault/v1/sys/health",
    "category": "secret_store",
    "severity": "MEDIUM"
  },
  {
    "path": "/v1/sys/mounts",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/v1/auth/token/lookup-self",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/keystore",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/keystore.jks",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/truststore.jks",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/.keystore",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/server.jks",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/app.jks",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/app.p12",
    "category": "secret_store",
    "severity": "HIGH"
  },
  {
    "path": "/backup.tar.bz2",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/web-backup.zip",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/htdocs.tar.gz",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/html.tar.gz",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/public_html.tar.gz",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/full_backup.zip",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/db.dump",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/mysql.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/mysql.sql.gz",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/db_dump.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/backup_db.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/backup/",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/backups/",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/bak/",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/archive/",
    "category": "backup_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/old/",
    "category": "backup_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/prev/",
    "category": "backup_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/previous/",
    "category": "backup_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/original/",
    "category": "backup_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/snapshot/",
    "category": "backup_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/copy/",
    "category": "backup_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/2022/",
    "category": "backup_files",
    "severity": "LOW"
  },
  {
    "path": "/2023/",
    "category": "backup_files",
    "severity": "LOW"
  },
  {
    "path": "/2024/",
    "category": "backup_files",
    "severity": "LOW"
  },
  {
    "path": "/test_db.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/testdb.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/prod_backup.zip",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/production_db.sql",
    "category": "backup_files",
    "severity": "HIGH"
  },
  {
    "path": "/logs/",
    "category": "log_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/log/",
    "category": "log_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/var/log/",
    "category": "log_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/error_log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/errors.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/error.txt",
    "category": "log_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/system.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/security.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/audit.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/transaction.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/payment.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/auth.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/authentication.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/login.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/user.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/mail.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/smtp.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/cron.log",
    "category": "log_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/runtime.log",
    "category": "log_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/exception.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/query.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/sql.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/db.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/catalina.out",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/spring.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/rails.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/development.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/production.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/test.log",
    "category": "log_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/celery.log",
    "category": "log_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/worker.log",
    "category": "log_files",
    "severity": "MEDIUM"
  },
  {
    "path": "/api.log",
    "category": "log_files",
    "severity": "HIGH"
  },
  {
    "path": "/cloud-init.log",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/cloud-init-output.log",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/user-data",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/latest/meta-data/",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/latest/user-data",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/opc/v1/instance",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/metadata/instance",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/computeMetadata/v1/",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/metadata/v1/user-data",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/helm/",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/charts/",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/k8s/",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/kubernetes/",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/kustomization.yaml",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/skaffold.yaml",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/tilt.yaml",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/istio.yaml",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/cluster.yml",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/values.yaml",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/values-prod.yaml",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/values-secret.yaml",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/override.yaml",
    "category": "cloud_config",
    "severity": "MEDIUM"
  },
  {
    "path": "/aws-credentials",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/gcs-credentials.json",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/s3-config.json",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/storage.json",
    "category": "cloud_config",
    "severity": "HIGH"
  },
  {
    "path": "/gsutil.config",
    "category": "cloud_config",
    "severity": "HIGH"
  }
]
