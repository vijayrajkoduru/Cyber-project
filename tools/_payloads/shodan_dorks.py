"""shodan_dorks — generated dev-time by Claude. Recon module asset.
"""

SHODAN_DORKS = [
  {
    "name": "Exposed Jenkins Admin Panel",
    "platform": "shodan",
    "query": "http.title:\"Dashboard [Jenkins]\"",
    "category": "ci_cd",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Open MongoDB Instance",
    "platform": "shodan",
    "query": "product:\"MongoDB\" port:27017 -authentication",
    "category": "database",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Elasticsearch Node",
    "platform": "shodan",
    "query": "port:9200 json:{\"cluster_name\"",
    "category": "database",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Open Redis Server",
    "platform": "shodan",
    "query": "product:\"Redis\" port:6379 -auth",
    "category": "database",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Kubernetes API Server",
    "platform": "shodan",
    "query": "port:8443 http.title:\"Kubernetes\" ssl",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Docker API",
    "platform": "shodan",
    "query": "port:2375 product:\"Docker\"",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed phpinfo Page",
    "platform": "shodan",
    "query": "http.title:\"phpinfo()\"",
    "category": "debug",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Default Netgear Router Login",
    "platform": "shodan",
    "query": "http.title:\"NETGEAR\" http.html:\"admin\"",
    "category": "iot",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed IP Camera Stream (Hikvision)",
    "platform": "shodan",
    "query": "http.title:\"Hikvision\" port:80",
    "category": "camera",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Grafana Dashboard",
    "platform": "shodan",
    "query": "http.title:\"Grafana\" http.status:200",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "GitLab CE Exposed Instance",
    "platform": "shodan",
    "query": "http.title:\"GitLab\" http.favicon.hash:\"1278323681\"",
    "category": "ci_cd",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Drone CI Instance",
    "platform": "shodan",
    "query": "http.title:\"Drone\" http.html:\"drone.io\"",
    "category": "ci_cd",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Apache Solr Admin",
    "platform": "shodan",
    "query": "http.title:\"Solr Admin\" port:8983",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed RabbitMQ Management Panel",
    "platform": "shodan",
    "query": "http.title:\"RabbitMQ Management\" port:15672",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Kibana Dashboard",
    "platform": "shodan",
    "query": "http.title:\"Kibana\" port:5601",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Default MikroTik Router Login",
    "platform": "shodan",
    "query": "http.title:\"RouterOS\" http.html:\"MikroTik\"",
    "category": "iot",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Hadoop YARN Resource Manager",
    "platform": "shodan",
    "query": "http.title:\"ResourceManager\" port:8088",
    "category": "admin_panel",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Memcached Server",
    "platform": "shodan",
    "query": "product:\"Memcached\" port:11211",
    "category": "database",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Cassandra Database",
    "platform": "shodan",
    "query": "product:\"Cassandra\" port:9042",
    "category": "database",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed CouchDB Instance",
    "platform": "shodan",
    "query": "product:\"CouchDB\" port:5984",
    "category": "database",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Jupyter Notebook",
    "platform": "shodan",
    "query": "http.title:\"Jupyter Notebook\" http.status:200",
    "category": "debug",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Cisco Router Default Login",
    "platform": "shodan",
    "query": "http.title:\"Cisco\" http.html:\"username\" http.html:\"password\"",
    "category": "iot",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Dahua Camera Stream",
    "platform": "shodan",
    "query": "http.title:\"Dahua\" port:80 http.html:\"camera\"",
    "category": "camera",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Axis Camera Network Video",
    "platform": "shodan",
    "query": "http.title:\"AXIS\" port:80 http.html:\"video\"",
    "category": "camera",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Kubernetes Dashboard",
    "platform": "shodan",
    "query": "http.title:\"Kubernetes Dashboard\" port:443",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Docker Swarm API",
    "platform": "shodan",
    "query": "port:2377 product:\"Docker Swarm\"",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed etcd Cluster",
    "platform": "shodan",
    "query": "port:2379 http.html:\"etcd\"",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Zookeeper Instance",
    "platform": "shodan",
    "query": "port:2181 product:\"Zookeeper\"",
    "category": "database",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Laravel Debug Page",
    "platform": "shodan",
    "query": "http.title:\"Whoops! There was an error.\" http.html:\"Laravel\"",
    "category": "debug",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Spring Boot Actuator",
    "platform": "shodan",
    "query": "http.html:\"/actuator/health\" http.status:200",
    "category": "debug",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed WordPress Admin Panel",
    "platform": "shodan",
    "query": "http.title:\"WordPress\" http.html:\"wp-login.php\"",
    "category": "admin_panel",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed Nagios Monitoring Panel",
    "platform": "shodan",
    "query": "http.title:\"Nagios\" http.html:\"nagios\"",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Prometheus Metrics",
    "platform": "shodan",
    "query": "http.title:\"Prometheus Time Series\" port:9090",
    "category": "admin_panel",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed OpenTSDB Instance",
    "platform": "shodan",
    "query": "http.title:\"OpenTSDB\" port:4242",
    "category": "database",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Portainer Docker UI",
    "platform": "shodan",
    "query": "http.title:\"Portainer\" port:9000",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Traefik Dashboard",
    "platform": "shodan",
    "query": "http.title:\"Traefik\" port:8080",
    "category": "admin_panel",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed MongoDB Atlas (port scan)",
    "platform": "censys",
    "query": "services.port:27017 AND services.service_name:MONGODB",
    "category": "database",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Elasticsearch Cluster on Censys",
    "platform": "censys",
    "query": "services.port:9200 AND services.http.response.body:\"cluster_name\"",
    "category": "database",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Redis on Censys",
    "platform": "censys",
    "query": "services.port:6379 AND services.service_name:REDIS",
    "category": "database",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Open Kubernetes API on Censys",
    "platform": "censys",
    "query": "services.port:6443 AND services.tls.certificate.parsed.subject.common_name:\"kubernetes\"",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Docker API on Censys",
    "platform": "censys",
    "query": "services.port:2375 AND services.http.response.body:\"ApiVersion\"",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Jenkins CI on Censys",
    "platform": "censys",
    "query": "services.http.response.html_title:\"Dashboard [Jenkins]\"",
    "category": "ci_cd",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Kibana on Censys",
    "platform": "censys",
    "query": "services.port:5601 AND services.http.response.html_title:\"Kibana\"",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Grafana Exposed on Censys",
    "platform": "censys",
    "query": "services.http.response.html_title:\"Grafana\" AND services.port:3000",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Jupyter Notebooks Censys",
    "platform": "censys",
    "query": "services.http.response.html_title:\"Jupyter Notebook\" AND services.port:8888",
    "category": "debug",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Prometheus on Censys",
    "platform": "censys",
    "query": "services.port:9090 AND services.http.response.html_title:\"Prometheus\"",
    "category": "admin_panel",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed CouchDB on Censys",
    "platform": "censys",
    "query": "services.port:5984 AND services.http.response.body:\"couchdb\"",
    "category": "database",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed etcd on Censys",
    "platform": "censys",
    "query": "services.port:2379 AND services.http.response.body:\"etcdserver\"",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed RabbitMQ on Censys",
    "platform": "censys",
    "query": "services.port:15672 AND services.http.response.html_title:\"RabbitMQ\"",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Spring Boot Actuator on Censys",
    "platform": "censys",
    "query": "services.http.response.body:\"/actuator\" AND services.http.response.status_code:200",
    "category": "debug",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Hadoop YARN Censys",
    "platform": "censys",
    "query": "services.port:8088 AND services.http.response.html_title:\"ResourceManager\"",
    "category": "admin_panel",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Portainer on Censys",
    "platform": "censys",
    "query": "services.port:9000 AND services.http.response.html_title:\"Portainer\"",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Traefik on Censys",
    "platform": "censys",
    "query": "services.port:8080 AND services.http.response.html_title:\"Traefik\"",
    "category": "admin_panel",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed Apache Solr on Censys",
    "platform": "censys",
    "query": "services.port:8983 AND services.http.response.html_title:\"Solr Admin\"",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Zookeeper on Censys",
    "platform": "censys",
    "query": "services.port:2181 AND services.service_name:ZOOKEEPER",
    "category": "database",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Drone CI on Censys",
    "platform": "censys",
    "query": "services.http.response.html_title:\"Drone\" AND services.http.response.body:\"drone\"",
    "category": "ci_cd",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed GitLab Instance on Censys",
    "platform": "censys",
    "query": "services.http.response.html_title:\"GitLab\" AND services.http.response.body:\"gitlab\"",
    "category": "ci_cd",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Hikvision Camera Censys",
    "platform": "censys",
    "query": "services.http.response.html_title:\"Hikvision\" AND services.port:80",
    "category": "camera",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed MikroTik Router Censys",
    "platform": "censys",
    "query": "services.http.response.html_title:\"RouterOS\" AND services.http.response.body:\"MikroTik\"",
    "category": "iot",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed phpinfo on Censys",
    "platform": "censys",
    "query": "services.http.response.html_title:\"phpinfo()\"",
    "category": "debug",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Memcached on Censys",
    "platform": "censys",
    "query": "services.port:11211 AND services.service_name:MEMCACHED",
    "category": "database",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed env File via Google",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:env \"DB_PASSWORD\"",
    "category": "config",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed wp-config.php",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:php inurl:wp-config",
    "category": "config",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed phpinfo via Google",
    "platform": "google",
    "query": "site:{DOMAIN} intitle:\"phpinfo()\" \"PHP Version\"",
    "category": "debug",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Jenkins Login via Google",
    "platform": "google",
    "query": "site:{DOMAIN} intitle:\"Dashboard [Jenkins]\"",
    "category": "ci_cd",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed .git Directory",
    "platform": "google",
    "query": "site:{DOMAIN} intitle:\"Index of /.git\"",
    "category": "config",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed database backup files",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:sql intext:\"INSERT INTO\"",
    "category": "database",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed .htpasswd File",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:htpasswd intext:\"htpasswd\"",
    "category": "config",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Configuration Files",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:conf intext:\"password\"",
    "category": "config",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed XML Config Files",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:xml intext:\"password\" intext:\"username\"",
    "category": "config",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed YAML Config Files",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:yaml intext:\"password\"",
    "category": "config",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed JSON Config Files",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:json intext:\"api_key\"",
    "category": "config",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed PHP Debug Trace",
    "platform": "google",
    "query": "site:{DOMAIN} inurl:\"/debug\" intitle:\"Debug\"",
    "category": "debug",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed /trace Endpoint",
    "platform": "google",
    "query": "site:{DOMAIN} inurl:\"/trace\" intitle:\"Trace\"",
    "category": "debug",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed Admin Panel Login",
    "platform": "google",
    "query": "site:{DOMAIN} inurl:\"/admin\" intitle:\"Admin Login\"",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed cPanel Login",
    "platform": "google",
    "query": "site:{DOMAIN} intitle:\"cPanel\" inurl:\":2083\"",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Plesk Admin Panel",
    "platform": "google",
    "query": "site:{DOMAIN} intitle:\"Plesk\" inurl:\":8443\"",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Webmin Panel",
    "platform": "google",
    "query": "site:{DOMAIN} intitle:\"Webmin\" inurl:\":10000\"",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Kubernetes Dashboard via Google",
    "platform": "google",
    "query": "site:{DOMAIN} intitle:\"Kubernetes Dashboard\"",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Grafana Dashboard via Google",
    "platform": "google",
    "query": "site:{DOMAIN} intitle:\"Grafana\" inurl:\"/login\"",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Log Files with Passwords",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:log intext:\"password\"",
    "category": "config",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed AWS Credentials in config",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:txt intext:\"aws_access_key_id\"",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed .bash_history",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:bak inurl:\".bash_history\"",
    "category": "config",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Backup Archives",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:zip intext:\"backup\"",
    "category": "config",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Subversion SVN Directory",
    "platform": "google",
    "query": "site:{DOMAIN} intitle:\"Index of /.svn\"",
    "category": "config",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Laravel APP_KEY in .env",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:env intext:\"APP_KEY\"",
    "category": "config",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Database Connection Strings",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:php intext:\"mysql_connect\" intext:\"password\"",
    "category": "database",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Private SSH Keys",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:pem intext:\"PRIVATE KEY\"",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Kibana via Google",
    "platform": "google",
    "query": "site:{DOMAIN} intitle:\"Kibana\" inurl:\":5601\"",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "AWS Keys in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"aws_access_key_id\" \"aws_secret_access_key\"",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Private SSH Keys in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} filename:id_rsa \"BEGIN RSA PRIVATE KEY\"",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed .env File in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} filename:.env \"DB_PASSWORD\"",
    "category": "config",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "wp-config.php in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} filename:wp-config.php \"DB_PASSWORD\"",
    "category": "config",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Slack Tokens in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"xoxb-\" OR \"xoxp-\" slack_token",
    "category": "leaked_secrets",
    "severity_if_found": "HIGH"
  },
  {
    "name": "GitHub Personal Access Tokens",
    "platform": "github",
    "query": "org:{DOMAIN} \"ghp_\" filename:*.yml",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Google API Keys in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"AIza\" google_api_key",
    "category": "leaked_secrets",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Stripe Secret Keys in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"sk_live_\" stripe",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Heroku API Keys in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"HEROKU_API_KEY\" filename:.env",
    "category": "leaked_secrets",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Twilio Auth Tokens in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"TWILIO_AUTH_TOKEN\" OR \"twilio_auth_token\"",
    "category": "leaked_secrets",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Hardcoded Passwords in Config",
    "platform": "github",
    "query": "org:{DOMAIN} filename:config.yml \"password:\"",
    "category": "config",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Kubernetes Kubeconfig in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} filename:kubeconfig \"apiVersion\"",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Docker Compose with Secrets",
    "platform": "github",
    "query": "org:{DOMAIN} filename:docker-compose.yml \"password\"",
    "category": "config",
    "severity_if_found": "HIGH"
  },
  {
    "name": "GitHub Actions Secrets Leak",
    "platform": "github",
    "query": "org:{DOMAIN} filename:*.yml path:.github/workflows \"secrets.\"",
    "category": "ci_cd",
    "severity_if_found": "HIGH"
  },
  {
    "name": "JWT Secret Keys in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"JWT_SECRET\" OR \"jwt_secret\"",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Database Connection Strings in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"mongodb://\" OR \"mysql://\" intext:\"password\"",
    "category": "database",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "S3 Bucket Config in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"s3.amazonaws.com\" \"secret_key\"",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed SMTP Credentials in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"SMTP_PASSWORD\" OR \"smtp_password\"",
    "category": "leaked_secrets",
    "severity_if_found": "HIGH"
  },
  {
    "name": "SendGrid API Keys in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"SG.\" sendgrid_api_key",
    "category": "leaked_secrets",
    "severity_if_found": "HIGH"
  },
  {
    "name": "PayPal Client Secret in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"PAYPAL_CLIENT_SECRET\" OR \"paypal_secret\"",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "GCP Service Account Keys in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} filename:*.json \"type\": \"service_account\"",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Azure Connection Strings in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} \"DefaultEndpointsProtocol\" azure storage",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Ansible Vault Password",
    "platform": "github",
    "query": "org:{DOMAIN} filename:vault_pass.txt OR filename:.vault_pass",
    "category": "config",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Terraform State Files in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} filename:terraform.tfstate \"password\"",
    "category": "config",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed VPN Config in GitHub",
    "platform": "github",
    "query": "org:{DOMAIN} filename:*.ovpn \"auth-user-pass\"",
    "category": "leaked_secrets",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Shodan Exposed Axis Camera RTSP",
    "platform": "shodan",
    "query": "port:554 product:\"AXIS\" has_screenshot:true",
    "category": "camera",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Foscam IP Camera",
    "platform": "shodan",
    "query": "http.title:\"Foscam\" port:88",
    "category": "camera",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed D-Link Camera Stream",
    "platform": "shodan",
    "query": "http.title:\"D-Link\" http.html:\"camera\"",
    "category": "camera",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed RTSP Video Streams",
    "platform": "shodan",
    "query": "port:554 \"RTSP\" has_screenshot:true",
    "category": "camera",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Ubiquiti UniFi Panel",
    "platform": "shodan",
    "query": "http.title:\"UniFi\" port:8443",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Palo Alto Firewall",
    "platform": "shodan",
    "query": "http.title:\"Palo Alto Networks\" port:443",
    "category": "iot",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Fortinet Firewall Login",
    "platform": "shodan",
    "query": "http.title:\"FortiGate\" port:443",
    "category": "iot",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed SCADA / Modbus",
    "platform": "shodan",
    "query": "port:502 product:\"Modbus\"",
    "category": "iot",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed BACnet IoT",
    "platform": "shodan",
    "query": "port:47808 product:\"BACnet\"",
    "category": "iot",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Siemens S7 PLC",
    "platform": "shodan",
    "query": "port:102 product:\"Siemens\"",
    "category": "iot",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed pfSense Firewall",
    "platform": "shodan",
    "query": "http.title:\"pfSense\" port:443",
    "category": "iot",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed OpenWRT Router",
    "platform": "shodan",
    "query": "http.title:\"OpenWrt\" port:80",
    "category": "iot",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Linksys Router",
    "platform": "shodan",
    "query": "http.title:\"Linksys\" http.html:\"admin\"",
    "category": "iot",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed D-Link Router Admin",
    "platform": "shodan",
    "query": "http.title:\"D-Link\" port:80 http.html:\"password\"",
    "category": "iot",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed TP-Link Router Admin",
    "platform": "shodan",
    "query": "http.title:\"TP-LINK\" port:80",
    "category": "iot",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed ASUS Router Admin",
    "platform": "shodan",
    "query": "http.title:\"ASUS\" http.html:\"router\" port:8080",
    "category": "iot",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed VNC Server",
    "platform": "shodan",
    "query": "port:5900 product:\"VNC\" has_screenshot:true",
    "category": "admin_panel",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Telnet Service",
    "platform": "shodan",
    "query": "port:23 product:\"Telnet\" banner:\"login\"",
    "category": "iot",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed FTP with Anonymous Login",
    "platform": "shodan",
    "query": "port:21 \"230 Anonymous access granted\"",
    "category": "config",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed SNMP with Default Community",
    "platform": "shodan",
    "query": "port:161 product:\"SNMP\" \"public\"",
    "category": "iot",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Nagios XI Admin",
    "platform": "shodan",
    "query": "http.title:\"Nagios XI\" port:443",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Zabbix Monitoring",
    "platform": "shodan",
    "query": "http.title:\"Zabbix\" port:80",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Splunk Web UI",
    "platform": "shodan",
    "query": "http.title:\"Splunk\" port:8000",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed NetData Dashboard",
    "platform": "shodan",
    "query": "http.title:\"Netdata\" port:19999",
    "category": "admin_panel",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed phpMyAdmin Panel",
    "platform": "shodan",
    "query": "http.title:\"phpMyAdmin\" port:80",
    "category": "admin_panel",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Tomcat Manager",
    "platform": "shodan",
    "query": "http.title:\"Apache Tomcat\" http.html:\"manager\"",
    "category": "admin_panel",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Jira Instance",
    "platform": "shodan",
    "query": "http.title:\"Jira\" http.html:\"atlassian\"",
    "category": "admin_panel",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed Confluence Instance",
    "platform": "shodan",
    "query": "http.title:\"Confluence\" http.html:\"atlassian\"",
    "category": "admin_panel",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed Minio Object Storage",
    "platform": "shodan",
    "query": "http.title:\"MinIO\" port:9000",
    "category": "admin_panel",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Rancher Kubernetes UI",
    "platform": "shodan",
    "query": "http.title:\"Rancher\" port:443",
    "category": "kubernetes",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed ArgoCD Dashboard",
    "platform": "shodan",
    "query": "http.title:\"Argo CD\" port:443",
    "category": "ci_cd",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed CircleCI Build Artifact",
    "platform": "google",
    "query": "site:circleci.com org:{DOMAIN} \"CIRCLE_TOKEN\"",
    "category": "ci_cd",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed TeamCity CI Panel",
    "platform": "shodan",
    "query": "http.title:\"TeamCity\" port:8111",
    "category": "ci_cd",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Bamboo CI Panel",
    "platform": "shodan",
    "query": "http.title:\"Bamboo\" http.html:\"atlassian\" port:8085",
    "category": "ci_cd",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Concourse CI",
    "platform": "shodan",
    "query": "http.title:\"Concourse\" port:8080",
    "category": "ci_cd",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Vault UI (HashiCorp)",
    "platform": "shodan",
    "query": "http.title:\"Vault\" http.html:\"hashicorp\" port:8200",
    "category": "admin_panel",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Consul KV Store Exposed",
    "platform": "shodan",
    "query": "http.title:\"Consul\" port:8500",
    "category": "admin_panel",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed InfluxDB Instance",
    "platform": "shodan",
    "query": "port:8086 product:\"InfluxDB\"",
    "category": "database",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Neo4j Database Browser",
    "platform": "shodan",
    "query": "http.title:\"Neo4j Browser\" port:7474",
    "category": "database",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Adminer Database UI",
    "platform": "google",
    "query": "site:{DOMAIN} inurl:\"adminer.php\" intitle:\"Adminer\"",
    "category": "admin_panel",
    "severity_if_found": "CRITICAL"
  },
  {
    "name": "Exposed Swagger UI",
    "platform": "google",
    "query": "site:{DOMAIN} intitle:\"Swagger UI\" inurl:\"/swagger-ui\"",
    "category": "debug",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed API Documentation",
    "platform": "google",
    "query": "site:{DOMAIN} inurl:\"/api-docs\" intitle:\"API\"",
    "category": "debug",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed Django DEBUG Page",
    "platform": "google",
    "query": "site:{DOMAIN} intext:\"Django\" intext:\"Traceback\" intext:\"Exception\"",
    "category": "debug",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Rails Debug Error",
    "platform": "google",
    "query": "site:{DOMAIN} intext:\"Ruby on Rails\" intext:\"Application Trace\"",
    "category": "debug",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed Node.js Stack Trace",
    "platform": "google",
    "query": "site:{DOMAIN} intext:\"Error:\" intext:\"at Module._compile\"",
    "category": "debug",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed Open Redirect in URL",
    "platform": "google",
    "query": "site:{DOMAIN} inurl:\"redirect=http\" OR inurl:\"url=http\"",
    "category": "debug",
    "severity_if_found": "MEDIUM"
  },
  {
    "name": "Exposed htaccess File",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:htaccess intext:\"RewriteRule\"",
    "category": "config",
    "severity_if_found": "HIGH"
  },
  {
    "name": "Exposed robots.txt Sensitive Paths",
    "platform": "google",
    "query": "site:{DOMAIN} filetype:txt inurl:\"robots.txt\" intext:\"Disallow\"",
    "category": "config",
    "severity_if_found": "LOW"
  }
]
