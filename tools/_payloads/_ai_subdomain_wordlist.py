"""AI-curated subdomain wordlist — high-hit patterns from real-world bug bounty corpora.
Generated from open BB writeups + nuclei project discovery + custom curation."""
AI_SUBDOMAINS = (
    # Infrastructure
    "ns","ns1","ns2","ns3","ns4","mx","mx1","mx2","mx3","relay","gateway","gw",
    "router","switch","fw","firewall","lb","loadbalancer","proxy","edge",
    # DevOps / CI / Tooling
    "ci","cd","jenkins","gitlab","github","git","build","deploy","artifactory",
    "nexus","registry","docker","k8s","kube","kubernetes","helm","argo","rancher",
    "spinnaker","tekton","drone","circleci","travis","bamboo","teamcity",
    # Monitoring
    "monitor","monitoring","grafana","kibana","prometheus","alertmanager",
    "sentry","newrelic","datadog","splunk","logstash","fluentd","elastic","es",
    "stats","metrics","health","healthcheck","status","uptime",
    # Internal tools
    "internal","intranet","extranet","corp","corporate","employees","staff",
    "hr","payroll","finance","accounting","sales","marketing","crm","erp",
    # Databases
    "db","database","mysql","mariadb","postgres","postgresql","redis","mongo",
    "mongodb","cassandra","elastic","es","clickhouse","kafka","rabbitmq","amq",
    # Common services
    "auth","sso","oauth","oidc","saml","ldap","ad","login","signin","signup",
    "register","portal","dashboard","admin","administrator","root","sudo",
    "panel","cp","manage","management","console","control","ops",
    # Web app variants
    "api","apis","api1","api2","api-v1","api-v2","api-v3","apiv1","apiv2",
    "rest","graphql","grpc","webhook","webhooks","cb","callback","oauth-cb",
    # Environments
    "dev","development","staging","stage","stg","test","testing","qa","uat",
    "preprod","pre-prod","prod","production","beta","alpha","gamma","sandbox",
    "demo","poc","playground","scratch","tmp","temp","experimental",
    # Cloud / Storage
    "s3","cdn","cdn1","cdn2","static","assets","files","upload","uploads",
    "downloads","backup","backups","archive","archives","storage","media",
    "images","img","photos","videos","docs","documents",
    # Communications
    "mail","email","webmail","smtp","pop","pop3","imap","exchange","owa",
    "autodiscover","calendar","cal","meet","chat","slack","teams","jitsi",
    "voip","sip","pbx","fax",
    # Documentation
    "docs","documentation","wiki","kb","knowledgebase","help","support","faq",
    "guide","manual","tutorials","learn","academy","training",
    # Customer-facing
    "shop","store","cart","checkout","pay","payment","billing","invoices",
    "subscribe","subscriptions","customers","clients","partners","resellers",
    "vendors","suppliers","affiliates","referrals",
    # Modern app patterns
    "app","apps","mobile","m","www2","www3","old","new","next","v2","v3","v4",
    "legacy","beta2","beta3","preview","early","public","private","secret",
)
