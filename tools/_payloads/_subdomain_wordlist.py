"""Built-in subdomain wordlist — high-hit-rate common subs."""
COMMON_SUBDOMAINS = (
    "www","mail","ftp","webmail","smtp","pop","ns1","ns2","ns3","webdisk",
    "admin","api","app","apps","blog","cdn","dev","staging","prod","test",
    "demo","docs","forum","help","static","img","media","support","portal",
    "shop","store","my","secure","login","auth","sso","vpn","gateway","gw",
    "remote","email","exchange","autodiscover","mx","mx1","mx2","relay",
    "owa","webapp","beta","alpha","old","new","internal","intranet","extranet",
    "git","gitlab","github","ci","jenkins","build","deploy","backup","db",
    "database","mysql","postgres","redis","cache","monitor","monitoring",
    "stats","status","health","metrics","grafana","kibana","prometheus",
    "sentry","jira","confluence","wiki","share","files","drive","upload",
    "download","cdn1","cdn2","s3","storage","assets","img1","img2",
)
PERMUTATION_PREFIXES = ("dev-","staging-","test-","prod-","qa-","uat-","beta-","internal-","old-","new-")
PERMUTATION_SUFFIXES = ("-dev","-staging","-test","-prod","-qa","-uat","-beta","-internal","-old","-new","-v2","-v3","1","2","3","01","02")
