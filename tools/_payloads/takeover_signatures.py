"""takeover_signatures — generated dev-time by Claude. Recon module asset.
"""

TAKEOVER_SIGNATURES = [
  {
    "service": "AWS S3",
    "cname_patterns": [
      "s3\\.amazonaws\\.com",
      "s3-website[.-][a-z0-9-]+\\.amazonaws\\.com"
    ],
    "fingerprint_body": "NoSuchBucket|The specified bucket does not exist",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Unclaimed S3 bucket can be registered by attacker to serve malicious content under victim domain."
  },
  {
    "service": "AWS S3 Website",
    "cname_patterns": [
      "s3-website\\.amazonaws\\.com",
      "s3-website-[a-z0-9-]+\\.amazonaws\\.com"
    ],
    "fingerprint_body": "NoSuchBucket|The specified bucket does not exist|NoSuchWebsiteConfiguration",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "S3 static website endpoint pointing to deleted bucket allows attacker to reclaim and host arbitrary content."
  },
  {
    "service": "AWS CloudFront",
    "cname_patterns": [
      "cloudfront\\.net"
    ],
    "fingerprint_body": "ERROR: The request could not be satisfied|Bad request|The Amazon CloudFront distribution is configured to block access",
    "fingerprint_status": 403,
    "severity": "HIGH",
    "documentation": "Misconfigured CloudFront distribution with no valid origin allows partial takeover via distribution reconfiguration."
  },
  {
    "service": "AWS Elastic Beanstalk",
    "cname_patterns": [
      "elasticbeanstalk\\.com"
    ],
    "fingerprint_body": "404 Not Found|No Application|HTTP Status 404",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Deleted Elastic Beanstalk environment CNAME can be re-registered by attacker to control the subdomain."
  },
  {
    "service": "AWS Elastic Beanstalk Regional",
    "cname_patterns": [
      "[a-z0-9-]+\\.[a-z0-9-]+\\.elasticbeanstalk\\.com"
    ],
    "fingerprint_body": "404 Not Found|Application Not Available|HTTP Status 404",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Regional Elastic Beanstalk CNAME pointing to unclaimed environment allows full subdomain takeover."
  },
  {
    "service": "Heroku",
    "cname_patterns": [
      "herokuapp\\.com",
      "herokussl\\.com",
      "herokudns\\.com"
    ],
    "fingerprint_body": "No such app|There's nothing here|herokucdn\\.com/error-pages/no-such-app",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Heroku app referenced by CNAME no longer exists and can be claimed by anyone with a free account."
  },
  {
    "service": "Heroku SSL",
    "cname_patterns": [
      "herokussl\\.com",
      "ssl\\.herokudns\\.com"
    ],
    "fingerprint_body": "No such app|herokucdn\\.com/error-pages/no-such-app",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Heroku SSL endpoint pointing to unclaimed app allows attacker to register app and take over the subdomain."
  },
  {
    "service": "Fly.io",
    "cname_patterns": [
      "fly\\.dev",
      "[a-z0-9-]+\\.fly\\.dev"
    ],
    "fingerprint_body": "404 Not Found|This site is not available|fly\\.io.*not found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Fly.io app referenced by CNAME has been deleted allowing attacker to deploy new app with same name."
  },
  {
    "service": "Render",
    "cname_patterns": [
      "onrender\\.com",
      "[a-z0-9-]+\\.onrender\\.com"
    ],
    "fingerprint_body": "Service Not Found|404.*onrender|This service does not exist",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Render service CNAME pointing to nonexistent service can be claimed by creating a new Render deployment."
  },
  {
    "service": "GitHub Pages",
    "cname_patterns": [
      "github\\.io",
      "[a-z0-9-]+\\.github\\.io"
    ],
    "fingerprint_body": "There isn't a GitHub Pages site here|404 There is nothing here|If you're trying to publish one",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "GitHub Pages CNAME pointing to unclaimed username/repo allows attacker to create matching repo and take over."
  },
  {
    "service": "GitHub Pages Organization",
    "cname_patterns": [
      "[a-z0-9-]+\\.github\\.io"
    ],
    "fingerprint_body": "There isn't a GitHub Pages site here|404.*github",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Organization GitHub Pages endpoint can be taken over by creating the organization and corresponding repository."
  },
  {
    "service": "GitLab Pages",
    "cname_patterns": [
      "gitlab\\.io",
      "[a-z0-9-]+\\.gitlab\\.io"
    ],
    "fingerprint_body": "404|GitLab Pages.*not found|The page you are looking for could not be found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "GitLab Pages CNAME pointing to deleted project namespace can be reclaimed by registering matching GitLab project."
  },
  {
    "service": "Cloudflare Pages",
    "cname_patterns": [
      "pages\\.dev",
      "[a-z0-9-]+\\.pages\\.dev"
    ],
    "fingerprint_body": "Not Found|1001|DNS resolution error|This page has been suspended",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Cloudflare Pages project subdomain pointing to unclaimed project can be registered by attacker on their account."
  },
  {
    "service": "Vercel",
    "cname_patterns": [
      "vercel\\.app",
      "now\\.sh",
      "[a-z0-9-]+\\.vercel\\.app"
    ],
    "fingerprint_body": "The deployment could not be found|404: NOT_FOUND|DEPLOYMENT_NOT_FOUND",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Vercel deployment URL no longer exists and attacker can deploy new project to claim the same subdomain."
  },
  {
    "service": "Vercel Now",
    "cname_patterns": [
      "now\\.sh",
      "[a-z0-9-]+\\.now\\.sh"
    ],
    "fingerprint_body": "The deployment could not be found|404.*now\\.sh|DEPLOYMENT_NOT_FOUND",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Legacy Vercel now.sh CNAME pointing to removed deployment allows takeover via new Vercel project registration."
  },
  {
    "service": "Netlify",
    "cname_patterns": [
      "netlify\\.app",
      "netlify\\.com",
      "[a-z0-9-]+\\.netlify\\.app"
    ],
    "fingerprint_body": "Not Found - Request ID|404.*netlify|Page Not Found.*Looks like you've followed a broken link",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Netlify site subdomain pointing to deleted site allows attacker to claim subdomain by creating matching Netlify project."
  },
  {
    "service": "Netlify Legacy",
    "cname_patterns": [
      "[a-z0-9-]+\\.netlify\\.com"
    ],
    "fingerprint_body": "Not Found - Request ID|404.*netlify",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Legacy Netlify .com subdomain pointing to unclaimed site can be registered by any Netlify user."
  },
  {
    "service": "Azure Blob Storage",
    "cname_patterns": [
      "blob\\.core\\.windows\\.net",
      "[a-z0-9-]+\\.blob\\.core\\.windows\\.net"
    ],
    "fingerprint_body": "BlobNotFound|The specified container does not exist|ResourceNotFound",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Azure Blob Storage endpoint pointing to deleted container or account can be reclaimed by attacker creating matching storage account."
  },
  {
    "service": "Azure CDN",
    "cname_patterns": [
      "azureedge\\.net",
      "[a-z0-9-]+\\.azureedge\\.net"
    ],
    "fingerprint_body": "CDN endpoint not found|The endpoint.*does not exist|404.*azureedge",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Azure CDN endpoint CNAME pointing to deleted profile allows attacker to create new endpoint with same name."
  },
  {
    "service": "Azure Front Door",
    "cname_patterns": [
      "azurefd\\.net",
      "[a-z0-9-]+\\.azurefd\\.net"
    ],
    "fingerprint_body": "Provided request is not a valid Front Door request|404.*azurefd|Front Door.*not found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Azure Front Door endpoint pointing to removed profile allows subdomain takeover by registering matching Front Door instance."
  },
  {
    "service": "Azure App Service",
    "cname_patterns": [
      "azurewebsites\\.net",
      "[a-z0-9-]+\\.azurewebsites\\.net"
    ],
    "fingerprint_body": "404 Web Site not found|No web site was found for the web address|Error 404 - Web app not found",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Azure App Service custom domain CNAME pointing to deleted web app allows attacker to create new app with same name."
  },
  {
    "service": "Azure Traffic Manager",
    "cname_patterns": [
      "trafficmanager\\.net",
      "[a-z0-9-]+\\.trafficmanager\\.net"
    ],
    "fingerprint_body": "404|No web site was found|Error 404",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Azure Traffic Manager profile pointing to decommissioned endpoint allows takeover via profile name registration."
  },
  {
    "service": "GCP Cloud Storage",
    "cname_patterns": [
      "storage\\.googleapis\\.com",
      "storage\\.cloud\\.google\\.com"
    ],
    "fingerprint_body": "NoSuchBucket|The specified bucket does not exist|404.*google",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Google Cloud Storage bucket CNAME pointing to deleted bucket allows attacker to create bucket with matching name."
  },
  {
    "service": "GCP App Engine",
    "cname_patterns": [
      "appspot\\.com",
      "[a-z0-9-]+\\.appspot\\.com"
    ],
    "fingerprint_body": "404 Not Found|This application does not exist|Error: Not Found",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Google App Engine subdomain pointing to deleted application allows project ID to be reclaimed for takeover."
  },
  {
    "service": "Firebase Hosting",
    "cname_patterns": [
      "firebaseapp\\.com",
      "web\\.app",
      "[a-z0-9-]+\\.firebaseapp\\.com"
    ],
    "fingerprint_body": "404.*firebase|Site Not Found|Firebase.*not found",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Firebase Hosting CNAME pointing to deleted project can be taken over by creating new Firebase project with same ID."
  },
  {
    "service": "Firebase Web App",
    "cname_patterns": [
      "[a-z0-9-]+\\.web\\.app"
    ],
    "fingerprint_body": "404.*web\\.app|Site Not Found|Firebase.*project.*not found",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Firebase web.app domain pointing to unclaimed project ID allows takeover by registering matching Firebase project."
  },
  {
    "service": "Fastly",
    "cname_patterns": [
      "fastly\\.net",
      "[a-z0-9-]+\\.fastly\\.net",
      "global\\.ssl\\.fastly\\.net"
    ],
    "fingerprint_body": "Fastly error: unknown domain|Please check that this domain has been added to a Fastly service|803",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Fastly CDN service CNAME pointing to unconfigured or deleted service allows attacker to configure new service for domain."
  },
  {
    "service": "BunnyCDN",
    "cname_patterns": [
      "b-cdn\\.net",
      "[a-z0-9-]+\\.b-cdn\\.net"
    ],
    "fingerprint_body": "Pull Zone Not Found|404.*bunny|BunnyCDN.*not found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "BunnyCDN pull zone CNAME pointing to deleted zone allows attacker to create matching zone and serve content."
  },
  {
    "service": "Zendesk",
    "cname_patterns": [
      "zendesk\\.com",
      "[a-z0-9-]+\\.zendesk\\.com"
    ],
    "fingerprint_body": "Help Center Closed|Page not found|Oops, this page no longer exists|This help center no longer exists",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Zendesk Help Center CNAME pointing to deleted subdomain allows attacker to register matching Zendesk account."
  },
  {
    "service": "Statuspage",
    "cname_patterns": [
      "statuspage\\.io",
      "[a-z0-9-]+\\.statuspage\\.io"
    ],
    "fingerprint_body": "Status Page Not Found|You are being redirected|404.*statuspage",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Statuspage.io CNAME pointing to deleted status page allows attacker to create matching page and display false status."
  },
  {
    "service": "Tilda",
    "cname_patterns": [
      "tilda\\.ws",
      "[a-z0-9-]+\\.tilda\\.ws"
    ],
    "fingerprint_body": "Domain is not connected to Tilda|Please go back|404.*tilda",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Tilda page CNAME pointing to disconnected or deleted project allows attacker to link their Tilda project to the domain."
  },
  {
    "service": "Surge",
    "cname_patterns": [
      "surge\\.sh",
      "[a-z0-9-]+\\.surge\\.sh"
    ],
    "fingerprint_body": "project not found|404.*surge|This page is not available",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Surge.sh project CNAME pointing to unpublished domain allows attacker to publish new Surge project under same name."
  },
  {
    "service": "Webflow",
    "cname_patterns": [
      "webflow\\.io",
      "proxy\\.webflow\\.com",
      "[a-z0-9-]+\\.webflow\\.io"
    ],
    "fingerprint_body": "The page you are looking for doesn't exist|404.*webflow|Site Not Published",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Webflow site CNAME pointing to deleted or unpublished project allows attacker to publish matching Webflow site."
  },
  {
    "service": "Tumblr",
    "cname_patterns": [
      "tumblr\\.com",
      "domains\\.tumblr\\.com"
    ],
    "fingerprint_body": "There's nothing here|Whatever you were looking for doesn't currently exist|404.*tumblr",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Tumblr custom domain CNAME pointing to deleted blog allows attacker to create matching Tumblr blog and claim the domain."
  },
  {
    "service": "Shopify",
    "cname_patterns": [
      "myshopify\\.com",
      "shops\\.myshopify\\.com"
    ],
    "fingerprint_body": "Sorry, this shop is currently unavailable|only a few seconds|404.*shopify",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Shopify store CNAME pointing to nonexistent shop allows attacker to register matching myshopify subdomain."
  },
  {
    "service": "ReadTheDocs",
    "cname_patterns": [
      "readthedocs\\.io",
      "readthedocs\\.org",
      "[a-z0-9-]+\\.readthedocs\\.io"
    ],
    "fingerprint_body": "unknown to Read the Docs|No project with that slug|404.*readthedocs",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "ReadTheDocs project CNAME pointing to nonexistent project slug allows attacker to register matching documentation project."
  },
  {
    "service": "GitBook",
    "cname_patterns": [
      "gitbook\\.io",
      "gitbook\\.com",
      "[a-z0-9-]+\\.gitbook\\.io"
    ],
    "fingerprint_body": "Not Found|404.*gitbook|Gitbook.*not found|If you need to urgently",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "GitBook space CNAME pointing to deleted space allows attacker to create new GitBook space and link to the domain."
  },
  {
    "service": "Pantheon",
    "cname_patterns": [
      "pantheonsite\\.io",
      "[a-z0-9-]+\\.pantheonsite\\.io"
    ],
    "fingerprint_body": "404 error unknown site|The gods are wise|Pantheon.*no.*site",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Pantheon site CNAME pointing to deleted environment allows attacker to spin up new Pantheon site with matching subdomain."
  },
  {
    "service": "WPEngine",
    "cname_patterns": [
      "wpengine\\.com",
      "[a-z0-9-]+\\.wpengine\\.com"
    ],
    "fingerprint_body": "The site you are looking for|install not found|404.*wpengine",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "WP Engine install CNAME pointing to deleted install allows attacker to create new install with same subdomain."
  },
  {
    "service": "Mailgun",
    "cname_patterns": [
      "mailgun\\.org",
      "email\\.mailgun\\.org"
    ],
    "fingerprint_body": "Unknown domain|This domain is not configured|mailgun.*not found",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Mailgun email subdomain pointing to deleted domain allows attacker to receive or send email under victim domain."
  },
  {
    "service": "SendGrid",
    "cname_patterns": [
      "sendgrid\\.net",
      "em[0-9]+\\.sendgrid\\.net",
      "u[0-9]+\\.wl[0-9]+\\.sendgrid\\.net"
    ],
    "fingerprint_body": "CNAME not configured|The CNAME record|This domain is not configured",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "SendGrid CNAME pointing to unregistered domain key allows attacker to send email authenticated as victim domain."
  },
  {
    "service": "Postmark",
    "cname_patterns": [
      "pm\\.mtasv\\.net",
      "[a-z0-9-]+\\.mtasv\\.net"
    ],
    "fingerprint_body": "This page is reserved for Postmark|Oops.*page not found|404.*postmark",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Postmark tracking link CNAME pointing to unclaimed server allows attacker to intercept click tracking and email links."
  },
  {
    "service": "AWS S3 US East",
    "cname_patterns": [
      "s3-us-east-1\\.amazonaws\\.com",
      "s3\\.us-east-1\\.amazonaws\\.com"
    ],
    "fingerprint_body": "NoSuchBucket|The specified bucket does not exist",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "US East S3 bucket CNAME pointing to deleted bucket can be reclaimed by registering new bucket with identical name."
  },
  {
    "service": "AWS S3 EU West",
    "cname_patterns": [
      "s3-eu-west-1\\.amazonaws\\.com",
      "s3\\.eu-west-1\\.amazonaws\\.com"
    ],
    "fingerprint_body": "NoSuchBucket|The specified bucket does not exist",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "EU West S3 bucket CNAME pointing to deleted bucket allows takeover by registering new bucket with same name in same region."
  },
  {
    "service": "AWS S3 AP Southeast",
    "cname_patterns": [
      "s3-ap-southeast-1\\.amazonaws\\.com",
      "s3\\.ap-southeast-1\\.amazonaws\\.com"
    ],
    "fingerprint_body": "NoSuchBucket|The specified bucket does not exist",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "AP Southeast S3 bucket pointing to nonexistent bucket allows subdomain takeover via bucket name registration."
  },
  {
    "service": "Heroku Custom Domain",
    "cname_patterns": [
      "herokudns\\.com",
      "[a-z0-9-]+\\.herokudns\\.com"
    ],
    "fingerprint_body": "No such app|herokucdn\\.com/error-pages/no-such-app|404.*heroku",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Heroku DNS target pointing to deleted app can be taken over by creating new Heroku app with same name and adding domain."
  },
  {
    "service": "GitHub Pages User",
    "cname_patterns": [
      "[a-z0-9-]+\\.github\\.io"
    ],
    "fingerprint_body": "There isn't a GitHub Pages site here|404.*github\\.io",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "User GitHub Pages site CNAME can be taken over by registering the GitHub username and creating the username.github.io repository."
  },
  {
    "service": "Vercel Custom",
    "cname_patterns": [
      "cname\\.vercel-dns\\.com",
      "[a-z0-9-]+\\.vercel-dns\\.com"
    ],
    "fingerprint_body": "The deployment could not be found|404.*vercel|DEPLOYMENT_NOT_FOUND",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Vercel DNS CNAME pointing to deleted project allows attacker to deploy new project and add matching custom domain."
  },
  {
    "service": "Netlify DNS",
    "cname_patterns": [
      "[a-z0-9-]+\\.netlify\\.com",
      "ssl\\.netlify\\.app"
    ],
    "fingerprint_body": "Not Found - Request ID|404.*netlify",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Netlify DNS entry pointing to deleted project allows any Netlify user to claim the subdomain via new site deployment."
  },
  {
    "service": "Azure Static Web Apps",
    "cname_patterns": [
      "azurestaticapps\\.net",
      "[a-z0-9-]+\\.azurestaticapps\\.net"
    ],
    "fingerprint_body": "This Azure Static Web App doesn't exist|404.*azurestaticapps",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Azure Static Web Apps CNAME pointing to deleted static app allows attacker to deploy new app with same resource name."
  },
  {
    "service": "GCP Firebase Realtime DB",
    "cname_patterns": [
      "firebaseio\\.com",
      "[a-z0-9-]+\\.firebaseio\\.com"
    ],
    "fingerprint_body": "404 Not Found|Firebase.*not found|This project has been deleted",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Firebase Realtime Database endpoint pointing to deleted project allows takeover by creating matching GCP project."
  },
  {
    "service": "Fastly Global SSL",
    "cname_patterns": [
      "global\\.ssl\\.fastly\\.net",
      "dualstack\\.n\\.ssl\\.fastly\\.net"
    ],
    "fingerprint_body": "Fastly error: unknown domain|803|unknown domain|Please check that this domain",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Fastly SSL CDN CNAME pointing to removed or unconfigured service allows attacker to provision matching Fastly service."
  },
  {
    "service": "AWS Amplify",
    "cname_patterns": [
      "amplifyapp\\.com",
      "[a-z0-9-]+\\.amplifyapp\\.com"
    ],
    "fingerprint_body": "404 Not Found|No app exists|AWS Amplify.*not found",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "AWS Amplify app CNAME pointing to deleted app allows attacker to deploy new Amplify app with matching subdomain."
  },
  {
    "service": "AWS API Gateway",
    "cname_patterns": [
      "execute-api\\.[a-z0-9-]+\\.amazonaws\\.com",
      "[a-z0-9]+\\.execute-api\\.[a-z0-9-]+\\.amazonaws\\.com"
    ],
    "fingerprint_body": "Missing Authentication Token|{\"message\":\"Missing Authentication Token\"}|403.*Forbidden",
    "fingerprint_status": 403,
    "severity": "HIGH",
    "documentation": "API Gateway custom domain CNAME pointing to deleted API stage allows attacker to create new API and claim the endpoint."
  },
  {
    "service": "Google Firebase Hosting",
    "cname_patterns": [
      "[a-z0-9-]+\\.web\\.app",
      "[a-z0-9-]+\\.firebaseapp\\.com"
    ],
    "fingerprint_body": "Firebase Hosting Setup Complete|404.*firebase|Site Not Found",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Firebase Hosting custom domain CNAME to unclaimed project allows takeover by registering matching Firebase project ID."
  },
  {
    "service": "Cargo Collective",
    "cname_patterns": [
      "cargocollective\\.com",
      "[a-z0-9-]+\\.cargocollective\\.com"
    ],
    "fingerprint_body": "404 Not Found|Cargo.*not found|This site does not exist",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Cargo Collective site CNAME pointing to deleted portfolio site can be taken over by registering matching Cargo account."
  },
  {
    "service": "Squarespace",
    "cname_patterns": [
      "squarespace\\.com",
      "ext-cust\\.squarespace\\.com"
    ],
    "fingerprint_body": "No Such Account|404.*squarespace|This domain has not been added",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Squarespace CNAME pointing to deactivated site allows attacker to create new Squarespace site and configure the custom domain."
  },
  {
    "service": "Wix",
    "cname_patterns": [
      "wixdns\\.net",
      "www\\.wixdns\\.net"
    ],
    "fingerprint_body": "wix\\.com.*Error|Looks Like This Page is Gone|404.*wix",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Wix site CNAME pointing to deactivated site allows attacker to connect domain to attacker-controlled Wix account."
  },
  {
    "service": "Strikingly",
    "cname_patterns": [
      "s\\.strikinglydns\\.com",
      "strikinglydns\\.com"
    ],
    "fingerprint_body": "Page Not Found|Strikingly.*not found|404.*strikingly",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Strikingly site CNAME pointing to deleted site allows attacker to claim subdomain via new Strikingly site registration."
  },
  {
    "service": "HubSpot",
    "cname_patterns": [
      "hubspot\\.net",
      "[a-z0-9-]+\\.hs-sites\\.com",
      "sites\\.hubspot\\.net"
    ],
    "fingerprint_body": "Domain not found|This HubSpot page doesn't exist|Does Not Exist",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "HubSpot landing page CNAME pointing to deleted portal or page allows attacker to spin up phishing portal."
  },
  {
    "service": "Ghost",
    "cname_patterns": [
      "ghost\\.io",
      "[a-z0-9-]+\\.ghost\\.io"
    ],
    "fingerprint_body": "404.*ghost|Site not found|Ghost.*not found|This site has been removed",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Ghost blog CNAME pointing to nonexistent Ghost Pro subdomain allows takeover by registering same subdomain on Ghost."
  },
  {
    "service": "Acquia",
    "cname_patterns": [
      "acquia-sites\\.com",
      "[a-z0-9-]+\\.acquia-sites\\.com"
    ],
    "fingerprint_body": "Unknown site|The site you are looking for|404.*acquia",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Acquia hosting CNAME pointing to removed environment allows attacker to claim matching Acquia site environment."
  },
  {
    "service": "Kinsta",
    "cname_patterns": [
      "kinsta\\.cloud",
      "[a-z0-9-]+\\.kinsta\\.cloud"
    ],
    "fingerprint_body": "No Site For Domain|404.*kinsta|This site is unavailable",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Kinsta hosting CNAME pointing to deleted environment allows attacker to create matching Kinsta site with same subdomain."
  },
  {
    "service": "Intercom",
    "cname_patterns": [
      "custom\\.intercom\\.help",
      "intercom\\.help"
    ],
    "fingerprint_body": "Uh oh. That page doesn't exist|404.*intercom|This page is not available",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Intercom Help Center CNAME pointing to deleted workspace allows attacker to create new Intercom workspace with same URL."
  },
  {
    "service": "Unbounce",
    "cname_patterns": [
      "unbouncepages\\.com",
      "[a-z0-9-]+\\.unbouncepages\\.com"
    ],
    "fingerprint_body": "The requested URL was not found|404.*unbounce|Page not found.*unbounce",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Unbounce landing page CNAME pointing to deleted account allows attacker to register matching Unbounce subdomain."
  },
  {
    "service": "Desk.com",
    "cname_patterns": [
      "desk\\.com",
      "[a-z0-9-]+\\.desk\\.com"
    ],
    "fingerprint_body": "Please try again|We couldn't find your helpdesk|404.*desk",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Desk.com help portal CNAME pointing to closed account allows attacker to register matching Desk.com subdomain."
  },
  {
    "service": "Campaign Monitor",
    "cname_patterns": [
      "cmail[0-9]+\\.com",
      "createsend\\.com"
    ],
    "fingerprint_body": "Link Not Found|Double-check your URL|404.*campaignmonitor",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Campaign Monitor email link CNAME pointing to unclaimed account allows attacker to intercept email clicks."
  },
  {
    "service": "Feedpress",
    "cname_patterns": [
      "feedpress\\.me",
      "[a-z0-9-]+\\.feedpress\\.me"
    ],
    "fingerprint_body": "The feed has not been found|404.*feedpress",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Feedpress RSS feed CNAME pointing to deleted feed allows attacker to register matching feed and serve arbitrary content."
  },
  {
    "service": "UserVoice",
    "cname_patterns": [
      "uservoice\\.com",
      "[a-z0-9-]+\\.uservoice\\.com"
    ],
    "fingerprint_body": "This UserVoice subdomain is currently available|404.*uservoice",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "UserVoice feedback portal CNAME pointing to deleted subdomain allows attacker to register matching UserVoice account."
  },
  {
    "service": "Pingdom",
    "cname_patterns": [
      "stats\\.pingdom\\.com"
    ],
    "fingerprint_body": "This public report page has not been activated|404.*pingdom",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Pingdom public status page CNAME pointing to unclaimed report allows attacker to register matching Pingdom report page."
  },
  {
    "service": "Launchrock",
    "cname_patterns": [
      "launchrock\\.com",
      "[a-z0-9-]+\\.launchrock\\.com"
    ],
    "fingerprint_body": "It looks like you may have taken a wrong turn|404.*launchrock",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Launchrock coming-soon page CNAME pointing to deleted site allows attacker to claim subdomain for phishing or defacement."
  },
  {
    "service": "Brightcove",
    "cname_patterns": [
      "bcvp0rtal\\.com",
      "brightcovegallery\\.com",
      "[a-z0-9-]+\\.bcvp0rtal\\.com"
    ],
    "fingerprint_body": "Page Not Found|404.*brightcove|This site does not exist",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Brightcove gallery or portal CNAME pointing to deleted gallery allows attacker to create matching Brightcove portal."
  },
  {
    "service": "Helpjuice",
    "cname_patterns": [
      "helpjuice\\.com",
      "[a-z0-9-]+\\.helpjuice\\.com"
    ],
    "fingerprint_body": "We could not find what you're looking for|404.*helpjuice",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Helpjuice knowledge base CNAME pointing to deleted account allows attacker to register same subdomain for phishing."
  },
  {
    "service": "HelpScout",
    "cname_patterns": [
      "helpscoutdocs\\.com",
      "[a-z0-9-]+\\.helpscoutdocs\\.com"
    ],
    "fingerprint_body": "No settings were found for this company|404.*helpscout",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "HelpScout Docs CNAME pointing to deleted collection allows attacker to register matching HelpScout subdomain."
  },
  {
    "service": "Freshdesk",
    "cname_patterns": [
      "freshdesk\\.com",
      "[a-z0-9-]+\\.freshdesk\\.com"
    ],
    "fingerprint_body": "There is no helpdesk here with that URL|404.*freshdesk",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Freshdesk support portal CNAME pointing to closed account can be taken over by registering matching Freshdesk subdomain."
  },
  {
    "service": "Kajabi",
    "cname_patterns": [
      "kajabi\\.com",
      "[a-z0-9-]+\\.kajabi\\.com"
    ],
    "fingerprint_body": "this site|kajabi.*unavailable|404.*kajabi",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Kajabi course platform CNAME pointing to deleted account allows attacker to register matching subdomain and host content."
  },
  {
    "service": "Teachable",
    "cname_patterns": [
      "teachable\\.com",
      "[a-z0-9-]+\\.teachable\\.com"
    ],
    "fingerprint_body": "Site Not Found|There's no site here|404.*teachable",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Teachable school CNAME pointing to deleted school allows attacker to create matching Teachable subdomain and host fake courses."
  },
  {
    "service": "Thinkific",
    "cname_patterns": [
      "thinkific\\.com",
      "[a-z0-9-]+\\.thinkific\\.com"
    ],
    "fingerprint_body": "This school doesn't exist|404.*thinkific",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Thinkific online school CNAME pointing to nonexistent school allows takeover by registering matching Thinkific subdomain."
  },
  {
    "service": "Podia",
    "cname_patterns": [
      "podia\\.com",
      "[a-z0-9-]+\\.podia\\.com"
    ],
    "fingerprint_body": "The store you are looking for|404.*podia",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Podia storefront CNAME pointing to closed account allows attacker to claim subdomain via new Podia account registration."
  },
  {
    "service": "Pagecloud",
    "cname_patterns": [
      "pagecloud\\.com",
      "[a-z0-9-]+\\.pagecloud\\.com"
    ],
    "fingerprint_body": "This page is no longer available|404.*pagecloud",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Pagecloud site CNAME pointing to deleted page allows attacker to create matching Pagecloud site and serve content."
  },
  {
    "service": "Stitch Labs",
    "cname_patterns": [
      "stitchlabs\\.com",
      "[a-z0-9-]+\\.stitchlabs\\.com"
    ],
    "fingerprint_body": "Not Found|Page not found|404.*stitch",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Stitch Labs CNAME pointing to removed account allows subdomain takeover via new account registration."
  },
  {
    "service": "Proposify",
    "cname_patterns": [
      "proposify\\.biz",
      "[a-z0-9-]+\\.proposify\\.biz"
    ],
    "fingerprint_body": "There is no proposal here|404.*proposify",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Proposify proposal subdomain pointing to nonexistent account allows attacker to register matching subdomain."
  },
  {
    "service": "Fly.io App",
    "cname_patterns": [
      "fly\\.dev",
      "[a-z0-9-]+\\.fly\\.dev"
    ],
    "fingerprint_body": "Not Found|404.*fly\\.dev|No app found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Fly.io app deleted but CNAME remains, allowing attacker to deploy new app with same name on Fly.io platform."
  },
  {
    "service": "Platform.sh",
    "cname_patterns": [
      "platform\\.sh",
      "[a-z0-9-]+\\.platform\\.sh"
    ],
    "fingerprint_body": "404.*platform\\.sh|This project is not available|No route was found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Platform.sh environment CNAME pointing to deleted environment allows attacker to provision matching project environment."
  },
  {
    "service": "Duda",
    "cname_patterns": [
      "dudaone\\.com",
      "[a-z0-9-]+\\.multiscreensite\\.com"
    ],
    "fingerprint_body": "404.*duda|This site is unavailable|The URL you are trying to reach",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Duda website builder CNAME pointing to deleted site allows attacker to create matching Duda site for content injection."
  },
  {
    "service": "Webnode",
    "cname_patterns": [
      "webnode\\.com",
      "[a-z0-9-]+\\.webnode\\.com"
    ],
    "fingerprint_body": "This website does not exist|404.*webnode",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Webnode site CNAME pointing to deleted account allows attacker to register matching Webnode subdomain and serve content."
  },
  {
    "service": "Jimdo",
    "cname_patterns": [
      "jimdo\\.com",
      "[a-z0-9-]+\\.jimdo\\.com"
    ],
    "fingerprint_body": "This website is not available|404.*jimdo",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Jimdo site CNAME pointing to deleted or deactivated account allows takeover by registering matching Jimdo subdomain."
  },
  {
    "service": "Weebly",
    "cname_patterns": [
      "weebly\\.com",
      "[a-z0-9-]+\\.weebly\\.com"
    ],
    "fingerprint_body": "This site.*unavailable|We're sorry|404.*weebly",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Weebly site CNAME pointing to deleted site allows attacker to claim matching Weebly subdomain for malicious use."
  },
  {
    "service": "Blogspot",
    "cname_patterns": [
      "blogspot\\.com",
      "[a-z0-9-]+\\.blogspot\\.com"
    ],
    "fingerprint_body": "Blog not found|Sorry, the blog at|404.*blogspot",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Blogger/Blogspot custom domain pointing to deleted blog allows attacker to create matching blog and take over the domain."
  },
  {
    "service": "WordPress.com",
    "cname_patterns": [
      "wordpress\\.com",
      "[a-z0-9-]+\\.wordpress\\.com"
    ],
    "fingerprint_body": "doesn't exist|Do you want to register|404.*wordpress",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "WordPress.com hosted site CNAME pointing to deleted blog allows attacker to register matching WordPress.com subdomain."
  },
  {
    "service": "Medium",
    "cname_patterns": [
      "medium\\.com",
      "medium-cname\\.com"
    ],
    "fingerprint_body": "Page not found|This page is gone|404.*medium",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Medium publication CNAME pointing to unclaimed publication allows attacker to create publication with matching custom domain."
  },
  {
    "service": "Substack",
    "cname_patterns": [
      "substack\\.com",
      "[a-z0-9-]+\\.substack\\.com"
    ],
    "fingerprint_body": "Not Found|This Substack does not exist|404.*substack",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Substack newsletter CNAME pointing to deleted publication allows attacker to claim subdomain for phishing newsletters."
  },
  {
    "service": "Mailchimp",
    "cname_patterns": [
      "mcsv\\.net",
      "mailchimpapp\\.net",
      "[a-z0-9-]+\\.mcsv\\.net"
    ],
    "fingerprint_body": "Oops.*the page you were looking for|Snap.*this page|404.*mailchimp",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Mailchimp tracking CNAME pointing to deleted account allows attacker to intercept campaign link clicks."
  },
  {
    "service": "Constant Contact",
    "cname_patterns": [
      "constantcontact\\.com",
      "r[0-9]+\\.cts\\.constantcontact\\.com"
    ],
    "fingerprint_body": "Link not found|This link is no longer valid|404.*constantcontact",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Constant Contact email tracking CNAME pointing to removed account allows attacker to hijack email click tracking."
  },
  {
    "service": "ActiveCampaign",
    "cname_patterns": [
      "activehosted\\.com",
      "[a-z0-9-]+\\.activehosted\\.com"
    ],
    "fingerprint_body": "404.*activecampaign|This page is not available|No campaign found",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "ActiveCampaign tracking CNAME pointing to deleted account allows attacker to register matching subdomain for email tracking hijack."
  },
  {
    "service": "Klaviyo",
    "cname_patterns": [
      "klaviyo\\.com",
      "a\\.klaviyo\\.com"
    ],
    "fingerprint_body": "Link not found|404.*klaviyo|This page doesn't exist",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Klaviyo email tracking domain CNAME pointing to removed account allows attacker to intercept email marketing links."
  },
  {
    "service": "Drift",
    "cname_patterns": [
      "drift\\.com",
      "[a-z0-9-]+\\.drift\\.com"
    ],
    "fingerprint_body": "This page is not available|404.*drift|Page not found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Drift chat landing page CNAME pointing to deleted workspace allows attacker to register matching Drift subdomain."
  },
  {
    "service": "Crisp",
    "cname_patterns": [
      "go\\.crisp\\.chat",
      "crisp\\.chat"
    ],
    "fingerprint_body": "This helpdesk is not available|404.*crisp",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Crisp helpdesk CNAME pointing to deleted workspace allows attacker to spin up fake helpdesk portal under victim domain."
  },
  {
    "service": "Typeform",
    "cname_patterns": [
      "typeform\\.com",
      "[a-z0-9-]+\\.typeform\\.com"
    ],
    "fingerprint_body": "Oops.*form not found|This form is gone|404.*typeform",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Typeform form CNAME pointing to deleted account allows attacker to host phishing forms under victim domain."
  },
  {
    "service": "JotForm",
    "cname_patterns": [
      "jotform\\.com",
      "[a-z0-9-]+\\.jotform\\.com"
    ],
    "fingerprint_body": "Form Not Found|This form is no longer active|404.*jotform",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "JotForm custom subdomain pointing to deleted form allows attacker to host credential-harvesting forms."
  },
  {
    "service": "Formstack",
    "cname_patterns": [
      "formstack\\.com",
      "[a-z0-9-]+\\.formstack\\.com"
    ],
    "fingerprint_body": "The form you're looking for|404.*formstack",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Formstack form CNAME pointing to deleted account allows attacker to create matching Formstack subdomain for phishing."
  },
  {
    "service": "Calendly",
    "cname_patterns": [
      "calendly\\.com",
      "[a-z0-9-]+\\.calendly\\.com"
    ],
    "fingerprint_body": "Page not found|Oops.*calendly|404.*calendly",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Calendly scheduling page CNAME pointing to removed account allows attacker to register matching Calendly link."
  },
  {
    "service": "Acuity Scheduling",
    "cname_patterns": [
      "acuityscheduling\\.com",
      "[a-z0-9-]+\\.acuityscheduling\\.com"
    ],
    "fingerprint_body": "This scheduling page doesn't exist|404.*acuity",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Acuity Scheduling subdomain pointing to deleted account allows attacker to create matching scheduling page for fraud."
  },
  {
    "service": "DockerHub",
    "cname_patterns": [
      "hub\\.docker\\.com"
    ],
    "fingerprint_body": "Page not found|404.*docker|Repository Not Found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Docker Hub custom domain pointing to deleted organization allows attacker to register matching Docker Hub namespace."
  },
  {
    "service": "Cloudflare Workers",
    "cname_patterns": [
      "workers\\.dev",
      "[a-z0-9-]+\\.workers\\.dev"
    ],
    "fingerprint_body": "Error 1101|Worker threw exception|1101.*worker",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Cloudflare Workers subdomain pointing to deleted worker script allows attacker to deploy new worker with same subdomain."
  },
  {
    "service": "Fly.io Certificates",
    "cname_patterns": [
      "fly\\.io",
      "[a-z0-9-]+\\.fly\\.io"
    ],
    "fingerprint_body": "No application found|404.*fly\\.io|App Not Found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Fly.io certificate validation CNAME to deleted app allows attacker to deploy replacement app and claim TLS certificate."
  },
  {
    "service": "Render Static",
    "cname_patterns": [
      "onrender\\.com",
      "static\\.onrender\\.com"
    ],
    "fingerprint_body": "404.*onrender|Service Not Found|This render service does not exist",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Render static site CNAME pointing to deleted service allows attacker to redeploy static site with same service name."
  },
  {
    "service": "Coolify",
    "cname_patterns": [
      "coolify\\.io",
      "[a-z0-9-]+\\.coolify\\.io"
    ],
    "fingerprint_body": "404.*coolify|Application Not Found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Coolify deployment CNAME pointing to removed application allows subdomain takeover via new deployment on Coolify."
  },
  {
    "service": "Railway",
    "cname_patterns": [
      "railway\\.app",
      "[a-z0-9-]+\\.railway\\.app",
      "up\\.railway\\.app"
    ],
    "fingerprint_body": "Application not found|404.*railway|No application is currently deployed",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Railway deployment CNAME pointing to deleted project allows attacker to claim subdomain by deploying new Railway service."
  },
  {
    "service": "Cyclic",
    "cname_patterns": [
      "cyclic\\.app",
      "[a-z0-9-]+\\.cyclic\\.app"
    ],
    "fingerprint_body": "Not Found|404.*cyclic|App not deployed",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Cyclic serverless app CNAME pointing to removed app allows attacker to deploy replacement app with same name."
  },
  {
    "service": "Glitch",
    "cname_patterns": [
      "glitch\\.me",
      "[a-z0-9-]+\\.glitch\\.me"
    ],
    "fingerprint_body": "Not Found|No project found|Glitch.*not found|404.*glitch",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Glitch project CNAME pointing to deleted project allows attacker to create new Glitch project with same name."
  },
  {
    "service": "Replit",
    "cname_patterns": [
      "replit\\.app",
      "repl\\.co",
      "[a-z0-9-]+\\.repl\\.co"
    ],
    "fingerprint_body": "404.*repl|This repl doesn't exist|Repl not found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Replit CNAME pointing to deleted repl allows attacker to create replacement repl with same subdomain for malicious hosting."
  },
  {
    "service": "Deno Deploy",
    "cname_patterns": [
      "deno\\.dev",
      "[a-z0-9-]+\\.deno\\.dev"
    ],
    "fingerprint_body": "404.*deno|No project found at this URL|Deployment not found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Deno Deploy project CNAME pointing to removed deployment allows attacker to claim subdomain via new deployment."
  },
  {
    "service": "Cloudflare R2",
    "cname_patterns": [
      "r2\\.dev",
      "[a-z0-9-]+\\.r2\\.dev"
    ],
    "fingerprint_body": "NoSuchBucket|Bucket not found|Access Denied",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Cloudflare R2 bucket CNAME pointing to deleted bucket allows attacker to create new bucket with same name for content injection."
  },
  {
    "service": "DigitalOcean Spaces",
    "cname_patterns": [
      "digitaloceanspaces\\.com",
      "[a-z0-9-]+\\.[a-z0-9-]+\\.digitaloceanspaces\\.com"
    ],
    "fingerprint_body": "NoSuchBucket|The specified bucket does not exist|AccessDenied",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "DigitalOcean Spaces bucket CNAME pointing to deleted space allows attacker to create matching space and serve malicious content."
  },
  {
    "service": "Linode Object Storage",
    "cname_patterns": [
      "linodeobjects\\.com",
      "[a-z0-9-]+\\.linodeobjects\\.com"
    ],
    "fingerprint_body": "NoSuchBucket|Bucket Not Found|AccessDenied",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Linode Object Storage bucket CNAME pointing to deleted bucket allows attacker to register matching bucket name."
  },
  {
    "service": "Vultr Object Storage",
    "cname_patterns": [
      "vultrobjects\\.com",
      "[a-z0-9-]+\\.vultrobjects\\.com"
    ],
    "fingerprint_body": "NoSuchBucket|The specified bucket does not exist",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Vultr Object Storage CNAME pointing to removed bucket allows attacker to create bucket with same name under victim domain."
  },
  {
    "service": "Wasabi Storage",
    "cname_patterns": [
      "wasabisys\\.com",
      "s3\\.wasabisys\\.com",
      "[a-z0-9-]+\\.s3\\.wasabisys\\.com"
    ],
    "fingerprint_body": "NoSuchBucket|The specified bucket does not exist|AccessDenied",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Wasabi Cloud Storage bucket CNAME pointing to deleted bucket allows takeover by registering matching bucket name."
  },
  {
    "service": "Backblaze B2",
    "cname_patterns": [
      "backblazeb2\\.com",
      "f[0-9]+\\.backblazeb2\\.com"
    ],
    "fingerprint_body": "bucket_not_found|No such file or directory|Bucket Not Found",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Backblaze B2 bucket CNAME pointing to deleted bucket allows attacker to create replacement bucket and serve malicious files."
  },
  {
    "service": "Oracle Cloud Storage",
    "cname_patterns": [
      "objectstorage\\.[a-z0-9-]+\\.oraclecloud\\.com"
    ],
    "fingerprint_body": "NotFound|The object does not exist|404.*oracle",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Oracle Cloud Object Storage CNAME pointing to deleted bucket allows attacker to create matching namespace/bucket combination."
  },
  {
    "service": "IBM Cloud Storage",
    "cname_patterns": [
      "s3\\.us\\.cloud-object-storage\\.appdomain\\.cloud",
      "[a-z0-9-]+\\.cloud-object-storage\\.appdomain\\.cloud"
    ],
    "fingerprint_body": "NoSuchBucket|The specified bucket does not exist",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "IBM Cloud Object Storage CNAME pointing to deleted bucket allows takeover via registration of same bucket name."
  },
  {
    "service": "Alibaba Cloud OSS",
    "cname_patterns": [
      "oss-[a-z0-9-]+\\.aliyuncs\\.com",
      "[a-z0-9-]+\\.oss-[a-z0-9-]+\\.aliyuncs\\.com"
    ],
    "fingerprint_body": "NoSuchBucket|The specified bucket does not exist",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Alibaba Cloud OSS bucket CNAME pointing to deleted bucket allows attacker to register matching bucket name for content injection."
  },
  {
    "service": "Cloudinary",
    "cname_patterns": [
      "cloudinary\\.com",
      "[a-z0-9-]+\\.cloudinary\\.com"
    ],
    "fingerprint_body": "Unknown cloud_name|404.*cloudinary|Resource not found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Cloudinary media CDN CNAME pointing to deleted cloud name allows attacker to register matching Cloudinary account."
  },
  {
    "service": "Imgix",
    "cname_patterns": [
      "imgix\\.net",
      "[a-z0-9-]+\\.imgix\\.net"
    ],
    "fingerprint_body": "404 Not Found|Source not found|imgix.*not found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Imgix image CDN CNAME pointing to deleted source allows attacker to create matching Imgix source for image substitution."
  },
  {
    "service": "Skypack",
    "cname_patterns": [
      "cdn\\.skypack\\.dev",
      "skypack\\.dev"
    ],
    "fingerprint_body": "Package not found|404.*skypack",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Skypack CDN CNAME pointing to removed package allows attacker to serve modified package content via subdomain."
  },
  {
    "service": "jsDelivr",
    "cname_patterns": [
      "cdn\\.jsdelivr\\.net"
    ],
    "fingerprint_body": "Couldn't find the requested release|404.*jsdelivr",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "jsDelivr CDN CNAME pointing to deleted repository package allows attacker to serve malicious JS under victim domain."
  },
  {
    "service": "Akamai EdgeSuite",
    "cname_patterns": [
      "edgesuite\\.net",
      "[a-z0-9-]+\\.edgesuite\\.net"
    ],
    "fingerprint_body": "The request cannot be fulfilled|Reference.*Error|Akamai.*Error",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Akamai EdgeSuite CNAME pointing to deleted property allows partial takeover via new property configuration."
  },
  {
    "service": "Akamai EdgeKey",
    "cname_patterns": [
      "edgekey\\.net",
      "[a-z0-9-]+\\.edgekey\\.net"
    ],
    "fingerprint_body": "The request cannot be fulfilled|Reference.*Error",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Akamai EdgeKey CDN CNAME pointing to unconfigured property allows attacker to provision matching edge configuration."
  },
  {
    "service": "Rackspace Cloud Files",
    "cname_patterns": [
      "rackcdn\\.com",
      "[a-z0-9-]+\\.rackcdn\\.com"
    ],
    "fingerprint_body": "404 Not Found|Container not found|403 Forbidden",
    "fingerprint_status": 404,
    "severity": "CRITICAL",
    "documentation": "Rackspace Cloud Files CDN CNAME pointing to deleted container allows attacker to create matching container and serve content."
  },
  {
    "service": "Squarespace Circle",
    "cname_patterns": [
      "sqsp\\.net",
      "[a-z0-9-]+\\.sqsp\\.net"
    ],
    "fingerprint_body": "Page Not Found|404.*squarespace|This domain isn't connected",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Squarespace Circle subdomain CNAME pointing to deactivated site allows attacker to reclaim domain via new Squarespace project."
  },
  {
    "service": "Contentful",
    "cname_patterns": [
      "contentful\\.com",
      "[a-z0-9-]+\\.contentful\\.com",
      "cdn\\.contentful\\.com"
    ],
    "fingerprint_body": "Space not found|This API request|404.*contentful",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Contentful CMS CNAME pointing to deleted space allows attacker to create new Contentful space with matching subdomain."
  },
  {
    "service": "Prismic",
    "cname_patterns": [
      "prismic\\.io",
      "[a-z0-9-]+\\.prismic\\.io",
      "cdn\\.prismic\\.io"
    ],
    "fingerprint_body": "Repository not found|404.*prismic|This repository does not exist",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Prismic CMS repository CNAME pointing to deleted repository allows attacker to create matching repository for content injection."
  },
  {
    "service": "Storyblok",
    "cname_patterns": [
      "storyblok\\.com",
      "[a-z0-9-]+\\.storyblok\\.com"
    ],
    "fingerprint_body": "Space not found|404.*storyblok",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Storyblok headless CMS CNAME pointing to removed space allows attacker to register matching Storyblok space."
  },
  {
    "service": "Sanity",
    "cname_patterns": [
      "sanity\\.studio",
      "[a-z0-9-]+\\.sanity\\.studio"
    ],
    "fingerprint_body": "Studio not found|404.*sanity|Project does not exist",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Sanity Studio CNAME pointing to removed project allows attacker to claim subdomain by registering matching Sanity project."
  },
  {
    "service": "Strapi Cloud",
    "cname_patterns": [
      "strapi\\.io",
      "[a-z0-9-]+\\.strapi\\.io"
    ],
    "fingerprint_body": "Application not found|404.*strapi",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Strapi Cloud CMS CNAME pointing to deleted application allows attacker to deploy new Strapi instance with same subdomain."
  },
  {
    "service": "Directus Cloud",
    "cname_patterns": [
      "directus\\.io",
      "[a-z0-9-]+\\.directus\\.io"
    ],
    "fingerprint_body": "Project not found|404.*directus",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Directus Cloud headless CMS CNAME pointing to removed project allows attacker to register matching Directus project."
  },
  {
    "service": "Ghost Pro",
    "cname_patterns": [
      "ghost\\.io",
      "[a-z0-9-]+\\.ghost\\.io"
    ],
    "fingerprint_body": "404.*ghost|Site not found|This Ghost site is not found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Ghost Pro publication CNAME to deleted publication can be taken over by creating same subdomain on Ghost Pro."
  },
  {
    "service": "Hashnode",
    "cname_patterns": [
      "hashnode\\.dev",
      "[a-z0-9-]+\\.hashnode\\.dev"
    ],
    "fingerprint_body": "Blog not found|404.*hashnode|This blog doesn't exist",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Hashnode developer blog CNAME pointing to deleted blog allows attacker to register matching Hashnode subdomain."
  },
  {
    "service": "Dev.to",
    "cname_patterns": [
      "dev\\.to"
    ],
    "fingerprint_body": "Page not found|404.*dev\\.to",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Dev.to organization page CNAME pointing to nonexistent organization allows attacker to claim matching organization."
  },
  {
    "service": "Notion Sites",
    "cname_patterns": [
      "notion\\.site",
      "[a-z0-9-]+\\.notion\\.site"
    ],
    "fingerprint_body": "Page Not Found|404.*notion|This page does not exist",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Notion Sites CNAME pointing to deleted public page allows attacker to publish matching Notion page under victim domain."
  },
  {
    "service": "Super",
    "cname_patterns": [
      "super\\.so",
      "[a-z0-9-]+\\.super\\.so"
    ],
    "fingerprint_body": "No site found|404.*super\\.so|Site not found",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Super.so Notion site wrapper CNAME pointing to deleted site allows attacker to create matching Super.so site."
  },
  {
    "service": "Fruition",
    "cname_patterns": [
      "fruitionsite\\.com",
      "[a-z0-9-]+\\.fruitionsite\\.com"
    ],
    "fingerprint_body": "Page not found|404.*fruition",
    "fingerprint_status": 404,
    "severity": "HIGH",
    "documentation": "Fruition Notion wrapper CNAME pointing to deleted proxy site allows attacker to reconfigure for malicious Notion content."
  }
]
