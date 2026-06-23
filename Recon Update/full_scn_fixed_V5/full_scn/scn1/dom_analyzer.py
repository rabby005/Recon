import logging
import re
from typing import Dict, List
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ─── Dangerous Sinks ───────────────────────────────────────────────────────────
SINK_PATTERNS = [

    # ── Vanilla JS / Browser DOM ───────────────────────────────────────────────
    (r"innerHTML\s*[+]?=",               "HIGH",   "innerHTML এ directly value বসানো হচ্ছে"),
    (r"outerHTML\s*[+]?=",               "HIGH",   "outerHTML এ directly value বসানো হচ্ছে"),
    (r"document\.write\s*\(",            "HIGH",   "document.write() দিয়ে output করা হচ্ছে"),
    (r"document\.writeln\s*\(",          "HIGH",   "document.writeln() দিয়ে output করা হচ্ছে"),
    (r"eval\s*\(",                       "HIGH",   "eval() দিয়ে code execute হচ্ছে"),
    (r"new\s+Function\s*\(",             "HIGH",   "new Function() দিয়ে dynamic code তৈরি হচ্ছে"),
    (r"insertAdjacentHTML\s*\(",         "HIGH",   "insertAdjacentHTML দিয়ে HTML inject হচ্ছে"),
    (r"insertAdjacentElement\s*\(",      "MEDIUM", "insertAdjacentElement দিয়ে element insert হচ্ছে"),
    (r"createContextualFragment\s*\(",   "HIGH",   "createContextualFragment দিয়ে HTML parse হচ্ছে"),
    (r"setTimeout\s*\(\s*['\"`]",        "MEDIUM", "setTimeout এ string pass হচ্ছে"),
    (r"setInterval\s*\(\s*['\"`]",       "MEDIUM", "setInterval এ string pass হচ্ছে"),
    (r"setImmediate\s*\(\s*['\"`]",      "MEDIUM", "setImmediate এ string pass হচ্ছে"),
    (r"location\.href\s*=",             "MEDIUM", "location.href এ value assign হচ্ছে"),
    (r"location\.replace\s*\(",         "MEDIUM", "location.replace() দিয়ে redirect হচ্ছে"),
    (r"location\.assign\s*\(",          "MEDIUM", "location.assign() দিয়ে redirect হচ্ছে"),
    (r"window\.location\s*=",           "MEDIUM", "window.location এ value assign হচ্ছে"),
    (r"window\.open\s*\(",              "MEDIUM", "window.open() এ dynamic URL দেওয়া হচ্ছে"),
    (r"src\s*=\s*['\"`]?\s*\$",         "MEDIUM", "src attribute এ dynamic value বসানো হচ্ছে"),
    (r"href\s*=\s*['\"`]?\s*\$",        "MEDIUM", "href attribute এ dynamic value বসানো হচ্ছে"),
    (r"action\s*=\s*['\"`]?\s*\$",      "MEDIUM", "form action এ dynamic value বসানো হচ্ছে"),
    (r"\.setAttribute\s*\(\s*['\"`]on", "HIGH",   "setAttribute দিয়ে event handler বসানো হচ্ছে"),
    (r"\.setAttribute\s*\(\s*['\"`]src","MEDIUM",  "setAttribute দিয়ে src বসানো হচ্ছে"),
    (r"\.setAttribute\s*\(\s*['\"`]href","MEDIUM", "setAttribute দিয়ে href বসানো হচ্ছে"),
    (r"scriptElement\.text\s*=",        "HIGH",   "script element এ text inject হচ্ছে"),
    (r"\.textContent\s*=",              "LOW",    "textContent এ value বসানো হচ্ছে (safe কিন্তু track করো)"),
    (r"importScripts\s*\(",             "HIGH",   "importScripts দিয়ে external script load হচ্ছে"),
    (r"\.execScript\s*\(",              "HIGH",   "execScript দিয়ে code execute হচ্ছে (IE legacy)"),

    # ── jQuery ────────────────────────────────────────────────────────────────
    (r"\.html\s*\(",                          "HIGH",   "jQuery .html() দিয়ে raw HTML set হচ্ছে"),
    (r"\.append\s*\(\s*[^'\"`\s,)]+\s*[\),]","MEDIUM", "jQuery .append() এ variable pass হচ্ছে"),
    (r"\.prepend\s*\(\s*[^'\"`\s,)]+\s*[\),]","MEDIUM","jQuery .prepend() এ variable pass হচ্ছে"),
    (r"\.after\s*\(\s*[^'\"`\s,)]+\s*[\),]", "MEDIUM", "jQuery .after() এ variable pass হচ্ছে"),
    (r"\.before\s*\(\s*[^'\"`\s,)]+\s*[\),]","MEDIUM", "jQuery .before() এ variable pass হচ্ছে"),
    (r"\.replaceWith\s*\(",                   "MEDIUM", "jQuery .replaceWith() এ HTML দেওয়া হচ্ছে"),
    (r"\.wrap\s*\(\s*[^'\"`\s,)]+\s*[\),]",  "MEDIUM", "jQuery .wrap() এ variable pass হচ্ছে"),
    (r"\.wrapAll\s*\(\s*[^'\"`\s,)]+\s*[\),]","MEDIUM","jQuery .wrapAll() এ variable pass হচ্ছে"),
    (r"\.wrapInner\s*\(\s*[^'\"`\s,)]+\s*[\),]","MEDIUM","jQuery .wrapInner() এ variable pass হচ্ছে"),
    (r"\$\s*\(\s*[^'\"`#\.\s]",               "HIGH",  "jQuery selector এ variable দেওয়া হচ্ছে (injection risk)"),
    (r"jQuery\s*\(\s*[^'\"`#\.\s]",           "HIGH",  "jQuery() এ variable দেওয়া হচ্ছে (injection risk)"),
    (r"\.load\s*\(",                          "MEDIUM", "jQuery .load() দিয়ে external content আনা হচ্ছে"),
    (r"\.parseHTML\s*\(",                     "MEDIUM", "jQuery .parseHTML() দিয়ে HTML parse হচ্ছে"),
    (r"\.globalEval\s*\(",                    "HIGH",   "jQuery.globalEval() দিয়ে code execute হচ্ছে"),

    # ── React ─────────────────────────────────────────────────────────────────
    (r"dangerouslySetInnerHTML",              "HIGH",   "React dangerouslySetInnerHTML — raw HTML inject হচ্ছে"),
    (r"useRef\s*\(\s*\).*innerHTML",          "HIGH",   "React useRef + innerHTML দিয়ে DOM manipulation হচ্ছে"),

    # ── Vue ───────────────────────────────────────────────────────────────────
    (r"v-html\s*=",                           "HIGH",   "Vue v-html directive — raw HTML render হচ্ছে"),
    (r"Vue\.compile\s*\(",                    "HIGH",   "Vue.compile() দিয়ে dynamic template compile হচ্ছে"),
    (r"createApp.*template\s*:",              "MEDIUM", "Vue dynamic template string দিয়ে app তৈরি হচ্ছে"),

    # ── Angular ───────────────────────────────────────────────────────────────
    (r"bypassSecurityTrustHtml\s*\(",         "HIGH",   "Angular DomSanitizer bypass — HTML trust করা হচ্ছে"),
    (r"bypassSecurityTrustScript\s*\(",       "HIGH",   "Angular DomSanitizer bypass — Script trust করা হচ্ছে"),
    (r"bypassSecurityTrustUrl\s*\(",          "HIGH",   "Angular DomSanitizer bypass — URL trust করা হচ্ছে"),
    (r"bypassSecurityTrustResourceUrl\s*\(",  "HIGH",   "Angular DomSanitizer bypass — ResourceUrl trust করা হচ্ছে"),
    (r"bypassSecurityTrustStyle\s*\(",        "MEDIUM", "Angular DomSanitizer bypass — Style trust করা হচ্ছে"),
    (r"nativeElement\.innerHTML",             "HIGH",   "Angular ElementRef.nativeElement.innerHTML — DOM bypass হচ্ছে"),
    (r"nativeElement\.outerHTML",             "HIGH",   "Angular ElementRef.nativeElement.outerHTML — DOM bypass হচ্ছে"),
    (r"\[innerHTML\]",                        "MEDIUM", "Angular [innerHTML] binding — sanitize হলেও risky"),

    # ── Next.js / SSR ─────────────────────────────────────────────────────────
    (r"getServerSideProps.*query\.",          "MEDIUM", "Next.js getServerSideProps এ raw query data ব্যবহার হচ্ছে"),
    (r"getStaticProps.*params\.",             "LOW",    "Next.js getStaticProps এ params access হচ্ছে"),
    (r"res\.write\s*\(",                      "MEDIUM", "Next.js API route এ raw write হচ্ছে"),
    (r"res\.end\s*\(",                        "LOW",    "Next.js API route এ res.end() call হচ্ছে"),

    # ── Svelte ────────────────────────────────────────────────────────────────
    (r"\{@html\s+",                           "HIGH",   "Svelte {@html} tag — raw HTML render হচ্ছে"),

    # ── Template engines (Handlebars, EJS, Pug, Nunjucks) ────────────────────
    (r"\{!--.*--\}|\{!\s*\w",                 "MEDIUM", "Handlebars unescaped triple-stash ব্যবহার হচ্ছে"),
    (r"\{\{\{.*\}\}\}",                       "HIGH",   "Handlebars triple-brace {{{ }}} — unescaped output"),
    (r"<%[-=]",                               "HIGH",   "EJS <%- বা <%= দিয়ে unescaped output হচ্ছে"),
    (r"!\s*=\s*(?:null|undefined|false)",     "LOW",    "Falsy check — null-check pattern (context দেখো)"),
    (r"\|\s*safe",                            "HIGH",   "Nunjucks/Jinja2 |safe filter — HTML escape বন্ধ"),
    (r"\|\s*raw",                             "HIGH",   "Template |raw filter — HTML escape বন্ধ"),

    # ── Prototype pollution ───────────────────────────────────────────────────
    (r"Object\.assign\s*\(\s*\{\s*\}",        "LOW",    "Object.assign — prototype pollution possible যদি input unvalidated হয়"),
    (r"__proto__",                            "HIGH",   "__proto__ access — prototype pollution risk"),
    (r"constructor\s*\[\s*['\"`]prototype",   "HIGH",   "constructor[prototype] access — prototype pollution risk"),

    # ── PostMessage / Message channel ─────────────────────────────────────────
    (r"addEventListener\s*\(\s*['\"`]message","MEDIUM", "postMessage listener — origin check আছে কিনা দেখো"),
    (r"\.data\s*(?:;|\)|\s*==|\s*!|\.)",      "LOW",    "MessageEvent.data access — source validate হচ্ছে কিনা দেখো"),

    # ── Misc high-risk patterns ───────────────────────────────────────────────
    (r"atob\s*\(",                            "MEDIUM", "atob() দিয়ে base64 decode হচ্ছে — payload obfuscation possible"),
    (r"unescape\s*\(",                        "MEDIUM", "unescape() deprecated — encoded payload আসতে পারে"),
    (r"decodeURIComponent\s*\(",              "LOW",    "decodeURIComponent — URL-encoded input decode হচ্ছে"),
    (r"\.srcdoc\s*=",                         "HIGH",   "iframe srcdoc এ HTML inject হচ্ছে"),
    (r"\.sandbox\s*=",                        "MEDIUM", "iframe sandbox attribute modify হচ্ছে"),
    (r"crypto\.subtle",                       "LOW",    "Web Crypto API ব্যবহার হচ্ছে"),
    (r"fetch\s*\(\s*[^'\"`\s]+\s*[\),]",      "LOW",    "fetch() এ dynamic URL দেওয়া হচ্ছে"),
    (r"XMLHttpRequest",                       "LOW",    "XHR ব্যবহার হচ্ছে — URL ও response handling দেখো"),
    (r"WebSocket\s*\(\s*[^'\"`\s]+",          "LOW",    "WebSocket এ dynamic URL দেওয়া হচ্ছে"),
]

# ─── Dangerous HTML Event Attributes ──────────────────────────────────────────
DANGEROUS_EVENTS = [
    "onload", "onclick", "onerror", "onfocus", "onmouseover",
    "onchange", "onkeyup", "onkeydown", "onsubmit", "onblur",
    "ondblclick", "onmouseout", "onmouseenter", "oninput",
    "onmousedown", "onmouseup", "onpointerdown", "onpointerup",
    "ontouchstart", "ontouchend", "ondragstart", "ondrop",
    "onpaste", "oncopy", "oncut", "onbeforeinput",
    "onanimationstart", "ontransitionend", "onsearch",
    "onwheel", "onscroll", "onresize", "oncontextmenu",
]

# ─── Source Patterns (user input sources) ─────────────────────────────────────
SOURCE_PATTERNS = [
    (r"location\.search",        "URL query parameter থেকে input নেওয়া হচ্ছে"),
    (r"location\.hash",          "URL hash থেকে input নেওয়া হচ্ছে"),
    (r"location\.pathname",      "URL pathname থেকে input নেওয়া হচ্ছে"),
    (r"document\.referrer",      "Referrer header থেকে input নেওয়া হচ্ছে"),
    (r"document\.cookie",        "Cookie থেকে input নেওয়া হচ্ছে"),
    (r"document\.URL",           "document.URL থেকে input নেওয়া হচ্ছে"),
    (r"document\.documentURI",   "document.documentURI থেকে input নেওয়া হচ্ছে"),
    (r"document\.baseURI",       "document.baseURI থেকে input নেওয়া হচ্ছে"),
    (r"window\.name",            "window.name থেকে input নেওয়া হচ্ছে"),
    (r"postMessage",             "postMessage দিয়ে data আসছে"),
    (r"URLSearchParams",         "URLSearchParams দিয়ে query parse হচ্ছে"),
    (r"getParameter\s*\(",       "getParameter() দিয়ে input নেওয়া হচ্ছে"),
    (r"localStorage\.getItem",   "localStorage থেকে data পড়া হচ্ছে"),
    (r"sessionStorage\.getItem", "sessionStorage থেকে data পড়া হচ্ছে"),
    (r"indexedDB\.open",         "indexedDB থেকে data access হচ্ছে"),
    (r"navigator\.userAgent",    "userAgent string পড়া হচ্ছে — spoofable"),
    (r"history\.pushState",      "history.pushState দিয়ে URL change হচ্ছে"),
    (r"MessageEvent\.data",      "MessageEvent.data থেকে input আসছে"),
    (r"req\.params\.",           "Express req.params থেকে user input আসছে"),
    (r"req\.query\.",            "Express req.query থেকে user input আসছে"),
    (r"req\.body\.",             "Express req.body থেকে user input আসছে"),
    (r"req\.headers\.",          "Express req.headers থেকে input আসছে"),
    (r"request\.GET\.",          "Django/Flask GET param থেকে input আসছে"),
    (r"request\.POST\.",         "Django/Flask POST param থেকে input আসছে"),
    (r"\$_GET\[",                "PHP $_GET থেকে user input আসছে"),
    (r"\$_POST\[",               "PHP $_POST থেকে user input আসছে"),
    (r"\$_REQUEST\[",            "PHP $_REQUEST থেকে user input আসছে"),
    (r"\$_COOKIE\[",             "PHP $_COOKIE থেকে user input আসছে"),
    (r"\$_SERVER\[",             "PHP $_SERVER থেকে user input আসছে"),
]


def _snippet(html: str, match_start: int, match_end: int, radius: int = 100) -> str:
    start = max(0, match_start - radius)
    end   = min(len(html), match_end + radius)
    return html[start:end].replace("\n", " ").strip()


def find_sinks(html: str) -> List[Dict[str, str]]:
    """JS/HTML এ dangerous sink খোঁজো।"""
    found = []
    for pattern, severity, reason in SINK_PATTERNS:
        for m in re.finditer(pattern, html, flags=re.IGNORECASE):
            found.append({
                "sink":     m.group(0),
                "severity": severity,
                "reason":   reason,
                "snippet":  _snippet(html, m.start(), m.end()),
            })
    logger.debug("Found %d sinks", len(found))
    return found


def find_sources(html: str) -> List[Dict[str, str]]:
    """User-controlled input source গুলো খোঁজো।"""
    found = []
    for pattern, reason in SOURCE_PATTERNS:
        for m in re.finditer(pattern, html, flags=re.IGNORECASE):
            found.append({
                "source":  m.group(0),
                "reason":  reason,
                "snippet": _snippet(html, m.start(), m.end()),
            })
    return found


def extract_dom_candidates(html: str) -> List[Dict[str, str]]:
    """HTML tag এ inline event handler এবং script block এ sink খোঁজো।"""
    soup = BeautifulSoup(html, "html.parser")
    candidates = []

    # Inline event handlers
    for tag in soup.find_all(True):
        for attr in DANGEROUS_EVENTS:
            if tag.has_attr(attr):
                candidates.append({
                    "tag":     tag.name,
                    "attr":    attr,
                    "value":   tag[attr][:200],
                    "snippet": str(tag)[:300],
                    "severity": "HIGH",
                    "reason":  f"Inline {attr} handler পাওয়া গেছে",
                })

    # Script block analysis
    for tag in soup.find_all("script"):
        content = (tag.string or "").strip()
        if not content:
            continue
        for pattern, severity, reason in SINK_PATTERNS:
            for m in re.finditer(pattern, content, flags=re.IGNORECASE):
                candidates.append({
                    "tag":     "script",
                    "attr":    "content",
                    "value":   m.group(0),
                    "snippet": _snippet(content, m.start(), m.end(), radius=80),
                    "severity": severity,
                    "reason":  reason,
                })

    logger.debug("Found %d DOM candidates", len(candidates))
    return candidates


def analyze_page(url: str, html: str) -> Dict:
    """
    একটা পেজের পুরো source code analyze করে structured result দাও।
    Reporter এ আলাদা source_analysis.txt তে যাবে।
    """
    sinks      = find_sinks(html)
    sources    = find_sources(html)
    candidates = extract_dom_candidates(html)

    high   = [s for s in sinks if s.get("severity") == "HIGH"]
    medium = [s for s in sinks if s.get("severity") == "MEDIUM"]
    low    = [s for s in sinks if s.get("severity") == "LOW"]

    # Overall risk
    if high:
        risk = "HIGH"
    elif medium:
        risk = "MEDIUM"
    elif low or sources:
        risk = "LOW"
    else:
        risk = "SAFE"

    return {
        "url":        url,
        "risk":       risk,
        "sinks":      sinks,
        "sources":    sources,
        "dom_candidates": candidates,
        "summary": {
            "total_sinks":   len(sinks),
            "high":          len(high),
            "medium":        len(medium),
            "low":           len(low),
            "sources_found": len(sources),
            "dom_events":    len(candidates),
        }
    }
