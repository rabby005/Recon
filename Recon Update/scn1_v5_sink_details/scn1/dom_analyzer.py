import logging
import re
from typing import Dict, List
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ─── Dangerous Sinks ───────────────────────────────────────────────────────────
SINK_PATTERNS = [
    (r"innerHTML\s*[+]?=",          "HIGH",   "innerHTML এ directly value বসানো হচ্ছে"),
    (r"outerHTML\s*[+]?=",          "HIGH",   "outerHTML এ directly value বসানো হচ্ছে"),
    (r"document\.write\s*\(",       "HIGH",   "document.write() দিয়ে output করা হচ্ছে"),
    (r"eval\s*\(",                  "HIGH",   "eval() দিয়ে code execute হচ্ছে"),
    (r"insertAdjacentHTML\s*\(",    "HIGH",   "insertAdjacentHTML দিয়ে HTML inject হচ্ছে"),
    (r"setTimeout\s*\(\s*['\"`]",   "MEDIUM", "setTimeout এ string pass হচ্ছে"),
    (r"setInterval\s*\(\s*['\"`]",  "MEDIUM", "setInterval এ string pass হচ্ছে"),
    (r"location\.href\s*=",         "MEDIUM", "location.href এ value assign হচ্ছে"),
    (r"location\.replace\s*\(",     "MEDIUM", "location.replace() দিয়ে redirect হচ্ছে"),
    (r"window\.location\s*=",       "MEDIUM", "window.location এ value assign হচ্ছে"),
    (r"src\s*=\s*['\"`]?\s*\$",     "MEDIUM", "src attribute এ dynamic value বসানো হচ্ছে"),
    (r"href\s*=\s*['\"`]?\s*\$",    "MEDIUM", "href attribute এ dynamic value বসানো হচ্ছে"),
    (r"\.html\s*\(",                "MEDIUM", "jQuery .html() দিয়ে content set হচ্ছে"),
    (r"\.append\s*\(\s*[^'\"`,)]+\)","LOW",  "jQuery .append() এ variable pass হচ্ছে"),
    (r"\.prepend\s*\(\s*[^'\"`,)]+\)","LOW", "jQuery .prepend() এ variable pass হচ্ছে"),
    (r"location\.search",           "LOW",   "URL query string পড়া হচ্ছে"),
    (r"location\.hash",             "LOW",   "URL hash পড়া হচ্ছে"),
    (r"document\.cookie",           "LOW",   "Cookie access হচ্ছে"),
    (r"document\.referrer",         "LOW",   "Referrer header পড়া হচ্ছে"),
]

# ─── Dangerous HTML Event Attributes ──────────────────────────────────────────
DANGEROUS_EVENTS = [
    "onload", "onclick", "onerror", "onfocus", "onmouseover",
    "onchange", "onkeyup", "onkeydown", "onsubmit", "onblur",
    "ondblclick", "onmouseout", "onmouseenter", "oninput",
]

# ─── Source Patterns (user input sources) ─────────────────────────────────────
SOURCE_PATTERNS = [
    (r"location\.search",    "URL query parameter থেকে input নেওয়া হচ্ছে"),
    (r"location\.hash",      "URL hash থেকে input নেওয়া হচ্ছে"),
    (r"document\.referrer",  "Referrer header থেকে input নেওয়া হচ্ছে"),
    (r"document\.cookie",    "Cookie থেকে input নেওয়া হচ্ছে"),
    (r"window\.name",        "window.name থেকে input নেওয়া হচ্ছে"),
    (r"postMessage",         "postMessage দিয়ে data আসছে"),
    (r"URLSearchParams",     "URLSearchParams দিয়ে query parse হচ্ছে"),
    (r"getParameter\s*\(",   "getParameter() দিয়ে input নেওয়া হচ্ছে"),
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
