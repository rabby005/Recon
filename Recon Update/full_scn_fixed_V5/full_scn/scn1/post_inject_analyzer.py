"""
post_inject_analyzer.py
-----------------------
Payload inject করার পরে response HTML analyze করে
CONFIRMED VULNERABLE / POSSIBLY VULNERABLE / SAFE নির্ধারণ করে।

Logic:
  CONFIRMED VULNERABLE → payload dangerous context এ গেছে এবং execute হবে
  POSSIBLY VULNERABLE  → payload reflect হয়েছে কিন্তু context পুরোপুরি নিশ্চিত না
  SAFE                 → payload encode হয়ে গেছে অথবা reflect হয়নি
"""

import re
import logging
from typing import Dict, List, Tuple, Optional
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ── HTML Encoding চেক patterns ────────────────────────────────────────────────
# এগুলো থাকলে payload execute হবে না
ENCODED_PATTERNS = [
    "&lt;",    # < encode
    "&gt;",    # > encode
    "&amp;",   # & encode
    "&#x3c;",  # < hex encode
    "&#60;",   # < decimal encode
    "&#x3e;",  # > hex encode
    "&#62;",   # > decimal encode
    "&#x27;",  # ' hex encode
    "&quot;",  # " encode
    "\\u003c", # < unicode escape
    "\\u003e", # > unicode escape
]

# ── Dangerous Sinks ──────────────────────────────────────────────────────────
SINK_PATTERNS = [
    (r"innerHTML\s*[+]?=",          "HIGH",   "innerHTML"),
    (r"outerHTML\s*[+]?=",          "HIGH",   "outerHTML"),
    (r"document\.write\s*\(",       "HIGH",   "document.write()"),
    (r"eval\s*\(",                  "HIGH",   "eval()"),
    (r"insertAdjacentHTML\s*\(",    "HIGH",   "insertAdjacentHTML()"),
    (r"\.html\s*\(",                "HIGH",   "jQuery .html()"),
    (r"setTimeout\s*\(\s*['\"`]",   "MEDIUM", "setTimeout()"),
    (r"setInterval\s*\(\s*['\"`]",  "MEDIUM", "setInterval()"),
    (r"location\.href\s*=",         "MEDIUM", "location.href"),
    (r"window\.location\s*=",       "MEDIUM", "window.location"),
    (r"location\.replace\s*\(",     "MEDIUM", "location.replace()"),
    (r"\.append\s*\(",              "LOW",    "jQuery .append()"),
    (r"\.prepend\s*\(",             "LOW",    "jQuery .prepend()"),
]

# ── Dangerous Event Attributes ────────────────────────────────────────────────
DANGEROUS_EVENTS = [
    "onload", "onclick", "onerror", "onfocus", "onmouseover",
    "onchange", "onkeyup", "onkeydown", "onsubmit", "onblur",
    "ondblclick", "onmouseout", "onmouseenter", "oninput",
]

# ── Verdict constants ────────────────────────────────────────────────────────
CONFIRMED  = "CONFIRMED VULNERABLE"
POSSIBLY   = "POSSIBLY VULNERABLE"
SAFE       = "SAFE"
NOT_FOUND  = "NOT REFLECTED"


def _snippet(text: str, pos: int, radius: int = 150) -> str:
    start = max(0, pos - radius)
    end   = min(len(text), pos + radius)
    return text[start:end].replace("\n", " ").strip()


def _is_payload_encoded(html: str, payload: str) -> bool:
    """
    Payload HTML encode হয়ে গেছে কিনা check করো।
    যদি encode হয়ে গেছে → execute হবে না → SAFE
    """
    # payload এর < বা > character encode হয়েছে কিনা দেখো
    if "<" in payload or ">" in payload:
        for enc in ENCODED_PATTERNS:
            if enc.lower() in html.lower():
                # encode করা version response এ আছে — payload neutralized
                return True
    return False


def _get_script_ranges(html: str) -> List[Tuple[int, int]]:
    """HTML এর সব <script>...</script> block এর position বের করো।"""
    ranges = []
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.IGNORECASE | re.DOTALL):
        ranges.append((m.start(), m.end()))
    return ranges


def _in_script_block(pos: int, script_ranges: List[Tuple[int, int]]) -> bool:
    for s, e in script_ranges:
        if s < pos < e:
            return True
    return False


def _check_script_context(html: str, payload: str, script_ranges: List[Tuple[int, int]]) -> Optional[Dict]:
    """
    Payload কি <script> block এর ভেতরে গেছে?
    গেলে কোনো dangerous sink এর সাথে আছে কিনা দেখো।
    """
    lower_html    = html.lower()
    lower_payload = payload.lower()

    idx = 0
    while True:
        pos = lower_html.find(lower_payload, idx)
        if pos < 0:
            break
        idx = pos + 1

        if not _in_script_block(pos, script_ranges):
            continue

        # Script block এ আছে — sink খোঁজো কাছাকাছি (±300 char)
        surrounding = html[max(0, pos - 300): pos + 300]
        for pattern, severity, sink_name in SINK_PATTERNS:
            if re.search(pattern, surrounding, re.IGNORECASE):
                return {
                    "verdict":   CONFIRMED,
                    "reason":    f"Payload <script> block এ `{sink_name}` sink এর কাছে reflect হয়েছে — XSS execute হবে",
                    "context":   "script_with_sink",
                    "severity":  severity,
                    "snippet":   _snippet(html, pos),
                    "sink":      sink_name,
                }

        # Sink নেই কিন্তু script block এ আছে
        return {
            "verdict":  POSSIBLY,
            "reason":   "Payload <script> block এ reflect হয়েছে — sink না থাকলেও JS string break করা সম্ভব",
            "context":  "script_block",
            "severity": "MEDIUM",
            "snippet":  _snippet(html, pos),
            "sink":     None,
        }

    return None


def _check_event_handler_context(html: str, payload: str) -> Optional[Dict]:
    """
    Payload কি কোনো HTML event handler attribute (onclick, onerror...) এ গেছে?
    গেলে CONFIRMED VULNERABLE।
    """
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(True):
        for attr in DANGEROUS_EVENTS:
            val = tag.get(attr, "")
            if payload.lower() in val.lower():
                return {
                    "verdict":  CONFIRMED,
                    "reason":   f"Payload `<{tag.name} {attr}=\"...\">` এ directly reflect হয়েছে — browser এ execute হবে",
                    "context":  f"event_handler:{attr}",
                    "severity": "HIGH",
                    "snippet":  str(tag)[:300],
                    "sink":     attr,
                }
    return None


def _check_html_attribute_context(html: str, payload: str) -> Optional[Dict]:
    """
    Payload কি কোনো HTML attribute value এ গেছে (event handler ছাড়া)?
    যেমন: value="payload", src="payload", href="payload"
    """
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            if attr in DANGEROUS_EVENTS:
                continue  # আগেই check হয়েছে
            if isinstance(val, list):
                val = " ".join(val)
            if payload.lower() in str(val).lower():
                # href বা src এ javascript: আছে কিনা দেখো
                if attr in ("href", "src") and "javascript:" in str(val).lower():
                    return {
                        "verdict":  CONFIRMED,
                        "reason":   f"`{attr}` attribute এ javascript: payload reflect হয়েছে — click করলে execute হবে",
                        "context":  f"attribute:{attr}",
                        "severity": "HIGH",
                        "snippet":  str(tag)[:300],
                        "sink":     attr,
                    }
                return {
                    "verdict":  POSSIBLY,
                    "reason":   f"Payload `{attr}` attribute এ reflect হয়েছে — attribute breakout দিয়ে XSS সম্ভব",
                    "context":  f"attribute:{attr}",
                    "severity": "MEDIUM",
                    "snippet":  str(tag)[:300],
                    "sink":     attr,
                }
    return None


def _check_inline_html_context(html: str, payload: str, script_ranges: List[Tuple[int, int]]) -> Optional[Dict]:
    """
    Payload কি HTML body তে directly গেছে (script/attribute ছাড়া)?
    যদি payload এ <script>, <img onerror>, <svg> ইত্যাদি tag আছে
    এবং সেটা encode হয়নি — CONFIRMED।
    """
    lower_html    = html.lower()
    lower_payload = payload.lower()

    # HTML tag injection signs payload এ আছে কিনা
    injectable_tags = ["<script", "<img", "<svg", "<iframe", "<body", "<input", "<details"]
    has_tag = any(t in lower_payload for t in injectable_tags)

    idx = 0
    while True:
        pos = lower_html.find(lower_payload, idx)
        if pos < 0:
            break
        idx = pos + 1

        if _in_script_block(pos, script_ranges):
            continue  # script context আগেই handle হয়েছে

        snippet = _snippet(html, pos)

        if has_tag:
            return {
                "verdict":  CONFIRMED,
                "reason":   "Payload HTML tag সহ inline HTML body তে unencoded reflect হয়েছে — tag injection সফল",
                "context":  "inline_html",
                "severity": "HIGH",
                "snippet":  snippet,
                "sink":     "inline_injection",
            }
        else:
            return {
                "verdict":  POSSIBLY,
                "reason":   "Payload HTML body তে reflect হয়েছে — tag character (<, >) inject করা সম্ভব কিনা manually যাচাই করো",
                "context":  "inline_html",
                "severity": "LOW",
                "snippet":  snippet,
                "sink":     None,
            }

    return None


def analyze_injected_response(
    response_html: str,
    payload: str,
    tested_url: str,
    parameter_name: str,
) -> Dict:
    """
    Main function।
    Payload inject করার পরে response HTML analyze করে verdict দেয়।

    Verdict:
      CONFIRMED VULNERABLE → payload dangerous context এ গেছে, execute হবে
      POSSIBLY VULNERABLE  → payload reflect হয়েছে কিন্তু নিশ্চিত না
      SAFE                 → payload encode হয়েছে বা reflect হয়নি
      NOT REFLECTED        → payload response এ নেই
    """
    result_base = {
        "tested_url":     tested_url,
        "parameter_name": parameter_name,
        "payload":        payload,
        "verdict":        NOT_FOUND,
        "reason":         "Payload response এ পাওয়া যায়নি।",
        "context":        None,
        "severity":       "NONE",
        "snippet":        "",
        "sink":           None,
        # backward compat
        "dom_risk":       "NONE",
        "reflected":      False,
        "contexts":       [],
        "event_handler_hits": [],
        "summary":        "Payload response এ reflect হয়নি।",
        "source":         "http_response",
    }

    if not response_html or not payload:
        return result_base

    # ── Step 1: Payload response এ আছে কিনা দেখো ────────────────────────────
    reflected = payload.lower() in response_html.lower()
    if not reflected:
        return result_base

    # ── Step 2: Encode হয়ে গেছে কিনা দেখো → SAFE ───────────────────────────
    if _is_payload_encoded(response_html, payload):
        return {
            **result_base,
            "verdict":   SAFE,
            "reason":    "Payload HTML encode হয়ে গেছে (&lt; &gt;) — browser execute করবে না",
            "severity":  "NONE",
            "dom_risk":  "NONE",
            "reflected": True,
            "summary":   "✅ SAFE — Payload encode হয়েছে, execute হবে না।",
        }

    # ── Step 3: Context analysis — priority অনুযায়ী ────────────────────────
    script_ranges = _get_script_ranges(response_html)

    # Priority 1: Event handler (সবচেয়ে বিপজ্জনক)
    hit = _check_event_handler_context(response_html, payload)
    if hit:
        return _build_result(result_base, hit)

    # Priority 2: Script block + sink
    hit = _check_script_context(response_html, payload, script_ranges)
    if hit:
        return _build_result(result_base, hit)

    # Priority 3: HTML attribute
    hit = _check_html_attribute_context(response_html, payload)
    if hit:
        return _build_result(result_base, hit)

    # Priority 4: Inline HTML body
    hit = _check_inline_html_context(response_html, payload, script_ranges)
    if hit:
        return _build_result(result_base, hit)

    # Reflect হয়েছে কিন্তু কোনো dangerous context পাওয়া যায়নি
    return {
        **result_base,
        "verdict":   POSSIBLY,
        "reason":    "Payload reflect হয়েছে কিন্তু dangerous context detect করা যায়নি — manually যাচাই করো",
        "severity":  "LOW",
        "dom_risk":  "LOW",
        "reflected": True,
        "summary":   "🟡 POSSIBLY VULNERABLE — Manual check দরকার।",
    }


def _build_result(base: Dict, hit: Dict) -> Dict:
    """Hit result থেকে full result dict তৈরি করো।"""
    verdict  = hit["verdict"]
    severity = hit["severity"]

    # dom_risk backward compat
    dom_risk_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "NONE": "NONE"}
    dom_risk = dom_risk_map.get(severity, "LOW")

    # Summary
    if verdict == CONFIRMED:
        summary = f"🔴 CONFIRMED VULNERABLE — {hit['reason']}"
    elif verdict == POSSIBLY:
        summary = f"🟡 POSSIBLY VULNERABLE — {hit['reason']}"
    else:
        summary = f"✅ SAFE — {hit['reason']}"

    return {
        **base,
        "verdict":            verdict,
        "reason":             hit["reason"],
        "context":            hit.get("context"),
        "severity":           severity,
        "snippet":            hit.get("snippet", ""),
        "sink":               hit.get("sink"),
        "dom_risk":           dom_risk,
        "reflected":          True,
        "summary":            summary,
        "contexts":           [hit],
        "event_handler_hits": [hit] if "event_handler" in str(hit.get("context", "")) else [],
    }
