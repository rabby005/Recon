import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests
from post_inject_analyzer import analyze_injected_response

try:
    from playwright.sync_api import Browser, BrowserContext, sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class BrowserEngine:
    headers: Dict[str, str]
    cookies: Dict[str, str]
    timeout: int
    browser: Optional[Browser] = None
    context: Optional[BrowserContext] = None

    def __enter__(self) -> "BrowserEngine":
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=True)
        self.context = self.browser.new_context(ignore_https_errors=True)
        if self.headers:
            self.context.set_extra_http_headers(self.headers)
        if self.cookies:
            self.context.set_extra_http_headers(self.headers)
        return self

    def open_page(self, url: str) -> Dict[str, str]:
        assert self.context is not None
        page = self.context.new_page()
        page.set_default_timeout(self.timeout * 1000)
        page.goto(url, wait_until="domcontentloaded")
        content = page.content()
        dom = page.locator("body").inner_html()
        page.close()
        return {"content": content, "dom": dom}

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()
        self.playwright.stop()


def extract_source_snippet(text: str, marker: str, radius: int = 120) -> str:
    index = text.find(marker)
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(text), index + len(marker) + radius)
    return text[start:end].replace("\n", " ")


def inspect_response_for_payload(response_text: str, payload: str) -> Optional[str]:
    if payload in response_text:
        return extract_source_snippet(response_text, payload)
    if payload.lower() in response_text.lower():
        return extract_source_snippet(response_text, payload)
    return None


def inspect_dom_for_payload(dom_text: str, payload: str) -> Optional[str]:
    if payload in dom_text:
        return extract_source_snippet(dom_text, payload)
    if payload.lower() in dom_text.lower():
        return extract_source_snippet(dom_text, payload)
    return None


def build_request_for_input(input_point: Dict, payload: str) -> Dict:
    if input_point["location"] == "url_parameter":
        return {
            "method": "GET",
            "url": input_point["page_url"],
            "params": {input_point["parameter_name"]: payload},
            "data": None,
        }
    if input_point["location"] == "form":
        values = {input_point["parameter_name"]: payload}
        return {
            "method": input_point["method"],
            "url": input_point["form_action"] or input_point["page_url"],
            "params": values if input_point["method"] == "GET" else None,
            "data": values if input_point["method"] == "POST" else None,
        }
    return {
        "method": "GET",
        "url": input_point["page_url"],
        "params": {input_point["parameter_name"] or "injected": payload},
        "data": None,
    }


def test_payload(
    input_point: Dict,
    payload: str,
    headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: int,
    retries: int,
    use_browser: bool,
    browser_engine: Optional[BrowserEngine] = None,
) -> Dict[str, str]:
    session = requests.Session()
    session.headers.update(headers)
    session.cookies.update(cookies)
    request_data = build_request_for_input(input_point, payload)
    error = ""
    response_text = ""
    dom_text = ""
    source_snippet = ""
    dom_snippet = ""
    status = "none"
    last_exception = None

    for attempt in range(1, retries + 1):
        try:
            if request_data["method"] == "GET":
                response = session.get(request_data["url"], params=request_data["params"], timeout=timeout, allow_redirects=True)
            else:
                response = session.post(request_data["url"], params=request_data["params"], data=request_data["data"], timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            response_text = response.text
            source_snippet = inspect_response_for_payload(response_text, payload) or ""
            if source_snippet:
                status = "source"
            break
        except Exception as exc:
            last_exception = exc
            time.sleep(1)
            continue
    if last_exception and not response_text:
        error = str(last_exception)

    if use_browser and PLAYWRIGHT_AVAILABLE and browser_engine is not None:
        try:
            browser_result = browser_engine.open_page(request_data["url"])
            browser_content = browser_result.get("content", "")
            browser_dom = browser_result.get("dom", "")
            browser_snippet = inspect_dom_for_payload(browser_content, payload)
            dom_text = browser_dom
            if browser_snippet:
                dom_snippet = browser_snippet
                status = "dom" if status == "none" else f"{status}+dom"
        except Exception as exc:
            logger.debug("Browser inspection failed for %s: %s", request_data["url"], exc)
            if not error:
                error = str(exc)

    # ── Post-Inject Source Code Analysis ──────────────────────────────────────
    # Payload inject করার পরে response HTML analyze করো —
    # DOM-based XSS এর সম্ভাবনা আছে কিনা দেখো
    post_analysis = analyze_injected_response(
        response_html=response_text,
        payload=payload,
        tested_url=request_data["url"],
        parameter_name=input_point.get("parameter_name") or "",
    )

    # Browser DOM analysis থেকেও চেক করো (যদি browser mode চালু থাকে)
    if use_browser and PLAYWRIGHT_AVAILABLE and browser_engine is not None and dom_text:
        browser_post = analyze_injected_response(
            response_html=dom_text,
            payload=payload,
            tested_url=request_data["url"],
            parameter_name=input_point.get("parameter_name") or "",
        )
        # Browser result এর risk বেশি হলে সেটা নাও
        risk_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        if risk_order.get(browser_post["dom_risk"], 0) > risk_order.get(post_analysis["dom_risk"], 0):
            post_analysis = browser_post
            post_analysis["source"] = "browser_dom"
        else:
            post_analysis["source"] = "http_response"
    else:
        post_analysis["source"] = "http_response"

    return {
        "target_url": input_point["page_url"],
        "tested_url": request_data["url"],
        "input_name": input_point.get("name") or "",
        "parameter_name": input_point.get("parameter_name") or "",
        "payload": payload,
        "reflection_status": status,
        "source_snippet": source_snippet,
        "dom_snippet": dom_snippet,
        "error": error,
        # ── নতুন post-inject analysis ──
        "post_inject": post_analysis,
    }


def scan_inputs(
    input_points: List[Dict],
    payloads: List[str],
    headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: int,
    retries: int,
    concurrency: int,
    rate_limit: float,
    use_browser: bool,
) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    browser_engine = None
    if use_browser and PLAYWRIGHT_AVAILABLE:
        browser_engine = BrowserEngine(headers=headers, cookies=cookies, timeout=timeout)
        browser_engine.__enter__()

    try:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []
            for input_point in input_points:
                for payload in payloads:
                    futures.append(executor.submit(test_payload, input_point, payload, headers, cookies, timeout, retries, use_browser, browser_engine))
            for future in as_completed(futures):
                result = future.result()
                findings.append(result)
                if rate_limit > 0:
                    time.sleep(rate_limit)
    finally:
        if browser_engine is not None:
            browser_engine.__exit__(None, None, None)
    return findings
