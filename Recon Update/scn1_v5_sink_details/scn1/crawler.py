import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": "ReconSecurityCrawler/1.0 (+https://example.com)"
}

SIMPLE_JS_INPUT_PATTERNS = [
    r"document\.getElementById\(['\"](?P<name>[^'\"]+)['\"]\)",
    r"document\.querySelector\(['\"](?P<name>[^'\"]+)['\"]\)",
    r"document\.getElementsByName\(['\"](?P<name>[^'\"]+)['\"]\)",
    r"querySelectorAll\(['\"](?P<name>[^'\"]+)['\"]\)",
    r"\$\(['\"](?P<name>[^'\"]+)['\"]\)",
]

DANGEROUS_JS_REGEX = re.compile(
    r"\b(innerHTML|outerHTML|document\.write|eval\(|setTimeout\(|setInterval\(|location\.|href\s*=|src\s*=|insertAdjacentHTML|replace\()",
    re.IGNORECASE,
)


@dataclass
class InputPoint:
    location: str
    name: Optional[str]
    input_type: str
    value: Optional[str]
    form_action: Optional[str] = None
    method: str = "GET"
    element_html: str = ""
    page_url: str = ""
    parameter_name: Optional[str] = None


@dataclass
class TargetPage:
    url: str
    final_url: str
    html: str
    inputs: List[InputPoint] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    sinks: List[Dict[str, str]] = field(default_factory=list)
    js_candidates: List[str] = field(default_factory=list)
    login_required: bool = False
    login_reason: str = ""


def normalize_url(value: str, default_scheme: str = "https") -> str:
    parsed = urlparse(value.strip())
    if not parsed.scheme:
        value = f"{default_scheme}://{value.strip()}"
        parsed = urlparse(value)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {value}")
    return urlunparse(parsed._replace(path=parsed.path or "/"))


def extract_query_inputs(url: str) -> List[InputPoint]:
    parsed = urlparse(url)
    inputs = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        inputs.append(
            InputPoint(
                location="url_parameter",
                name=name,
                input_type="query",
                value=value,
                page_url=url,
                parameter_name=name,
            )
        )
    return inputs


def parse_form(form, base_url: str) -> List[InputPoint]:
    inputs = []
    action = form.get("action") or base_url
    method = form.get("method", "GET").upper()
    for element in form.find_all(["input", "textarea", "select"]):
        name = element.get("name") or element.get("id")
        if not name:
            continue
        input_type = element.name
        if element.name == "input":
            input_type = element.get("type", "text")
        value = element.get("value") or element.text or ""
        inputs.append(
            InputPoint(
                location="form",
                name=name,
                input_type=input_type,
                value=value,
                form_action=urljoin(base_url, action),
                method=method,
                element_html=str(element),
                page_url=base_url,
                parameter_name=name,
            )
        )
    return inputs


def parse_html_inputs(url: str, html: str) -> Tuple[List[InputPoint], List[str], List[Dict[str, str]]]:
    soup = BeautifulSoup(html, "html.parser")
    input_points: List[InputPoint] = []
    js_candidates = []
    sinks = []

    for form in soup.find_all("form"):
        input_points.extend(parse_form(form, url))

    for input_tag in soup.find_all("input"):
        if input_tag.get("type") in {"search", "text", "email", "url", "tel", "password"}:
            if not input_tag.get("name"):
                continue
            input_points.append(
                InputPoint(
                    location="input_field",
                    name=input_tag.get("name"),
                    input_type=input_tag.get("type", "text"),
                    value=input_tag.get("value", ""),
                    element_html=str(input_tag),
                    page_url=url,
                    parameter_name=input_tag.get("name"),
                )
            )
    for textarea in soup.find_all("textarea"):
        if not textarea.get("name"):
            continue
        input_points.append(
            InputPoint(
                location="textarea",
                name=textarea.get("name"),
                input_type="textarea",
                value=textarea.text or "",
                element_html=str(textarea),
                page_url=url,
                parameter_name=textarea.get("name"),
            )
        )
    for hidden in soup.find_all("input", type="hidden"):
        if not hidden.get("name"):
            continue
        input_points.append(
            InputPoint(
                location="hidden_input",
                name=hidden.get("name"),
                input_type="hidden",
                value=hidden.get("value", ""),
                element_html=str(hidden),
                page_url=url,
                parameter_name=hidden.get("name"),
            )
        )

    url_inputs = extract_query_inputs(url)
    input_points.extend(url_inputs)

    script_text = "\n".join([script.string or "" for script in soup.find_all("script")])
    for pattern in SIMPLE_JS_INPUT_PATTERNS:
        for match in re.finditer(pattern, script_text):
            name = match.groupdict().get("name")
            if name:
                js_candidates.append(name)
                input_points.append(
                    InputPoint(
                        location="js_dynamic",
                        name=name,
                        input_type="dynamic",
                        value="",
                        element_html=match.group(0),
                        page_url=url,
                        parameter_name=name,
                    )
                )

    for snippet in soup.find_all(text=re.compile(r"(innerHTML|outerHTML|document\.write|eval\(|location\.|src=)", re.IGNORECASE)):
        sinks.append({"sink": snippet.strip(), "context": str(snippet)[:250]})

    for script in soup.find_all("script"):
        content = script.string or ""
        for match in DANGEROUS_JS_REGEX.finditer(content):
            sinks.append({"sink": match.group(0), "context": content[match.start() - 40: match.end() + 40]})

    return input_points, js_candidates, sinks


LOGIN_KEYWORDS = [
    "login", "log in", "sign in", "signin",
    "please login", "please sign in",
    "you must be logged in", "you need to log in",
    "members only", "restricted area",
    "authentication required", "access denied",
    "unauthorized", "401",
]

LOGIN_URL_KEYWORDS = [
    "login", "signin", "sign-in", "log-in",
    "auth", "authenticate", "account/login",
    "user/login", "wp-login",
]

LOGIN_REDIRECT_KEYWORDS = [
    "login", "signin", "sign-in", "auth",
]


def detect_login_required(url: str, final_url: str, html: str, status_code: int) -> Tuple[bool, str]:
    """
    Page টা login required কিনা detect করো।
    Returns: (is_login_required, reason)
    """
    # 401 বা 403 status code
    if status_code in (401, 403):
        return True, f"HTTP {status_code} — access denied"

    # Final URL এ login page এ redirect হয়েছে কিনা
    final_lower = final_url.lower()
    for kw in LOGIN_REDIRECT_KEYWORDS:
        if kw in final_lower and kw not in url.lower():
            return True, f"Login page এ redirect হয়েছে → {final_url}"

    # HTML content এ login keyword আছে কিনা
    if html:
        html_lower = html.lower()
        for kw in LOGIN_KEYWORDS:
            if kw in html_lower:
                # Login form আছে কিনা confirm করো
                soup = BeautifulSoup(html, "html.parser")
                password_inputs = soup.find_all("input", type="password")
                if password_inputs:
                    return True, f"Login form পাওয়া গেছে (keyword: '{kw}')"

    return False, ""


def fetch_page(session: requests.Session, url: str, headers: Dict[str, str], cookies: Dict[str, str], timeout: int) -> TargetPage:
    try:
        response = session.get(url, headers=headers, cookies=cookies, timeout=timeout, allow_redirects=True)
        response.raise_for_status()
        html = response.text
        inputs, js_candidates, sinks = parse_html_inputs(response.url, html)
        login_required, login_reason = detect_login_required(url, response.url, html, response.status_code)
        return TargetPage(
            url=url,
            final_url=response.url,
            html=html,
            inputs=inputs,
            js_candidates=js_candidates,
            sinks=sinks,
            login_required=login_required,
            login_reason=login_reason,
        )
    except Exception as error:
        message = str(error)
        logger.debug("Error fetching %s: %s", url, message)
        return TargetPage(url=url, final_url=url, html="", errors=[message])


def crawl_subdomain(
    start_url: str,
    session: requests.Session,
    headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: int,
    rate_limit: float,
    max_pages: int,
) -> List[TargetPage]:
    pages: List[TargetPage] = []
    visited: Set[str] = set()
    queue: List[str] = [start_url]
    parsed_start = urlparse(start_url)
    host = parsed_start.netloc.lower()

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        target = fetch_page(session, url, headers, cookies, timeout)
        pages.append(target)
        if target.html and len(pages) < max_pages:
            soup = BeautifulSoup(target.html, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"].strip()
                if href.startswith("mailto:") or href.startswith("javascript:"):
                    continue
                candidate = urljoin(target.final_url, href)
                parsed = urlparse(candidate)
                if parsed.netloc.lower() == host and candidate not in visited:
                    queue.append(candidate)
            for tag in soup.find_all(["script", "link"], src=True):
                candidate = urljoin(target.final_url, tag["src"])
                parsed = urlparse(candidate)
                if parsed.netloc.lower() == host and candidate not in visited:
                    queue.append(candidate)
        if rate_limit > 0:
            time.sleep(rate_limit)
    return pages


def crawl_subdomains(
    subdomains: List[str],
    concurrency: int,
    timeout: int,
    retries: int,
    rate_limit: float,
    headers: Dict[str, str],
    cookies: Dict[str, str],
    max_pages: int,
) -> List[TargetPage]:
    normalized_urls = []
    for domain in subdomains:
        try:
            normalized_urls.append(normalize_url(domain))
        except ValueError:
            logger.warning("Skipping invalid subdomain entry: %s", domain)
    results: List[TargetPage] = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_url = {
            executor.submit(
                crawl_subdomain,
                target_url,
                requests.Session(),
                {**DEFAULT_HEADERS, **headers},
                cookies,
                timeout,
                rate_limit,
                max_pages,
            ): target_url
            for target_url in normalized_urls
        }
        for future in as_completed(future_to_url):
            try:
                pages = future.result()
                results.extend(pages)
            except Exception as error:
                logger.error("Exception crawling %s: %s", future_to_url[future], error)
    unique_targets: List[TargetPage] = []
    seen: Set[str] = set()
    for page in results:
        if page.final_url not in seen:
            unique_targets.append(page)
            seen.add(page.final_url)
    return unique_targets
