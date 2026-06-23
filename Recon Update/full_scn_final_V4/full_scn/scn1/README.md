# Recon Security Scanner

A modular Python tool for authorized web security testing, bug bounty reconnaissance, and internal security assessments.

## Features

- Crawl subdomains from a TXT list
- Discover user-controllable input points:
  - forms
  - inputs
  - textareas
  - hidden fields
  - URL query parameters
  - JavaScript-derived dynamic inputs
- Inspect page source and DOM structure
- Detect potential dangerous sinks and injection candidates
- Inject custom XSS payloads from a TXT file
- Test each input point automatically
- Inspect reflected payloads in source and DOM
- Save detailed reports in TXT and JSON formats
- Colored terminal output with progress reporting
- Concurrency with safe rate limiting, timeout, and retries
- Optional headless browser support using Playwright
- Support custom headers, cookies, and user-agent

## Files

- `cli.py` — command line interface and orchestrator
- `crawler.py` — subdomain crawler and input discovery
- `payload_manager.py` — payload file loader and defaults
- `reflection_checker.py` — payload injection and response/DOM analysis
- `dom_analyzer.py` — source and DOM candidate extraction
- `reporter.py` — report generation

## Requirements

- Python 3.8+
- `requests`
- `beautifulsoup4`
- `rich`
- `playwright`

Install dependencies with:

```bash
pip install -r requirements.txt
```

Install Playwright browser (required):

```bash
pip install playwright
python -m playwright install
```

## Usage

**Recommended command (with browser mode):**

```bash
python cli.py --subdomains-file subdomains.txt --payloads-file payloads.txt --output-dir reports --use-browser
```

> **Why `--use-browser`?**
> Most modern websites use JavaScript to dynamically render content. Without `--use-browser`,
> the tool only sees the raw HTML response — JavaScript-driven DOM changes are invisible.
> This means vulnerabilities in dynamic content will be missed and reported as safe.
> Using `--use-browser` launches a real Chromium browser via Playwright, waits for JavaScript
> to execute, then inspects the actual rendered DOM — giving accurate results on all site types.

Additional options:

- `--concurrency` — number of concurrent workers (default: 5)
- `--timeout` — request timeout seconds (default: 15)
- `--retries` — retries for failed requests (default: 2)
- `--rate-limit` — delay seconds between requests (default: 0.5)
- `--max-pages` — pages to crawl per subdomain (default: 25)
- `--headers` — custom headers, for example `Referer=https://example.com`
- `--cookies` — custom cookies, for example `session=abcd`
- `--user-agent` — custom User-Agent string
- `--use-browser` — enable Playwright browser rendering (recommended)
- `--debug` — enable debug logging

## Output

The tool writes report files under the chosen output directory:

```
results/
└── subdomain.com/
    ├── tested_urls.txt           — all tested URLs
    ├── vulnerable_urls.txt       — confirmed vulnerable URLs
    ├── post_inject_analysis.txt  — post-injection source code analysis
    ├── source_analysis.txt       — pre-injection DOM/sink analysis
    ├── sensitive_files.txt       — exposed sensitive files
    ├── login_required_urls.txt   — pages that require login (test separately)
    └── errors.txt                — request errors
```

### Login Required Pages

During crawling, the scanner automatically detects pages that require authentication
(401/403 responses, login redirects, or pages containing a login form).
These are saved to `login_required_urls.txt` so you can test them separately
by running the scanner again with session cookies:

```bash
python cli.py --subdomains-file subdomains.txt --payloads-file payloads.txt --output-dir reports --use-browser --cookies "session=your_session_cookie_here"
```

## Authorization Notice

This tool is intended only for authorized security testing, bug bounty programs, and internal security assessments.
Do not use it against systems without explicit permission.
