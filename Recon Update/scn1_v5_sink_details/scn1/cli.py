import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich import box

from crawler import crawl_subdomains
from dom_analyzer import extract_dom_candidates, analyze_page
from payload_manager import load_payloads
from reflection_checker import scan_inputs
from sensitive_checker import check_sensitive_files
from reporter import Reporter

logger = logging.getLogger("recon")
console = Console()


def parse_key_value_pairs(raw_values: List[str]) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw in raw_values or []:
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def load_lines(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]


def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


def get_subdomain(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith("http") else f"https://{url}")
        return parsed.netloc or url
    except Exception:
        return url


def truncate(text: str, max_len: int = 50) -> str:
    return text if len(text) <= max_len else text[:max_len - 3] + "..."


# ── Tables ─────────────────────────────────────────────────────────────────────

def print_sensitive_table(results: List[Dict]) -> None:
    table = Table(
        title="\n[bold red]Sensitive File Exposure[/bold red]",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
        header_style="bold white on dark_red",
    )
    table.add_column("URL",         style="cyan",  min_width=40)
    table.add_column("Severity",    justify="center", min_width=10)
    table.add_column("Description", style="white", min_width=28)
    table.add_column("Confirmed",   justify="center", min_width=10)

    for r in results:
        sev = r.get("severity", "LOW")
        sev_display = {
            "HIGH":   "[bold red]🔴 HIGH[/bold red]",
            "MEDIUM": "[yellow]🟡 MEDIUM[/yellow]",
            "LOW":    "[dim]🟢 LOW[/dim]",
        }.get(sev, sev)

        confirmed = "[bold red]✔ YES[/bold red]" if r.get("confirmed") else "[dim]—[/dim]"

        table.add_row(
            truncate(r.get("url", ""), 55),
            sev_display,
            r.get("description", ""),
            confirmed,
        )

    console.print(table)


def print_source_analysis_table(analysis_results: List[Dict]) -> None:
    relevant = [r for r in analysis_results if r.get("risk", "SAFE") != "SAFE"]
    if not relevant:
        console.print("  [green]Source Code Analysis: সব page SAFE — কোনো dangerous sink পাওয়া যায়নি।[/green]\n")
        return

    table = Table(
        title="\n[bold yellow]Source Code Analysis[/bold yellow]",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
        header_style="bold white on dark_blue",
    )
    table.add_column("URL",      style="cyan",    min_width=32)
    table.add_column("Risk",     justify="center", min_width=10)
    table.add_column("Sink",     style="red",     min_width=20)
    table.add_column("Severity", justify="center", min_width=10)
    table.add_column("Reason",   style="magenta", min_width=30)
    table.add_column("Snippet",  style="dim",     min_width=35)

    for r in relevant:
        risk = r.get("risk", "UNKNOWN")
        risk_display = {
            "HIGH":   "[bold red]🔴 HIGH[/bold red]",
            "MEDIUM": "[yellow]🟡 MEDIUM[/yellow]",
            "LOW":    "[green]🟢 LOW[/green]",
        }.get(risk, risk)

        url = truncate(r.get("url", ""), 40)

        all_findings = []
        for s in r.get("sinks", []):
            all_findings.append({
                "sink":     s.get("sink", ""),
                "severity": s.get("severity", ""),
                "reason":   s.get("reason", ""),
                "snippet":  s.get("snippet", ""),
            })
        for d in r.get("dom_candidates", []):
            all_findings.append({
                "sink":     f"<{d.get('tag','')} {d.get('attr','')}>",
                "severity": d.get("severity", "HIGH"),
                "reason":   d.get("reason", ""),
                "snippet":  d.get("snippet", ""),
            })
        for src in r.get("sources", []):
            all_findings.append({
                "sink":     src.get("source", ""),
                "severity": "LOW",
                "reason":   src.get("reason", ""),
                "snippet":  src.get("snippet", ""),
            })

        if not all_findings:
            table.add_row(url, risk_display, "—", "—", "—", "—")
            continue

        for i, f in enumerate(all_findings):
            sev = f.get("severity", "")
            sev_display = {
                "HIGH":   "[bold red]HIGH[/bold red]",
                "MEDIUM": "[yellow]MEDIUM[/yellow]",
                "LOW":    "[green]LOW[/green]",
            }.get(sev, sev)
            table.add_row(
                url if i == 0 else "",
                risk_display if i == 0 else "",
                truncate(f.get("sink", ""), 25),
                sev_display,
                truncate(f.get("reason", ""), 38),
                truncate(f.get("snippet", ""), 45),
            )

    console.print(table)


def print_scan_results_table(results: List[Dict]) -> None:
    table = Table(
        title="\n[bold cyan]XSS Payload Scan Results[/bold cyan]",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
        header_style="bold white on dark_blue",
    )
    table.add_column("Subdomain",  style="cyan",   no_wrap=True, min_width=22)
    table.add_column("Parameter",  style="yellow", no_wrap=True, min_width=12)
    table.add_column("Payload",    style="magenta",              min_width=30)
    table.add_column("Status",     justify="center",             min_width=14)

    for r in results:
        status_raw = r.get("reflection_status", "UNKNOWN").upper()
        if "REFLECT" in status_raw or "VULNERABLE" in status_raw or status_raw == "TRUE":
            status_display = "[bold red]✗ VULNERABLE[/bold red]"
        elif "NOT" in status_raw or status_raw in ("FALSE", "CLEAN", "SAFE"):
            status_display = "[green]✓ SAFE[/green]"
        elif "ERROR" in status_raw:
            status_display = "[dim red]⚠ ERROR[/dim red]"
        else:
            status_display = f"[dim]{status_raw}[/dim]"

        table.add_row(
            get_subdomain(r.get("target_url", "")),
            r.get("parameter_name", "-"),
            truncate(r.get("payload", "-"), 50),
            status_display,
        )

    console.print(table)


def print_post_inject_table(findings: List[Dict]) -> None:
    """Payload inject করার পরের source code analysis result দেখাও।"""
    relevant = [
        f for f in findings
        if f.get("post_inject") and f["post_inject"].get("verdict") not in ("NOT REFLECTED", None)
    ]
    if not relevant:
        console.print("  [green]Post-inject analysis: কোনো reflected payload dangerous context এ পাওয়া যায়নি।[/green]\n")
        return

    table = Table(
        title="\n[bold magenta]Post-Inject Source Code Analysis[/bold magenta]",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
        header_style="bold white on dark_magenta",
    )
    table.add_column("URL",       style="cyan",     min_width=30)
    table.add_column("Parameter", style="yellow",   min_width=12)
    table.add_column("Payload",   style="magenta",  min_width=25)
    table.add_column("Verdict",   justify="center", min_width=22)
    table.add_column("Context",   style="white",    min_width=18)
    table.add_column("Reason",    style="white",    min_width=35)

    verdict_order = {"CONFIRMED VULNERABLE": 3, "POSSIBLY VULNERABLE": 2, "SAFE": 1, "NOT REFLECTED": 0}
    sorted_findings = sorted(
        relevant,
        key=lambda f: verdict_order.get(f["post_inject"].get("verdict", ""), 0),
        reverse=True,
    )

    for f in sorted_findings:
        pi      = f["post_inject"]
        verdict = pi.get("verdict", "")

        verdict_display = {
            "CONFIRMED VULNERABLE": "[bold red]CONFIRMED VULNERABLE[/bold red]",
            "POSSIBLY VULNERABLE":  "[yellow]POSSIBLY VULNERABLE[/yellow]",
            "SAFE":                 "[green]SAFE[/green]",
        }.get(verdict, f"[dim]{verdict}[/dim]")

        context = str(pi.get("context") or "")
        reason  = truncate(pi.get("reason", ""), 55)

        table.add_row(
            truncate(f.get("target_url", ""), 38),
            f.get("parameter_name", "-"),
            truncate(f.get("payload", "-"), 30),
            verdict_display,
            context,
            reason,
        )

    console.print(table)


def print_summary(
    scan_results: List[Dict],
    analysis_results: List[Dict],
    sensitive_results: List[Dict],
    output_dir: str,
    login_required_count: int = 0,
) -> None:
    total      = len(scan_results)
    vulnerable = sum(
        1 for r in scan_results
        if "REFLECT" in r.get("reflection_status", "").upper()
        or r.get("reflection_status", "").upper() in ("TRUE", "VULNERABLE")
    )
    high_risk    = sum(1 for a in analysis_results if a.get("risk") == "HIGH")
    med_risk     = sum(1 for a in analysis_results if a.get("risk") == "MEDIUM")
    sensitive_h  = sum(1 for s in sensitive_results if s.get("severity") == "HIGH")
    sensitive_m  = sum(1 for s in sensitive_results if s.get("severity") == "MEDIUM")

    # Post-inject DOM risk count
    dom_high   = sum(1 for r in scan_results if r.get("post_inject", {}).get("dom_risk") == "HIGH")
    dom_medium = sum(1 for r in scan_results if r.get("post_inject", {}).get("dom_risk") == "MEDIUM")
    dom_low    = sum(1 for r in scan_results if r.get("post_inject", {}).get("dom_risk") == "LOW")

    summary = Table(box=box.SIMPLE_HEAVY, show_header=False, expand=False)
    summary.add_column("Key",   style="bold white", min_width=26)
    summary.add_column("Value", style="cyan")

    summary.add_row("Total Payload Tests",     str(total))
    summary.add_row("XSS Vulnerable",          f"[bold red]{vulnerable}[/bold red]")
    summary.add_row("XSS Safe",                f"[green]{total - vulnerable}[/green]")
    summary.add_row("─" * 26,                  "─" * 10)
    summary.add_row("Pages Analyzed",          str(len(analysis_results)))
    summary.add_row("High Risk Pages",         f"[bold red]{high_risk}[/bold red]")
    summary.add_row("Medium Risk Pages",       f"[yellow]{med_risk}[/yellow]")
    summary.add_row("─" * 26,                  "─" * 10)
    summary.add_row("Post-Inject DOM HIGH",    f"[bold red]{dom_high}[/bold red]")
    summary.add_row("Post-Inject DOM MEDIUM",  f"[yellow]{dom_medium}[/yellow]")
    summary.add_row("Post-Inject DOM LOW",     f"[green]{dom_low}[/green]")
    summary.add_row("─" * 26,                  "─" * 10)
    summary.add_row("Sensitive Files Exposed", f"[bold red]{len(sensitive_results)}[/bold red]")
    summary.add_row("  HIGH severity",         f"[bold red]{sensitive_h}[/bold red]")
    summary.add_row("  MEDIUM severity",       f"[yellow]{sensitive_m}[/yellow]")
    summary.add_row("─" * 26,                  "─" * 10)
    summary.add_row("Login Required Pages",    f"[yellow]{login_required_count}[/yellow]")
    summary.add_row("─" * 26,                  "─" * 10)
    summary.add_row("Reports saved",           f"[cyan]{Path(output_dir).resolve()}[/cyan]")

    console.print("\n[bold white on dark_blue]  Final Summary  [/bold white on dark_blue]")
    console.print(summary)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recon security scanner for authorized bug bounty and internal assessments."
    )
    parser.add_argument("--subdomains-file", required=True)
    parser.add_argument("--payloads-file",   required=True)
    parser.add_argument("--output-dir",      default="results")
    parser.add_argument("--concurrency",     type=int,   default=5)
    parser.add_argument("--timeout",         type=int,   default=15)
    parser.add_argument("--retries",         type=int,   default=2)
    parser.add_argument("--rate-limit",      type=float, default=0.5)
    parser.add_argument("--max-pages",       type=int,   default=25)
    parser.add_argument("--headers",  action="append")
    parser.add_argument("--cookies",  action="append")
    parser.add_argument("--user-agent", default="ReconSecurityScanner/1.0")
    parser.add_argument("--use-browser", action="store_true")
    parser.add_argument("--skip-sensitive", action="store_true",
                        help="Sensitive file check skip করো।")
    parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()
    configure_logging(args.debug)

    try:
        subdomains = load_lines(Path(args.subdomains_file))
        payloads   = load_payloads(args.payloads_file)
    except Exception as error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        sys.exit(1)

    headers = parse_key_value_pairs(args.headers)
    cookies = parse_key_value_pairs(args.cookies)
    if args.user_agent:
        headers["User-Agent"] = args.user_agent

    console.rule("[bold cyan]Recon Security Scanner[/bold cyan]")
    console.print(f"  Subdomains : [cyan]{len(subdomains)}[/cyan]")
    console.print(f"  Payloads   : [cyan]{len(payloads)}[/cyan]")
    console.print(f"  Output     : [cyan]{Path(args.output_dir).resolve()}[/cyan]\n")

    reporter = Reporter(args.output_dir)

    # ── Step 1: Sensitive File Check ───────────────────────────────────────────
    sensitive_results = []
    if not args.skip_sensitive:
        console.print("[bold red]Step 1/3 — Sensitive File Exposure Check...[/bold red]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            total_checks = len(subdomains) * 50  # approximate
            task = progress.add_task("[red]Checking sensitive files...", total=total_checks)
            sensitive_results = check_sensitive_files(
                subdomains=subdomains,
                headers=headers,
                cookies=cookies,
                timeout=args.timeout,
                rate_limit=args.rate_limit,
                concurrency=args.concurrency,
            )
            progress.update(task, completed=total_checks)

        if sensitive_results:
            print_sensitive_table(sensitive_results)
            reporter.write_sensitive_report(sensitive_results)
        else:
            console.print("  [green]No sensitive files exposed.[/green]\n")

    # ── Step 2: Crawl + Source Code Analysis ──────────────────────────────────
    console.print("[bold yellow]Step 2/3 — Crawling & Source Code Analysis...[/bold yellow]")
    pages = crawl_subdomains(
        subdomains=subdomains,
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
        rate_limit=args.rate_limit,
        headers=headers,
        cookies=cookies,
        max_pages=args.max_pages,
    )

    if not pages:
        console.print("[bold yellow]No pages discovered.[/bold yellow]")
        sys.exit(0)

    console.print(f"  Crawled [cyan]{len(pages)}[/cyan] pages.")

    # ── Login Required URLs ────────────────────────────────────────────────────
    login_required_count = reporter.write_login_required_urls(pages)
    if login_required_count > 0:
        console.print(f"  [yellow]Login required pages : {login_required_count} — saved to login_required_urls.txt[/yellow]")
        console.print(f"  [dim]Run again with --cookies to test these pages.[/dim]\n")
    else:
        console.print(f"  [green]Login required pages : 0[/green]\n")

    analysis_results = []
    candidates = []
    for page in pages:
        result = analyze_page(page.final_url or page.url, page.html)
        analysis_results.append(result)
        if page.inputs:
            candidates.extend(page.inputs)

    print_source_analysis_table(analysis_results)
    reporter.write_source_analysis(analysis_results)

    if not candidates:
        console.print("[bold yellow]No input points found.[/bold yellow]")
        print_summary([], analysis_results, sensitive_results, args.output_dir, login_required_count)
        sys.exit(0)

    # ── Step 3: XSS Payload Scan ──────────────────────────────────────────────
    total_tests = len(candidates) * len(payloads)
    console.print(f"\n[bold cyan]Step 3/3 — XSS Payload Scan...[/bold cyan]")
    console.print(f"  Input points : [cyan]{len(candidates)}[/cyan]")
    console.print(f"  Total tests  : [cyan]{total_tests}[/cyan]\n")

    summary_data = []
    errors = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("{task.completed}/{task.total}"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning payloads...", total=total_tests)
        raw_inputs = [inp.__dict__ for inp in candidates]
        findings = scan_inputs(
            input_points=raw_inputs,
            payloads=payloads,
            headers=headers,
            cookies=cookies,
            timeout=args.timeout,
            retries=args.retries,
            concurrency=args.concurrency,
            rate_limit=args.rate_limit,
            use_browser=args.use_browser,
        )
        for result in findings:
            progress.advance(task)
            summary_data.append(result)
            if result.get("error"):
                errors.append(f"{result['target_url']} | {result['payload']} | {result['error']}")

    if summary_data:
        print_scan_results_table(summary_data)

        # ── Post-Inject Source Code Analysis ──────────────────────────────────
        console.print("\n[bold magenta]Post-Inject Source Code Analysis...[/bold magenta]")
        print_post_inject_table(summary_data)
        reporter.write_post_inject_analysis(summary_data)

    reporter.write_reports(summary_data, errors)
    print_summary(summary_data, analysis_results, sensitive_results, args.output_dir, login_required_count)
    console.rule("[bold green]Scan Complete[/bold green]")


if __name__ == "__main__":
    main()
