import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

FILENAME_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def sanitize_filename(value: str) -> str:
    return FILENAME_SAFE.sub("_", value)[:120]


def get_subdomain(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith("http") else f"https://{url}")
        return parsed.netloc or url
    except Exception:
        return sanitize_filename(url)[:60]


class Reporter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _folder(self, subdomain: str) -> Path:
        folder = self.output_dir / sanitize_filename(subdomain)
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def _write(self, folder: Path, filename: str, lines: List[str]) -> None:
        (folder / filename).write_text("\n".join(lines), encoding="utf-8")

    # ── Source Code Analysis Report ────────────────────────────────────────────
    def write_source_analysis(self, analysis_results: List[Dict[str, Any]]) -> None:
        """
        প্রতিটা subdomain এর জন্য source_analysis.txt লেখো।
        Format:
            results/
            └── subdomain.com/
                └── source_analysis.txt
        """
        grouped: Dict[str, List[Dict]] = {}
        for result in analysis_results:
            key = get_subdomain(result.get("url", "unknown"))
            grouped.setdefault(key, []).append(result)

        for subdomain, entries in grouped.items():
            folder = self._folder(subdomain)
            lines = [
                f"=== Source Code Analysis — {subdomain} ===\n",
            ]

            for entry in entries:
                url     = entry.get("url", "")
                risk    = entry.get("risk", "UNKNOWN")
                summary = entry.get("summary", {})

                risk_label = {
                    "HIGH":   "🔴 HIGH",
                    "MEDIUM": "🟡 MEDIUM",
                    "LOW":    "🟢 LOW",
                    "SAFE":   "✅ SAFE",
                }.get(risk, risk)

                lines += [
                    f"URL    : {url}",
                    f"Risk   : {risk_label}",
                    f"Sinks  : {summary.get('total_sinks', 0)}  "
                    f"(HIGH={summary.get('high',0)}  "
                    f"MEDIUM={summary.get('medium',0)}  "
                    f"LOW={summary.get('low',0)})",
                    f"Sources: {summary.get('sources_found', 0)}",
                    f"DOM Events: {summary.get('dom_events', 0)}",
                    "",
                ]

                # Sink details
                if entry.get("sinks"):
                    lines.append("  ── Dangerous Sinks ──")
                    for s in entry["sinks"]:
                        lines += [
                            f"  [{s['severity']}] {s['sink']}",
                            f"  Reason : {s['reason']}",
                            f"  Snippet: ...{s['snippet']}...",
                            "",
                        ]

                # Source details
                if entry.get("sources"):
                    lines.append("  ── User Input Sources ──")
                    for s in entry["sources"]:
                        lines += [
                            f"  {s['source']}",
                            f"  Reason : {s['reason']}",
                            f"  Snippet: ...{s['snippet']}...",
                            "",
                        ]

                # DOM event details
                if entry.get("dom_candidates"):
                    lines.append("  ── DOM Event Handlers ──")
                    for d in entry["dom_candidates"]:
                        lines += [
                            f"  <{d['tag']} {d['attr']}=\"{d['value'][:80]}\">",
                            f"  Reason : {d.get('reason', '')}",
                            "",
                        ]

                lines.append("─" * 65 + "\n")

            self._write(folder, "source_analysis.txt", lines)
            logger.info("Source analysis saved → %s/source_analysis.txt", folder)

    # ── Post-Inject Source Code Analysis Report ───────────────────────────────
    def write_post_inject_analysis(self, findings: List[Dict[str, Any]]) -> None:
        """
        Payload inject করার পরের source code analysis report লেখো।
        শুধু যেগুলোতে payload reflect হয়েছে সেগুলো লেখো।

        results/
        └── subdomain.com/
            └── post_inject_analysis.txt
        """
        grouped: Dict[str, List[Dict]] = {}
        for item in findings:
            pi = item.get("post_inject")
            if not pi or not pi.get("reflected"):
                continue
            key = get_subdomain(item.get("target_url", "unknown"))
            grouped.setdefault(key, []).append(item)

        for subdomain, entries in grouped.items():
            folder = self._folder(subdomain)

            high_count   = sum(1 for e in entries if e["post_inject"].get("verdict") == "CONFIRMED VULNERABLE")
            maybe_count  = sum(1 for e in entries if e["post_inject"].get("verdict") == "POSSIBLY VULNERABLE")
            safe_count   = sum(1 for e in entries if e["post_inject"].get("verdict") == "SAFE")

            lines = [
                f"=== Post-Inject Source Code Analysis — {subdomain} ===\n",
                f"Reflected Total      : {len(entries)}",
                f"CONFIRMED VULNERABLE : {high_count}",
                f"POSSIBLY VULNERABLE  : {maybe_count}",
                f"SAFE                 : {safe_count}",
                "",
            ]

            verdict_order = {"CONFIRMED VULNERABLE": 3, "POSSIBLY VULNERABLE": 2, "SAFE": 1}
            sorted_entries = sorted(
                entries,
                key=lambda e: verdict_order.get(e["post_inject"].get("verdict", ""), 0),
                reverse=True,
            )

            for e in sorted_entries:
                pi      = e["post_inject"]
                risk    = pi.get("dom_risk", "NONE")
                risk_label = {
                    "HIGH":   "🔴 HIGH",
                    "MEDIUM": "🟡 MEDIUM",
                    "LOW":    "🟢 LOW",
                    "NONE":   "✅ NONE",
                }.get(risk, risk)

                verdict = pi.get("verdict", "")
                verdict_label = {
                    "CONFIRMED VULNERABLE": "🔴 CONFIRMED VULNERABLE",
                    "POSSIBLY VULNERABLE":  "🟡 POSSIBLY VULNERABLE",
                    "SAFE":                 "✅ SAFE",
                }.get(verdict, verdict)

                lines += [
                    f"URL        : {e.get('target_url', '')}",
                    f"Parameter  : {e.get('parameter_name', '')}",
                    f"Payload    : {e.get('payload', '')}",
                    f"Verdict    : {verdict_label}",
                    f"Context    : {pi.get('context', '')}",
                    f"Sink       : {pi.get('sink', '')}",
                    f"Reason     : {pi.get('reason', '')}",
                    f"Snippet    : ...{pi.get('snippet', '')[:120]}...",
                    "",
                ]

                # Event handler hits
                if pi.get("event_handler_hits"):
                    lines.append("  ── Event Handler Hits (Critical) ──")
                    for hit in pi["event_handler_hits"]:
                        lines += [
                            f"  Tag    : <{hit['tag']} {hit['attr']}>",
                            f"  Value  : {hit['value'][:100]}",
                            f"  Reason : {hit['reason']}",
                            "",
                        ]

                # Context details
                if pi.get("contexts"):
                    lines.append("  ── Reflection Contexts ──")
                    for ctx in pi["contexts"]:
                        lines += [
                            f"  Context : {ctx['context']}",
                            f"  Risk    : {ctx['risk']}",
                            f"  Reason  : {ctx['reason']}",
                            f"  Snippet : ...{ctx['snippet'][:120]}...",
                            "",
                        ]

                lines.append("─" * 65 + "\n")

            self._write(folder, "post_inject_analysis.txt", lines)
            logger.info(
                "Post-inject analysis saved → %s/post_inject_analysis.txt", folder
            )

    # ── XSS Scan Reports ───────────────────────────────────────────────────────
    def write_reports(self, findings: List[Dict[str, Any]], errors: List[str]) -> None:
        """
        results/
        └── subdomain.com/
            ├── vulnerable_urls.txt   ← vulnerable URL + parameter + payload
            ├── tested_urls.txt       ← সব tested URL
            └── errors.txt            ← errors
        """
        # Group by subdomain
        grouped: Dict[str, List[Dict]] = {}
        for item in findings:
            key = get_subdomain(item.get("target_url", "unknown"))
            grouped.setdefault(key, []).append(item)

        error_grouped: Dict[str, List[str]] = {}
        for err in errors:
            url = err.split(" | ")[0].strip()
            key = get_subdomain(url)
            error_grouped.setdefault(key, []).append(err)

        for subdomain, entries in grouped.items():
            folder = self._folder(subdomain)

            # tested_urls.txt
            tested = sorted({e["target_url"] for e in entries})
            self._write(folder, "tested_urls.txt", tested)

            # vulnerable_urls.txt
            vuln_lines = [f"=== Vulnerable URLs — {subdomain} ===\n"]
            found_any = False
            for e in entries:
                status = e.get("reflection_status", "").upper()
                if "REFLECT" in status or "VULNERABLE" in status or status == "TRUE":
                    found_any = True
                    vuln_lines += [
                        f"URL      : {e.get('target_url', '')}",
                        f"Parameter: {e.get('parameter_name', '')}",
                        f"Payload  : {e.get('payload', '')}",
                        f"Status   : {status}",
                        "─" * 60,
                        "",
                    ]

            if not found_any:
                vuln_lines.append("No vulnerabilities found.")

            self._write(folder, "vulnerable_urls.txt", vuln_lines)

            # errors.txt
            sub_errors = error_grouped.get(subdomain, [])
            if sub_errors:
                self._write(folder, "errors.txt", sub_errors)

            logger.info("Reports saved → %s/", folder)


    # ── Sensitive File Exposure Report ─────────────────────────────────────────
    def write_sensitive_report(self, sensitive_results: List[Dict[str, Any]]) -> None:
        """
        results/
        └── subdomain.com/
            └── sensitive_files.txt   ← exposed sensitive files
        """
        from urllib.parse import urlparse

        grouped: Dict[str, List[Dict]] = {}
        for item in sensitive_results:
            url = item.get("url", "")
            try:
                parsed = urlparse(url)
                key = parsed.netloc or url
            except Exception:
                key = url
            grouped.setdefault(key, []).append(item)

        for subdomain, entries in grouped.items():
            folder = self._folder(subdomain)

            high   = [e for e in entries if e.get("severity") == "HIGH"]
            medium = [e for e in entries if e.get("severity") == "MEDIUM"]
            low    = [e for e in entries if e.get("severity") == "LOW"]

            lines = [
                f"=== Sensitive File Exposure — {subdomain} ===\n",
                f"Total Exposed : {len(entries)}",
                f"HIGH          : {len(high)}",
                f"MEDIUM        : {len(medium)}",
                f"LOW           : {len(low)}",
                "",
            ]

            for severity_label, group in [("HIGH", high), ("MEDIUM", medium), ("LOW", low)]:
                if not group:
                    continue
                lines.append(f"── {severity_label} ──────────────────────────────────")
                for e in group:
                    confirmed = "✔ CONFIRMED SENSITIVE CONTENT" if e.get("confirmed") else ""
                    lines += [
                        f"URL         : {e.get('url', '')}",
                        f"Description : {e.get('description', '')}",
                        f"Status Code : {e.get('status_code', '')}",
                    ]
                    if confirmed:
                        lines.append(f"Confirmed   : {confirmed}")
                    if e.get("indicators"):
                        lines.append(f"Indicators  : {', '.join(e['indicators'])}")
                    if e.get("content_preview"):
                        lines.append(f"Preview     : {e['content_preview'][:150]}")
                    lines += ["─" * 60, ""]

            self._write(folder, "sensitive_files.txt", lines)
            logger.info("Sensitive file report saved → %s/sensitive_files.txt", folder)

    # ── Login Required URLs Report ─────────────────────────────────────────────
    def write_login_required_urls(self, pages: list) -> int:
        """
        Crawl এর সময় যেসব page এ login required detect হয়েছে
        সেগুলো প্রতিটা subdomain এর folder এ login_required_urls.txt তে save করো।

        results/
        └── subdomain.com/
            └── login_required_urls.txt

        Returns: total login-required pages found
        """
        grouped = {}
        for page in pages:
            if not getattr(page, "login_required", False):
                continue
            key = get_subdomain(page.final_url or page.url)
            grouped.setdefault(key, []).append(page)

        total = sum(len(v) for v in grouped.values())

        for subdomain, entries in grouped.items():
            folder = self._folder(subdomain)

            lines = [
                f"=== Login Required URLs — {subdomain} ===\n",
                f"Total : {len(entries)}",
                "",
                "These pages require authentication.",
                "To test them, run the scanner again with --cookies or --login credentials.",
                "",
                "─" * 65,
                "",
            ]

            for entry in entries:
                url    = entry.final_url or entry.url
                reason = getattr(entry, "login_reason", "")
                lines += [
                    f"URL    : {url}",
                    f"Reason : {reason}",
                    "",
                ]

            self._write(folder, "login_required_urls.txt", lines)
            logger.info(
                "Login required URLs saved → %s/login_required_urls.txt (%d pages)",
                folder, len(entries),
            )

        return total
