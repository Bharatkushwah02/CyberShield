#!/usr/bin/env python3
"""
CyberShield — Automated Web Vulnerability Scanner
=====================================================
CLI entry point. Orchestrates crawling, scanning, and report generation.

Usage:
    python main.py --url https://example.com
    python main.py --url https://example.com --scan sqli,xss --verbose
    python main.py --url https://example.com --scan all --output report.html
"""

import argparse
import sys
import time
from typing import Any

from utils.colors import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    RED,
    RESET,
    WHITE,
    YELLOW,
    error,
    info,
    print_banner,
    section,
    severity_label,
    success,
    warning,
)
from utils.helpers import (
    get_domain,
    is_valid_url,
    normalize_url,
    save_results,
    timestamp,
    timestamp_filename,
)

# ──────────────────────────────────────────────
# Scanner & Module Imports
# ──────────────────────────────────────────────
from scanner.crawler import Crawler

# Lazy imports for scanners – each scanner module may not exist yet.
# We import them inside functions so the main file can be used as a
# template even before every scanner is implemented.

SCANNER_MODULES: dict[str, tuple[str, str, str]] = {
    # key: (module_path, class_name, display_name)
    "sqli":    ("scanner.sqli_scanner",  "SQLiScanner",    "SQL Injection Scanner"),
    "xss":     ("scanner.xss_scanner",   "XSSScanner",     "XSS Scanner"),
    "csrf":    ("scanner.csrf_scanner",  "CSRFScanner",    "CSRF Scanner"),
    "dirs":    ("scanner.dir_bruteforce","DirBruteforcer",  "Directory Bruteforce"),
    "headers": ("scanner.header_scanner","HeaderScanner",   "HTTP Header Scanner"),
    "ssl":     ("scanner.ssl_scanner",   "SSLScanner",      "SSL/TLS Scanner"),
    "ports":   ("scanner.port_scanner",  "PortScanner",     "Port Scanner"),
}


def _import_scanner(key: str) -> Any:
    """
    Dynamically import a scanner class by its key.

    Args:
        key: Scanner identifier (e.g. 'sqli', 'xss').

    Returns:
        The scanner class, or None if the module is unavailable.
    """
    if key not in SCANNER_MODULES:
        return None
    module_path, class_name, _ = SCANNER_MODULES[key]
    try:
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except (ImportError, AttributeError) as e:
        warning(f"Scanner module '{module_path}.{class_name}' not available: {e}")
        return None


def parse_args() -> argparse.Namespace:
    """Parse and return CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="CyberShield",
        description="Automated Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --url https://example.com\n"
            "  python main.py --url https://example.com --scan sqli,xss --verbose\n"
            "  python main.py --url https://example.com --scan all --output report.html\n"
        ),
    )
    parser.add_argument(
        "--url", required=True,
        help="Target URL to scan (required)",
    )
    parser.add_argument(
        "--scan", default="all",
        help="Comma-separated scan types: all, sqli, xss, csrf, dirs, headers, ssl, ports (default: all)",
    )
    parser.add_argument(
        "--port-range", default="1-1024",
        help="Port range for port scanning (default: 1-1024)",
    )
    parser.add_argument(
        "--threads", type=int, default=10,
        help="Number of threads for concurrent operations (default: 10)",
    )
    parser.add_argument(
        "--depth", type=int, default=2,
        help="Crawl depth — how many link-levels deep to follow (default: 2)",
    )
    parser.add_argument(
        "--wordlist", default=None,
        help="Custom wordlist file for directory bruteforce",
    )
    parser.add_argument(
        "--output", default="report.html",
        help="Output report file path (default: report.html)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "--no-crawl", action="store_true",
        help="Skip crawling — only scan the provided URL directly",
    )
    return parser.parse_args()


def resolve_scan_types(scan_arg: str) -> list[str]:
    """
    Parse the --scan argument into a list of scanner keys.

    Args:
        scan_arg: Comma-separated string (e.g. 'sqli,xss' or 'all').

    Returns:
        List of scanner key strings.
    """
    if scan_arg.strip().lower() == "all":
        return list(SCANNER_MODULES.keys())

    requested: list[str] = []
    for token in scan_arg.split(","):
        key = token.strip().lower()
        if key in SCANNER_MODULES:
            requested.append(key)
        else:
            warning(f"Unknown scan type '{key}' — skipping")
    return requested


def print_crawl_summary(crawled_urls: set[str], forms: list[dict[str, Any]]) -> None:
    """Print a summary of crawl results."""
    section("Crawl Summary")
    info(f"Pages discovered : {BOLD}{len(crawled_urls)}{RESET}")
    info(f"Forms found      : {BOLD}{len(forms)}{RESET}")
    if forms:
        for i, form in enumerate(forms[:10], 1):
            method = form.get("method", "?")
            action = form.get("action", "?")
            n_inputs = len(form.get("inputs", []))
            print(f"  {DIM}{i}. [{method}] {action} ({n_inputs} inputs){RESET}")
        if len(forms) > 10:
            print(f"  {DIM}... and {len(forms) - 10} more{RESET}")


def print_findings_summary(all_findings: list[dict[str, str]]) -> None:
    """Print a summary table of findings grouped by severity."""
    section("Findings Summary")

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts: dict[str, int] = {s: 0 for s in severity_order}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    total = len(all_findings)
    print(f"\n  {'Severity':<12} {'Count':>6}")
    print(f"  {'─' * 20}")
    for sev in severity_order:
        count = counts[sev]
        if count > 0:
            print(f"  {severity_label(sev):<23} {BOLD}{count:>6}{RESET}")
    print(f"  {'─' * 20}")
    print(f"  {'TOTAL':<12} {BOLD}{total:>6}{RESET}\n")


def run_scanner(
    scanner_key: str,
    target_url: str,
    crawled_urls: set[str],
    forms: list[dict[str, Any]],
    args: argparse.Namespace,
) -> list[dict[str, str]]:
    """
    Instantiate and run a single scanner, returning its findings.

    Args:
        scanner_key: The scanner identifier.
        target_url: Normalised target URL.
        crawled_urls: Set of discovered URLs from the crawl phase.
        forms: List of form dicts from the crawl phase.
        args: Parsed CLI arguments.

    Returns:
        List of finding dicts produced by the scanner.
    """
    scanner_cls = _import_scanner(scanner_key)
    if scanner_cls is None:
        return []

    _, _, display_name = SCANNER_MODULES[scanner_key]
    info(f"Starting {BOLD}{display_name}{RESET}...")

    start = time.time()

    try:
        # Different scanners accept different constructor arguments.
        # We pass what we can; scanners should accept **kwargs gracefully.
        if scanner_key == "sqli":
            scanner = scanner_cls(
                target_url=target_url,
                crawled_urls=list(crawled_urls),
                forms=forms,
                verbose=args.verbose,
            )
        elif scanner_key == "xss":
            scanner = scanner_cls(
                target_url=target_url,
                crawled_urls=list(crawled_urls),
                forms=forms,
                verbose=args.verbose,
            )
        elif scanner_key == "csrf":
            scanner = scanner_cls(
                target_url=target_url,
                forms=forms,
                verbose=args.verbose,
            )
        elif scanner_key == "dirs":
            scanner = scanner_cls(
                target_url=target_url,
                wordlist_path=args.wordlist,
                threads=args.threads,
                verbose=args.verbose,
            )
        elif scanner_key == "headers":
            scanner = scanner_cls(
                target_url=target_url,
                verbose=args.verbose,
            )
        elif scanner_key == "ssl":
            scanner = scanner_cls(
                target_url=target_url,
                verbose=args.verbose,
            )
        elif scanner_key == "ports":
            scanner = scanner_cls(
                target_url=target_url,
                port_range=args.port_range,
                threads=args.threads,
                verbose=args.verbose,
            )
        else:
            scanner = scanner_cls(
                target_url=target_url,
                verbose=args.verbose,
            )

        scanner.run()
        findings = scanner.get_findings()

    except Exception as e:
        error(f"{display_name} crashed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        findings = []

    elapsed = time.time() - start
    count = len(findings)
    color = GREEN if count == 0 else (RED if count > 0 else WHITE)
    success(
        f"{display_name} complete — "
        f"{color}{count} finding(s){RESET} in {elapsed:.1f}s"
    )
    return findings


def generate_report(
    all_findings: list[dict[str, str]],
    target_url: str,
    output_path: str,
    crawled_urls: set[str],
) -> None:
    """
    Attempt to generate an HTML report using the report generator.

    Falls back to saving raw JSON if the report module is unavailable.

    Args:
        all_findings: Combined list of all scanner findings.
        target_url: The original target URL.
        output_path: Desired output file path.
        crawled_urls: Set of crawled URLs (for report metadata).
    """
    try:
        from report.report_generator import ReportGenerator
        generator = ReportGenerator(
            target_url=target_url,
            findings=all_findings,
            scan_info={
                "urls_crawled": len(crawled_urls),
                "crawled_urls": list(crawled_urls),
            },
        )
        generator.generate(output_path)
        success(f"HTML report saved to: {BOLD}{output_path}{RESET}")
    except ImportError:
        # Report module not available yet — save JSON instead
        json_path = output_path.replace(".html", ".json")
        report_data = {
            "target": target_url,
            "scan_time": timestamp(),
            "total_findings": len(all_findings),
            "pages_crawled": len(crawled_urls),
            "findings": all_findings,
        }
        if save_results(report_data, json_path):
            success(f"JSON report saved to: {BOLD}{json_path}{RESET}")
        else:
            error("Failed to save report")
    except Exception as e:
        error(f"Report generation failed: {e}")
        # Fallback to JSON
        json_path = output_path.replace(".html", ".json")
        report_data = {
            "target": target_url,
            "scan_time": timestamp(),
            "total_findings": len(all_findings),
            "pages_crawled": len(crawled_urls),
            "findings": all_findings,
        }
        save_results(report_data, json_path)
        warning(f"Fallback JSON report saved to: {json_path}")


def main() -> None:
    """Main CyberShield entry point."""
    args = parse_args()

    # ── Banner ──
    print_banner()

    # ── Validate URL ──
    target_url = normalize_url(args.url)
    if not is_valid_url(target_url):
        error(f"Invalid URL: {args.url}")
        sys.exit(1)

    domain = get_domain(target_url)
    section("Target Information")
    info(f"Target URL : {BOLD}{target_url}{RESET}")
    info(f"Domain     : {BOLD}{domain}{RESET}")
    info(f"Scan types : {BOLD}{args.scan}{RESET}")
    info(f"Threads    : {BOLD}{args.threads}{RESET}")
    info(f"Started at : {BOLD}{timestamp()}{RESET}")

    overall_start = time.time()

    # ── Crawl Phase ──
    crawled_urls: set[str] = set()
    forms: list[dict[str, Any]] = []

    if args.no_crawl:
        warning("Crawling skipped (--no-crawl). Scanning target URL only.")
        crawled_urls = {target_url}
    else:
        section("Crawling")
        crawler = Crawler(
            target_url=target_url,
            max_depth=args.depth,
            max_pages=50,
            verbose=args.verbose,
        )
        crawled_urls, forms = crawler.crawl()

    print_crawl_summary(crawled_urls, forms)

    # ── Scan Phase ──
    scan_types = resolve_scan_types(args.scan)
    if not scan_types:
        error("No valid scan types selected. Exiting.")
        sys.exit(1)

    section("Scanning")
    info(f"Running {len(scan_types)} scanner(s): {', '.join(scan_types)}")

    all_findings: list[dict[str, str]] = []
    for scanner_key in scan_types:
        findings = run_scanner(
            scanner_key=scanner_key,
            target_url=target_url,
            crawled_urls=crawled_urls,
            forms=forms,
            args=args,
        )
        all_findings.extend(findings)

    # ── Results ──
    print_findings_summary(all_findings)

    # ── Report Generation ──
    section("Report")
    generate_report(
        all_findings=all_findings,
        target_url=target_url,
        output_path=args.output,
        crawled_urls=crawled_urls,
    )

    # ── Done ──
    elapsed = time.time() - overall_start
    section("Scan Complete")
    success(
        f"Finished in {elapsed:.1f}s — "
        f"{len(all_findings)} total finding(s) across {len(crawled_urls)} page(s)"
    )
    info(f"Report: {BOLD}{args.output}{RESET}")


if __name__ == "__main__":
    main()
