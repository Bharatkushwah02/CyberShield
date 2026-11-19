"""
CyberShield - XSS Scanner
============================
Detects Reflected Cross-Site Scripting (XSS) vulnerabilities by injecting
payloads into GET parameters and form inputs, then checking whether the
exact payload string appears unescaped in the response body.
"""

import os
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from scanner.base import BaseScanner
from utils.colors import error, info, success, warning
from utils.helpers import load_wordlist, make_request


# ─────────────────────────────────────────────
# Built-in fallback XSS payloads
# ─────────────────────────────────────────────
FALLBACK_XSS_PAYLOADS: list[str] = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\"><img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "<iframe src=\"javascript:alert('XSS')\">",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
]

# Remediation text
XSS_REMEDIATION: str = (
    "Implement proper input validation and output encoding. "
    "Use Content-Security-Policy headers."
)

# Path to external payload file relative to project root
PAYLOAD_FILE: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "payloads",
    "xss_payloads.txt",
)


class XSSScanner(BaseScanner):
    """
    Reflected XSS vulnerability scanner.

    Injects payloads into GET parameters (from crawled URLs) and form
    inputs, then verifies whether the exact payload is reflected
    unescaped in the server's response body.
    """

    scanner_name: str = "XSS Scanner"

    def __init__(
        self,
        target_url: str,
        forms: Optional[list[dict[str, Any]]] = None,
        crawled_urls: Optional[list[str]] = None,
        verbose: bool = False,
    ) -> None:
        """
        Initialise the XSS scanner.

        Args:
            target_url: Root URL of the target application.
            forms: List of form dicts (``action``, ``method``, ``inputs``).
            crawled_urls: URLs discovered during crawling (may have GET params).
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
        Load XSS payloads from file, falling back to built-in list.

        Returns:
            Deduplicated list of payload strings.
        """
        payloads = load_wordlist(PAYLOAD_FILE)
        if payloads:
            self.log(f"Loaded {len(payloads)} payloads from {PAYLOAD_FILE}")
        else:
            payloads = list(FALLBACK_XSS_PAYLOADS)
            self.log(f"Using {len(payloads)} built-in fallback payloads")

        # Merge fallbacks for complete coverage
        seen: set[str] = set(payloads)
        for p in FALLBACK_XSS_PAYLOADS:
            if p not in seen:
                payloads.append(p)
                seen.add(p)
        return payloads

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
    # URL parameter helpers
    # ─────────────────────────────────────────
    @staticmethod
    def _extract_params(url: str) -> dict[str, str]:
        """
        Parse query parameters from a URL.

        Args:
            url: URL string possibly containing query parameters.

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
            param: Parameter name to replace.
            value: New value.

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
    # Reflected XSS — GET parameters
    # ─────────────────────────────────────────
    def _test_reflected_get(self, url: str) -> None:
        """
        Test GET parameters in a URL for reflected XSS.

        For each parameter, injects each payload and checks whether
        the exact payload string appears in the response body.

        Args:
            url: A crawled URL with query parameters.
        """
        params = self._extract_params(url)
        if not params:
            return

        for param_name, original_value in params.items():
            for payload in self.payloads:
                injected_url = self._replace_param(url, param_name, payload)
                self.log(f"XSS-GET: {param_name}={payload[:50]}…")

                response = make_request(injected_url, timeout=10)
                if response is None:
                    continue

                # Check for exact payload reflection in the response body
                if payload in response.text:
                    dedup_key = f"xss-get:{urlparse(url).path}:{param_name}"
                    if self._is_duplicate(dedup_key):
                        continue

                    self.add_finding(
                        vuln_type="Reflected XSS",
                        severity="HIGH",
                        url=injected_url,
                        description=(
                            f"Parameter '{param_name}' reflects user input "
                            f"without encoding. The injected payload was "
                            f"found unescaped in the response body."
                        ),
                        evidence=(
                            f"Payload: {payload} | "
                            f"Reflected in response at URL: {injected_url}"
                        ),
                        remediation=XSS_REMEDIATION,
                    )
                    break  # One confirmed payload per param is enough

    # ─────────────────────────────────────────
    # Reflected XSS — Form inputs
    # ─────────────────────────────────────────
    def _test_reflected_forms(self) -> None:
        """
        Test form inputs for reflected XSS.

        For each form field, submits the form with the payload injected
        into that field and checks the response for unescaped reflection.
        """
        for form in self.forms:
            action: str = form.get("action", "")
            method: str = form.get("method", "GET").upper()
            inputs: list[dict[str, str]] = form.get("inputs", [])

            form_url = urljoin(self.target_url, action) if action else self.target_url

            for field in inputs:
                field_name: str = field.get("name", "")
                field_type: str = field.get("type", "text").lower()
                if not field_name or field_type in (
                    "submit", "button", "hidden", "image", "file",
                ):
                    continue

                for payload in self.payloads:
                    # Build form data — inject payload into target field
                    form_data: dict[str, str] = {}
                    for inp in inputs:
                        name = inp.get("name", "")
                        if not name:
                            continue
                        if name == field_name:
                            form_data[name] = payload
                        else:
                            form_data[name] = inp.get("value", "test")

                    self.log(f"XSS-Form: {field_name}={payload[:50]}…")

                    if method == "POST":
                        response = make_request(
                            form_url, method="POST", data=form_data, timeout=10
                        )
                    else:
                        get_url = form_url + "?" + urlencode(form_data)
                        response = make_request(get_url, timeout=10)

                    if response is None:
                        continue

                    if payload in response.text:
                        dedup_key = f"xss-form:{form_url}:{field_name}"
                        if self._is_duplicate(dedup_key):
                            continue

                        self.add_finding(
                            vuln_type="Reflected XSS",
                            severity="HIGH",
                            url=form_url,
                            description=(
                                f"Form field '{field_name}' ({method}) reflects "
                                f"input without encoding. The payload was "
                                f"found unescaped in the response."
                            ),
                            evidence=(
                                f"Payload: {payload} | "
                                f"Form action: {form_url} | "
                                f"Method: {method}"
                            ),
                            remediation=XSS_REMEDIATION,
                        )
                        break  # Move to next field

    # ─────────────────────────────────────────
    # Main entry point
    # ─────────────────────────────────────────
    def run(self) -> None:
        """
        Execute the full XSS scan.

        Tests all crawled URLs (GET params) and discovered forms
        for reflected XSS vulnerabilities.
        """
        info(f"Starting XSS scan on {self.target_url}")
        info(f"  Payloads loaded: {len(self.payloads)}")
        info(f"  Forms to test : {len(self.forms)}")
        info(f"  URLs to test  : {len(self.crawled_urls)}")

        # ── Phase 1: GET parameter testing ──
        info("Phase 1/2: Testing GET parameters for reflected XSS…")
        for url in self.crawled_urls:
            self._test_reflected_get(url)

        # ── Phase 2: Form input testing ──
        info("Phase 2/2: Testing form inputs for reflected XSS…")
        self._test_reflected_forms()

        # ── Summary ──
        total = self.finding_count()
        if total:
            warning(f"XSS scan complete: {total} finding(s) detected!")
        else:
            success("XSS scan complete: no vulnerabilities found.")
