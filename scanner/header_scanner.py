"""
CyberShield - HTTP Security Headers Scanner
==============================================
Analyzes HTTP response headers and cookies for security best-practices.
Checks for missing, misconfigured, or information-leaking headers and
reports findings with actionable remediation guidance.
"""

from typing import Optional

from scanner.base import BaseScanner
from utils.colors import info, success, warning, error, section
from utils.helpers import make_request


class HeaderScanner(BaseScanner):
    """
    Scanner that evaluates HTTP security headers against industry
    best-practices (OWASP Secure Headers Project).

    Checked headers:
        Strict-Transport-Security, Content-Security-Policy,
        X-Content-Type-Options, X-Frame-Options, X-XSS-Protection,
        Referrer-Policy, Permissions-Policy, Cache-Control,
        Server, X-Powered-By.

    Cookie attributes (HttpOnly, Secure, SameSite) are also inspected.
    """

    scanner_name: str = "Header Scanner"

    # ── Header definitions ───────────────────────────────────────
    # Each entry: (header_name, severity_if_missing, description, remediation)
    _HEADER_CHECKS: list[tuple[str, str, str, str]] = [
        (
            "Strict-Transport-Security",
            "HIGH",
            "HSTS header is missing — the browser will not enforce HTTPS connections, "
            "leaving users vulnerable to protocol downgrade and cookie hijacking attacks.",
            "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        ),
        (
            "Content-Security-Policy",
            "MEDIUM",
            "Content-Security-Policy header is missing — the site is more susceptible "
            "to Cross-Site Scripting (XSS) and data-injection attacks.",
            "Define a strict CSP, e.g.: Content-Security-Policy: default-src 'self'; "
            "script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'",
        ),
        (
            "X-Content-Type-Options",
            "LOW",
            "X-Content-Type-Options header is missing — browsers may MIME-sniff "
            "responses away from the declared Content-Type, enabling drive-by attacks.",
            "Add the header: X-Content-Type-Options: nosniff",
        ),
        (
            "X-Frame-Options",
            "MEDIUM",
            "X-Frame-Options header is missing — the site can be framed by any "
            "origin, enabling clickjacking attacks.",
            "Add the header: X-Frame-Options: DENY  (or SAMEORIGIN if iframes are required).",
        ),
        (
            "X-XSS-Protection",
            "INFO",
            "X-XSS-Protection header is missing — while deprecated in modern browsers, "
            "legacy user agents may lack reflective-XSS filtering.",
            "This header is deprecated. Rely on a strong Content-Security-Policy instead. "
            "If legacy support is needed: X-XSS-Protection: 1; mode=block",
        ),
        (
            "Referrer-Policy",
            "LOW",
            "Referrer-Policy header is missing — full URLs (including query params "
            "with tokens) may leak to third-party sites via the Referer header.",
            "Add the header: Referrer-Policy: strict-origin-when-cross-origin  "
            "(or 'no-referrer' for maximum privacy).",
        ),
        (
            "Permissions-Policy",
            "LOW",
            "Permissions-Policy header is missing — browser features like camera, "
            "microphone, and geolocation are not explicitly restricted.",
            "Add the header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        ),
    ]

    def __init__(self, target_url: str, verbose: bool = False) -> None:
        """
        Initialise the HTTP Security Headers scanner.

        Args:
            target_url: The root URL of the target to scan.
            verbose: If True, print detailed progress messages.
        """
        super().__init__(target_url, verbose)

    # ── Public entry point ───────────────────────────────────────
    def run(self) -> None:
        """Execute the full HTTP security-headers scan."""
        section("HTTP Security Headers Scan")
        info(f"Target: {self.target_url}")

        response = make_request(self.target_url, timeout=15)
        if response is None:
            error(f"Could not connect to {self.target_url} — skipping header scan.")
            self.add_finding(
                vuln_type="Connection Failure",
                severity="INFO",
                url=self.target_url,
                description="Unable to establish a connection to the target for header analysis.",
                remediation="Verify the target URL is reachable and try again.",
            )
            return

        headers = response.headers
        self.log(f"HTTP {response.status_code} — received {len(headers)} headers")

        # Run all checks
        self._check_security_headers(headers)
        self._check_xcto_value(headers)
        self._check_xfo_value(headers)
        self._check_cache_control(headers)
        self._check_server_header(headers)
        self._check_x_powered_by(headers)
        self._check_cookies(response)

        if self.finding_count() == 0:
            success("All checked security headers are present and correctly configured!")
        else:
            info(f"Header scan complete — {self.finding_count()} finding(s) recorded.")

    # ── Internal checks ──────────────────────────────────────────
    def _check_security_headers(self, headers: dict) -> None:
        """Check for presence of each required security header."""
        for header_name, severity, description, remediation in self._HEADER_CHECKS:
            value = headers.get(header_name)
            if value is None:
                self.log(f"Missing header: {header_name}")
                self.add_finding(
                    vuln_type=f"Missing Header: {header_name}",
                    severity=severity,
                    url=self.target_url,
                    description=description,
                    evidence=f"Response does not contain the '{header_name}' header.",
                    remediation=remediation,
                )
            else:
                self.log(f"Present: {header_name}: {value}")

    def _check_xcto_value(self, headers: dict) -> None:
        """Verify X-Content-Type-Options is set to 'nosniff'."""
        value = headers.get("X-Content-Type-Options")
        if value is not None and value.strip().lower() != "nosniff":
            self.add_finding(
                vuln_type="Misconfigured Header: X-Content-Type-Options",
                severity="LOW",
                url=self.target_url,
                description=(
                    f"X-Content-Type-Options is set to '{value}' instead of 'nosniff'. "
                    "The browser may still perform MIME-type sniffing."
                ),
                evidence=f"X-Content-Type-Options: {value}",
                remediation="Set the header value to exactly: nosniff",
            )

    def _check_xfo_value(self, headers: dict) -> None:
        """Verify X-Frame-Options uses DENY or SAMEORIGIN."""
        value = headers.get("X-Frame-Options")
        if value is not None:
            normalised = value.strip().upper()
            if normalised not in ("DENY", "SAMEORIGIN"):
                self.add_finding(
                    vuln_type="Misconfigured Header: X-Frame-Options",
                    severity="MEDIUM",
                    url=self.target_url,
                    description=(
                        f"X-Frame-Options is set to '{value}', which is not a "
                        "recommended value (DENY or SAMEORIGIN)."
                    ),
                    evidence=f"X-Frame-Options: {value}",
                    remediation="Set the header to: X-Frame-Options: DENY  "
                    "(or SAMEORIGIN if you need to frame the page on the same origin).",
                )

    def _check_cache_control(self, headers: dict) -> None:
        """Check Cache-Control for sensitive content caching."""
        value = headers.get("Cache-Control")
        if value is None:
            self.add_finding(
                vuln_type="Missing Header: Cache-Control",
                severity="INFO",
                url=self.target_url,
                description=(
                    "No Cache-Control header is present. Sensitive responses may be "
                    "stored in browser or proxy caches."
                ),
                evidence="Response does not contain the 'Cache-Control' header.",
                remediation=(
                    "For pages with sensitive data set: "
                    "Cache-Control: no-store, no-cache, must-revalidate, private"
                ),
            )
        else:
            lower_val = value.lower()
            if "no-store" not in lower_val and "private" not in lower_val:
                self.log(f"Cache-Control present but may allow caching: {value}")
                self.add_finding(
                    vuln_type="Weak Cache-Control Policy",
                    severity="INFO",
                    url=self.target_url,
                    description=(
                        f"Cache-Control is set to '{value}'. If this page contains "
                        "sensitive data it may be cached by proxies or the browser."
                    ),
                    evidence=f"Cache-Control: {value}",
                    remediation=(
                        "For sensitive pages add: "
                        "Cache-Control: no-store, no-cache, must-revalidate, private"
                    ),
                )

    def _check_server_header(self, headers: dict) -> None:
        """Detect information disclosure via the Server header."""
        value = headers.get("Server")
        if value is None:
            self.log("Server header not present (good).")
            return

        # Flag if the value looks like it contains a version number
        import re
        if re.search(r"\d+\.\d+", value):
            self.add_finding(
                vuln_type="Information Disclosure: Server Header",
                severity="INFO",
                url=self.target_url,
                description=(
                    f"The Server header exposes version information: '{value}'. "
                    "This helps attackers fingerprint the software and target known CVEs."
                ),
                evidence=f"Server: {value}",
                remediation=(
                    "Remove the version string from the Server header or suppress "
                    "the header entirely. In Apache: ServerTokens Prod. "
                    "In Nginx: server_tokens off;"
                ),
            )
        else:
            self.log(f"Server header present without version detail: {value}")

    def _check_x_powered_by(self, headers: dict) -> None:
        """Detect information disclosure via X-Powered-By."""
        value = headers.get("X-Powered-By")
        if value is not None:
            self.add_finding(
                vuln_type="Information Disclosure: X-Powered-By",
                severity="MEDIUM",
                url=self.target_url,
                description=(
                    f"The X-Powered-By header is present with value '{value}'. "
                    "This reveals backend technology and aids attacker reconnaissance."
                ),
                evidence=f"X-Powered-By: {value}",
                remediation=(
                    "Remove the X-Powered-By header entirely. "
                    "In PHP: expose_php = Off in php.ini. "
                    "In Express.js: app.disable('x-powered-by')."
                ),
            )

    def _check_cookies(self, response) -> None:
        """Inspect Set-Cookie headers for security attributes."""
        set_cookie_headers: list[str] = response.headers.get("Set-Cookie", "").split(",")
        # Also grab all raw Set-Cookie headers via response.raw if available
        raw_cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, "headers") else []
        # Merge — use raw if available (preserves multiple Set-Cookie headers)
        cookie_lines = raw_cookies if raw_cookies else [
            c.strip() for c in set_cookie_headers if c.strip()
        ]

        if not cookie_lines:
            self.log("No Set-Cookie headers found.")
            return

        for cookie_str in cookie_lines:
            if not cookie_str.strip():
                continue

            # Extract cookie name (everything before the first '=')
            cookie_name = cookie_str.split("=", 1)[0].strip()
            lower = cookie_str.lower()

            if "httponly" not in lower:
                self.add_finding(
                    vuln_type="Insecure Cookie: Missing HttpOnly",
                    severity="MEDIUM",
                    url=self.target_url,
                    description=(
                        f"Cookie '{cookie_name}' is missing the HttpOnly flag. "
                        "JavaScript can access this cookie, increasing XSS impact."
                    ),
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    remediation=f"Add the HttpOnly attribute to the '{cookie_name}' cookie.",
                )

            if "secure" not in lower:
                self.add_finding(
                    vuln_type="Insecure Cookie: Missing Secure",
                    severity="MEDIUM",
                    url=self.target_url,
                    description=(
                        f"Cookie '{cookie_name}' is missing the Secure flag. "
                        "It may be transmitted over unencrypted HTTP connections."
                    ),
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    remediation=f"Add the Secure attribute to the '{cookie_name}' cookie.",
                )

            if "samesite" not in lower:
                self.add_finding(
                    vuln_type="Insecure Cookie: Missing SameSite",
                    severity="LOW",
                    url=self.target_url,
                    description=(
                        f"Cookie '{cookie_name}' is missing the SameSite attribute. "
                        "This may make it susceptible to CSRF attacks in older browsers."
                    ),
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    remediation=(
                        f"Add SameSite=Lax (or SameSite=Strict) to the "
                        f"'{cookie_name}' cookie."
                    ),
                )
