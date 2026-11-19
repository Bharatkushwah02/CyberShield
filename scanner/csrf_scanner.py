"""
CyberShield - CSRF Scanner
=============================
Detects Cross-Site Request Forgery (CSRF) vulnerabilities by analysing
discovered HTML forms for the presence of anti-CSRF tokens and inspecting
session cookie attributes (SameSite).
"""

import re
from typing import Any, Optional

from scanner.base import BaseScanner
from utils.colors import error, info, success, warning
from utils.helpers import make_request


# ─────────────────────────────────────────────
# Known anti-CSRF token field names (lowercase)
# ─────────────────────────────────────────────
CSRF_TOKEN_NAMES: list[str] = [
    "csrf",
    "csrf_token",
    "csrftoken",
    "csrfmiddlewaretoken",  # Django
    "_csrf",
    "_csrf_token",
    "token",
    "_token",               # Laravel
    "authenticity_token",   # Rails
    "anti_csrf",
    "anticsrf",
    "xsrf",
    "xsrf_token",
    "_xsrf",
    "__requestverificationtoken",  # ASP.NET MVC
    "formtoken",
    "form_token",
    "nonce",
    "wp_nonce",
    "_wpnonce",             # WordPress
]

# Compiled regex for matching token names loosely
CSRF_TOKEN_PATTERN: re.Pattern[str] = re.compile(
    r"(csrf|xsrf|token|nonce|authenticity|verification)",
    re.IGNORECASE,
)

# Remediation text
CSRF_REMEDIATION: str = (
    "Implement anti-CSRF tokens in all state-changing forms. "
    "Set SameSite attribute on session cookies."
)


class CSRFScanner(BaseScanner):
    """
    CSRF vulnerability scanner.

    Analyses discovered HTML forms for missing anti-CSRF protections
    and inspects cookie attributes on the target's responses.
    """

    scanner_name: str = "CSRF Scanner"

    def __init__(
        self,
        target_url: str,
        forms: Optional[list[dict[str, Any]]] = None,
        verbose: bool = False,
    ) -> None:
        """
        Initialise the CSRF scanner.

        Args:
            target_url: Root URL of the target application.
            forms: List of form dicts with keys
                   ``action``, ``method``, ``inputs``.
            verbose: Enable verbose debug output.
        """
        super().__init__(target_url, verbose)
        self.forms: list[dict[str, Any]] = forms or []
        # Track already-reported vulns to avoid duplicates
        self._reported: set[str] = set()

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
    # Anti-CSRF token detection
    # ─────────────────────────────────────────
    @staticmethod
    def _has_csrf_token(inputs: list[dict[str, str]]) -> tuple[bool, str]:
        """
        Check whether a form's input fields contain an anti-CSRF token.

        Searches for hidden inputs whose ``name`` attribute matches
        known CSRF token names or the broader regex pattern.

        Args:
            inputs: List of form input dicts (``name``, ``type``, ``value``).

        Returns:
            Tuple of (has_token: bool, token_name: str). If a token is
            found, ``token_name`` contains the matching field name.
        """
        for inp in inputs:
            field_name: str = inp.get("name", "").lower().strip()
            field_type: str = inp.get("type", "").lower().strip()

            # Token is typically a hidden field
            if field_type != "hidden":
                continue

            # Exact match against known names
            if field_name in CSRF_TOKEN_NAMES:
                return True, field_name

            # Fuzzy regex match
            if CSRF_TOKEN_PATTERN.search(field_name):
                return True, field_name

        return False, ""

    # ─────────────────────────────────────────
    # SameSite cookie check
    # ─────────────────────────────────────────
    def _check_samesite_cookies(self) -> dict[str, dict[str, Any]]:
        """
        Fetch the target URL and inspect Set-Cookie headers for
        the SameSite attribute.

        Returns:
            Dict mapping cookie names to analysis dicts with keys:
              - ``has_samesite`` (bool)
              - ``samesite_value`` (str or None)
              - ``raw_header`` (str)
        """
        results: dict[str, dict[str, Any]] = {}

        response = make_request(self.target_url, timeout=10)
        if response is None:
            self.log("Could not fetch target URL for cookie analysis.")
            return results

        # Iterate over raw Set-Cookie headers
        set_cookie_headers: list[str] = response.raw.headers.getlist("Set-Cookie") if hasattr(
            response.raw.headers, "getlist"
        ) else [
            v for k, v in response.headers.items() if k.lower() == "set-cookie"
        ]

        for header_value in set_cookie_headers:
            # Extract cookie name
            cookie_name_match = re.match(r"^([^=]+)=", header_value)
            if not cookie_name_match:
                continue
            cookie_name: str = cookie_name_match.group(1).strip()

            # Check for SameSite attribute
            samesite_match = re.search(
                r"samesite\s*=\s*(\w+)", header_value, re.IGNORECASE
            )
            has_samesite: bool = samesite_match is not None
            samesite_value: Optional[str] = (
                samesite_match.group(1) if samesite_match else None
            )

            results[cookie_name] = {
                "has_samesite": has_samesite,
                "samesite_value": samesite_value,
                "raw_header": header_value,
            }

        return results

    # ─────────────────────────────────────────
    # Determine if action looks state-changing
    # ─────────────────────────────────────────
    @staticmethod
    def _is_state_changing_action(action: str) -> bool:
        """
        Heuristically determine whether a form action URL looks
        like it performs a state-changing operation.

        Args:
            action: The form's ``action`` attribute value.

        Returns:
            True if the action contains state-changing keywords.
        """
        state_changing_keywords: list[str] = [
            "delete", "remove", "update", "edit", "save",
            "create", "add", "post", "submit", "change",
            "modify", "reset", "password", "profile",
            "settings", "account", "transfer", "checkout",
            "purchase", "pay", "order", "subscribe",
        ]
        action_lower = action.lower()
        return any(kw in action_lower for kw in state_changing_keywords)

    # ─────────────────────────────────────────
    # Form analysis
    # ─────────────────────────────────────────
    def _analyse_forms(self) -> None:
        """
        Iterate over all discovered forms and check for CSRF
        protections (anti-CSRF tokens and HTTP method).
        """
        for idx, form in enumerate(self.forms):
            action: str = form.get("action", "")
            method: str = form.get("method", "GET").upper()
            inputs: list[dict[str, str]] = form.get("inputs", [])

            display_action: str = action if action else "(same page)"
            self.log(f"Analysing form #{idx + 1}: {method} {display_action}")

            has_token, token_name = self._has_csrf_token(inputs)

            # ── POST form without CSRF token → HIGH ──
            if method == "POST" and not has_token:
                dedup_key = f"csrf-notoken:{method}:{action}"
                if self._is_duplicate(dedup_key):
                    continue

                # Build a readable list of input field names
                field_names = [
                    inp.get("name", "?")
                    for inp in inputs
                    if inp.get("name") and inp.get("type", "").lower() != "submit"
                ]

                self.add_finding(
                    vuln_type="Missing CSRF Token",
                    severity="HIGH",
                    url=self.target_url,
                    description=(
                        f"POST form (action='{display_action}') has no "
                        f"anti-CSRF token. Fields: {', '.join(field_names) or 'none'}. "
                        f"This form is vulnerable to CSRF attacks."
                    ),
                    evidence=(
                        f"Method: {method} | Action: {display_action} | "
                        f"Inputs checked: {len(inputs)} | "
                        f"No hidden field matching known CSRF token names found."
                    ),
                    remediation=CSRF_REMEDIATION,
                )

            # ── GET form doing state-changing action → MEDIUM ──
            elif method == "GET" and self._is_state_changing_action(action):
                dedup_key = f"csrf-get-statechange:{action}"
                if self._is_duplicate(dedup_key):
                    continue

                self.add_finding(
                    vuln_type="State-Changing GET Form",
                    severity="MEDIUM",
                    url=self.target_url,
                    description=(
                        f"GET form (action='{display_action}') appears to "
                        f"perform a state-changing operation. GET requests "
                        f"should be idempotent and are more vulnerable to CSRF."
                    ),
                    evidence=(
                        f"Method: GET | Action: {display_action} | "
                        f"Action contains state-changing keywords."
                    ),
                    remediation=(
                        "Use POST method for state-changing operations. "
                        + CSRF_REMEDIATION
                    ),
                )

            # ── POST form WITH token → log for verbose, no finding ──
            elif method == "POST" and has_token:
                self.log(
                    f"Form #{idx + 1} ({display_action}) has CSRF token: "
                    f"'{token_name}' — OK."
                )

    # ─────────────────────────────────────────
    # Cookie analysis
    # ─────────────────────────────────────────
    def _analyse_cookies(self) -> None:
        """
        Check session cookies for SameSite attribute.
        Missing or misconfigured SameSite weakens CSRF protections.
        """
        cookie_results = self._check_samesite_cookies()

        if not cookie_results:
            self.log("No Set-Cookie headers found or could not connect.")
            return

        for cookie_name, analysis in cookie_results.items():
            has_samesite: bool = analysis["has_samesite"]
            samesite_value: Optional[str] = analysis["samesite_value"]

            # Session-like cookies without SameSite → MEDIUM
            session_keywords = [
                "session", "sess", "sid", "phpsessid", "jsessionid",
                "asp.net_sessionid", "connect.sid",
            ]
            is_session_cookie = any(
                kw in cookie_name.lower() for kw in session_keywords
            )

            if not has_samesite and is_session_cookie:
                dedup_key = f"csrf-cookie-samesite:{cookie_name}"
                if self._is_duplicate(dedup_key):
                    continue
                self.add_finding(
                    vuln_type="Missing SameSite Cookie Attribute",
                    severity="MEDIUM",
                    url=self.target_url,
                    description=(
                        f"Session cookie '{cookie_name}' does not have the "
                        f"SameSite attribute set. This weakens CSRF protection."
                    ),
                    evidence=f"Cookie: {cookie_name} | SameSite: not set",
                    remediation=CSRF_REMEDIATION,
                )

            elif has_samesite and samesite_value and samesite_value.lower() == "none":
                dedup_key = f"csrf-cookie-samesite-none:{cookie_name}"
                if self._is_duplicate(dedup_key):
                    continue
                self.add_finding(
                    vuln_type="SameSite=None Cookie",
                    severity="LOW",
                    url=self.target_url,
                    description=(
                        f"Cookie '{cookie_name}' has SameSite=None, which "
                        f"provides no CSRF protection. This is only acceptable "
                        f"for cross-site cookies that require it."
                    ),
                    evidence=(
                        f"Cookie: {cookie_name} | SameSite: None"
                    ),
                    remediation=(
                        "Set SameSite=Lax or SameSite=Strict on session "
                        "cookies unless cross-site access is specifically "
                        "required."
                    ),
                )
            else:
                self.log(
                    f"Cookie '{cookie_name}' has SameSite="
                    f"{samesite_value or '(not set)'} — OK."
                )

    # ─────────────────────────────────────────
    # Main entry point
    # ─────────────────────────────────────────
    def run(self) -> None:
        """
        Execute the full CSRF scan.

        Analyses all discovered forms for anti-CSRF tokens and
        inspects session cookie SameSite attributes.
        """
        info(f"Starting CSRF scan on {self.target_url}")
        info(f"  Forms to analyse: {len(self.forms)}")

        # ── Phase 1: Form analysis ──
        info("Phase 1/2: Analysing forms for CSRF protections…")
        if self.forms:
            self._analyse_forms()
        else:
            self.log("No forms provided — skipping form analysis.")

        # ── Phase 2: Cookie analysis ──
        info("Phase 2/2: Checking cookie SameSite attributes…")
        self._analyse_cookies()

        # ── Summary ──
        total = self.finding_count()
        if total:
            warning(f"CSRF scan complete: {total} finding(s) detected!")
        else:
            success("CSRF scan complete: no vulnerabilities found.")
