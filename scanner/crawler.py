"""
CyberShield - Web Crawler
===========================
BFS-based web crawler that discovers pages and forms on the target website.
Only follows links within the same domain. Extracts all HTML forms with
their action URLs, methods, and input fields.
"""

from collections import deque
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from utils.colors import debug, error, info, progress, success, warning
from utils.helpers import get_domain, make_request, normalize_url


class Crawler:
    """
    Simple BFS web crawler for target reconnaissance.

    Discovers linked pages and HTML forms on the same domain as the target URL.
    Respects configurable depth and page-count limits.
    """

    def __init__(
        self,
        target_url: str,
        max_depth: int = 2,
        max_pages: int = 50,
        verbose: bool = False,
    ) -> None:
        """
        Initialise the crawler.

        Args:
            target_url: Starting URL for the crawl.
            max_depth: Maximum link-follow depth (0 = target page only).
            max_pages: Maximum number of pages to visit.
            verbose: Print detailed progress messages.
        """
        self.target_url: str = normalize_url(target_url)
        self.max_depth: int = max_depth
        self.max_pages: int = max_pages
        self.verbose: bool = verbose

        self.target_domain: str = get_domain(self.target_url)

        self.crawled_urls: set[str] = set()
        self.forms: list[dict[str, Any]] = []

        # Internal state
        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()  # (url, depth)

    # ─────────────────────── public API ───────────────────────

    def crawl(self) -> tuple[set[str], list[dict[str, Any]]]:
        """
        Execute the BFS crawl starting from the target URL.

        Returns:
            A tuple of (crawled_urls, forms) where:
              - crawled_urls: set of all successfully visited URLs
              - forms: list of form dicts extracted from visited pages
        """
        info(f"Starting crawl on {self.target_url} (depth={self.max_depth}, max_pages={self.max_pages})")
        self._queue.append((self.target_url, 0))
        self._visited.add(self._normalize_for_dedup(self.target_url))

        while self._queue and len(self.crawled_urls) < self.max_pages:
            current_url, depth = self._queue.popleft()

            # Fetch the page
            response = make_request(current_url, timeout=10, verify=False)
            if response is None:
                self._log(f"Failed to fetch: {current_url}")
                continue

            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                self._log(f"Skipping non-HTML: {current_url} ({content_type})")
                continue

            self.crawled_urls.add(current_url)
            self._log(f"[depth={depth}] Crawled: {current_url}")

            # Parse the HTML
            try:
                soup = BeautifulSoup(response.text, "html.parser")
            except Exception as e:
                self._log(f"Parse error on {current_url}: {e}")
                continue

            # Extract forms from this page
            page_forms = self._extract_forms(soup, current_url)
            self.forms.extend(page_forms)
            if page_forms:
                self._log(f"  Found {len(page_forms)} form(s) on {current_url}")

            # Extract and queue links if we haven't hit max depth
            if depth < self.max_depth:
                links = self._extract_links(soup, current_url)
                for link in links:
                    dedup_key = self._normalize_for_dedup(link)
                    if dedup_key not in self._visited:
                        self._visited.add(dedup_key)
                        self._queue.append((link, depth + 1))

            # Show progress
            if not self.verbose:
                progress(
                    len(self.crawled_urls),
                    min(self.max_pages, len(self.crawled_urls) + len(self._queue)),
                    prefix="Crawling",
                )

        success(f"Crawl complete: {len(self.crawled_urls)} pages, {len(self.forms)} forms found")
        return self.crawled_urls, self.forms

    # ─────────────────── link extraction ───────────────────

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> list[str]:
        """
        Extract all same-domain links from a parsed HTML page.

        Args:
            soup: Parsed BeautifulSoup object.
            base_url: The URL of the page (used to resolve relative links).

        Returns:
            List of absolute, normalised URLs on the same domain.
        """
        links: list[str] = []

        for tag in soup.find_all("a", href=True):
            href: str = tag["href"].strip()

            # Skip non-navigable links
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue

            # Resolve relative URLs
            absolute = urljoin(base_url, href)

            # Parse and filter
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https"):
                continue

            # Same-domain check
            if parsed.netloc != self.target_domain:
                continue

            # Skip common non-page resources
            skip_extensions = (
                ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
                ".css", ".js", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
                ".zip", ".tar", ".gz", ".mp3", ".mp4", ".avi", ".mov",
                ".woff", ".woff2", ".ttf", ".eot", ".otf",
            )
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in skip_extensions):
                continue

            # Strip fragment, normalise
            clean_url = parsed._replace(fragment="").geturl()
            clean_url = normalize_url(clean_url)
            links.append(clean_url)

        return links

    # ─────────────────── form extraction ───────────────────

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list[dict[str, Any]]:
        """
        Extract all HTML forms and their input fields from a page.

        Args:
            soup: Parsed BeautifulSoup object.
            page_url: URL of the page containing the forms.

        Returns:
            List of form dictionaries, each containing:
              - page_url: The page where the form was found
              - action: The form's action URL (absolute)
              - method: HTTP method (GET/POST)
              - inputs: List of dicts with 'name', 'type', 'value' keys
        """
        forms: list[dict[str, Any]] = []

        for form_tag in soup.find_all("form"):
            # Resolve action URL
            raw_action = form_tag.get("action", "").strip()
            if raw_action:
                action = urljoin(page_url, raw_action)
            else:
                action = page_url  # form submits to the same page

            method = form_tag.get("method", "GET").upper()

            # Collect input fields
            inputs: list[dict[str, str]] = []

            # <input> elements
            for inp in form_tag.find_all("input"):
                input_name = inp.get("name", "")
                input_type = inp.get("type", "text").lower()
                input_value = inp.get("value", "")
                inputs.append({
                    "name": input_name,
                    "type": input_type,
                    "value": input_value,
                })

            # <textarea> elements
            for ta in form_tag.find_all("textarea"):
                inputs.append({
                    "name": ta.get("name", ""),
                    "type": "textarea",
                    "value": ta.string or "",
                })

            # <select> elements
            for sel in form_tag.find_all("select"):
                selected_option = sel.find("option", selected=True)
                default_val = selected_option.get("value", "") if selected_option else ""
                inputs.append({
                    "name": sel.get("name", ""),
                    "type": "select",
                    "value": default_val,
                })

            forms.append({
                "page_url": page_url,
                "action": action,
                "method": method,
                "inputs": inputs,
            })

        return forms

    # ─────────────────── helpers ───────────────────

    def _normalize_for_dedup(self, url: str) -> str:
        """
        Create a canonical key for URL deduplication.

        Strips fragments and trailing slashes so that functionally
        identical URLs map to the same key.
        """
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}?{parsed.query}"

    def _log(self, message: str) -> None:
        """Print a message only when verbose mode is enabled."""
        if self.verbose:
            debug(f"[Crawler] {message}")
