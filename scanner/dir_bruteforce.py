"""
CyberShield - Directory / File Bruteforcer
============================================
Discovers hidden directories and files by brute-forcing paths from a
wordlist. Uses concurrent requests via ``ThreadPoolExecutor`` for speed.
Classifies findings by severity based on the sensitivity of discovered paths.
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from scanner.base import BaseScanner
from utils.colors import error, info, success, warning
from utils.helpers import load_wordlist, make_request


# ─────────────────────────────────────────────
# Default wordlist path (relative to project root)
# ─────────────────────────────────────────────
DEFAULT_WORDLIST: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "payloads",
    "common_dirs.txt",
)

# ─────────────────────────────────────────────
# Sensitive paths → HIGH severity
# ─────────────────────────────────────────────
HIGH_SENSITIVITY_PATTERNS: list[str] = [
    ".env",
    ".git",
    ".git/config",
    ".git/HEAD",
    ".gitignore",
    ".svn",
    ".hg",
    ".htpasswd",
    ".htaccess",
    "wp-config.php",
    "wp-config.php.bak",
    "web.config",
    "config.php",
    "config.yml",
    "config.yaml",
    "config.json",
    "database.yml",
    "settings.py",
    "secrets.yml",
    "credentials",
    "id_rsa",
    "id_dsa",
    ".ssh",
    ".bash_history",
    ".dockerenv",
    "docker-compose.yml",
    "Dockerfile",
    ".aws/credentials",
    "phpinfo.php",
    "server-status",
    "server-info",
    "elmah.axd",
    "trace.axd",
    ".DS_Store",
    "crossdomain.xml",
    "backup.sql",
    "dump.sql",
    "db.sql",
    "database.sql",
    "backup.zip",
    "backup.tar.gz",
    ".bak",
    ".old",
    ".swp",
    ".swo",
]

# ─────────────────────────────────────────────
# Admin / config paths → MEDIUM severity
# ─────────────────────────────────────────────
MEDIUM_SENSITIVITY_PATTERNS: list[str] = [
    "admin",
    "administrator",
    "admin/login",
    "admin/dashboard",
    "panel",
    "cpanel",
    "manager",
    "phpmyadmin",
    "adminer",
    "wp-admin",
    "wp-login",
    "console",
    "dashboard",
    "login",
    "cgi-bin",
    "server-status",
    "debug",
    "test",
    "staging",
    "dev",
    "api",
    "api/v1",
    "api/v2",
    "swagger",
    "swagger-ui",
    "graphql",
    "graphiql",
]

# Remediation text
DIR_REMEDIATION: str = (
    "Remove or restrict access to sensitive files and directories. "
    "Implement proper access controls."
)

# Built-in minimal fallback wordlist (used if no file found)
FALLBACK_DIRS: list[str] = [
    "admin", "login", "dashboard", "backup", "test",
    "uploads", "images", "css", "js", "api",
    "config", "tmp", "temp", "logs", "old",
    "dev", "staging", "debug", "console", "phpmyadmin",
    ".env", ".git", ".htaccess", "robots.txt", "sitemap.xml",
    "wp-admin", "wp-login.php", "wp-config.php",
    "server-status", "phpinfo.php", "info.php",
    "cgi-bin", "bin", "includes", "inc", "lib",
    "static", "assets", "media", "files", "data",
    "db", "sql", "database", "dump", "export",
    "private", "secret", "hidden", "internal",
]


class DirBruteforcer(BaseScanner):
    """
    Directory and file brute-force scanner.

    Iterates over a wordlist, makes HTTP requests to
    ``{target_url}/{word}``, and reports accessible, redirecting,
    forbidden, or auth-required paths with severity classification.
    """

    scanner_name: str = "Directory Bruteforcer"

    def __init__(
        self,
        target_url: str,
        wordlist_path: Optional[str] = None,
        threads: int = 10,
        verbose: bool = False,
    ) -> None:
        """
        Initialise the directory bruteforcer.

        Args:
            target_url: Root URL of the target (e.g. ``https://example.com``).
            wordlist_path: Path to a newline-delimited wordlist file.
                           Defaults to ``payloads/common_dirs.txt``.
            threads: Number of concurrent threads for requests.
            verbose: Enable verbose debug output.
        """
        super().__init__(target_url, verbose)
        self.wordlist_path: str = wordlist_path or DEFAULT_WORDLIST
        self.threads: int = max(1, min(threads, 50))  # clamp 1..50
        self.wordlist: list[str] = self._load_wordlist()
        # Track already-reported paths to avoid duplicates
        self._reported: set[str] = set()

    # ─────────────────────────────────────────
    # Wordlist loading
    # ─────────────────────────────────────────
    def _load_wordlist(self) -> list[str]:
        """
        Load wordlist from file, falling back to built-in list.

        Returns:
            Deduplicated list of directory/file names.
        """
        entries = load_wordlist(self.wordlist_path)
        if entries:
            self.log(f"Loaded {len(entries)} entries from {self.wordlist_path}")
        else:
            entries = list(FALLBACK_DIRS)
            self.log(f"Using {len(entries)} built-in fallback entries")

        # Merge fallback for coverage
        seen: set[str] = set(entries)
        for d in FALLBACK_DIRS:
            if d not in seen:
                entries.append(d)
                seen.add(d)
        return entries

    # ─────────────────────────────────────────
    # Severity classification
    # ─────────────────────────────────────────
    @staticmethod
    def _classify_severity(path: str, status_code: int) -> str:
        """
        Determine severity based on the discovered path and status code.

        Args:
            path: The brute-forced path segment.
            status_code: HTTP response status code.

        Returns:
            Severity string: HIGH, MEDIUM, or INFO.
        """
        path_lower = path.lower().strip("/")

        # HIGH: sensitive files / credentials / source control
        for pattern in HIGH_SENSITIVITY_PATTERNS:
            if path_lower == pattern.lower() or path_lower.endswith(pattern.lower()):
                return "HIGH"

        # MEDIUM: admin panels / config / debug endpoints
        for pattern in MEDIUM_SENSITIVITY_PATTERNS:
            if path_lower == pattern.lower() or path_lower.startswith(pattern.lower()):
                return "MEDIUM"

        # 401/403 on unknown paths are noteworthy
        if status_code in (401, 403):
            return "MEDIUM"

        return "INFO"

    @staticmethod
    def _status_description(status_code: int) -> str:
        """
        Return a human-readable description for common HTTP status codes.

        Args:
            status_code: HTTP status code.

        Returns:
            Description string.
        """
        descriptions: dict[int, str] = {
            200: "OK (accessible)",
            201: "Created",
            204: "No Content",
            301: "Moved Permanently (redirect)",
            302: "Found (redirect)",
            307: "Temporary Redirect",
            308: "Permanent Redirect",
            401: "Unauthorized (auth required)",
            403: "Forbidden (access denied)",
        }
        return descriptions.get(status_code, f"HTTP {status_code}")

    # ─────────────────────────────────────────
    # Single path probe
    # ─────────────────────────────────────────
    def _probe_path(self, word: str) -> Optional[dict[str, object]]:
        """
        Probe a single path and return result if interesting.

        Args:
            word: Directory or file name to append to the target URL.

        Returns:
            Dict with probe results, or None if the path returned 404
            or the request failed.
        """
        # Normalize: strip leading slashes from the word
        word = word.lstrip("/")
        base = self.target_url.rstrip("/")
        probe_url = f"{base}/{word}"

        self.log(f"Probing: {probe_url}")

        response = make_request(
            probe_url, timeout=8, allow_redirects=False
        )
        if response is None:
            return None

        status: int = response.status_code

        # Skip 404 and other "not found" codes
        if status in (404, 410, 400):
            return None

        # Filter out soft-404s: responses that return 200 but with very
        # small or default-looking bodies (heuristic)
        content_length = len(response.content)

        return {
            "word": word,
            "url": probe_url,
            "status": status,
            "size": content_length,
            "redirect": response.headers.get("Location", "") if status in (301, 302, 307, 308) else "",
        }

    # ─────────────────────────────────────────
    # Concurrent brute-force loop
    # ─────────────────────────────────────────
    def _bruteforce(self) -> list[dict[str, object]]:
        """
        Run the brute-force scan with concurrent threads.

        Returns:
            List of result dicts for all interesting (non-404) paths.
        """
        results: list[dict[str, object]] = []
        total = len(self.wordlist)

        info(f"Brute-forcing {total} paths with {self.threads} threads…")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._probe_path, word): word
                for word in self.wordlist
            }

            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0 or completed == total:
                    self.log(f"Progress: {completed}/{total}")

                try:
                    result = future.result()
                except Exception as exc:
                    self.log(f"Thread exception for '{futures[future]}': {exc}")
                    continue

                if result is not None:
                    results.append(result)

        return results

    # ─────────────────────────────────────────
    # Process results into findings
    # ─────────────────────────────────────────
    def _process_results(self, results: list[dict[str, object]]) -> None:
        """
        Convert raw probe results into structured findings.

        Args:
            results: List of probe result dicts from ``_bruteforce()``.
        """
        for result in results:
            word: str = str(result["word"])
            url: str = str(result["url"])
            status: int = int(result["status"])  # type: ignore[arg-type]
            size: int = int(result["size"])  # type: ignore[arg-type]
            redirect: str = str(result.get("redirect", ""))

            # De-duplicate
            dedup_key = f"dir:{word}:{status}"
            if dedup_key in self._reported:
                continue
            self._reported.add(dedup_key)

            severity = self._classify_severity(word, status)
            status_desc = self._status_description(status)

            # Build description
            if status in (301, 302, 307, 308):
                description = (
                    f"/{word} → {status_desc}. "
                    f"Redirects to: {redirect}. Size: {size}B."
                )
            elif status == 403:
                description = (
                    f"/{word} → {status_desc}. Access is forbidden but "
                    f"the resource exists. Size: {size}B."
                )
            elif status == 401:
                description = (
                    f"/{word} → {status_desc}. Authentication required. "
                    f"Size: {size}B."
                )
            else:
                description = (
                    f"/{word} → {status_desc}. Size: {size}B."
                )

            self.add_finding(
                vuln_type="Directory/File Found",
                severity=severity,
                url=url,
                description=description,
                evidence=(
                    f"Path: /{word} | Status: {status} | "
                    f"Size: {size}B"
                    + (f" | Redirect: {redirect}" if redirect else "")
                ),
                remediation=DIR_REMEDIATION,
            )

    # ─────────────────────────────────────────
    # Main entry point
    # ─────────────────────────────────────────
    def run(self) -> None:
        """
        Execute the directory brute-force scan.

        Probes all wordlist entries against the target URL
        concurrently and classifies discovered paths by severity.
        """
        info(f"Starting directory brute-force on {self.target_url}")
        info(f"  Wordlist entries: {len(self.wordlist)}")
        info(f"  Threads         : {self.threads}")

        results = self._bruteforce()

        info(f"Brute-force complete: {len(results)} interesting path(s) found.")

        self._process_results(results)

        # ── Summary ──
        total = self.finding_count()
        counts = self.count_by_severity()
        if total:
            warning(
                f"Directory scan complete: {total} finding(s) — "
                f"HIGH: {counts.get('HIGH', 0)}, "
                f"MEDIUM: {counts.get('MEDIUM', 0)}, "
                f"INFO: {counts.get('INFO', 0)}"
            )
        else:
            success("Directory scan complete: no accessible paths found.")
