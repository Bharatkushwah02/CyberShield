"""
CyberShield - Helper Utilities
================================
Common utility functions used across the scanner modules.
Includes URL validation, HTTP request wrapper, file I/O, and more.
"""

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

import requests
import requests.exceptions

from utils.colors import debug, error, warning


def is_valid_url(url: str) -> bool:
    """
    Validate whether a given string is a properly formatted URL.

    Args:
        url: The URL string to validate.

    Returns:
        True if the URL has a valid scheme (http/https) and netloc, False otherwise.
    """
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """
    Normalize a URL by ensuring it has a scheme.

    If the URL has no scheme, 'https://' is prepended. Trailing slashes are
    stripped from the path for consistency.

    Args:
        url: The URL string to normalize.

    Returns:
        The normalized URL string.
    """
    url = url.strip()
    if not url:
        return url

    # Add scheme if missing
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)

    # Rebuild with cleaned path (strip trailing slash unless it's root)
    path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        path,
        parsed.params,
        parsed.query,
        "",  # drop fragment
    ))
    return normalized


def get_domain(url: str) -> str:
    """
    Extract the domain (netloc) from a URL.

    Args:
        url: The URL to extract the domain from.

    Returns:
        The domain string (e.g. 'example.com' or 'example.com:8080').
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return ""


def get_base_url(url: str) -> str:
    """
    Extract the base URL (scheme + netloc) from a URL.

    Args:
        url: The full URL.

    Returns:
        The base URL string (e.g. 'https://example.com').
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def timestamp() -> str:
    """
    Get the current UTC timestamp as an ISO 8601 formatted string.

    Returns:
        Current timestamp string (e.g. '2025-01-15T14:30:00Z').
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def timestamp_filename() -> str:
    """
    Get a filesystem-safe timestamp string for use in filenames.

    Returns:
        Timestamp string (e.g. '20250115_143000').
    """
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def save_results(data: Any, filepath: str) -> bool:
    """
    Save scan results data to a JSON file.

    Creates parent directories if they don't exist.

    Args:
        data: The data to serialize (must be JSON-serializable).
        filepath: The destination file path.

    Returns:
        True if the save was successful, False otherwise.
    """
    try:
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return True
    except (OSError, TypeError, ValueError) as e:
        error(f"Failed to save results to {filepath}: {e}")
        return False


def load_results(filepath: str) -> Optional[Any]:
    """
    Load JSON results from a file.

    Args:
        filepath: The path to the JSON file.

    Returns:
        The deserialized data, or None on failure.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        error(f"Failed to load results from {filepath}: {e}")
        return None


def load_wordlist(filepath: str) -> list[str]:
    """
    Load a wordlist file, returning one stripped entry per line.

    Blank lines and lines starting with '#' are skipped.

    Args:
        filepath: Path to the wordlist file.

    Returns:
        List of wordlist entries. Empty list if the file can't be read.
    """
    entries: list[str] = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)
    except OSError as e:
        error(f"Failed to load wordlist from {filepath}: {e}")
    return entries


def make_request(
    url: str,
    method: str = "GET",
    data: Optional[dict[str, Any]] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 10,
    allow_redirects: bool = True,
    verify: bool = True,
    cookies: Optional[dict[str, str]] = None,
    proxies: Optional[dict[str, str]] = None,
) -> Optional[requests.Response]:
    """
    Make an HTTP request with comprehensive error handling.

    This is a safe wrapper around requests that catches all common exceptions
    and returns None on failure instead of raising.

    Args:
        url: The target URL.
        method: HTTP method (GET, POST, PUT, DELETE, HEAD, OPTIONS).
        data: Request body data (for POST/PUT).
        headers: Custom HTTP headers.
        timeout: Request timeout in seconds.
        allow_redirects: Whether to follow redirects.
        verify: Whether to verify SSL certificates.
        cookies: Optional cookies dict.
        proxies: Optional proxies dict (e.g. {'http': 'http://127.0.0.1:8080'}).

    Returns:
        The Response object on success, or None on any failure.
    """
    default_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    if headers:
        default_headers.update(headers)

    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            data=data,
            headers=default_headers,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            cookies=cookies,
            proxies=proxies,
        )
        return response

    except requests.exceptions.ConnectionError:
        debug(f"Connection error: {url}")
        return None
    except requests.exceptions.Timeout:
        debug(f"Request timed out: {url}")
        return None
    except requests.exceptions.TooManyRedirects:
        debug(f"Too many redirects: {url}")
        return None
    except requests.exceptions.SSLError as e:
        debug(f"SSL error for {url}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        debug(f"Request failed for {url}: {e}")
        return None
    except Exception as e:
        debug(f"Unexpected error requesting {url}: {e}")
        return None


def sanitize_filename(name: str) -> str:
    """
    Sanitize a string for safe use as a filename.

    Args:
        name: The raw filename string.

    Returns:
        Sanitized filename with special characters replaced by underscores.
    """
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
