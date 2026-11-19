"""
CyberShield - Base Scanner
============================
Abstract base class that all vulnerability scanner modules inherit from.
Provides common infrastructure for findings management, logging, and reporting.
"""

from abc import ABC, abstractmethod
from typing import Optional

from utils.colors import debug, finding, info
from utils.helpers import timestamp


# Valid severity levels in descending order of criticality
SEVERITY_LEVELS: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class BaseScanner(ABC):
    """
    Abstract base scanner class.

    All CyberShield scanner modules must inherit from this class and
    implement the ``run()`` method. The base class provides:
      - Findings storage and management
      - Verbose logging helpers
      - Severity-aware output formatting
    """

    # Human-readable scanner name — override in subclasses
    scanner_name: str = "Base Scanner"

    def __init__(self, target_url: str, verbose: bool = False) -> None:
        """
        Initialise the scanner.

        Args:
            target_url: The root URL of the target to scan.
            verbose: If True, print detailed progress messages.
        """
        self.target_url: str = target_url
        self.verbose: bool = verbose
        self.findings: list[dict[str, str]] = []

    def log(self, message: str) -> None:
        """
        Print a debug/verbose message.

        Only produces output when ``self.verbose`` is True.

        Args:
            message: The message to print.
        """
        if self.verbose:
            debug(f"[{self.scanner_name}] {message}")

    def add_finding(
        self,
        vuln_type: str,
        severity: str,
        url: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
    ) -> None:
        """
        Record a new vulnerability finding.

        Args:
            vuln_type: Category of the vulnerability (e.g. 'SQL Injection').
            severity: Severity level — one of CRITICAL, HIGH, MEDIUM, LOW, INFO.
            url: The URL where the issue was found.
            description: Human-readable description of the finding.
            evidence: Raw evidence/payload that triggered the finding.
            remediation: Suggested fix or mitigation guidance.
        """
        severity_upper = severity.upper()
        if severity_upper not in SEVERITY_LEVELS:
            severity_upper = "INFO"

        entry: dict[str, str] = {
            "type": vuln_type,
            "severity": severity_upper,
            "url": url,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "scanner": self.scanner_name,
            "timestamp": timestamp(),
        }
        self.findings.append(entry)

        # Always print findings regardless of verbose mode
        finding(severity_upper, f"{vuln_type} — {url}")
        if self.verbose and evidence:
            debug(f"  Evidence: {evidence[:200]}")

    @abstractmethod
    def run(self) -> None:
        """
        Execute the scan.

        Subclasses **must** override this method with their scanning logic.
        All discovered vulnerabilities should be recorded via ``add_finding()``.
        """
        raise NotImplementedError("Subclasses must implement run()")

    def get_findings(self) -> list[dict[str, str]]:
        """
        Return all findings collected during the scan.

        Returns:
            A list of finding dictionaries.
        """
        return self.findings

    def finding_count(self) -> int:
        """Return the total number of findings."""
        return len(self.findings)

    def count_by_severity(self) -> dict[str, int]:
        """
        Count findings grouped by severity level.

        Returns:
            Dict mapping severity strings to their counts.
        """
        counts: dict[str, int] = {sev: 0 for sev in SEVERITY_LEVELS}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} target='{self.target_url}' "
            f"findings={self.finding_count()}>"
        )
