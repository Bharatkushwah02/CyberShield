"""
CyberShield - TCP Port Scanner
=================================
Multi-threaded TCP connect scanner with banner grabbing and service
identification. Supports flexible port-range syntax and categorises
open ports by risk level.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse

from scanner.base import BaseScanner
from utils.colors import info, success, warning, error, section, progress


# ─────────────────────────────────────────────────────────────────
# Common port → service name mapping
# ─────────────────────────────────────────────────────────────────
COMMON_PORTS: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPCbind",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP-Submission",
    636: "LDAPS",
    873: "rsync",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1434: "MSSQL-Browser",
    1521: "Oracle-DB",
    1723: "PPTP",
    2049: "NFS",
    2181: "ZooKeeper",
    3306: "MySQL",
    3389: "RDP",
    4443: "HTTPS-Alt",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    6443: "K8s-API",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Transport",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
    50000: "SAP",
}

# Ports that are considered dangerous when externally exposed
_DANGEROUS_SERVICES: set[int] = {23, 21, 69, 111, 135, 137, 138, 139, 161, 445, 514, 515}
_DATABASE_PORTS: set[int] = {
    1433, 1434, 1521, 3306, 5432, 6379, 9200, 9300, 11211, 27017, 27018, 2181,
}


class PortScanner(BaseScanner):
    """
    Multi-threaded TCP connect scanner.

    Features:
        - Flexible port-range parsing (e.g. ``"1-1024"``, ``"80,443,8080"``,
          ``"1-100,443,8080-8090"``).
        - Concurrent scanning via :class:`ThreadPoolExecutor`.
        - Banner grabbing on open ports.
        - Service identification from a 50+ entry mapping.
        - Risk-based finding categorisation (dangerous / database / info).
    """

    scanner_name: str = "Port Scanner"

    def __init__(
        self,
        target_url: str,
        port_range: str = "1-1024",
        threads: int = 10,
        verbose: bool = False,
    ) -> None:
        """
        Initialise the port scanner.

        Args:
            target_url: The target URL (hostname is extracted automatically).
            port_range: Comma-separated port ranges (e.g. ``"1-1024"``).
            threads: Number of concurrent scanner threads.
            verbose: If True, print per-port progress.
        """
        super().__init__(target_url, verbose)
        self._port_range_str: str = port_range
        self._threads: int = max(1, threads)
        parsed = urlparse(self.target_url)
        self._hostname: str = parsed.hostname or ""

    # ── Public entry point ───────────────────────────────────────
    def run(self) -> None:
        """Execute the port scan."""
        section("TCP Port Scan")
        info(f"Target: {self._hostname}")

        if not self._hostname:
            error("Could not extract hostname from target URL.")
            return

        # Resolve hostname to IP for user feedback
        try:
            ip = socket.gethostbyname(self._hostname)
            info(f"Resolved IP: {ip}")
        except socket.gaierror:
            warning(f"Could not resolve hostname '{self._hostname}'.")
            ip = self._hostname

        ports = self._parse_port_range(self._port_range_str)
        if not ports:
            error(f"Invalid or empty port range: '{self._port_range_str}'")
            return

        total = len(ports)
        info(f"Scanning {total} port(s) with {self._threads} thread(s)…")

        open_ports: list[tuple[int, str, str]] = []  # (port, service, banner)
        scanned = 0

        with ThreadPoolExecutor(max_workers=self._threads) as executor:
            futures = {
                executor.submit(self._scan_port, port): port for port in ports
            }
            for future in as_completed(futures):
                scanned += 1
                port = futures[future]

                if self.verbose:
                    progress(scanned, total, prefix="Ports")

                try:
                    result = future.result()
                except Exception:
                    continue

                if result is not None:
                    p, service, banner = result
                    open_ports.append((p, service, banner))

        # Print blank line after progress bar
        if self.verbose and total > 0:
            print()

        if not open_ports:
            success("No open ports found in the scanned range.")
            return

        open_ports.sort(key=lambda x: x[0])
        info(f"Found {len(open_ports)} open port(s):")
        for port, service, banner in open_ports:
            banner_display = f" — Banner: {banner}" if banner else ""
            info(f"  Port {port}/tcp  [{service}]{banner_display}")

        # Record findings
        for port, service, banner in open_ports:
            self._record_finding(port, service, banner)

    # ── Single port scan ─────────────────────────────────────────
    def _scan_port(self, port: int) -> Optional[tuple[int, str, str]]:
        """
        Attempt a TCP connect to a single port and grab a banner.

        Args:
            port: The port number to probe.

        Returns:
            ``(port, service_name, banner)`` if the port is open, else ``None``.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                result = sock.connect_ex((self._hostname, port))
                if result != 0:
                    return None

                service = COMMON_PORTS.get(port, "Unknown")
                banner = self._grab_banner(sock)
                return (port, service, banner)
        except (socket.error, OSError):
            return None

    @staticmethod
    def _grab_banner(sock: socket.socket) -> str:
        """
        Try to read a service banner from an already-connected socket.

        Args:
            sock: A connected TCP socket.

        Returns:
            The banner string (sanitised), or empty string on failure.
        """
        try:
            sock.settimeout(2.0)
            # Some services send a banner immediately, others need a nudge
            try:
                data = sock.recv(1024)
            except socket.timeout:
                # Send a blank line to coax a response (e.g. HTTP)
                sock.sendall(b"\r\n")
                try:
                    data = sock.recv(1024)
                except socket.timeout:
                    return ""

            if data:
                # Decode and sanitise for display
                banner = data.decode("utf-8", errors="replace").strip()
                # Collapse whitespace and limit length
                banner = " ".join(banner.split())
                return banner[:200]
        except (socket.error, OSError):
            pass
        return ""

    # ── Finding categorisation ───────────────────────────────────
    def _record_finding(self, port: int, service: str, banner: str) -> None:
        """Create a properly-categorised finding for an open port."""
        evidence_parts = [f"Port {port}/tcp is open", f"Service: {service}"]
        if banner:
            evidence_parts.append(f"Banner: {banner}")
        evidence = ". ".join(evidence_parts)

        if port in _DATABASE_PORTS:
            self.add_finding(
                vuln_type=f"Database Port Exposed: {port}/{service}",
                severity="HIGH",
                url=self.target_url,
                description=(
                    f"Database service '{service}' on port {port} is reachable externally. "
                    "Direct database exposure greatly increases the attack surface and "
                    "risk of data breach."
                ),
                evidence=evidence,
                remediation=(
                    f"Restrict access to port {port} via firewall rules so only "
                    "authorised application servers can connect. Never expose database "
                    "ports to the public internet."
                ),
            )
        elif port in _DANGEROUS_SERVICES:
            self.add_finding(
                vuln_type=f"Dangerous Service Exposed: {port}/{service}",
                severity="MEDIUM",
                url=self.target_url,
                description=(
                    f"Service '{service}' on port {port} is considered insecure or "
                    "should not be publicly accessible. It may transmit credentials "
                    "in plaintext or have well-known vulnerabilities."
                ),
                evidence=evidence,
                remediation=(
                    f"Disable the '{service}' service if not required, or restrict "
                    "access with firewall rules. Replace with encrypted alternatives "
                    "(e.g. SSH instead of Telnet, SFTP instead of FTP)."
                ),
            )
        else:
            self.add_finding(
                vuln_type=f"Open Port: {port}/{service}",
                severity="INFO",
                url=self.target_url,
                description=f"Port {port}/tcp ({service}) is open.",
                evidence=evidence,
                remediation=(
                    "Verify this service is intentionally exposed. Close or firewall "
                    "any ports that are not required."
                ),
            )

    # ── Port-range parser ────────────────────────────────────────
    @staticmethod
    def _parse_port_range(port_range: str) -> list[int]:
        """
        Parse a flexible port-range string into a sorted list of unique ports.

        Supported formats:
            - ``"80"`` → single port
            - ``"1-1024"`` → inclusive range
            - ``"80,443,8080"`` → comma-separated
            - ``"1-100,443,8080-8090"`` → mixed

        Args:
            port_range: The port specification string.

        Returns:
            Sorted list of unique port numbers (1–65535).
        """
        ports: set[int] = set()
        for segment in port_range.split(","):
            segment = segment.strip()
            if not segment:
                continue

            if "-" in segment:
                parts = segment.split("-", 1)
                try:
                    start = int(parts[0].strip())
                    end = int(parts[1].strip())
                    start = max(1, min(start, 65535))
                    end = max(1, min(end, 65535))
                    if start > end:
                        start, end = end, start
                    ports.update(range(start, end + 1))
                except ValueError:
                    continue
            else:
                try:
                    p = int(segment)
                    if 1 <= p <= 65535:
                        ports.add(p)
                except ValueError:
                    continue

        return sorted(ports)
