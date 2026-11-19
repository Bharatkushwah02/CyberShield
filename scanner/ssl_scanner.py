"""
CyberShield - SSL/TLS Scanner
================================
Evaluates the target's SSL/TLS configuration including certificate validity,
TLS protocol version support, and common deployment issues such as missing
HTTPS redirects and self-signed certificates.
"""

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from scanner.base import BaseScanner
from utils.colors import info, success, warning, error, section
from utils.helpers import make_request


class SSLScanner(BaseScanner):
    """
    Scanner for SSL/TLS certificate and protocol analysis.

    Checks performed:
        - Certificate validity period and expiration warning
        - Hostname / certificate mismatch detection
        - Self-signed certificate detection
        - Deprecated TLS versions (1.0, 1.1) enabled check
        - TLS 1.2 and 1.3 support verification
        - HTTP → HTTPS redirect validation
        - HTTP-only target reporting
    """

    scanner_name: str = "SSL/TLS Scanner"

    # Socket timeout for all SSL probe connections (seconds)
    _CONNECT_TIMEOUT: int = 10

    def __init__(self, target_url: str, verbose: bool = False) -> None:
        """
        Initialise the SSL/TLS scanner.

        Args:
            target_url: The root URL of the target to scan.
            verbose: If True, print detailed progress messages.
        """
        super().__init__(target_url, verbose)
        parsed = urlparse(self.target_url)
        self._hostname: str = parsed.hostname or ""
        self._port: int = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._scheme: str = parsed.scheme.lower()

    # ── Public entry point ───────────────────────────────────────
    def run(self) -> None:
        """Execute the full SSL/TLS scan."""
        section("SSL / TLS Scan")
        info(f"Target: {self.target_url}  (host={self._hostname}, port={self._port})")

        if not self._hostname:
            error("Could not extract hostname from target URL.")
            return

        # 1. HTTP-only target warning
        if self._scheme == "http":
            self._check_http_only()

        # 2. Check HTTPS redirect (always useful, even if target is https)
        self._check_https_redirect()

        # 3. Certificate analysis (only if we can reach port 443)
        ssl_port = self._port if self._scheme == "https" else 443
        self._check_certificate(ssl_port)

        # 4. TLS version probes
        self._check_tls_versions(ssl_port)

        if self.finding_count() == 0:
            success("SSL/TLS configuration looks solid — no issues found!")
        else:
            info(f"SSL/TLS scan complete — {self.finding_count()} finding(s) recorded.")

    # ── Certificate checks ───────────────────────────────────────
    def _check_certificate(self, port: int) -> None:
        """Connect via TLS and inspect the peer certificate."""
        self.log(f"Connecting to {self._hostname}:{port} for certificate analysis…")

        ctx = ssl.create_default_context()
        # First try with verification ON
        cert_dict: Optional[dict] = None
        cert_pem: Optional[bytes] = None
        try:
            with socket.create_connection(
                (self._hostname, port), timeout=self._CONNECT_TIMEOUT
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=self._hostname) as ssock:
                    cert_dict = ssock.getpeercert()
                    cert_pem = ssock.getpeercert(binary_form=True)
                    self.log(f"TLS negotiated protocol: {ssock.version()}")
        except ssl.SSLCertVerificationError as e:
            self.log(f"Certificate verification failed: {e}")
            # Try again without verification to still get cert info
            cert_dict, cert_pem = self._get_cert_unverified(port)
            if cert_dict is None:
                self.add_finding(
                    vuln_type="SSL Certificate Error",
                    severity="HIGH",
                    url=self.target_url,
                    description=f"SSL certificate verification failed: {e}",
                    evidence=str(e),
                    remediation="Obtain a valid certificate from a trusted CA (e.g. Let's Encrypt).",
                )
                return
            self._flag_verification_error(str(e))
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            self.log(f"Could not connect to {self._hostname}:{port} — {e}")
            self.add_finding(
                vuln_type="SSL Connection Failure",
                severity="INFO",
                url=self.target_url,
                description=f"Unable to establish TLS connection on port {port}: {e}",
                evidence=str(e),
                remediation="Ensure TLS is configured and the port is accessible.",
            )
            return

        if cert_dict is None:
            return

        # ── Subject & Issuer ──
        subject = dict(x[0] for x in cert_dict.get("subject", ()))
        issuer = dict(x[0] for x in cert_dict.get("issuer", ()))
        cn = subject.get("commonName", "N/A")
        issuer_cn = issuer.get("commonName", "N/A")
        issuer_org = issuer.get("organizationName", "N/A")
        self.log(f"Subject CN: {cn}")
        self.log(f"Issuer: {issuer_cn} ({issuer_org})")

        # ── Self-signed detection ──
        if subject == issuer:
            self.add_finding(
                vuln_type="Self-Signed Certificate",
                severity="HIGH",
                url=self.target_url,
                description=(
                    "The certificate is self-signed (subject equals issuer). "
                    "Browsers will show a security warning and MITM attacks are easier."
                ),
                evidence=f"Subject={cn}, Issuer={issuer_cn}",
                remediation="Replace with a certificate issued by a trusted Certificate Authority.",
            )

        # ── Validity period ──
        not_before_str: str = cert_dict.get("notBefore", "")
        not_after_str: str = cert_dict.get("notAfter", "")

        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days

                self.log(f"Certificate valid until {not_after_str} ({days_left} days remaining)")

                if days_left < 0:
                    self.add_finding(
                        vuln_type="Expired SSL Certificate",
                        severity="CRITICAL",
                        url=self.target_url,
                        description=(
                            f"The certificate expired on {not_after_str} "
                            f"({abs(days_left)} day(s) ago)."
                        ),
                        evidence=f"notAfter: {not_after_str}",
                        remediation="Renew the certificate immediately.",
                    )
                elif days_left <= 30:
                    self.add_finding(
                        vuln_type="SSL Certificate Expiring Soon",
                        severity="MEDIUM",
                        url=self.target_url,
                        description=(
                            f"The certificate expires in {days_left} day(s) "
                            f"(on {not_after_str}). Renew before expiry."
                        ),
                        evidence=f"notAfter: {not_after_str}, days remaining: {days_left}",
                        remediation="Renew the certificate before it expires.",
                    )
            except ValueError as e:
                self.log(f"Could not parse certificate date: {e}")

        # ── Hostname mismatch ──
        san_list: list[str] = []
        for entry_type, entry_value in cert_dict.get("subjectAltName", ()):
            if entry_type.lower() == "dns":
                san_list.append(entry_value.lower())

        if san_list:
            self.log(f"SANs: {', '.join(san_list)}")
            hostname_lower = self._hostname.lower()
            if not self._hostname_matches(hostname_lower, san_list, cn):
                self.add_finding(
                    vuln_type="Certificate Hostname Mismatch",
                    severity="HIGH",
                    url=self.target_url,
                    description=(
                        f"The hostname '{self._hostname}' does not match "
                        f"the certificate's CN ({cn}) or SANs ({', '.join(san_list)})."
                    ),
                    evidence=f"Hostname: {self._hostname}, CN: {cn}, SANs: {san_list}",
                    remediation="Obtain a certificate that covers this hostname.",
                )
        else:
            # No SANs — check CN only
            if cn.lower().replace("*.", "") not in self._hostname.lower():
                if not self._wildcard_match(self._hostname.lower(), cn.lower()):
                    self.add_finding(
                        vuln_type="Certificate Hostname Mismatch",
                        severity="HIGH",
                        url=self.target_url,
                        description=(
                            f"The hostname '{self._hostname}' does not match "
                            f"the certificate's CN ({cn}). No SANs present."
                        ),
                        evidence=f"Hostname: {self._hostname}, CN: {cn}",
                        remediation="Obtain a certificate that covers this hostname.",
                    )

    def _get_cert_unverified(self, port: int) -> tuple[Optional[dict], Optional[bytes]]:
        """Connect without verification to retrieve cert details."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection(
                (self._hostname, port), timeout=self._CONNECT_TIMEOUT
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=self._hostname) as ssock:
                    return ssock.getpeercert(binary_form=False), ssock.getpeercert(binary_form=True)
        except Exception as e:
            self.log(f"Unverified connection also failed: {e}")
            return None, None

    def _flag_verification_error(self, err_str: str) -> None:
        """Add a finding for a certificate that failed CA verification."""
        err_lower = err_str.lower()
        if "self" in err_lower and "signed" in err_lower:
            return  # Handled separately
        self.add_finding(
            vuln_type="SSL Certificate Verification Failure",
            severity="HIGH",
            url=self.target_url,
            description=f"The certificate failed CA trust verification: {err_str}",
            evidence=err_str,
            remediation="Use a certificate signed by a trusted CA. "
            "If using an internal CA, ensure it is in the system trust store.",
        )

    # ── TLS version probes ───────────────────────────────────────
    def _check_tls_versions(self, port: int) -> None:
        """Probe for support of various TLS protocol versions."""
        # Map: (protocol_constant_or_None, label, should_be_disabled, severity_if_enabled)
        probes: list[tuple[Optional[int], str, bool, str]] = [
            (ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None,
             "TLSv1.0", True, "HIGH"),
            (ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None,
             "TLSv1.1", True, "HIGH"),
            (ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, "PROTOCOL_TLSv1_2") else None,
             "TLSv1.2", False, ""),
            # TLS 1.3 is probed separately
        ]

        for proto_const, label, should_disabled, severity in probes:
            supported = self._probe_tls_protocol(port, proto_const, label)
            if supported and should_disabled:
                self.add_finding(
                    vuln_type=f"Deprecated TLS Version: {label}",
                    severity=severity,
                    url=self.target_url,
                    description=(
                        f"{label} is enabled on the server. This protocol version "
                        "has known vulnerabilities (POODLE, BEAST, etc.) and should be disabled."
                    ),
                    evidence=f"{label} connection succeeded on {self._hostname}:{port}",
                    remediation=f"Disable {label} in your TLS configuration. "
                    "Only enable TLS 1.2 and TLS 1.3.",
                )
            elif not supported and not should_disabled and proto_const is not None:
                self.add_finding(
                    vuln_type=f"TLS Version Not Supported: {label}",
                    severity="MEDIUM",
                    url=self.target_url,
                    description=f"{label} does not appear to be supported by the server.",
                    evidence=f"{label} connection failed on {self._hostname}:{port}",
                    remediation=f"Enable {label} on the server (it is still considered secure).",
                )

        # TLS 1.3 probe via generic context
        tls13_supported = self._probe_tls13(port)
        if tls13_supported:
            self.log("TLS 1.3 is supported (excellent).")
        else:
            self.add_finding(
                vuln_type="TLS 1.3 Not Supported",
                severity="INFO",
                url=self.target_url,
                description=(
                    "TLS 1.3 is not supported. While TLS 1.2 is acceptable, "
                    "TLS 1.3 offers improved security and performance."
                ),
                evidence=f"TLS 1.3 handshake failed on {self._hostname}:{port}",
                remediation="Upgrade your TLS stack to support TLS 1.3.",
            )

    def _probe_tls_protocol(
        self, port: int, proto_const: Optional[int], label: str
    ) -> bool:
        """Try to connect with a specific TLS protocol constant."""
        if proto_const is None:
            self.log(f"{label} constant not available in this Python build — skipping.")
            return False

        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (self._hostname, port), timeout=self._CONNECT_TIMEOUT
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=self._hostname) as ssock:
                    self.log(f"{label} probe succeeded — negotiated {ssock.version()}")
                    return True
        except (ssl.SSLError, OSError, AttributeError):
            self.log(f"{label} probe failed (not supported or disabled).")
            return False

    def _probe_tls13(self, port: int) -> bool:
        """Check TLS 1.3 support using the highest available context."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Restrict to TLS 1.3 only
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection(
                (self._hostname, port), timeout=self._CONNECT_TIMEOUT
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=self._hostname) as ssock:
                    version = ssock.version()
                    self.log(f"TLS 1.3 probe succeeded — {version}")
                    return version is not None and "1.3" in version
        except (ssl.SSLError, OSError, ValueError, AttributeError):
            self.log("TLS 1.3 probe failed.")
            return False

    # ── HTTP → HTTPS redirect ────────────────────────────────────
    def _check_https_redirect(self) -> None:
        """Verify that the HTTP endpoint redirects to HTTPS."""
        http_url = re.sub(r"^https://", "http://", self.target_url, flags=re.IGNORECASE)
        if http_url == self.target_url and self._scheme == "https":
            # Construct an http version
            http_url = self.target_url.replace("https://", "http://", 1)

        self.log(f"Checking HTTP→HTTPS redirect: {http_url}")
        response = make_request(http_url, allow_redirects=False, timeout=10, verify=False)
        if response is None:
            self.log("HTTP endpoint unreachable — cannot test redirect.")
            return

        location = response.headers.get("Location", "")
        if response.status_code in (301, 302, 307, 308) and location.lower().startswith("https://"):
            self.log(f"HTTP redirects to HTTPS: {location}")
        else:
            self.add_finding(
                vuln_type="Missing HTTP→HTTPS Redirect",
                severity="MEDIUM",
                url=http_url,
                description=(
                    "The HTTP endpoint does not redirect to HTTPS. Users who navigate "
                    "to the HTTP URL will receive an unencrypted response."
                ),
                evidence=f"HTTP {response.status_code}, Location: {location or '(none)'}",
                remediation=(
                    "Configure a 301 redirect from HTTP to HTTPS for all paths. "
                    "Apache: Redirect permanent / https://your-domain/. "
                    "Nginx: return 301 https://$host$request_uri;"
                ),
            )

    # ── HTTP-only target ─────────────────────────────────────────
    def _check_http_only(self) -> None:
        """Report when the target URL itself uses plain HTTP."""
        self.add_finding(
            vuln_type="No HTTPS Configured",
            severity="HIGH",
            url=self.target_url,
            description=(
                "The target URL uses plain HTTP. All traffic between the user "
                "and the server is transmitted in clear text and can be intercepted."
            ),
            evidence=f"Scheme: {self._scheme}",
            remediation=(
                "Enable HTTPS with a valid TLS certificate (e.g. Let's Encrypt) "
                "and redirect all HTTP traffic to HTTPS."
            ),
        )

    # ── Hostname matching helpers ────────────────────────────────
    @staticmethod
    def _hostname_matches(hostname: str, san_list: list[str], cn: str) -> bool:
        """Return True if hostname matches any SAN entry or the CN."""
        for san in san_list:
            if SSLScanner._wildcard_match(hostname, san):
                return True
        return SSLScanner._wildcard_match(hostname, cn.lower())

    @staticmethod
    def _wildcard_match(hostname: str, pattern: str) -> bool:
        """Simple wildcard certificate matching (e.g. *.example.com)."""
        if pattern == hostname:
            return True
        if pattern.startswith("*."):
            # *.example.com should match sub.example.com but NOT example.com
            suffix = pattern[2:]
            if hostname.endswith(suffix) and hostname.count(".") >= pattern.count("."):
                return True
        return False
