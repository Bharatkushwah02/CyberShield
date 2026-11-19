"""
CyberShield — Report Generator Module

Generates professional, self-contained HTML vulnerability assessment reports
with a dark cybersecurity-themed design and JSON export capability.
"""

import json
import html
from datetime import datetime
from typing import Any, Dict, List, Optional


class ReportGenerator:
    """Generates beautiful HTML and JSON vulnerability assessment reports.

    Produces a single self-contained HTML file with embedded CSS featuring
    a dark-themed cybersecurity design with neon accents, severity-coded
    color badges, charts, collapsible sections, and a detailed findings table.

    Attributes:
        target_url: The scanned target URL.
        findings: List of finding dictionaries.
        scan_info: Optional scan metadata dictionary.
    """

    # Severity ordering and color mapping
    SEVERITY_ORDER: List[str] = ["critical", "high", "medium", "low", "info"]
    SEVERITY_COLORS: Dict[str, str] = {
        "critical": "#ff3333",
        "high": "#ff3333",
        "medium": "#ff9933",
        "low": "#ffcc00",
        "info": "#3399ff",
    }
    SEVERITY_BG: Dict[str, str] = {
        "critical": "rgba(255,51,51,0.15)",
        "high": "rgba(255,51,51,0.10)",
        "medium": "rgba(255,153,51,0.10)",
        "low": "rgba(255,204,0,0.10)",
        "info": "rgba(51,153,255,0.10)",
    }

    def __init__(
        self,
        target_url: str,
        findings: List[Dict[str, Any]],
        scan_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the ReportGenerator.

        Args:
            target_url: The scanned target URL.
            findings: List of dicts with keys: type, severity, url,
                      description, evidence, remediation.
            scan_info: Optional dict with scan metadata containing keys like
                       start_time, end_time, scanners_used, urls_crawled,
                       forms_found.
        """
        self.target_url: str = target_url
        self.findings: List[Dict[str, Any]] = findings
        self.scan_info: Dict[str, Any] = scan_info or {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _severity_counts(self) -> Dict[str, int]:
        """Count findings by severity level.

        Returns:
            Dictionary mapping severity names to their counts.
        """
        counts: Dict[str, int] = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1
        return counts

    def _overall_risk(self) -> str:
        """Determine the overall risk rating based on findings.

        Returns:
            String risk rating label.
        """
        counts = self._severity_counts()
        if counts["critical"] > 0:
            return "CRITICAL"
        if counts["high"] > 0:
            return "HIGH"
        if counts["medium"] > 0:
            return "MEDIUM"
        if counts["low"] > 0:
            return "LOW"
        if counts["info"] > 0:
            return "INFORMATIONAL"
        return "NONE"

    def _risk_color(self) -> str:
        """Get the color associated with the overall risk rating.

        Returns:
            CSS hex color string.
        """
        mapping = {
            "CRITICAL": "#ff3333",
            "HIGH": "#ff3333",
            "MEDIUM": "#ff9933",
            "LOW": "#ffcc00",
            "INFORMATIONAL": "#3399ff",
            "NONE": "#00ff41",
        }
        return mapping.get(self._overall_risk(), "#00ff41")

    def _group_by_type(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by their vulnerability type.

        Returns:
            Dictionary mapping type names to lists of findings.
        """
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for f in self.findings:
            ftype = f.get("type", "Unknown")
            groups.setdefault(ftype, []).append(f)
        return groups

    @staticmethod
    def _esc(text: Any) -> str:
        """HTML-escape a string safely.

        Args:
            text: Value to escape.

        Returns:
            HTML-safe string.
        """
        return html.escape(str(text)) if text else ""

    # ------------------------------------------------------------------
    # CSS
    # ------------------------------------------------------------------

    def _build_css(self) -> str:
        """Build the complete embedded CSS stylesheet.

        Returns:
            CSS string.
        """
        return """
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #0f1117;
            --bg-card: #131620;
            --bg-card-hover: #181c28;
            --border: #1e2233;
            --border-glow: #00ff4122;
            --text-primary: #e0e0e8;
            --text-secondary: #8890a0;
            --accent-green: #00ff41;
            --accent-cyan: #00d4ff;
            --severity-critical: #ff3333;
            --severity-high: #ff3333;
            --severity-medium: #ff9933;
            --severity-low: #ffcc00;
            --severity-info: #3399ff;
        }
        *, *::before, *::after { box-sizing: border-box; margin:0; padding:0; }
        html { scroll-behavior: smooth; }
        body {
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Segoe UI', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.7;
            min-height: 100vh;
        }
        .container { max-width: 1140px; margin: 0 auto; padding: 0 24px; }

        /* ---- Header ---- */
        .report-header {
            text-align: center;
            padding: 60px 20px 44px;
            background: linear-gradient(180deg, #0d1020 0%, var(--bg-primary) 100%);
            border-bottom: 1px solid var(--border);
            position: relative;
            overflow: hidden;
        }
        .report-header::before {
            content: '';
            position: absolute; inset: 0;
            background: radial-gradient(ellipse at 50% 0%, rgba(0,255,65,0.06) 0%, transparent 70%);
            pointer-events: none;
        }
        .logo {
            font-family: 'Courier New', 'Fira Code', monospace;
            font-size: 3rem;
            font-weight: 900;
            color: var(--accent-green);
            letter-spacing: 4px;
            text-shadow: 0 0 30px rgba(0,255,65,0.35), 0 0 60px rgba(0,255,65,0.10);
            margin-bottom: 6px;
        }
        .logo .shield-icon { font-style: normal; }
        .subtitle {
            font-size: 1.15rem;
            color: var(--text-secondary);
            font-weight: 400;
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-bottom: 14px;
        }
        .scan-date {
            font-size: 0.9rem;
            color: var(--accent-cyan);
            font-family: 'Courier New', monospace;
        }

        /* ---- Cards ---- */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 28px 32px;
            margin-bottom: 28px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.25), 0 0 1px var(--border-glow);
            transition: border-color 0.3s;
        }
        .card:hover { border-color: #00ff4133; }
        .card-title {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--accent-green);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card-title .icon { font-size: 1.3rem; }
        .section-heading {
            font-size: 1.6rem;
            font-weight: 700;
            color: var(--accent-green);
            margin: 48px 0 24px;
            padding-bottom: 10px;
            border-bottom: 2px solid #00ff4122;
            letter-spacing: 1px;
        }

        /* ---- Executive Summary ---- */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .summary-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px 20px;
        }
        .summary-item .label {
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }
        .summary-item .value {
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--text-primary);
            word-break: break-all;
        }
        .severity-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 8px;
        }
        .severity-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 700;
            border: 1px solid;
        }
        .risk-rating {
            display: inline-block;
            padding: 6px 22px;
            border-radius: 6px;
            font-weight: 800;
            font-size: 1rem;
            letter-spacing: 2px;
            text-transform: uppercase;
        }

        /* ---- Chart ---- */
        .chart-container { margin: 20px 0; }
        .chart-bar-row {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
            gap: 12px;
        }
        .chart-label {
            width: 90px;
            text-align: right;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .chart-bar-track {
            flex: 1;
            background: var(--bg-secondary);
            border-radius: 6px;
            height: 30px;
            overflow: hidden;
            border: 1px solid var(--border);
        }
        .chart-bar-fill {
            height: 100%;
            border-radius: 6px;
            display: flex;
            align-items: center;
            padding-left: 12px;
            font-size: 0.8rem;
            font-weight: 700;
            color: #fff;
            min-width: fit-content;
            transition: width 0.8s ease;
        }
        .chart-count {
            width: 36px;
            text-align: center;
            font-weight: 700;
            font-size: 0.95rem;
        }

        /* ---- Findings ---- */
        details.category-section {
            margin-bottom: 16px;
        }
        details.category-section > summary {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 22px;
            cursor: pointer;
            font-size: 1.05rem;
            font-weight: 600;
            color: var(--accent-cyan);
            list-style: none;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s, border-color 0.2s;
        }
        details.category-section > summary::-webkit-details-marker { display: none; }
        details.category-section > summary::after {
            content: '▸';
            font-size: 1.1rem;
            color: var(--accent-green);
            transition: transform 0.25s;
        }
        details.category-section[open] > summary::after { transform: rotate(90deg); }
        details.category-section > summary:hover {
            background: var(--bg-card-hover);
            border-color: var(--accent-cyan);
        }
        details.category-section > .category-body {
            padding: 16px 8px 4px;
        }
        .finding-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-left: 4px solid var(--accent-green);
            border-radius: 8px;
            padding: 22px 26px;
            margin-bottom: 16px;
            transition: border-color 0.2s;
        }
        .finding-card:hover { border-color: #00ff4144; }
        .finding-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
            flex-wrap: wrap;
        }
        .finding-type {
            font-size: 1.05rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        .finding-url {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            color: var(--accent-cyan);
            background: var(--bg-secondary);
            padding: 4px 12px;
            border-radius: 4px;
            word-break: break-all;
            margin-top: 4px;
        }
        .finding-desc {
            color: var(--text-secondary);
            font-size: 0.95rem;
            margin: 10px 0;
            line-height: 1.6;
        }
        .evidence-block {
            background: #0c0e16;
            border: 1px solid #1a1e2e;
            border-radius: 6px;
            padding: 14px 18px;
            font-family: 'Courier New', 'Fira Code', monospace;
            font-size: 0.84rem;
            color: #c8d0e0;
            overflow-x: auto;
            margin: 10px 0;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .remediation-box {
            background: rgba(0,212,255,0.06);
            border: 1px solid rgba(0,212,255,0.18);
            border-left: 4px solid var(--accent-cyan);
            border-radius: 6px;
            padding: 14px 18px;
            margin-top: 10px;
            font-size: 0.92rem;
            color: #b8c8d8;
        }
        .remediation-box strong { color: var(--accent-cyan); }

        /* ---- Table ---- */
        .findings-table-wrapper { overflow-x: auto; }
        table.findings-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            font-size: 0.9rem;
        }
        table.findings-table thead th {
            background: var(--bg-secondary);
            color: var(--accent-green);
            padding: 14px 16px;
            text-align: left;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.78rem;
            border-bottom: 2px solid var(--accent-green);
            position: sticky;
            top: 0;
        }
        table.findings-table tbody tr {
            transition: background 0.15s;
        }
        table.findings-table tbody tr:nth-child(even) { background: var(--bg-secondary); }
        table.findings-table tbody tr:hover { background: var(--bg-card-hover); }
        table.findings-table tbody td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
            color: var(--text-primary);
        }
        table.findings-table tbody td:first-child {
            font-weight: 700;
            color: var(--text-secondary);
            width: 40px;
            text-align: center;
        }
        table.findings-table tbody td.sev-cell {
            border-left: 4px solid;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
        }
        table.findings-table tbody td.url-cell {
            font-family: 'Courier New', monospace;
            font-size: 0.82rem;
            color: var(--accent-cyan);
            word-break: break-all;
            max-width: 280px;
        }
        table.findings-table tbody td.desc-cell {
            max-width: 340px;
            color: var(--text-secondary);
        }

        /* ---- Footer ---- */
        .report-footer {
            text-align: center;
            padding: 40px 20px 48px;
            border-top: 1px solid var(--border);
            margin-top: 60px;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }
        .report-footer .brand {
            color: var(--accent-green);
            font-weight: 700;
            font-family: 'Courier New', monospace;
        }
        .report-footer .disclaimer {
            margin-top: 16px;
            font-size: 0.78rem;
            color: #555;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }

        /* ---- Responsive ---- */
        @media (max-width: 640px) {
            .logo { font-size: 2rem; }
            .summary-grid { grid-template-columns: 1fr; }
            .card { padding: 18px 16px; }
        }
        """

    # ------------------------------------------------------------------
    # HTML building blocks
    # ------------------------------------------------------------------

    def _build_header(self) -> str:
        """Build the report header section.

        Returns:
            HTML string for the header.
        """
        scan_date = self.scan_info.get(
            "start_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        return f"""
        <header class="report-header">
            <div class="logo"><span class="shield-icon">🛡️</span> CYBERSHIELD</div>
            <div class="subtitle">Vulnerability Assessment Report</div>
            <div class="scan-date">Scan Date: {self._esc(scan_date)}</div>
        </header>"""

    def _build_executive_summary(self) -> str:
        """Build the executive summary card.

        Returns:
            HTML string for the executive summary section.
        """
        counts = self._severity_counts()
        total = sum(counts.values())
        risk = self._overall_risk()
        risk_color = self._risk_color()
        scan_date = self.scan_info.get(
            "start_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        end_time = self.scan_info.get("end_time", "N/A")
        scanners = ", ".join(self.scan_info.get("scanners_used", ["All"]))
        urls_crawled = self.scan_info.get("urls_crawled", "N/A")
        forms_found = self.scan_info.get("forms_found", "N/A")

        badges_html = ""
        for sev in self.SEVERITY_ORDER:
            color = self.SEVERITY_COLORS[sev]
            count = counts[sev]
            badges_html += (
                f'<span class="severity-badge" '
                f'style="color:{color}; border-color:{color}33; background:{self.SEVERITY_BG[sev]}">'
                f"{sev.upper()}: {count}</span>\n"
            )

        return f"""
        <div class="container">
            <h2 class="section-heading">📋 Executive Summary</h2>
            <div class="card">
                <div class="summary-grid">
                    <div class="summary-item">
                        <div class="label">Target</div>
                        <div class="value" style="color:var(--accent-cyan);">{self._esc(self.target_url)}</div>
                    </div>
                    <div class="summary-item">
                        <div class="label">Scan Started</div>
                        <div class="value">{self._esc(scan_date)}</div>
                    </div>
                    <div class="summary-item">
                        <div class="label">Scan Ended</div>
                        <div class="value">{self._esc(end_time)}</div>
                    </div>
                    <div class="summary-item">
                        <div class="label">Total Findings</div>
                        <div class="value" style="color:var(--accent-green); font-size:1.5rem;">{total}</div>
                    </div>
                    <div class="summary-item">
                        <div class="label">URLs Crawled</div>
                        <div class="value">{self._esc(str(urls_crawled))}</div>
                    </div>
                    <div class="summary-item">
                        <div class="label">Forms Found</div>
                        <div class="value">{self._esc(str(forms_found))}</div>
                    </div>
                    <div class="summary-item">
                        <div class="label">Scanners Used</div>
                        <div class="value" style="font-size:0.95rem;">{self._esc(scanners)}</div>
                    </div>
                    <div class="summary-item">
                        <div class="label">Risk Rating</div>
                        <div class="value">
                            <span class="risk-rating" style="background:{risk_color}22; color:{risk_color}; border:1px solid {risk_color}44;">{risk}</span>
                        </div>
                    </div>
                </div>
                <div style="margin-top:16px;">
                    <div class="label" style="font-size:0.78rem; text-transform:uppercase; letter-spacing:1.5px; color:var(--text-secondary); margin-bottom:8px;">Severity Breakdown</div>
                    <div class="severity-badges">
                        {badges_html}
                    </div>
                </div>
            </div>
        </div>"""

    def _build_chart(self) -> str:
        """Build the severity distribution chart section.

        Returns:
            HTML string for the CSS-only bar chart.
        """
        counts = self._severity_counts()
        total = sum(counts.values())
        if total == 0:
            return ""

        max_count = max(counts.values()) if counts.values() else 1
        rows = ""
        for sev in self.SEVERITY_ORDER:
            count = counts[sev]
            color = self.SEVERITY_COLORS[sev]
            pct = (count / max_count * 100) if max_count > 0 else 0
            bar_width = max(pct, 2) if count > 0 else 0
            rows += f"""
            <div class="chart-bar-row">
                <span class="chart-label" style="color:{color};">{sev.upper()}</span>
                <div class="chart-bar-track">
                    <div class="chart-bar-fill" style="width:{bar_width}%; background: linear-gradient(90deg, {color}cc, {color}88);">
                        {count if count > 0 else ''}
                    </div>
                </div>
                <span class="chart-count" style="color:{color};">{count}</span>
            </div>"""

        return f"""
        <div class="container">
            <h2 class="section-heading">📊 Severity Distribution</h2>
            <div class="card">
                <div class="chart-container">
                    {rows}
                </div>
            </div>
        </div>"""

    def _build_findings_by_category(self) -> str:
        """Build the findings-by-category collapsible sections.

        Returns:
            HTML string for grouped findings.
        """
        groups = self._group_by_type()
        if not groups:
            return ""

        sections = ""
        for ftype, items in groups.items():
            # Sort items by severity
            items_sorted = sorted(
                items,
                key=lambda x: self.SEVERITY_ORDER.index(
                    x.get("severity", "info").lower()
                )
                if x.get("severity", "info").lower() in self.SEVERITY_ORDER
                else 99,
            )

            cards = ""
            for finding in items_sorted:
                sev = finding.get("severity", "info").lower()
                sev_color = self.SEVERITY_COLORS.get(sev, "#3399ff")
                cards += self._build_finding_card(finding, sev, sev_color)

            count = len(items)
            sections += f"""
            <details class="category-section">
                <summary>
                    <span>{self._esc(ftype)} <span style="color:var(--text-secondary); font-weight:400;">({count} finding{'s' if count != 1 else ''})</span></span>
                </summary>
                <div class="category-body">
                    {cards}
                </div>
            </details>"""

        return f"""
        <div class="container">
            <h2 class="section-heading">🔍 Findings by Category</h2>
            {sections}
        </div>"""

    def _build_finding_card(
        self, finding: Dict[str, Any], sev: str, sev_color: str
    ) -> str:
        """Build an individual finding card.

        Args:
            finding: Finding dictionary.
            sev: Normalized severity string.
            sev_color: CSS color for the severity.

        Returns:
            HTML string for a single finding card.
        """
        evidence = finding.get("evidence", "")
        remediation = finding.get("remediation", "")

        evidence_html = ""
        if evidence:
            evidence_html = f"""
            <div style="margin-top:6px;">
                <strong style="color:var(--text-secondary); font-size:0.8rem; text-transform:uppercase; letter-spacing:1px;">Evidence</strong>
                <div class="evidence-block">{self._esc(evidence)}</div>
            </div>"""

        remediation_html = ""
        if remediation:
            remediation_html = f"""
            <div class="remediation-box">
                <strong>🛠 Remediation:</strong> {self._esc(remediation)}
            </div>"""

        return f"""
            <div class="finding-card" style="border-left-color:{sev_color};">
                <div class="finding-header">
                    <span class="severity-badge" style="color:{sev_color}; border-color:{sev_color}33; background:{self.SEVERITY_BG.get(sev, 'transparent')};">{sev.upper()}</span>
                    <span class="finding-type">{self._esc(finding.get('type', 'Unknown'))}</span>
                </div>
                <div class="finding-url">🔗 {self._esc(finding.get('url', 'N/A'))}</div>
                <div class="finding-desc">{self._esc(finding.get('description', ''))}</div>
                {evidence_html}
                {remediation_html}
            </div>"""

    def _build_findings_table(self) -> str:
        """Build the detailed findings table section.

        Returns:
            HTML string for the findings table.
        """
        if not self.findings:
            return ""

        rows = ""
        for idx, finding in enumerate(self.findings, 1):
            sev = finding.get("severity", "info").lower()
            sev_color = self.SEVERITY_COLORS.get(sev, "#3399ff")
            rows += f"""
            <tr>
                <td>{idx}</td>
                <td class="sev-cell" style="border-left-color:{sev_color}; color:{sev_color};">{sev.upper()}</td>
                <td>{self._esc(finding.get('type', 'Unknown'))}</td>
                <td class="url-cell">{self._esc(finding.get('url', 'N/A'))}</td>
                <td class="desc-cell">{self._esc(finding.get('description', ''))}</td>
            </tr>"""

        return f"""
        <div class="container">
            <h2 class="section-heading">📝 Detailed Findings</h2>
            <div class="card">
                <div class="findings-table-wrapper">
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Severity</th>
                                <th>Type</th>
                                <th>URL</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>"""

    def _build_footer(self) -> str:
        """Build the report footer section.

        Returns:
            HTML string for the footer.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"""
        <footer class="report-footer">
            <div>
                Generated by <span class="brand">CyberShield v1.0</span> &mdash; Automated Web Vulnerability Scanner
            </div>
            <div style="margin-top:6px; color:var(--accent-cyan); font-family:'Courier New',monospace; font-size:0.82rem;">
                {timestamp}
            </div>
            <div class="disclaimer">
                ⚠️ DISCLAIMER: This report is generated by an automated tool and is intended for authorized security
                assessments only. Findings should be verified manually. The authors are not responsible for any
                misuse of this tool or the information contained in this report. Always obtain proper authorization
                before conducting security testing.
            </div>
        </footer>"""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, output_path: str) -> str:
        """Generate the full HTML report and write it to disk.

        Produces a single self-contained HTML file with all CSS embedded
        inline. No external dependencies are required.

        Args:
            output_path: File path where the HTML report will be saved.

        Returns:
            The absolute path of the written report file.

        Raises:
            OSError: If the file cannot be written.
        """
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberShield — Vulnerability Assessment Report</title>
    <style>{self._build_css()}</style>
</head>
<body>
    {self._build_header()}
    {self._build_executive_summary()}
    {self._build_chart()}
    {self._build_findings_by_category()}
    {self._build_findings_table()}
    {self._build_footer()}
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

        return output_path

    def generate_json(self, output_path: str) -> str:
        """Export findings as a structured JSON report.

        Args:
            output_path: File path where the JSON report will be saved.

        Returns:
            The absolute path of the written JSON file.

        Raises:
            OSError: If the file cannot be written.
        """
        counts = self._severity_counts()
        report_data: Dict[str, Any] = {
            "report_metadata": {
                "tool": "CyberShield",
                "version": "1.0",
                "generated_at": datetime.now().isoformat(),
                "target_url": self.target_url,
            },
            "scan_info": self.scan_info,
            "summary": {
                "total_findings": len(self.findings),
                "risk_rating": self._overall_risk(),
                "severity_counts": counts,
            },
            "findings": self.findings,
        }

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=2, default=str)

        return output_path
