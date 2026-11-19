# 🛡️ CyberShield — Automated Web Vulnerability Scanner

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity%20%26%20VAPT-red.svg)]()
[![Status](https://img.shields.io/badge/Status-Complete-success.svg)]()

**CyberShield** is an advanced, automated, multi-threaded Web Application Vulnerability Scanner and Security Assessment tool written in Python. It bridges offensive penetration testing and defensive mitigation by detecting critical OWASP Top 10 vulnerabilities, evaluating infrastructure security, and producing high-impact, professional executive and technical reports in HTML and JSON formats.

---

## 📌 Project Overview

Built as a capstone-grade cybersecurity engineering project, CyberShield automates the manual workflows involved in Web Application Penetration Testing (VAPT). Inspired by enterprise scanners and hands-on laboratory testing on environments like DVWA and Metasploitable, it enables security engineers and developers to discover flaws before adversaries can exploit them.

---

## 🚀 Key Features

| Module | Capability & Description |
| :--- | :--- |
| 🕷️ **Intelligent Web Crawler** | Multi-depth BFS recursive crawling, internal link extraction, and HTML form schema mapping. |
| 💉 **SQL Injection (SQLi)** | Multi-vector testing: Error-based (MySQL, PgSQL, MSSQL, Oracle, SQLite), Boolean-based diffing, and Time-based latency analysis. |
| 🎯 **Cross-Site Scripting (XSS)** | Reflected and context-aware payload injection in URL parameters and input forms with unescaped reflection detection. |
| 🔐 **CSRF Detection** | Form audit for missing Anti-CSRF tokens, risky HTTP methods, and missing `SameSite` cookie restrictions. |
| 📁 **Directory & File Bruteforcer** | Concurrent wordlist-based enumeration discovering hidden admin panels, backups, exposed `.git`, and sensitive `.env` files. |
| 🛡️ **HTTP Security Headers** | Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and info disclosure banners (`Server`, `X-Powered-By`). |
| 🔒 **SSL/TLS Configuration** | Validates certificate validity, expiration warnings, hostname mismatch, legacy TLS protocols (TLSv1.0/1.1), and HTTPS enforcement. |
| 🌐 **TCP Port & Service Scanner** | Multi-threaded TCP connect port scanner covering top services with automatic banner grabbing and risk categorization. |
| 📊 **Modern Cyber HTML Report** | High-contrast dark cybersecurity dashboard with severity breakdown, risk rating, collapsible category details, and actionable remediations. |

---

## 🏗️ Architecture & Directory Structure

```text
CyberShield/
├── main.py                     # Central CLI runner & execution engine
├── requirements.txt            # Python dependencies
├── README.md                   # Complete documentation
├── scanner/                    # Security scanning engine modules
│   ├── __init__.py
│   ├── base.py                 # Abstract BaseScanner architecture
│   ├── crawler.py              # Recursive web spider & form extractor
│   ├── sqli_scanner.py         # Advanced SQLi detection engine
│   ├── xss_scanner.py          # Cross-Site Scripting detector
│   ├── csrf_scanner.py         # Cross-Site Request Forgery auditor
│   ├── dir_bruteforce.py       # Multi-threaded path enumerator
│   ├── header_scanner.py       # Security headers & cookie flags check
│   ├── ssl_scanner.py          # SSL/TLS cert & protocol inspector
│   └── port_scanner.py         # TCP connect scanner & banner grabber
├── payloads/                   # Attack dictionaries & wordlists
│   ├── sqli_payloads.txt       # Error, union, boolean, and time-based payloads
│   ├── xss_payloads.txt        # Script, event-handler, and tag-injection vectors
│   └── common_dirs.txt         # Endpoints, admin portals, configs, & backups
├── report/                     # Reporting & visualization
│   ├── __init__.py
│   └── report_generator.py     # Cyber-themed self-contained HTML/JSON generator
└── utils/                      # Helper libraries & terminal output
    ├── __init__.py
    ├── colors.py               # ANSI terminal color scheme & ASCII banners
    └── helpers.py              # Safe HTTP wrapper, wordlist loaders, URL validators
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.8 or higher
- Git (optional)

### Steps

1. **Clone or Navigate to the Project:**
   ```bash
   cd CyberShield
   ```

2. **Install Required Libraries:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Usage & CLI Guide

### 1. Full Comprehensive Scan (Recommended)
Performs crawling, port scanning, header checks, SSL validation, directory bruteforcing, SQLi, XSS, and CSRF checks:
```bash
python3 main.py --url http://testphp.vulnweb.com/ --scan all --output report.html
```

### 2. Specific Vulnerability Scans
You can target individual vectors using comma-separated scan types:
```bash
# Only test for Web Application bugs (SQLi and XSS)
python3 main.py --url http://192.168.1.50/dvwa/ --scan sqli,xss

# Test infrastructure only (Ports, SSL, Security Headers)
python3 main.py --url https://example.com --scan ports,ssl,headers
```

### 3. Fast Targeted Scan (No Crawl)
Skip BFS crawling and run checks strictly against the specified URL:
```bash
python3 main.py --url http://target.local/login.php --no-crawl --scan sqli,csrf
```

### 4. Advanced Options
```bash
python3 main.py --url http://target.local/ \
  --scan dirs,ports \
  --threads 20 \
  --port-range 20-445,8080,3306 \
  --wordlist payloads/common_dirs.txt \
  --verbose \
  --output custom_report.html
```

---

## 📋 Available CLI Flags

| Flag | Argument | Default | Description |
| :--- | :--- | :--- | :--- |
| `--url` | `<URL>` | *Required* | Target website or IP address to assess |
| `--scan` | `<types>` | `all` | Comma-separated list (`all`, `sqli`, `xss`, `csrf`, `dirs`, `headers`, `ssl`, `ports`) |
| `--depth` | `<int>` | `2` | Maximum crawl depth for BFS spidering |
| `--threads` | `<int>` | `10` | Worker threads for concurrent operations |
| `--port-range`| `<range>` | `1-1024`| Port range syntax (e.g., `80,443,8080` or `1-500`) |
| `--wordlist` | `<file>` | `common_dirs.txt` | Custom wordlist path for directory bruteforce |
| `--no-crawl` | — | `False` | Disables crawling and scans single target URL only |
| `--output` | `<file>` | `report.html` | Output path for the interactive HTML security report |
| `--verbose` | — | `False` | Enables detailed debug and execution logs in terminal |

---

## 🛡️ Vulnerability Classifications & Severity Matrix

CyberShield categorizes findings adhering to the **CVSS v3.1** standard:
- 🔴 **CRITICAL**: Remote Code Execution, high-confidence SQL Injection with system access.
- 🟠 **HIGH**: SQL Injection, Sensitive exposed configuration files (`.env`, `.git`), disabled TLS encryption.
- 🟡 **MEDIUM**: Cross-Site Scripting (XSS), missing Anti-CSRF tokens on POST forms, exposed administration routes, sensitive headers (`X-Powered-By`).
- 🟢 **LOW**: Missing HTTP security headers (HSTS, CSP, X-Frame-Options), cookie missing `HttpOnly`/`Secure` flags.
- 🔵 **INFO**: Open standard network ports, server technology identification, general reconnaissance findings.

---

## 📊 Sample Report Preview

The generated report features:
- **Dark Mode Cybersecurity Dashboard** with neon accents.
- **Executive Summary** including overall Risk Score, total scan duration, and crawled assets.
- **Severity Breakdown Visualizer** using custom responsive CSS bars.
- **Interactive Accordion Details** displaying vulnerable URL, injected payload, response proof/evidence, and industry-standard developer remediation guidance.

---

## ⚠️ Legal & Ethical Disclaimer

> [!CAUTION]
> This tool is strictly developed for **educational purposes**, authorized academic projects, and security assessments performed with explicit, written authorization from the system owners. Unauthorized scanning of targets without prior consent is illegal and violates local, state, and federal laws. The author assumes no liability for misuse.

---

## 👤 Author

- **Bharat Verma**
- B.Tech in Computer Science & Engineering (Cyber Security)
- Govt. Engineering College, Ajmer (Bikaner Technical University)
- Roll No: `24EEACY005`
