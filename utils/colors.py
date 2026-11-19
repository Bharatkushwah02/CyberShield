"""
CyberShield - Terminal Color Utilities
========================================
ANSI escape code based terminal coloring and formatting utilities.
Provides color constants, styled message helpers, and ASCII art banner.
"""


# ─────────────────────────────────────────────
# ANSI Color Constants
# ─────────────────────────────────────────────
RED: str = "\033[91m"
GREEN: str = "\033[92m"
YELLOW: str = "\033[93m"
BLUE: str = "\033[94m"
MAGENTA: str = "\033[95m"
CYAN: str = "\033[96m"
WHITE: str = "\033[97m"
BOLD: str = "\033[1m"
DIM: str = "\033[2m"
UNDERLINE: str = "\033[4m"
RESET: str = "\033[0m"

# Severity color mapping
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": RED + BOLD,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": CYAN,
    "INFO": BLUE,
}


# ─────────────────────────────────────────────
# Styled Message Helpers
# ─────────────────────────────────────────────
def success(msg: str) -> None:
    """Print a green success message with [+] prefix."""
    print(f"{GREEN}[+]{RESET} {msg}")


def error(msg: str) -> None:
    """Print a red error message with [-] prefix."""
    print(f"{RED}[-]{RESET} {msg}")


def warning(msg: str) -> None:
    """Print a yellow warning message with [!] prefix."""
    print(f"{YELLOW}[!]{RESET} {msg}")


def info(msg: str) -> None:
    """Print a blue informational message with [*] prefix."""
    print(f"{BLUE}[*]{RESET} {msg}")


def debug(msg: str) -> None:
    """Print a dim debug message with [~] prefix."""
    print(f"{DIM}[~] {msg}{RESET}")


def finding(severity: str, msg: str) -> None:
    """Print a finding message colored by severity level."""
    color = SEVERITY_COLORS.get(severity.upper(), WHITE)
    print(f"  {color}[{severity.upper()}]{RESET} {msg}")


def banner(text: str) -> None:
    """Print text inside a styled banner box."""
    width = max(len(line) for line in text.split("\n")) + 4 if text else 40
    border = f"{CYAN}{'═' * width}{RESET}"
    print(border)
    for line in text.split("\n"):
        padded = line.center(width - 4)
        print(f"{CYAN}║{RESET} {padded} {CYAN}║{RESET}")
    print(border)


def section(title: str) -> None:
    """Print a section header with decorative formatting."""
    line = "─" * 55
    print(f"\n{BOLD}{CYAN}┌{line}┐{RESET}")
    print(f"{BOLD}{CYAN}│{RESET} {BOLD}{WHITE}{title}{RESET}")
    print(f"{BOLD}{CYAN}└{line}┘{RESET}")


def print_banner() -> None:
    """Print the main CyberShield ASCII art banner."""
    art = f"""{CYAN}{BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    ██████╗██╗   ██╗██████╗ ███████╗██████╗                   ║
    ║   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗                 ║
    ║   ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝                 ║
    ║   ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗                 ║
    ║   ╚██████╗   ██║   ██████╔╝███████╗██║  ██║                 ║
    ║    ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝                ║
    ║   ███████╗██╗  ██╗██╗███████╗██╗     ██████╗                 ║
    ║   ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗                ║
    ║   ███████╗███████║██║█████╗  ██║     ██║  ██║                ║
    ║   ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║                ║
    ║   ███████║██║  ██║██║███████╗███████╗██████╔╝                ║
    ║   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝                ║
    ║                                                              ║
    ║         {WHITE}Automated Web Vulnerability Scanner{CYAN}                 ║
    ║                  {DIM}{WHITE}v1.0 — by CyberShield Team{RESET}{CYAN}{BOLD}                ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝{RESET}
"""
    print(art)


def severity_label(severity: str) -> str:
    """Return a colored severity label string for display purposes."""
    color = SEVERITY_COLORS.get(severity.upper(), WHITE)
    return f"{color}{severity.upper()}{RESET}"


def progress(current: int, total: int, prefix: str = "", suffix: str = "") -> None:
    """Print a simple progress indicator on the same line."""
    pct = (current / total * 100) if total > 0 else 0
    bar_len = 30
    filled = int(bar_len * current // total) if total > 0 else 0
    bar = f"{GREEN}{'█' * filled}{DIM}{'░' * (bar_len - filled)}{RESET}"
    print(f"\r  {prefix} [{bar}] {pct:.0f}% ({current}/{total}) {suffix}", end="", flush=True)
    if current >= total:
        print()  # newline when complete
