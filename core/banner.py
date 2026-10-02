# core/banner.py
# BlackHunter Pro - Banner Module
# ASCII art banners and visual elements

import os
import sys
import time
import random


# =============================================
# COLORS
# =============================================

class Colors:
    """ANSI color codes"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    RESET = '\033[0m'


C = Colors


# =============================================
# BANNERS
# =============================================

BLACKHUNTER_BANNER = f"""
{C.RED}   ██████╗ ██╗      █████╗  ██████╗██╗  ██╗
{C.RED}   ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝
{C.RED}   ██████╔╝██║     ███████║██║     █████╔╝ 
{C.RED}   ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ 
{C.RED}   ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗
{C.RED}   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{C.RED}   
{C.RED}   ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
{C.RED}   ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
{C.RED}   ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
{C.RED}   ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
{C.RED}   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
{C.RED}   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RESET}
{C.YELLOW}                P R O   v1.0
{C.CYAN}      Academic Penetration Testing Tool
{C.GREEN}      Isolated Lab Environment Only
{C.RESET}
"""

SMALL_BANNER = f"""
{C.RED}╔═══════════════════════════════════════════════════════╗
{C.RED}║{C.YELLOW}          🎯  B L A C K H U N T E R  🎯              {C.RED}║
{C.RED}║{C.CYAN}         Academic Penetration Testing Tool            {C.RED}║
{C.RED}║{C.GREEN}              v1.0.0  |  Termux Edition               {C.RED}║
{C.RED}╚═══════════════════════════════════════════════════════╝{C.RESET}
"""

MINI_BANNER = f"{C.RED}[🎯 BlackHunter]{C.RESET}"

TINY_BANNER = f"{C.RED}BH{C.RESET}"


# =============================================
# FUNCTIONS - BASIC
# =============================================

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def get_terminal_width():
    """Get terminal width"""
    try:
        return os.get_terminal_size().columns
    except:
        return 80


def get_terminal_height():
    """Get terminal height"""
    try:
        return os.get_terminal_size().lines
    except:
        return 24


def center_text(text, width=None):
    """Center text in terminal"""
    if width is None:
        width = get_terminal_width()

    # Remove ANSI codes for length calculation
    import re
    clean_text = re.sub(r'\033\[[0-9;]*m', '', text)
    padding = max(0, (width - len(clean_text)) // 2)

    return ' ' * padding + text


# =============================================
# FUNCTIONS - MAIN BANNERS
# =============================================

def show_banner(clear=True):
    """Show main banner"""
    if clear:
        clear_screen()
    print(BLACKHUNTER_BANNER)


def show_small_banner():
    """Show small banner"""
    print(SMALL_BANNER)


def show_mini_banner():
    """Show mini banner"""
    print(MINI_BANNER)


def show_tiny_banner():
    """Show tiny banner"""
    print(TINY_BANNER)


def show_completion_banner():
    """Show completion banner"""
    print(f"""
{C.GREEN}╔═══════════════════════════════════════════════════════╗
{C.GREEN}║{C.WHITE}          ✓ SCAN COMPLETED SUCCESSFULLY              {C.GREEN}║
{C.GREEN}╚═══════════════════════════════════════════════════════╝{C.RESET}
""")


def show_error_banner():
    """Show error banner"""
    print(f"""
{C.RED}╔═══════════════════════════════════════════════════════╗
{C.RED}║{C.WHITE}          ✗ SCAN FAILED                              {C.RED}║
{C.RED}╚═══════════════════════════════════════════════════════╝{C.RESET}
""")


# =============================================
# FUNCTIONS - LOADING & PROGRESS
# =============================================

def show_loading_banner(message="Loading", duration=2):
    """Show loading message with spinner"""
    spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

    iterations = int(duration * 10)
    for i in range(iterations):
        sys.stdout.write(f'\r{C.CYAN}{spinner[i % len(spinner)]}{C.RESET} {message}...')
        sys.stdout.flush()
        time.sleep(0.1)

    sys.stdout.write(f'\r{C.GREEN}✓{C.RESET} {message}... Done!{" " * 30}\n')
    sys.stdout.flush()


def show_progress_bar(current, total, prefix="Progress", length=40, show_eta=False):
    """Show progress bar"""
    percent = current / total if total > 0 else 0
    filled = int(length * percent)
    bar = '█' * filled + '░' * (length - filled)

    output = f'\r{C.CYAN}{prefix}:{C.RESET} |{C.GREEN}{bar}{C.RESET}| {percent*100:.1f}%'

    if show_eta and current > 0:
        eta = (total - current) * 0.1
        output += f' ETA: {eta:.0f}s'

    sys.stdout.write(output)
    sys.stdout.flush()

    if current == total:
        sys.stdout.write('\n')


# =============================================
# FUNCTIONS - SECTION HEADERS
# =============================================

def show_phase_header(phase_num, phase_name, total_phases=6):
    """Show phase header"""
    print(f"""
{C.MAGENTA}═══════════════════════════════════════════════════════
{C.WHITE}  PHASE {phase_num}/{total_phases}: {phase_name.upper()}
{C.MAGENTA}═══════════════════════════════════════════════════════{C.RESET}
""")


def show_section_header(title, width=60):
    """Show section header"""
    print(f"\n{C.CYAN}{'─' * width}{C.RESET}")
    print(f"{C.WHITE}  {title}{C.RESET}")
    print(f"{C.CYAN}{'─' * width}{C.RESET}\n")


def show_subsection_header(title):
    """Show subsection header"""
    print(f"\n{C.YELLOW}▶ {title}{C.RESET}")


# =============================================
# FUNCTIONS - ALERTS
# =============================================

def show_vuln_alert(vuln_type, severity, url):
    """Show vulnerability alert"""
    severity_colors = {
        'CRITICAL': C.RED,
        'HIGH': C.YELLOW,
        'MEDIUM': C.CYAN,
        'LOW': C.GREEN,
    }

    color = severity_colors.get(severity.upper(), C.WHITE)

    print(f"""
{color}  ┌─────────────────────────────────────────────────┐
{color}  │ {C.WHITE}[!] VULNERABILITY DETECTED{C.RESET}
{color}  ├─────────────────────────────────────────────────┤
{color}  │ {C.WHITE}Type:{C.RESET}     {vuln_type}
{color}  │ {C.WHITE}Severity:{C.RESET} {color}{severity.upper()}{C.RESET}
{color}  │ {C.WHITE}URL:{C.RESET}      {url[:45]}
{color}  └─────────────────────────────────────────────────┘{C.RESET}
""")


def show_success(message):
    """Show success message"""
    print(f"{C.GREEN}  [✓] {message}{C.RESET}")


def show_error(message):
    """Show error message"""
    print(f"{C.RED}  [✗] {message}{C.RESET}")


def show_warning(message):
    """Show warning message"""
    print(f"{C.YELLOW}  [!] {message}{C.RESET}")


def show_info(message):
    """Show info message"""
    print(f"{C.CYAN}  [*] {message}{C.RESET}")


# =============================================
# FUNCTIONS - SUMMARY BOXES
# =============================================

def show_scan_summary(target, duration, vulns_count, report_path=None):
    """Show scan summary"""
    report_line = f"  Report:       {report_path[:30]:<30}" if report_path else ""

    print(f"""
{C.CYAN}╔═══════════════════════════════════════════════════════╗
{C.CYAN}║{C.WHITE}                 SCAN SUMMARY                        {C.CYAN}║
{C.CYAN}╠═══════════════════════════════════════════════════════╣
{C.CYAN}║{C.GREEN}  Target:       {C.WHITE}{target[:35]:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Duration:     {C.WHITE}{str(duration):<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Vulnerabilities: {C.RED}{str(vulns_count):<31}{C.CYAN}║
{report_line}
{C.CYAN}╚═══════════════════════════════════════════════════════╝{C.RESET}
""")


def show_info_box(title, content):
    """Show information box"""
    print(f"""
{C.CYAN}╔═══════════════════════════════════════════════════════╗
{C.CYAN}║{C.WHITE}  {title:<51}{C.CYAN}║
{C.CYAN}╠═══════════════════════════════════════════════════════╣
{C.CYAN}║{C.RESET}  {content}
{C.CYAN}╚═══════════════════════════════════════════════════════╝{C.RESET}
""")


# =============================================
# FUNCTIONS - ANIMATIONS
# =============================================

def animate_text(text, delay=0.03, color=C.GREEN):
    """Animate text typing"""
    for char in text:
        sys.stdout.write(f'{color}{char}{C.RESET}')
        sys.stdout.flush()
        time.sleep(delay)
    print()


def show_matrix_effect(duration=1.5):
    """Show matrix effect"""
    chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノ"
    width = get_terminal_width()

    start = time.time()
    while time.time() - start < duration:
        line = ''.join(random.choice(chars) for _ in range(width))
        print(f"{C.GREEN}{line}{C.RESET}")
        time.sleep(0.05)


def show_skull():
    """Show ASCII skull"""
    print(f"""
{C.RED}        ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
{C.RED}      ████████████████████████████████████
{C.RED}    ████████████████████████████████████████
{C.RED}   ██████████████████████████████████████████
{C.RED}   ████████████▀▀████████████▀▀████████████
{C.RED}   ████████████  ████████████  ████████████
{C.RED}   ████████████▄▄████████████▄▄████████████
{C.RED}   ██████████████████████████████████████████
{C.RED}   ██████████████████████████████████████████
{C.RED}    ████████████████████████████████████████
{C.RED}      ████████████████████████████████████
{C.RED}        ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
{C.RESET}""")


def show_target_icon():
    """Show target icon"""
    print(f"""
{C.RED}           ╔═══════════════╗
{C.RED}           ║       ●       ║
{C.RED}           ║     ●   ●     ║
{C.RED}           ║   ●       ●   ║
{C.RED}           ║ ●     ●     ● ║
{C.RED}           ║   ●       ●   ║
{C.RED}           ║     ●   ●     ║
{C.RED}           ║       ●       ║
{C.RED}           ╚═══════════════╝
{C.RESET}""")


# =============================================
# FUNCTIONS - BADGES
# =============================================

def show_severity_badge(severity):
    """Show severity badge"""
    colors = {
        'CRITICAL': f"{C.RED}▓▓ CRITICAL ▓▓{C.RESET}",
        'HIGH': f"{C.YELLOW}▓▓ HIGH ▓▓{C.RESET}",
        'MEDIUM': f"{C.CYAN}▓▓ MEDIUM ▓▓{C.RESET}",
        'LOW': f"{C.GREEN}▓▓ LOW ▓▓{C.RESET}",
        'INFO': f"{C.WHITE}▓▓ INFO ▓▓{C.RESET}",
    }
    return colors.get(severity.upper(), f"{C.WHITE}▓▓ UNKNOWN ▓▓{C.RESET}")


def show_status_badge(status):
    """Show status badge"""
    badges = {
        'success': f"{C.GREEN}[✓ SUCCESS]{C.RESET}",
        'failed': f"{C.RED}[✗ FAILED]{C.RESET}",
        'running': f"{C.YELLOW}[◌ RUNNING]{C.RESET}",
        'pending': f"{C.CYAN}[◯ PENDING]{C.RESET}",
        'skipped': f"{C.DIM}[─ SKIPPED]{C.RESET}",
    }
    return badges.get(status.lower(), f"{C.WHITE}[? UNKNOWN]{C.RESET}")


# =============================================
# EXPORTS
# =============================================

__all__ = [
    # Colors
    "Colors",
    "C",

    # Banners
    "BLACKHUNTER_BANNER",
    "SMALL_BANNER",
    "MINI_BANNER",
    "TINY_BANNER",

    # Functions - Basic
    "clear_screen",
    "get_terminal_width",
    "get_terminal_height",
    "center_text",

    # Functions - Banners
    "show_banner",
    "show_small_banner",
    "show_mini_banner",
    "show_tiny_banner",
    "show_completion_banner",
    "show_error_banner",

    # Functions - Loading
    "show_loading_banner",
    "show_progress_bar",

    # Functions - Sections
    "show_phase_header",
    "show_section_header",
    "show_subsection_header",

    # Functions - Alerts
    "show_vuln_alert",
    "show_success",
    "show_error",
    "show_warning",
    "show_info",

    # Functions - Summary
    "show_scan_summary",
    "show_info_box",

    # Functions - Animations
    "animate_text",
    "show_matrix_effect",
    "show_skull",
    "show_target_icon",

    # Functions - Badges
    "show_severity_badge",
    "show_status_badge",
]