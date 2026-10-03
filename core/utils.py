# core/utils.py
# BlackHunter Pro - Utility Functions
# Helper functions for the entire tool

import os
import re
import sys
import time
import json
import socket
import random
import string
import hashlib
import subprocess
from datetime import datetime
from urllib.parse import urlparse, urljoin

# Force UTF-8 console output on non-UTF-8 terminals (e.g. cp1252)
if (sys.stdout is not None and hasattr(sys.stdout, 'reconfigure')
        and getattr(sys.stdout, 'encoding', None)
        and sys.stdout.encoding.lower() not in ('utf-8', 'utf8')):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


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
    RESET = '\033[0m'


C = Colors


# =============================================
# LOGGING
# =============================================

def log_info(message):
    """Log info message"""
    print(f"{C.CYAN}[*]{C.RESET} {message}")


def log_ok(message):
    """Log success message"""
    print(f"{C.GREEN}[✓]{C.RESET} {message}")


def log_warn(message):
    """Log warning message"""
    print(f"{C.YELLOW}[!]{C.RESET} {message}")


def log_error(message):
    """Log error message"""
    print(f"{C.RED}[✗]{C.RESET} {message}")


def log_debug(message):
    """Log debug message"""
    print(f"{C.DIM}[D]{C.RESET} {message}")


def log_step(message):
    """Log step header"""
    print(f"\n{C.MAGENTA}▶ {message}{C.RESET}")


def log_vuln(vuln_type, severity, url):
    """Log vulnerability found"""
    sev_colors = {
        "CRITICAL": C.RED,
        "HIGH": C.YELLOW,
        "MEDIUM": C.CYAN,
        "LOW": C.GREEN,
    }
    color = sev_colors.get(severity.upper(), C.WHITE)
    print(f"{color}[!] {vuln_type}{C.RESET} [{severity}] - {url}")


# =============================================
# PRINTING HELPERS
# =============================================

def print_separator(char="─", length=60, color=None):
    """Print separator line"""
    color = color or C.CYAN
    print(f"{color}{char * length}{C.RESET}")


def print_header(title, char="═", length=60):
    """Print header"""
    print()
    print_separator(char, length, C.MAGENTA)
    print(f"{C.WHITE}{title.center(length)}{C.RESET}")
    print_separator(char, length, C.MAGENTA)
    print()


def print_table(headers, rows, col_widths=None):
    """Print simple table"""
    if not headers or not rows:
        return

    # Calculate column widths
    if col_widths is None:
        col_widths = []
        for i, header in enumerate(headers):
            max_width = len(header)
            for row in rows:
                if i < len(row):
                    max_width = max(max_width, len(str(row[i])))
            col_widths.append(min(max_width + 2, 40))

    # Print headers
    header_line = "│".join(h.center(w) for h, w in zip(headers, col_widths))
    print(f"{C.CYAN}┌{'┬'.join('─' * w for w in col_widths)}┐{C.RESET}")
    print(f"{C.CYAN}│{C.WHITE}{header_line}{C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}├{'┼'.join('─' * w for w in col_widths)}┤{C.RESET}")

    # Print rows
    for row in rows:
        row_line = "│".join(str(cell).ljust(w)[:w] for cell, w in zip(row, col_widths))
        print(f"{C.CYAN}│{C.RESET}{row_line}{C.CYAN}│{C.RESET}")

    print(f"{C.CYAN}└{'┴'.join('─' * w for w in col_widths)}┘{C.RESET}")


def print_success_box(message):
    """Print success box"""
    print(f"""
{C.GREEN}╔═══════════════════════════════════════════════════════╗
{C.GREEN}║{C.WHITE}  ✓ {message[:49].ljust(49)}  {C.GREEN}║
{C.GREEN}╚═══════════════════════════════════════════════════════╝{C.RESET}
""")


def print_error_box(message):
    """Print error box"""
    print(f"""
{C.RED}╔═══════════════════════════════════════════════════════╗
{C.RED}║{C.WHITE}  ✗ {message[:49].ljust(49)}  {C.RED}║
{C.RED}╚═══════════════════════════════════════════════════════╝{C.RESET}
""")


# =============================================
# TARGET VALIDATION
# =============================================

def validate_target(target):
    """Validate and normalize target URL"""
    if not target:
        return None

    target = target.strip()

    # Remove trailing slash
    target = target.rstrip('/')

    # Add http:// if missing
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    # Parse URL
    try:
        parsed = urlparse(target)

        if not parsed.netloc:
            return None

        hostname = parsed.hostname
        if not hostname:
            return None

        if len(hostname) > 253:
            return None

        return target
    except Exception:
        return None


def get_target(prompt="Enter target URL"):
    """Get target from user input"""
    try:
        target = input(f"{C.YELLOW}[?] {prompt}: {C.RESET}").strip()
        return validate_target(target)
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def is_valid_url(url):
    """Check if URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def get_domain(url):
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc.split(':')[0]
    except Exception:
        return url


def get_base_url(url):
    """Get base URL (scheme + netloc)"""
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return url


# =============================================
# NETWORK UTILITIES
# =============================================

def resolve_host(hostname):
    """Resolve hostname to IP"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def is_host_reachable(host, port=80, timeout=5):
    """Check if host is reachable"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_local_ip():
    """Get local IP address"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


# =============================================
# STRING UTILITIES
# =============================================

def random_string(length=8, chars=None):
    """Generate random string"""
    if chars is None:
        chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))


def random_token(length=16):
    """Generate random hex token"""
    return ''.join(random.choices(string.hexdigits.lower(), k=length))


def safe_filename(filename):
    """Convert string to safe filename"""
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = ''.join(c for c in filename if ord(c) >= 32)
    return filename[:200]


def truncate(text, max_length=50, suffix="..."):
    """Truncate text to max length"""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def strip_ansi(text):
    """Remove ANSI color codes from text"""
    ansi_pattern = re.compile(r'\033\[[0-9;]*m')
    return ansi_pattern.sub('', text)


# =============================================
# FORMATTING
# =============================================

def format_size(bytes_size):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.2f} PB"


def format_time(seconds):
    """Format seconds to human readable"""
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def format_number(number):
    """Format number with thousand separators"""
    return f"{number:,}"


def timestamp():
    """Get current timestamp string"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def timestamp_readable():
    """Get readable timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =============================================
# FILE UTILITIES
# =============================================

def ensure_dir(path):
    """Ensure directory exists"""
    os.makedirs(path, exist_ok=True)
    return path


def file_exists(path):
    """Check if file exists"""
    return os.path.isfile(path)


def dir_exists(path):
    """Check if directory exists"""
    return os.path.isdir(path)


def read_file(path, encoding='utf-8'):
    """Read file content"""
    try:
        with open(path, 'r', encoding=encoding, errors='ignore') as f:
            return f.read()
    except Exception:
        return None


def write_file(path, content, encoding='utf-8'):
    """Write content to file"""
    try:
        ensure_dir(os.path.dirname(path))
        with open(path, 'w', encoding=encoding) as f:
            f.write(content)
        return True
    except Exception:
        return False


def append_file(path, content, encoding='utf-8'):
    """Append content to file"""
    try:
        ensure_dir(os.path.dirname(path))
        with open(path, 'a', encoding=encoding) as f:
            f.write(content)
        return True
    except Exception:
        return False


def load_json(path):
    """Load JSON file"""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def save_json(path, data):
    """Save data to JSON file"""
    try:
        ensure_dir(os.path.dirname(path))
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, default=str, ensure_ascii=False)
        return True
    except Exception:
        return False


def load_lines(path):
    """Load file as list of lines (stripped)"""
    content = read_file(path)
    if content is None:
        return []
    return [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]


def list_files(directory, extension=None):
    """List files in directory"""
    if not dir_exists(directory):
        return []

    files = []
    for f in os.listdir(directory):
        path = os.path.join(directory, f)
        if os.path.isfile(path):
            if extension is None or f.endswith(extension):
                files.append(path)

    return files


# =============================================
# USER INTERACTION
# =============================================

def confirm_action(prompt="Are you sure?", default=False):
    """Ask user for confirmation"""
    suffix = " (Y/n)" if default else " (y/N)"
    try:
        response = input(f"{C.YELLOW}[?] {prompt}{suffix}: {C.RESET}").strip().lower()

        if not response:
            return default

        return response in ['y', 'yes', 'نعم']
    except (KeyboardInterrupt, EOFError):
        print()
        return False


def wait_for_enter(message="Press Enter to continue"):
    """Wait for user to press Enter"""
    try:
        input(f"\n{C.DIM}[*] {message}...{C.RESET}")
    except (KeyboardInterrupt, EOFError):
        print()


def select_option(options, prompt="Select option"):
    """Let user select from a list of options"""
    print()
    for i, option in enumerate(options, 1):
        print(f"  {C.GREEN}[{i}]{C.RESET} {option}")
    print()

    try:
        choice = input(f"{C.YELLOW}[?] {prompt} (1-{len(options)}): {C.RESET}").strip()
        idx = int(choice) - 1

        if 0 <= idx < len(options):
            return options[idx]
        return None
    except (ValueError, KeyboardInterrupt, EOFError):
        print()
        return None


# =============================================
# HASHING
# =============================================

def md5_hash(text):
    """Get MD5 hash"""
    return hashlib.md5(text.encode()).hexdigest()


def sha1_hash(text):
    """Get SHA1 hash"""
    return hashlib.sha1(text.encode()).hexdigest()


def sha256_hash(text):
    """Get SHA256 hash"""
    return hashlib.sha256(text.encode()).hexdigest()


# =============================================
# TIMING
# =============================================

class Timer:
    """Simple timer class"""

    def __init__(self):
        self.start_time = None
        self.end_time = None

    def start(self):
        """Start timer"""
        self.start_time = time.time()
        self.end_time = None
        return self

    def stop(self):
        """Stop timer"""
        self.end_time = time.time()
        return self.elapsed()

    def elapsed(self):
        """Get elapsed time"""
        if self.start_time is None:
            return 0

        end = self.end_time if self.end_time else time.time()
        return end - self.start_time

    def elapsed_str(self):
        """Get elapsed time as string"""
        return format_time(self.elapsed())


def sleep_ms(milliseconds):
    """Sleep for milliseconds"""
    time.sleep(milliseconds / 1000)


# =============================================
# SEVERITY & SCORING
# =============================================

SEVERITY_SCORES = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 0.0,
}


def get_severity_color(severity):
    """Get color for severity"""
    colors = {
        "CRITICAL": C.RED,
        "HIGH": C.YELLOW,
        "MEDIUM": C.CYAN,
        "LOW": C.GREEN,
        "INFO": C.WHITE,
    }
    return colors.get(severity.upper(), C.WHITE)


def get_severity_score(severity):
    """Get numeric score for severity"""
    return SEVERITY_SCORES.get(severity.upper(), 0.0)


def calculate_risk_score(vulnerabilities):
    """Calculate overall risk score"""
    if not vulnerabilities:
        return 0.0

    total = sum(get_severity_score(v.get('severity', 'LOW')) for v in vulnerabilities)
    return min(total / len(vulnerabilities), 10.0)


# =============================================
# PROGRESS
# =============================================

class ProgressBar:
    """Simple progress bar"""

    def __init__(self, total, prefix="Progress", length=40):
        self.total = total
        self.current = 0
        self.prefix = prefix
        self.length = length
        self.start_time = time.time()

    def update(self, increment=1):
        """Update progress"""
        self.current += increment
        self._render()

    def set(self, value):
        """Set current value"""
        self.current = value
        self._render()

    def _render(self):
        """Render progress bar"""
        percent = self.current / self.total if self.total > 0 else 0
        filled = int(self.length * percent)
        bar = '█' * filled + '░' * (self.length - filled)

        elapsed = time.time() - self.start_time
        eta = (elapsed / self.current * (self.total - self.current)) if self.current > 0 else 0

        sys.stdout.write(
            f'\r{C.CYAN}{self.prefix}:{C.RESET} |{C.GREEN}{bar}{C.RESET}| '
            f'{percent*100:.1f}% [{self.current}/{self.total}] ETA: {format_time(eta)}'
        )
        sys.stdout.flush()

    def finish(self):
        """Complete progress bar"""
        self.current = self.total
        self._render()
        sys.stdout.write('\n')
        sys.stdout.flush()


# =============================================
# SHELL UTILITIES
# =============================================

def run_command(command, timeout=30):
    """Run shell command and return output"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except Exception as e:
        return "", str(e), -1


def check_dependencies(deps=None):
    """Check Python dependencies"""
    if deps is None:
            deps = ['requests', 'colorama', 'dns', 'whois']

    missing = []
    for dep in deps:
        try:
            __import__(dep)
        except ImportError:
            missing.append(dep)

    return missing


def check_native_modules(native_dir=None):
    """Check native modules availability"""
    if native_dir is None:
        native_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'native')

    modules = ['port_scanner', 'banner_grabber', 'payload_engine', 'hash_cracker', 'packet_crafter', 'crypto_utils']

    for module in modules:
        path = os.path.join(native_dir, module)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            available.append(module)

    return available


# =============================================
# CLI MODE
# =============================================

def main():
    """CLI entry point for utils"""
    import argparse

    parser = argparse.ArgumentParser(description="BlackHunter Pro - Utils")
    parser.add_argument('--check-deps', action='store_true', help="Check dependencies")
    parser.add_argument('--check-native', action='store_true', help="Check native modules")
    parser.add_argument('--version', action='store_true', help="Show version")

    args = parser.parse_args()

    if args.check_deps:
        print(f"{C.CYAN}[*] Checking Python dependencies...{C.RESET}")
        missing = check_dependencies()

        if not missing:
            print(f"{C.GREEN}[✓] All dependencies installed{C.RESET}")
        else:
            print(f"{C.RED}[✗] Missing: {', '.join(missing)}{C.RESET}")
            print(f"{C.YELLOW}[!] Run: pip install -r requirements.txt{C.RESET}")
            sys.exit(1)

    elif args.check_native:
        print(f"{C.CYAN}[*] Checking native modules...{C.RESET}")
        available = check_native_modules()

        if available:
            for mod in available:
                print(f"{C.GREEN}[✓] {mod}{C.RESET}")
        else:
            print(f"{C.YELLOW}[!] No native modules found{C.RESET}")
            print(f"{C.YELLOW}[!] Run: cd native && make{C.RESET}")

    elif args.version:
        from . import __version__
        print(f"BlackHunter Pro v{__version__}")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()


# =============================================
# EXPORTS
# =============================================

__all__ = [
    # Colors
    "Colors", "C",

    # Logging
    "log_info", "log_ok", "log_warn", "log_error", "log_debug", "log_step", "log_vuln",

    # Printing
    "print_separator", "print_header", "print_table",
    "print_success_box", "print_error_box",

    # Validation
    "validate_target", "get_target", "is_valid_url", "get_domain", "get_base_url",

    # Network
    "resolve_host", "is_host_reachable", "get_local_ip",

    # Strings
    "random_string", "random_token", "safe_filename", "truncate", "strip_ansi",

    # Formatting
    "format_size", "format_time", "format_number", "timestamp", "timestamp_readable",

    # Files
    "ensure_dir", "file_exists", "dir_exists", "read_file", "write_file",
    "append_file", "load_json", "save_json", "load_lines", "list_files",

    # Interaction
    "confirm_action", "wait_for_enter", "select_option",

    # Hashing
    "md5_hash", "sha1_hash", "sha256_hash",

    # Timing
    "Timer", "sleep_ms",

    # Severity
    "SEVERITY_SCORES", "get_severity_color", "get_severity_score", "calculate_risk_score",

    # Progress
    "ProgressBar",

    # Shell
    "run_command", "check_dependencies", "check_native_modules",

    # CLI
    "main",
]
