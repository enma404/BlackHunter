# core/__init__.py
# BlackHunter Pro - Core Package
# Academic Penetration Testing Tool - Isolated Lab Only

# =============================================
# PACKAGE INFO
# =============================================

__version__ = "1.0.0"
__author__ = "Academic Security Research Lab"
__description__ = "BlackHunter Pro - Web Penetration Testing Tool"
__license__ = "Academic Use Only"

# =============================================
# CORE MODULES
# =============================================

from .banner import (
    show_banner,
    show_small_banner,
    show_mini_banner,
    show_completion_banner,
    show_phase_header,
    show_section_header,
    show_vuln_alert,
    clear_screen,
    Colors as BannerColors,
)

from .utils import (
    Colors,
    C,
    log_info,
    log_ok,
    log_warn,
    log_error,
    log_debug,
    log_step,
    log_vuln,
    print_table,
    print_separator,
    print_header,
    print_success_box,
    print_error_box,
    validate_target,
    get_target,
    is_valid_url,
    get_domain,
    get_base_url,
    resolve_host,
    random_string,
    random_token,
    safe_filename,
    truncate,
    format_size,
    format_time,
    timestamp,
    timestamp_readable,
    ensure_dir,
    read_file,
    write_file,
    load_json,
    save_json,
    load_lines,
    confirm_action,
    wait_for_enter,
    Timer,
    ProgressBar,
    get_severity_color,
    get_severity_score,
    calculate_risk_score,
)

from .config import (
    Config,
    DEFAULT_CONFIG,
    get_config,
    load_config,
    save_config,
    reset_config,
)

from .logger import (
    Logger,
    get_logger,
    log_scan_start,
    log_scan_end,
    log_vulnerability,
    log_exploit,
    log_error as log_error_file,
)

from .session import (
    Session,
    SessionManager,
    get_session_manager,
    create_session,
    close_session,
)

from .runner import (
    Runner,
    run_scan,
    run_module,
    main as runner_main,
)

from .menu import (
    show_main_menu,
    show_settings_menu,
    show_c2_menu,
    show_help,
    get_menu_choice,
    get_target_input,
    get_yes_no,
    handle_main_menu_choice,
    handle_settings_choice,
    handle_c2_choice,
)

# =============================================
# EXPORTS
# =============================================

__all__ = [
    # Package info
    "__version__",
    "__author__",
    "__description__",
    "__license__",

    # Banner
    "show_banner",
    "show_small_banner",
    "show_mini_banner",
    "show_completion_banner",
    "show_phase_header",
    "show_section_header",
    "show_vuln_alert",
    "clear_screen",
    "BannerColors",

    # Utils - Colors
    "Colors",
    "C",

    # Utils - Logging
    "log_info",
    "log_ok",
    "log_warn",
    "log_error",
    "log_debug",
    "log_step",
    "log_vuln",

    # Utils - Printing
    "print_table",
    "print_separator",
    "print_header",
    "print_success_box",
    "print_error_box",

    # Utils - Validation
    "validate_target",
    "get_target",
    "is_valid_url",
    "get_domain",
    "get_base_url",

    # Utils - Network
    "resolve_host",

    # Utils - Strings
    "random_string",
    "random_token",
    "safe_filename",
    "truncate",

    # Utils - Formatting
    "format_size",
    "format_time",
    "timestamp",
    "timestamp_readable",

    # Utils - Files
    "ensure_dir",
    "read_file",
    "write_file",
    "load_json",
    "save_json",
    "load_lines",

    # Utils - Interaction
    "confirm_action",
    "wait_for_enter",

    # Utils - Timing
    "Timer",
    "ProgressBar",

    # Utils - Severity
    "get_severity_color",
    "get_severity_score",
    "calculate_risk_score",

    # Config
    "Config",
    "DEFAULT_CONFIG",
    "get_config",
    "load_config",
    "save_config",
    "reset_config",

    # Logger
    "Logger",
    "get_logger",
    "log_scan_start",
    "log_scan_end",
    "log_vulnerability",
    "log_exploit",
    "log_error_file",

    # Session
    "Session",
    "SessionManager",
    "get_session_manager",
    "create_session",
    "close_session",

    # Runner
    "Runner",
    "run_scan",
    "run_module",
    "runner_main",

    # Menu
    "show_main_menu",
    "show_settings_menu",
    "show_c2_menu",
    "show_help",
    "get_menu_choice",
    "get_target_input",
    "get_yes_no",
    "handle_main_menu_choice",
    "handle_settings_choice",
    "handle_c2_choice",
]

# =============================================
# CONSTANTS
# =============================================

VERSION = __version__
TOOL_NAME = "BlackHunter"
TOOL_NAME_FULL = "BlackHunter Pro"
AUTHOR = __author__

# Module categories
SCANNING_MODULES = [
    "recon",
    "port",
    "web",
    "cms",
    "subdomain",
]

VULNERABILITY_MODULES = [
    "sqli",
    "xss",
    "lfi",
    "cmdi",
    "ssrf",
    "upload",
    "xxe",
    "csrf",
    "idor",
    "redirect",
]

EXPLOITATION_MODULES = [
    "sqli_exploit",
    "lfi_exploit",
    "cmdi_exploit",
    "ssrf_exploit",
    "upload_exploit",
]

ALL_MODULES = SCANNING_MODULES + VULNERABILITY_MODULES

# Severity levels
SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

# =============================================
# HELPER FUNCTIONS
# =============================================

def get_version():
    """Return current version"""
    return __version__


def get_tool_name():
    """Return tool name"""
    return TOOL_NAME


def get_module_list(category=None):
    """
    Return list of available modules

    Args:
        category: 'scanning', 'vulnerability', 'exploitation', or None for all
    """
    if category == "scanning":
        return SCANNING_MODULES
    elif category == "vulnerability":
        return VULNERABILITY_MODULES
    elif category == "exploitation":
        return EXPLOITATION_MODULES
    else:
        return ALL_MODULES


def get_severity_score_by_name(severity):
    """Return numeric score for severity name"""
    return SEVERITY_LEVELS.get(severity.upper(), 0)


def is_valid_severity(severity):
    """Check if severity is valid"""
    return severity.upper() in SEVERITY_LEVELS


# =============================================
# WELCOME MESSAGE
# =============================================

def welcome():
    """Print welcome message"""
    print(f"""
{Colors.CYAN}═══════════════════════════════════════════════════════════
{Colors.WHITE}  {TOOL_NAME_FULL} v{VERSION}
{Colors.CYAN}  Academic Penetration Testing Tool
{Colors.GREEN}  Isolated Lab Environment Only
{Colors.CYAN}═══════════════════════════════════════════════════════════{Colors.RESET}
""")