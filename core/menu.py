# core/menu.py
# BlackHunter Pro - Interactive Menu System
# Academic Penetration Testing Tool - Isolated Lab Only

import os
import sys
import time

# Import banner and colors
try:
    from .banner import (
        Colors as C,
        show_banner,
        show_small_banner,
        show_section_header,
        clear_screen,
    )
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from banner import (
        Colors as C,
        show_banner,
        show_small_banner,
        show_section_header,
        clear_screen,
    )


# =============================================
# MAIN MENU
# =============================================

def show_main_menu():
    """Display the main menu"""
    clear_screen()
    show_banner(clear=False)

    print(f"""
{C.CYAN}  ╔═══════════════════════════════════════════════════════╗
{C.CYAN}  ║{C.WHITE}            RECONNAISSANCE & SCANNING                  {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.RESET}  {C.GREEN}[1]{C.RESET}  🎯  {C.WHITE}Reconnaissance{NC_RESET}         {C.DIM}(DNS, WHOIS, Tech){C.RESET}    {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[2]{C.RESET}  🔍  {C.WHITE}Port Scanning{NC_RESET}          {C.DIM}(TCP/UDP, Services){C.RESET}  {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[3]{C.RESET}  🌐  {C.WHITE}Web Scanning{NC_RESET}           {C.DIM}(Dirs, Files, HTTP){C.RESET}  {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[4]{C.RESET}  📦  {C.WHITE}CMS Detection{NC_RESET}          {C.DIM}(WP, Joomla, Craft){C.RESET}  {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[5]{C.RESET}  🔎  {C.WHITE}Subdomain Enumeration{NC_RESET}  {C.DIM}(DNS Bruteforce){C.RESET}      {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.WHITE}            VULNERABILITY DETECTION                    {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.RESET}  {C.GREEN}[6]{C.RESET}  💉  {C.WHITE}SQL Injection{NC_RESET}          {C.DIM}(Error, Union, Blind){C.RESET} {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[7]{C.RESET}  🎭  {C.WHITE}XSS{NC_RESET}                    {C.DIM}(Reflected, Stored){C.RESET}  {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[8]{C.RESET}  📂  {C.WHITE}LFI / RFI{NC_RESET}              {C.DIM}(Traversal, Wrappers){C.RESET}{C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[9]{C.RESET}  ⚡  {C.WHITE}Command Injection{NC_RESET}      {C.DIM}(Linux, Windows){C.RESET}      {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[10]{C.RESET} 🌐  {C.WHITE}SSRF{NC_RESET}                   {C.DIM}(Basic, Blind, Cloud){C.RESET} {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[11]{C.RESET} 📤  {C.WHITE}File Upload{NC_RESET}            {C.DIM}(Bypass, Shells){C.RESET}     {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[12]{C.RESET} 📜  {C.WHITE}XXE{NC_RESET}                    {C.DIM}(XML External Entity){C.RESET} {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[13]{C.RESET} 🔐  {C.WHITE}CSRF{NC_RESET}                   {C.DIM}(Token Analysis){C.RESET}     {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[14]{C.RESET} 🔓  {C.WHITE}IDOR{NC_RESET}                   {C.DIM}(Object Reference){C.RESET}    {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[15]{C.RESET} ↩️   {C.WHITE}Open Redirect{NC_RESET}          {C.DIM}(URL Redirection){C.RESET}    {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.WHITE}            EXPLOITATION & CONTROL                     {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.RESET}  {C.RED}[16]{C.RESET} ⚔️   {C.WHITE}Full Exploit{NC_RESET}           {C.DIM}(All Vulnerabilities){C.RESET}{C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.RED}[17]{C.RESET} 🎛️   {C.WHITE}C2 Server{NC_RESET}              {C.DIM}(Command & Control){C.RESET}  {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[18]{C.RESET} 📊  {C.WHITE}Generate Report{NC_RESET}        {C.DIM}(JSON, HTML, PDF){C.RESET}     {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.WHITE}            SYSTEM                                     {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.RESET}  {C.GREEN}[19]{C.RESET} ⚙️   {C.WHITE}Settings{NC_RESET}                                   {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[20]{C.RESET} ❓  {C.WHITE}Help{NC_RESET}                                       {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.RED}[0]{C.RESET}  🚪  {C.WHITE}Exit{NC_RESET}                                       {C.CYAN}║
{C.CYAN}  ╚═══════════════════════════════════════════════════════╝{C.RESET}
""")


# =============================================
# SETTINGS MENU
# =============================================

def show_settings_menu():
    """Display settings menu"""
    clear_screen()
    show_small_banner()

    print(f"""
{C.CYAN}  ╔═══════════════════════════════════════════════════════╗
{C.CYAN}  ║{C.WHITE}                    SETTINGS                           {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.RESET}  {C.GREEN}[1]{C.RESET}  View Configuration                 {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[2]{C.RESET}  Edit Configuration                 {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[3]{C.RESET}  Reset to Defaults                  {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.RESET}  {C.GREEN}[4]{C.RESET}  View Logs                          {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[5]{C.RESET}  Clear Logs                         {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[6]{C.RESET}  View Reports                       {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[7]{C.RESET}  Clear Reports                      {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.RESET}  {C.GREEN}[8]{C.RESET}  Update Tool                        {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[9]{C.RESET}  Check Dependencies                 {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.RESET}  {C.GREEN}[0]{C.RESET}  Back to Main Menu                  {C.CYAN}║
{C.CYAN}  ╚═══════════════════════════════════════════════════════╝{C.RESET}
""")


# =============================================
# C2 MENU
# =============================================

def show_c2_menu():
    """Display C2 server menu"""
    clear_screen()
    show_small_banner()

    print(f"""
{C.CYAN}  ╔═══════════════════════════════════════════════════════╗
{C.CYAN}  ║{C.WHITE}                 C2 SERVER CONTROL                     {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.RESET}  {C.GREEN}[1]{C.RESET}  Start C2 Server                    {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[2]{C.RESET}  Start with Web UI                  {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[3]{C.RESET}  Generate Payload                   {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[4]{C.RESET}  Start Listener                     {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[5]{C.RESET}  View Active Sessions               {C.CYAN}║
{C.CYAN}  ║{C.RESET}  {C.GREEN}[6]{C.RESET}  Stop All Sessions                  {C.CYAN}║
{C.CYAN}  ╠═══════════════════════════════════════════════════════╣
{C.CYAN}  ║{C.RESET}  {C.GREEN}[0]{C.RESET}  Back to Main Menu                  {C.CYAN}║
{C.CYAN}  ╚═══════════════════════════════════════════════════════╝{C.RESET}
""")


# =============================================
# HELP
# =============================================

def show_help():
    """Display help information"""
    clear_screen()
    show_small_banner()

    print(f"""
{C.CYAN}  ╔═══════════════════════════════════════════════════════╗
{C.CYAN}  ║{C.WHITE}                      HELP                             {C.CYAN}║
{C.CYAN}  ╚═══════════════════════════════════════════════════════╝{C.RESET}

{C.YELLOW}  About:{C.RESET}
  BlackHunter Pro is an academic penetration testing tool
  designed for Termux in isolated lab environments.

{C.YELLOW}  Scanning Modules:{C.RESET}
  {C.GREEN}[1]{C.RESET}  Reconnaissance    - DNS, WHOIS, Headers, Tech
  {C.GREEN}[2]{C.RESET}  Port Scanning     - Open ports (TCP/UDP)
  {C.GREEN}[3]{C.RESET}  Web Scanning      - Directories, Files
  {C.GREEN}[4]{C.RESET}  CMS Detection     - WordPress, Joomla, Craft
  {C.GREEN}[5]{C.RESET}  Subdomain Enum    - DNS Bruteforce

{C.YELLOW}  Vulnerability Modules:{C.RESET}
  {C.GREEN}[6]{C.RESET}   SQL Injection     - Error, Union, Boolean, Time
  {C.GREEN}[7]{C.RESET}   XSS               - Reflected, Stored, DOM
  {C.GREEN}[8]{C.RESET}   LFI / RFI         - File Inclusion, Traversal
  {C.GREEN}[9]{C.RESET}   Command Injection - OS Command Execution
  {C.GREEN}[10]{C.RESET}  SSRF              - Server-Side Request Forgery
  {C.GREEN}[11]{C.RESET}  File Upload       - Unrestricted Upload
  {C.GREEN}[12]{C.RESET}  XXE               - XML External Entity
  {C.GREEN}[13]{C.RESET}  CSRF              - Cross-Site Request Forgery
  {C.GREEN}[14]{C.RESET}  IDOR              - Object Reference
  {C.GREEN}[15]{C.RESET}  Open Redirect     - URL Redirection

{C.YELLOW}  Example Usage:{C.RESET}
  {C.CYAN}1.{C.RESET} Choose {C.GREEN}[16]{C.RESET} for Full Exploit
  {C.CYAN}2.{C.RESET} Enter target: {C.GREEN}http://testphp.vulnweb.com{C.RESET}
  {C.CYAN}3.{C.RESET} Wait for scan to complete
  {C.CYAN}4.{C.RESET} View report in {C.GREEN}reports/html/{C.RESET}

{C.YELLOW}  Output:{C.RESET}
  - JSON report: {C.GREEN}reports/json/report_*.json{C.RESET}
  - HTML report: {C.GREEN}reports/html/report_*.html{C.RESET}
  - Logs:        {C.GREEN}logs/scan_*.log{C.RESET}
  - Loot:        {C.GREEN}reports/loot/{C.RESET}

{C.YELLOW}  Important Notes:{C.RESET}
  {C.RED}⚠{C.RESET} Use ONLY in isolated lab environment
  {C.RED}⚠{C.RESET} Never target systems you don't own
  {C.RED}⚠{C.RESET} Get written authorization before testing

{C.YELLOW}  Troubleshooting:{C.RESET}
  - Permission denied: {C.GREEN}chmod +x *.sh{C.RESET}
  - Missing modules:   {C.GREEN}./setup.sh{C.RESET}
  - SSL errors:        {C.GREEN}pkg install ca-certificates{C.RESET}
  - Storage access:    {C.GREEN}termux-setup-storage{C.RESET}

{C.MAGENTA}═══════════════════════════════════════════════════════{C.RESET}
""")


# =============================================
# INPUT HANDLERS
# =============================================

def get_menu_choice(prompt="Choose option"):
    """Get user menu choice"""
    try:
        choice = input(f"{C.YELLOW}  [?] {prompt}: {C.RESET}").strip()
        return choice
    except (KeyboardInterrupt, EOFError):
        print()
        return "0"


def get_target_input():
    """Get target URL from user"""
    try:
        target = input(f"{C.YELLOW}  [?] Enter target (URL/IP/domain): {C.RESET}").strip()

        if not target:
            return None

        # Add http:// if it looks like a URL
        if not target.startswith(('http://', 'https://')) and '.' in target:
            target = 'http://' + target

        return target
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def get_yes_no(prompt="Continue"):
    """Get yes/no confirmation"""
    try:
        response = input(f"{C.YELLOW}  [?] {prompt} (y/n): {C.RESET}").strip().lower()
        return response in ['y', 'yes']
    except (KeyboardInterrupt, EOFError):
        print()
        return False


def wait_for_enter():
    """Wait for user to press Enter"""
    try:
        input(f"\n{C.DIM}  Press Enter to continue...{C.RESET}")
    except (KeyboardInterrupt, EOFError):
        print()


# =============================================
# MENU HANDLERS
# =============================================

def handle_main_menu_choice(choice):
    """Handle main menu choice - returns action string"""
    menu_actions = {
        # Scanning
        "1": "recon",
        "2": "port",
        "3": "web",
        "4": "cms",
        "5": "subdomain",

        # Vulnerabilities
        "6": "sqli",
        "7": "xss",
        "8": "lfi",
        "9": "cmdi",
        "10": "ssrf",
        "11": "upload",
        "12": "xxe",
        "13": "csrf",
        "14": "idor",
        "15": "redirect",

        # Exploitation
        "16": "full",
        "17": "c2",
        "18": "report",

        # System
        "19": "settings",
        "20": "help",

        # Exit
        "0": "exit",
        "q": "exit",
        "quit": "exit",
    }

    return menu_actions.get(choice, "invalid")


def handle_settings_choice(choice):
    """Handle settings menu choice"""
    settings_actions = {
        "1": "view_config",
        "2": "edit_config",
        "3": "reset_config",
        "4": "view_logs",
        "5": "clear_logs",
        "6": "view_reports",
        "7": "clear_reports",
        "8": "update_tool",
        "9": "check_deps",
        "0": "back",
    }

    return settings_actions.get(choice, "invalid")


def handle_c2_choice(choice):
    """Handle C2 menu choice"""
    c2_actions = {
        "1": "start_server",
        "2": "start_web_ui",
        "3": "generate_payload",
        "4": "start_listener",
        "5": "view_sessions",
        "6": "stop_sessions",
        "0": "back",
    }

    return c2_actions.get(choice, "invalid")


# =============================================
# UTILITY FUNCTIONS
# =============================================

def print_separator(char="─", length=60, color=None):
    """Print separator line"""
    color = color or C.CYAN
    print(f"{color}{char * length}{C.RESET}")


def print_menu_header(title):
    """Print menu header"""
    print(f"\n{C.MAGENTA}{'═' * 60}{C.RESET}")
    print(f"{C.WHITE}{title.center(60)}{C.RESET}")
    print(f"{C.MAGENTA}{'═' * 60}{C.RESET}\n")


def print_option(num, text, description="", color=None):
    """Print menu option"""
    color = color or C.GREEN
    desc = f" {C.DIM}{description}{C.RESET}" if description else ""
    print(f"  {color}[{num}]{C.RESET}  {text}{desc}")


# =============================================
# ALIASES
# =============================================

# For backward compatibility
handle_menu_choice = handle_main_menu_choice
NC_RESET = C.RESET


# =============================================
# EXPORTS
# =============================================

__all__ = [
    "show_main_menu",
    "show_settings_menu",
    "show_c2_menu",
    "show_help",
    "get_menu_choice",
    "get_target_input",
    "get_yes_no",
    "wait_for_enter",
    "handle_main_menu_choice",
    "handle_menu_choice",
    "handle_settings_choice",
    "handle_c2_choice",
    "print_separator",
    "print_menu_header",
    "print_option",
]