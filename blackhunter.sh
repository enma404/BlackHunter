#!/data/data/com.termux/files/usr/bin/bash
# blackhunter.sh
# BlackHunter Pro - Main Launcher
# Academic Penetration Testing Tool - Isolated Lab Only

# =============================================
# CONFIGURATION
# =============================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
DIM='\033[2m'
NC='\033[0m'

# =============================================
# CHECKS
# =============================================

check_environment() {
    # Check Termux
    if [ ! -d "/data/data/com.termux" ]; then
        echo -e "${RED}[✗] This tool must run inside Termux${NC}"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}[✗] Python3 not found${NC}"
        echo -e "${YELLOW}[!] Run: ./setup.sh${NC}"
        exit 1
    fi
    
    # Check dependencies
    python3 -c "import requests, bs4, colorama" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${RED}[✗] Missing Python dependencies${NC}"
        echo -e "${YELLOW}[!] Run: ./setup.sh${NC}"
        exit 1
    fi
    
    # Check native modules
    if [ ! -f "$SCRIPT_DIR/native/port_scanner" ]; then
        echo -e "${YELLOW}[!] Native modules not built${NC}"
        echo -e "${CYAN}[*] Building native modules...${NC}"
        if [ -f "$SCRIPT_DIR/native/Makefile" ]; then
            cd "$SCRIPT_DIR/native" && make 2>/dev/null
            cd "$SCRIPT_DIR"
        fi
    fi
}

# =============================================
# BANNER
# =============================================

show_banner() {
    clear
    echo -e "${RED}"
    cat << "EOF"
   ██████╗ ██╗      █████╗  ██████╗██╗  ██╗
   ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝
   ██████╔╝██║     ███████║██║     █████╔╝ 
   ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ 
   ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗
   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
   
   ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
   ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
   ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
   ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}              P R O   v1.0${NC}"
    echo -e "${CYAN}    Academic Penetration Testing Tool${NC}"
    echo -e "${GREEN}    Isolated Lab Environment Only${NC}"
    echo ""
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# =============================================
# QUICK INFO BAR
# =============================================

show_info_bar() {
    local time_now=$(date '+%H:%M:%S')
    local date_now=$(date '+%Y-%m-%d')
    
    echo -e "${DIM}┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "${DIM}│${NC} ${CYAN}Date:${NC} $date_now  ${CYAN}Time:${NC} $time_now              ${DIM}│${NC}"
    echo -e "${DIM}│${NC} ${CYAN}User:${NC} $(whoami)  ${CYAN}PWD:${NC} ${SCRIPT_DIR:0:35}  ${DIM}│${NC}"
    echo -e "${DIM}└─────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# =============================================
# MENU
# =============================================

show_menu() {
    echo -e "${CYAN}  ╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}  ║${NC}            ${WHITE}RECONNAISSANCE & SCANNING${NC}                  ${CYAN}║${NC}"
    echo -e "${CYAN}  ╠═══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[1]${NC}  🎯  ${WHITE}Reconnaissance${NC}         ${DIM}(DNS, WHOIS, Tech)${NC}    ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[2]${NC}  🔍  ${WHITE}Port Scanning${NC}          ${DIM}(TCP/UDP, Services)${NC}  ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[3]${NC}  🌐  ${WHITE}Web Scanning${NC}           ${DIM}(Dirs, Files, Methods)${NC}${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[4]${NC}  📦  ${WHITE}CMS Detection${NC}          ${DIM}(WP, Joomla, Craft)${NC}  ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[5]${NC}  🔎  ${WHITE}Subdomain Enumeration${NC}  ${DIM}(DNS Bruteforce)${NC}      ${CYAN}║${NC}"
    echo -e "${CYAN}  ╠═══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}  ║${NC}            ${WHITE}VULNERABILITY DETECTION${NC}                    ${CYAN}║${NC}"
    echo -e "${CYAN}  ╠═══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[6]${NC}  💉  ${WHITE}SQL Injection${NC}          ${DIM}(Error, Union, Blind)${NC} ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[7]${NC}  🎭  ${WHITE}XSS${NC}                    ${DIM}(Reflected, Stored)${NC}  ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[8]${NC}  📂  ${WHITE}LFI / RFI${NC}              ${DIM}(Traversal, Wrappers)${NC}${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[9]${NC}  ⚡  ${WHITE}Command Injection${NC}      ${DIM}(Linux, Windows)${NC}      ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[10]${NC} 🌐  ${WHITE}SSRF${NC}                   ${DIM}(Basic, Blind, Cloud)${NC} ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[11]${NC} 📤  ${WHITE}File Upload${NC}            ${DIM}(Bypass, Shells)${NC}     ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[12]${NC} 📜  ${WHITE}XXE${NC}                    ${DIM}(XML External Entity)${NC} ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[13]${NC} 🔐  ${WHITE}CSRF${NC}                   ${DIM}(Token Analysis)${NC}     ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[14]${NC} 🔓  ${WHITE}IDOR${NC}                   ${DIM}(Object Reference)${NC}    ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[15]${NC} ↩️   ${WHITE}Open Redirect${NC}          ${DIM}(URL Redirection)${NC}    ${CYAN}║${NC}"
    echo -e "${CYAN}  ╠═══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}  ║${NC}            ${WHITE}EXPLOITATION & CONTROL${NC}                     ${CYAN}║${NC}"
    echo -e "${CYAN}  ╠═══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}  ║${NC}  ${RED}[16]${NC} ⚔️   ${WHITE}Full Exploit${NC}           ${DIM}(All Vulnerabilities)${NC}${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${RED}[17]${NC} 🎛️   ${WHITE}C2 Server${NC}              ${DIM}(Command & Control)${NC}  ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[18]${NC} 📊  ${WHITE}Generate Report${NC}        ${DIM}(JSON, HTML, PDF)${NC}     ${CYAN}║${NC}"
    echo -e "${CYAN}  ╠═══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}  ║${NC}            ${WHITE}SYSTEM${NC}                                 ${CYAN}║${NC}"
    echo -e "${CYAN}  ╠═══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[19]${NC} ⚙️   ${WHITE}Settings${NC}                                   ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[20]${NC} ❓  ${WHITE}Help${NC}                                       ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${RED}[0]${NC}  🚪  ${WHITE}Exit${NC}                                       ${CYAN}║${NC}"
    echo -e "${CYAN}  ╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# =============================================
# TARGET INPUT
# =============================================

get_target() {
    echo -ne "${YELLOW}  [?] Enter target (URL/IP/domain): ${NC}"
    read -r TARGET
    
    if [ -z "$TARGET" ]; then
        echo -e "${RED}  [✗] No target provided${NC}"
        sleep 1
        return 1
    fi
    
    # Normalize URL
    if [[ ! "$TARGET" =~ ^https?:// ]] && [[ "$TARGET" =~ \. ]]; then
        TARGET="http://$TARGET"
    fi
    
    echo -e "${GREEN}  [✓] Target: $TARGET${NC}"
    echo ""
    return 0
}

# =============================================
# RUN MODULE
# =============================================

run_module() {
    local module="$1"
    local module_name="$2"
    local rc=0
    
    if ! get_target; then
        return
    fi
    
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  Starting: $module_name${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    python3 "$SCRIPT_DIR/core/runner.py" --target "$TARGET" --module "$module"
    rc=$?
    
    echo ""
    echo -e "${CYAN}  ─────────────────────────────────────────────────────${NC}"
    if [ $rc -eq 0 ]; then
        echo -e "${GREEN}  [✓] $module_name completed${NC}"
    else
        echo -e "${RED}  [✗] $module_name failed (exit code $rc)${NC}"
    fi
    echo -e "${YELLOW}  [*] Press Enter to return to menu...${NC}"
    read -r
}

# =============================================
# C2 SERVER LAUNCHER
# =============================================

launch_c2() {
    clear
    show_banner
    
    if [ ! -f "$SCRIPT_DIR/c2_server/server.py" ]; then
        echo -e "${RED}  [✗] C2 Server not found${NC}"
        sleep 2
        return
    fi
    
    echo -e "${CYAN}  ╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}  ║${NC}              ${WHITE}C2 SERVER CONTROL${NC}                         ${CYAN}║${NC}"
    echo -e "${CYAN}  ╠═══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[1]${NC}  Start C2 Server                    ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[2]${NC}  Start with Web UI                  ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[3]${NC}  Generate Payload                   ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[4]${NC}  Start Listener                     ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[5]${NC}  View Active Sessions               ${CYAN}║${NC}"
    echo -e "${CYAN}  ║${NC}  ${GREEN}[0]${NC}  Back                               ${CYAN}║${NC}"
    echo -e "${CYAN}  ╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -ne "${YELLOW}  [?] Choose: ${NC}"
    read -r c2_choice
    
    case $c2_choice in
        1) python3 "$SCRIPT_DIR/c2_server/server.py" ;;
        2) python3 "$SCRIPT_DIR/c2_server/server.py" --web ;;
        3) python3 "$SCRIPT_DIR/c2_server/server.py" --generate ;;
        4) python3 "$SCRIPT_DIR/c2_server/server.py" --listen ;;
        5) python3 "$SCRIPT_DIR/c2_server/server.py" --sessions ;;
        0) return ;;
        *) echo -e "${RED}  [✗] Invalid option${NC}" ; sleep 1 ;;
    esac
}

# =============================================
# SETTINGS
# =============================================

show_settings() {
    while true; do
        clear
        show_banner
        
        echo -e "${CYAN}  ╔═══════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}  ║${NC}                    ${WHITE}SETTINGS${NC}                           ${CYAN}║${NC}"
        echo -e "${CYAN}  ╠═══════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}  ║${NC}  ${GREEN}[1]${NC}  View Configuration                 ${CYAN}║${NC}"
        echo -e "${CYAN}  ║${NC}  ${GREEN}[2]${NC}  Edit Configuration                 ${CYAN}║${NC}"
        echo -e "${CYAN}  ║${NC}  ${GREEN}[3]${NC}  Reset to Defaults                  ${CYAN}║${NC}"
        echo -e "${CYAN}  ║${NC}  ${GREEN}[4]${NC}  View Logs                          ${CYAN}║${NC}"
        echo -e "${CYAN}  ║${NC}  ${GREEN}[5]${NC}  Clear Logs                         ${CYAN}║${NC}"
        echo -e "${CYAN}  ║${NC}  ${GREEN}[6]${NC}  View Reports                       ${CYAN}║${NC}"
        echo -e "${CYAN}  ║${NC}  ${GREEN}[7]${NC}  Clear Reports                      ${CYAN}║${NC}"
        echo -e "${CYAN}  ║${NC}  ${GREEN}[8]${NC}  Update Tool                        ${CYAN}║${NC}"
        echo -e "${CYAN}  ║${NC}  ${GREEN}[9]${NC}  Check Dependencies                 ${CYAN}║${NC}"
        echo -e "${CYAN}  ║${NC}  ${GREEN}[0]${NC}  Back                               ${CYAN}║${NC}"
        echo -e "${CYAN}  ╚═══════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        echo -ne "${YELLOW}  [?] Choose: ${NC}"
        read -r s_choice
        
        case $s_choice in
            1)
                if [ -f "$SCRIPT_DIR/config/config.json" ]; then
                    cat "$SCRIPT_DIR/config/config.json"
                fi
                echo ""
                echo -ne "${YELLOW}  Press Enter...${NC}"
                read -r
                ;;
            2)
                if command -v nano &>/dev/null; then
                    nano "$SCRIPT_DIR/config/config.json"
                elif command -v vi &>/dev/null; then
                    vi "$SCRIPT_DIR/config/config.json"
                fi
                ;;
            3)
                echo -ne "${YELLOW}  [?] Reset config? (y/n): ${NC}"
                read -r confirm
                if [[ "$confirm" == "y" ]]; then
                    rm -f "$SCRIPT_DIR/config/config.json"
                    echo -e "${GREEN}  [✓] Config reset${NC}"
                fi
                sleep 1
                ;;
            4)
                if [ -d "$SCRIPT_DIR/logs" ]; then
                    ls -la "$SCRIPT_DIR/logs/"
                fi
                echo ""
                echo -ne "${YELLOW}  Press Enter...${NC}"
                read -r
                ;;
            5)
                rm -rf "$SCRIPT_DIR/logs/"*.log 2>/dev/null
                echo -e "${GREEN}  [✓] Logs cleared${NC}"
                sleep 1
                ;;
            6)
                if [ -d "$SCRIPT_DIR/reports" ]; then
                    find "$SCRIPT_DIR/reports" -type f -name "*.html" -o -name "*.json" | head -20
                fi
                echo ""
                echo -ne "${YELLOW}  Press Enter...${NC}"
                read -r
                ;;
            7)
                echo -ne "${YELLOW}  [?] Clear all reports? (y/n): ${NC}"
                read -r confirm
                if [[ "$confirm" == "y" ]]; then
                    rm -rf "$SCRIPT_DIR/reports/"* 2>/dev/null
                    mkdir -p "$SCRIPT_DIR/reports/loot"
                    echo -e "${GREEN}  [✓] Reports cleared${NC}"
                fi
                sleep 1
                ;;
            8)
                echo -e "${CYAN}  [*] Updating...${NC}"
                cd "$SCRIPT_DIR" && git pull 2>/dev/null || echo -e "${YELLOW}  [!] Not a git repo${NC}"
                sleep 2
                ;;
            9)
                python3 "$SCRIPT_DIR/core/utils.py" --check-deps 2>/dev/null || {
                    echo -e "${CYAN}  Checking dependencies...${NC}"
                    for dep in requests bs4 colorama dns OpenSSL; do
                        if python3 -c "import $dep" 2>/dev/null; then
                            echo -e "${GREEN}  [✓] $dep${NC}"
                        else
                            echo -e "${RED}  [✗] $dep${NC}"
                        fi
                    done
                }
                echo ""
                echo -ne "${YELLOW}  Press Enter...${NC}"
                read -r
                ;;
            0)
                return
                ;;
        esac
    done
}

# =============================================
# HELP
# =============================================

show_help() {
    clear
    show_banner
    
    echo -e "${CYAN}  ╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}  ║${NC}                      ${WHITE}HELP${NC}                             ${CYAN}║${NC}"
    echo -e "${CYAN}  ╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${YELLOW}  About:${NC}"
    echo -e "  BlackHunter Pro is an academic penetration testing tool"
    echo -e "  designed for Termux in isolated lab environments."
    echo ""
    
    echo -e "${YELLOW}  Features:${NC}"
    echo -e "  ${GREEN}•${NC} Comprehensive reconnaissance & scanning"
    echo -e "  ${GREEN}•${NC} 10+ vulnerability detection modules"
    echo -e "  ${GREEN}•${NC} Full exploitation capabilities"
    echo -e "  ${GREEN}•${NC} C2 server for remote control"
    echo -e "  ${GREEN}•${NC} Professional reporting"
    echo ""
    
    echo -e "${YELLOW}  Quick Start:${NC}"
    echo -e "  ${CYAN}1.${NC} ./setup.sh          ${DIM}# Install${NC}"
    echo -e "  ${CYAN}2.${NC} ./blackhunter.sh    ${DIM}# Launch${NC}"
    echo -e "  ${CYAN}3.${NC} Choose [11] for full scan"
    echo -e "  ${CYAN}4.${NC} Enter target URL"
    echo ""
    
    echo -e "${YELLOW}  Examples:${NC}"
    echo -e "  ${GREEN}http://testphp.vulnweb.com${NC}"
    echo -e "  ${GREEN}http://demo.testfire.net${NC}"
    echo ""
    
    echo -e "${YELLOW}  Troubleshooting:${NC}"
    echo -e "  ${GREEN}•${NC} Permission denied:  chmod +x *.sh"
    echo -e "  ${GREEN}•${NC} Missing modules:    ./setup.sh"
    echo -e "  ${GREEN}•${NC} SSL errors:         pkg install ca-certificates"
    echo ""
    
    echo -e "${RED}  ⚠  Ethical Warning:${NC}"
    echo -e "${RED}  Use ONLY in isolated lab environment.${NC}"
    echo -e "${RED}  Never target systems you don't own.${NC}"
    echo ""
    
    echo -ne "${YELLOW}  Press Enter to return...${NC}"
    read -r
}

# =============================================
# MAIN LOOP
# =============================================

main() {
    check_environment
    
    while true; do
        show_banner
        show_info_bar
        show_menu
        
        echo -ne "${YELLOW}  [?] Choose option: ${NC}"
        read -r choice
        echo ""
        
        case $choice in
            1)  run_module "recon" "Reconnaissance" ;;
            2)  run_module "port" "Port Scanning" ;;
            3)  run_module "web" "Web Scanning" ;;
            4)  run_module "cms" "CMS Detection" ;;
            5)  run_module "subdomain" "Subdomain Enumeration" ;;
            6)  run_module "sqli" "SQL Injection" ;;
            7)  run_module "xss" "XSS Detection" ;;
            8)  run_module "lfi" "LFI/RFI Detection" ;;
            9)  run_module "cmdi" "Command Injection" ;;
            10) run_module "ssrf" "SSRF Detection" ;;
            11) run_module "upload" "File Upload" ;;
            12) run_module "xxe" "XXE Detection" ;;
            13) run_module "csrf" "CSRF Detection" ;;
            14) run_module "idor" "IDOR Detection" ;;
            15) run_module "redirect" "Open Redirect" ;;
            16) run_module "full" "Full Exploitation" ;;
            17) launch_c2 ;;
            18) run_module "report" "Report Generation" ;;
            19) show_settings ;;
            20) show_help ;;
            0)
                clear
                echo -e "${GREEN}  [✓] Thank you for using BlackHunter Pro${NC}"
                echo -e "${CYAN}  [*] Stay ethical. Stay legal.${NC}"
                echo ""
                exit 0
                ;;
            *)
                echo -e "${RED}  [✗] Invalid option: $choice${NC}"
                sleep 1
                ;;
        esac
    done
}

# =============================================
# ENTRY
# =============================================

trap 'echo -e "\n${YELLOW}[!] Interrupted${NC}"; exit 0' INT

main