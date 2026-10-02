#!/data/data/com.termux/files/usr/bin/bash
# setup.sh
# BlackHunter Pro - Setup Script for Termux
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

# Setup error counter (0 = success, >0 = failures detected)
SETUP_ERRORS=0

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
    echo -e "${YELLOW}      BY R2D RABBIT${NC}"
    echo -e "${CYAN}       FULL TOLS WEBSITE${NC}"
    echo -e "${GREEN}     MOLOTOV!${NC}"
    echo ""
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}                    SETUP INSTALLER${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# =============================================
# LOGGING
# =============================================

log_info()  { echo -e "${CYAN}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step()  { echo -e "\n${MAGENTA}▶ $1${NC}"; }

# =============================================
# CHECK TERMUX
# =============================================

check_termux() {
    if [ ! -d "/data/data/com.termux" ]; then
        log_error "This script must be run inside Termux"
        echo ""
        echo -e "${YELLOW}[!] Download Termux from F-Droid:${NC}"
        echo -e "    https://f-droid.org/packages/com.termux/"
        exit 1
    fi
    log_ok "Termux detected"
}

# =============================================
# STEP 1: UPDATE PACKAGES
# =============================================

update_packages() {
    log_step "STEP 1/9: Updating Package Lists"

    if ! pkg update -y 2>/dev/null; then
        log_warn "Package update failed, trying mirror change..."
        termux-change-repo
        pkg update -y
    fi

    log_ok "Package lists updated"
}

# =============================================
# STEP 2: INSTALL CORE PACKAGES
# =============================================

install_core_packages() {
    log_step "STEP 2/9: Installing Core Packages"

    PACKAGES=(
        "python"
        "python-pip"
        "git"
        "curl"
        "wget"
        "openssl"
        "openssl-tool"
        "libxml2"
        "libxslt"
        "clang"
        "make"
        "binutils"
        "nano"
        "which"
        "termux-api"
        "ca-certificates"
        "dnsutils"
        "whois"
    )

    for pkg in "${PACKAGES[@]}"; do
        if ! pkg list-installed 2>/dev/null | grep -q "^$pkg/"; then
            log_info "Installing $pkg..."
            pkg install -y "$pkg" -o Dpkg::Options::="--force-confnew" 2>/dev/null || {
                log_warn "Failed to install $pkg (may already exist)"
            }
        else
            log_ok "$pkg already installed"
        fi
    done

    log_ok "Core packages installed"
}

# =============================================
# STEP 3: UPGRADE PIP
# =============================================

upgrade_pip() {
    log_step "STEP 3/9: Upgrading pip"

    python3 -m pip install --upgrade pip setuptools wheel 2>&1 | tail -2

    log_ok "pip upgraded"
}

# =============================================
# STEP 4: INSTALL PYTHON LIBRARIES
# =============================================

install_python_libs() {
    log_step "STEP 4/9: Installing Python Libraries"

    LIBS=(
        "requests"
        "urllib3"
        "beautifulsoup4"
        "lxml"
        "html5lib"
        "colorama"
        "dnspython"
        "python-whois"
        "pyOpenSSL"
        "cryptography"
        "tldextract"
        "chardet"
        "idna"
        "certifi"
    )

    local -a FAILED_LIBS=()
    local out rc

    for lib in "${LIBS[@]}"; do
        log_info "Installing $lib..."
        out=$(python3 -m pip install "$lib" 2>&1)
        rc=$?
        echo "$out" | tail -1
        if [ $rc -ne 0 ]; then
            log_error "Failed to install $lib"
            FAILED_LIBS+=("$lib")
        fi
    done

    if [ ${#FAILED_LIBS[@]} -gt 0 ]; then
        SETUP_ERRORS=$((SETUP_ERRORS + ${#FAILED_LIBS[@]}))
        log_error "pip install failed for: ${FAILED_LIBS[*]}"
        log_warn "Run: python3 -m pip install -r requirements.txt"
    else
        log_ok "Python libraries installed"
    fi
}

# =============================================
# STEP 5: CREATE DIRECTORIES
# =============================================

create_directories() {
    log_step "STEP 5/9: Creating Project Directories"

    DIRS=(
        "core"
        "scanners"
        "vulns"
        "exploits"
        "native"
        "payloads"
        "payloads/sqli"
        "payloads/xss"
        "payloads/lfi"
        "payloads/cmdi"
        "payloads/ssrf"
        "payloads/upload"
        "c2_server"
        "c2_server/web_ui"
        "wordlists"
        "config"
        "reports"
        "reports/json"
        "reports/html"
        "reports/pdf"
        "reports/loot"
        "logs"
        "downloads"
        "docs"
    )

    for dir in "${DIRS[@]}"; do
        mkdir -p "$SCRIPT_DIR/$dir"
        touch "$SCRIPT_DIR/$dir/.gitkeep" 2>/dev/null
    done

    log_ok "Directories created: ${#DIRS[@]}"

    # Set permissions
    chmod +x "$SCRIPT_DIR/blackhunter.sh" 2>/dev/null || true
    chmod +x "$SCRIPT_DIR/setup.sh" 2>/dev/null || true

    log_ok "Permissions set"
}

# =============================================
# STEP 6: BUILD NATIVE MODULES (C/C++)
# =============================================

build_native_modules() {
    log_step "STEP 6/9: Building Native Modules (C/C++)"

    if [ ! -f "$SCRIPT_DIR/native/Makefile" ]; then
        log_warn "Makefile not found, skipping native build"
        return
    fi

    cd "$SCRIPT_DIR/native"

    # Clean old builds
    make clean 2>/dev/null || true

    # Build
    log_info "Compiling C modules..."
    if make 2>&1 | tail -5; then
        log_ok "Native modules built successfully"

        # List built binaries
        for bin in port_scanner banner_grabber payload_engine hash_cracker packet_crafter crypto_utils; do
            if [ -f "$bin" ]; then
                chmod +x "$bin"
                log_ok "  Built: $bin"
            fi
        done
    else
        log_warn "Native build failed (optional)"
    fi

    cd "$SCRIPT_DIR"
}

# =============================================
# STEP 7: CREATE CONFIG FILE
# =============================================

create_config() {
    log_step "STEP 7/9: Creating Configuration File"

    if [ ! -f "$SCRIPT_DIR/config/config.json" ]; then
        cat > "$SCRIPT_DIR/config/config.json" << 'EOF'
{
    "name": "BlackHunter",
    "version": "1.0.0",
    "description": "Academic Penetration Testing Tool - Isolated Lab Only",

    "scan_settings": {
        "timeout": 10,
        "threads": 10,
        "user_agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "max_redirects": 5,
        "verify_ssl": false,
        "follow_redirects": true,
        "retry_count": 2,
        "delay_between_requests": 0.1,
        "max_scan_time": 1200
    },

    "modules": {
        "recon": { "enabled": true },
        "port": { "enabled": true, "timeout": 2, "threads": 100 },
        "web": { "enabled": true, "threads": 20 },
        "cms": { "enabled": true },
        "subdomain": { "enabled": true },
        "sqli": { "enabled": true, "severity": "CRITICAL" },
        "xss": { "enabled": true, "severity": "MEDIUM" },
        "lfi": { "enabled": true, "severity": "HIGH" },
        "cmdi": { "enabled": true, "severity": "CRITICAL" },
        "ssrf": { "enabled": true, "severity": "HIGH" },
        "upload": { "enabled": true, "severity": "CRITICAL" },
        "xxe": { "enabled": true, "severity": "HIGH" },
        "csrf": { "enabled": true, "severity": "MEDIUM" },
        "idor": { "enabled": true, "severity": "HIGH" },
        "redirect": { "enabled": true, "severity": "LOW" }
    },

    "exploitation": {
        "enabled": false,
        "require_confirmation": true,
        "isolated_lab_only": true,
        "save_loot": true,
        "loot_dir": "reports/loot",
        "max_exploit_attempts": 3
    },

    "c2_server": {
        "host": "0.0.0.0",
        "port": 4443,
        "use_tls": true,
        "web_ui_enabled": true,
        "web_ui_port": 8080
    },

    "output": {
        "report_dir": "reports",
        "log_dir": "logs",
        "save_json": true,
        "save_html": true,
        "save_pdf": false,
        "verbose": true,
        "color_output": true,
        "show_progress": true
    },

    "stealth": {
        "randomize_user_agents": true,
        "randomize_delays": true,
        "min_delay": 0.1,
        "max_delay": 0.5,
        "use_proxies": false,
        "proxy_list": []
    },

    "ethical_guardrails": {
        "require_authorization": true,
        "target_whitelist": [
            "127.0.0.1",
            "localhost",
            "testphp.vulnweb.com",
            "demo.testfire.net",
            "testhtml5.vulnweb.com",
            "juice-shop.herokuapp.com"
        ],
        "block_public_targets": true,
        "warn_on_exploitation": true
    }
}
EOF
        log_ok "Config file created"
    else
        log_ok "Config file already exists"
    fi
}

# =============================================
# STEP 8: DOWNLOAD WORDLISTS
# =============================================

download_wordlists() {
    log_step "STEP 8/9: Preparing Wordlists"

    # Basic wordlists (built-in)
    if [ ! -f "$SCRIPT_DIR/wordlists/directories.txt" ]; then
        cat > "$SCRIPT_DIR/wordlists/directories.txt" << 'EOF'
admin
administrator
api
backup
backups
config
dashboard
db
download
downloads
files
images
includes
js
login
logs
media
panel
private
public
register
setup
sql
static
storage
temp
test
tmp
uploads
user
users
vendor
wp-admin
wp-content
wp-includes
EOF
        log_ok "Created directories.txt"
    fi

    if [ ! -f "$SCRIPT_DIR/wordlists/files.txt" ]; then
        cat > "$SCRIPT_DIR/wordlists/files.txt" << 'EOF'
.env
.env.bak
.env.old
.git/config
.git/HEAD
.htaccess
.htpasswd
.svn/entries
admin.php
backup.sql
backup.zip
composer.json
composer.lock
config.php
config.php.bak
database.sql
db.sql
debug.log
dump.sql
error.log
info.php
package.json
phpinfo.php
readme.html
readme.txt
robots.txt
sitemap.xml
web.config
wp-config.php
wp-config.php.bak
EOF
        log_ok "Created files.txt"
    fi

    if [ ! -f "$SCRIPT_DIR/wordlists/parameters.txt" ]; then
        cat > "$SCRIPT_DIR/wordlists/parameters.txt" << 'EOF'
id
page
file
path
url
uri
src
source
target
dest
destination
redirect
redirect_url
return
return_url
next
callback
callback_url
action
do
cmd
command
exec
execute
run
system
shell
query
search
user
username
email
name
data
input
param
arg
option
flag
test
debug
log
output
result
EOF
        log_ok "Created parameters.txt"
    fi

    if [ ! -f "$SCRIPT_DIR/wordlists/subdomains.txt" ]; then
        cat > "$SCRIPT_DIR/wordlists/subdomains.txt" << 'EOF'
www
mail
ftp
localhost
webmail
smtp
pop
ns1
webdisk
ns2
cpanel
whm
autodiscover
autoconfig
m
imap
test
ns
blog
pop3
dev
www2
admin
forum
news
vpn
ns3
mail2
new
mysql
old
lists
support
mobile
mx
static
docs
beta
shop
sql
secure
demo
cp
calendar
wiki
web
media
email
images
img
download
dns
dns1
dns2
api
app
apps
cdn
cloud
gateway
proxy
login
portal
my
internal
intranet
extranet
stage
staging
prod
production
EOF
        log_ok "Created subdomains.txt"
    fi

    log_ok "Wordlists ready"
}

# =============================================
# STEP 9: VERIFY INSTALLATION
# =============================================

verify_installation() {
    log_step "STEP 9/9: Verifying Installation"

    echo ""
    echo -e "${CYAN}  Environment Check:${NC}"
    echo -e "${CYAN}  ─────────────────────────────────────${NC}"

    # Python
    if command -v python3 &>/dev/null; then
        log_ok "$(python3 --version 2>&1)"
    else
        log_error "Python3 not found"
        SETUP_ERRORS=$((SETUP_ERRORS + 1))
    fi

    # Pip
    if python3 -m pip --version &>/dev/null; then
        log_ok "pip installed"
    else
        log_error "pip not found"
        SETUP_ERRORS=$((SETUP_ERRORS + 1))
    fi

    # Git
    if command -v git &>/dev/null; then
        log_ok "Git installed"
    else
        log_warn "Git not found"
    fi

    # Clang
    if command -v clang &>/dev/null; then
        log_ok "Clang installed"
    else
        log_warn "Clang not found"
    fi

    echo ""
    echo -e "${CYAN}  Python Libraries:${NC}"
    echo -e "${CYAN}  ─────────────────────────────────────${NC}"

    LIBS_CHECK=(
        "requests:requests"
        "colorama:colorama"
        "dns:dnspython"
        "whois:python-whois"
        "cryptography:cryptography"
    )

    for lib_check in "${LIBS_CHECK[@]}"; do
        lib_name="${lib_check%%:*}"
        lib_full="${lib_check##*:}"

        if python3 -c "import $lib_name" 2>/dev/null; then
            log_ok "$lib_full"
        else
            log_error "$lib_full missing"
            SETUP_ERRORS=$((SETUP_ERRORS + 1))
        fi
    done

    echo ""
    echo -e "${CYAN}  Directory Structure:${NC}"
    echo -e "${CYAN}  ─────────────────────────────────────${NC}"

    DIRS_CHECK=(
        "core"
        "scanners"
        "vulns"
        "exploits"
        "native"
        "payloads"
        "c2_server"
        "wordlists"
        "config"
        "reports"
        "logs"
    )

    for dir in "${DIRS_CHECK[@]}"; do
        if [ -d "$SCRIPT_DIR/$dir" ]; then
            log_ok "$dir/"
        else
            log_error "$dir/ missing"
        fi
    done
}

# =============================================
# FINAL MESSAGE
# =============================================

show_completion() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}           SETUP COMPLETED SUCCESSFULLY${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}  🎯 BlackHunter Pro is ready to use!${NC}"
    echo ""
    echo -e "${WHITE}  How to use:${NC}"
    echo -e "${CYAN}  ─────────────────────────────────────${NC}"
    echo -e "  ${GREEN}./blackhunter.sh${NC}          ${WHITE}# Launch${NC}"
    echo ""
    echo -e "${WHITE}  Quick commands:${NC}"
    echo -e "${CYAN}  ─────────────────────────────────────${NC}"
    echo -e "  ${GREEN}python3 core/runner.py --help${NC}"
    echo -e "  ${GREEN}ls reports/${NC}"
    echo -e "  ${GREEN}ls logs/${NC}"
    echo ""
    echo -e "${YELLOW}  [⚠] Ethical Warning:${NC}"
    echo -e "${YELLOW}  ─────────────────────────────────────${NC}"
    echo -e "${YELLOW}  Use ONLY in isolated lab environment.${NC}"
    echo -e "${YELLOW}  Never target systems you don't own.${NC}"
    echo ""
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# =============================================
# MAIN
# =============================================

main() {
    show_banner
    check_termux

    update_packages
    install_core_packages
    upgrade_pip
    install_python_libs
    create_directories
    build_native_modules
    create_config
    download_wordlists
    verify_installation

    if [ "$SETUP_ERRORS" -gt 0 ]; then
        echo ""
        log_error "Setup finished with $SETUP_ERRORS error(s) - fix the failures above"
        exit 1
    fi

    show_completion

    echo -ne "${YELLOW}[?] Launch BlackHunter now? (y/n): ${NC}"
    read -r launch

    if [[ "$launch" =~ ^[Yy]$ ]]; then
        exec "$SCRIPT_DIR/blackhunter.sh"
    fi
}

trap 'echo -e "\n${YELLOW}[!] Setup interrupted${NC}"; exit 1' INT

main