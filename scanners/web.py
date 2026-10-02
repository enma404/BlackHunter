# scanners/web.py
# BlackHunter Pro - Web Scanner
# Directory bruteforce, file discovery, HTTP methods, parameter discovery

import re
import os
import requests
import concurrent.futures
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class WebScanner:
    """
    Web Scanner Module
    - Directory & file bruteforce
    - HTTP methods testing
    - Parameter discovery
    - Backup file detection
    - Sensitive file detection
    - Virtual host detection
    - HTTP response analysis
    - Form discovery
    """

    # =============================================
    # COMMON DIRECTORIES
    # =============================================

    COMMON_DIRECTORIES = [
        # Admin & Login
        "admin", "administrator", "admin1", "admin2", "admin_area", "adminarea",
        "adm", "manager", "management", "panel", "cpanel",
        "dashboard", "login", "signin", "sign-in", "auth", "authenticate",
        "wp-admin", "wp-login", "wp-login.php", "user", "users", "account",
        "accounts", "profile", "profiles", "member", "members",

        # API & Backend
        "api", "api/v1", "api/v2", "api/v3", "apis", "rest", "graphql",
        "graphiql", "playground", "swagger", "swagger-ui", "swagger.json",
        "openapi", "openapi.json", "docs", "documentation", "doc", "help",
        "backend", "back-end", "server", "service", "services", "internal",
        "private", "restricted", "secure",

        # Files & Uploads
        "files", "file", "uploads", "upload", "downloads", "download",
        "media", "images", "img", "image", "assets", "static", "public",
        "content", "contents", "data", "storage", "cache", "tmp", "temp",
        "backup", "backups", "bak", "old", "archive", "archives",

        # Config & Dev
        "config", "configuration", "settings", "setup", "install",
        "installation", "update", "updates", "upgrade", "maintenance",
        "dev", "development", "staging", "test", "tests", "testing",
        "demo", "sandbox", "debug", "logs", "log",

        # Source Code
        "src", "source", "code", "app", "application", "apps",
        "lib", "library", "libraries", "include", "includes", "inc",
        "vendor", "node_modules", "bower_components",

        # CMS Specific
        "wp-content", "wp-includes", "wp-json", "wordpress",
        "components", "modules", "plugins", "themes", "templates",
        "sites", "core", "system", "cms",

        # Misc
        "info", "about", "contact", "support", "faq", "blog", "news",
        "rss", "feed", "sitemap", "sitemap.xml", "robots.txt",
        "crossdomain.xml", "clientaccesspolicy.xml",
        "phpinfo.php", "info.php", "test.php", "phpmyadmin", "pma",
        "myadmin", "mysql", "sql", "database", "db",
    ]

    # =============================================
    # SENSITIVE FILES
    # =============================================

    SENSITIVE_FILES = [
        # Config files
        ".env", ".env.local", ".env.backup", ".env.bak", ".env.old",
        ".env.dev", ".env.production", ".env.staging",
        "config.php", "config.php.bak", "config.php.old", "config.php.orig",
        "config.js", "config.json", "config.xml", "config.yml", "config.yaml",
        "configuration.php", "settings.php", "settings.py", "settings.json",
        "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        "web.config", "app.config", "application.yml", "application.properties",

        # Git & SVN
        ".git/config", ".git/HEAD", ".git/index", ".gitignore",
        ".svn/entries", ".svn/wc.db", ".hg/store", ".hgignore",

        # Backup files
        "backup.sql", "backup.zip", "backup.tar.gz", "backup.rar",
        "database.sql", "db.sql", "dump.sql", "data.sql",
        "site.zip", "www.zip", "website.zip", "public_html.zip",
        "backup-2024.zip", "backup-2023.zip", "backup-2025.zip",
        "index.php.bak", "index.php~", "index.php.old", "index.php.orig",
        "app.js.bak", "app.js.old", "styles.css.bak",

        # Logs
        "access.log", "error.log", "debug.log", "application.log",
        "app.log", "server.log", "web.log", "logs/error.log",
        "logs/access.log", "storage/logs/laravel.log",
        "var/log/apache2/error.log", "var/log/nginx/error.log",

        # Sensitive info
        "phpinfo.php", "info.php", "test.php", "phpinfo",
        "readme.txt", "readme.md", "README.md", "CHANGELOG.md",
        "LICENSE.txt", "license.txt", "VERSION", "version.txt",

        # Admin files
        "admin.php", "admin.html", "admin.jsp", "admin.aspx",
        "login.php", "login.html", "login.jsp", "login.aspx",
        "phpmyadmin/", "phpMyAdmin/", "pma/", "adminer.php", "adminer/",

        # API docs
        "swagger.json", "swagger.yaml", "swagger.yml",
        "openapi.json", "openapi.yaml", "openapi.yml",
        "api-docs", "api/docs", "docs/api",

        # Package managers
        "composer.json", "composer.lock",
        "package.json", "package-lock.json", "yarn.lock",
        "requirements.txt", "Pipfile", "Pipfile.lock",
        "Gemfile", "Gemfile.lock", "pom.xml", "build.gradle",

        # IDE & Editor
        ".idea/workspace.xml", ".vscode/settings.json",
        ".DS_Store", "Thumbs.db", "desktop.ini",

        # SSH & Keys
        ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/authorized_keys",
        "id_rsa", "id_rsa.pub", "id_dsa",

        # Docker & Kubernetes
        "Dockerfile", "docker-compose.yml", ".dockerenv",
        "kubernetes.yml", "k8s.yml",

        # CI/CD
        ".github/workflows/", ".gitlab-ci.yml", ".travis.yml",
        "Jenkinsfile", "circle.yml",
    ]

    # =============================================
    # HTTP METHODS
    # =============================================

    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'TRACE', 'HEAD', 'CONNECT']

    # =============================================
    # INITIALIZATION
    # =============================================

    def __init__(self, target, timeout=10, threads=20, user_agent=None):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        self.session.verify = False

        self.results = {
            'target': self.target,
            'directories': [],
            'files': [],
            'sensitive_files': [],
            'http_methods': [],
            'parameters': [],
            'forms': [],
            'status_codes': {},
            'tech_stack': [],
        }

        self._baseline = None
        self._lock = None

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute web scan"""
        print(f"{Fore.CYAN}[*] Web Scanner started")
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print()

        # Get baseline
        self._get_baseline()

        # Run scans
        self._scan_directories()
        self._scan_sensitive_files()
        self._test_http_methods()
        self._discover_parameters()
        self._discover_forms()

        return self.results

    # =============================================
    # BASELINE
    # =============================================

    def _get_baseline(self):
        """Get baseline response for filtering false positives"""
        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)
            self._baseline = {
                'status': r.status_code,
                'length': len(r.text),
                'content': r.text[:500]
            }
        except Exception:
            self._baseline = {'status': 0, 'length': 0, 'content': ''}

    def _is_false_positive(self, response):
        """Check if response is a soft 404 or false positive"""
        if not self._baseline:
            return False

        # Same length as baseline (likely 404 page)
        if abs(len(response.text) - self._baseline['length']) < 50:
            return True

        # Contains "not found" text
        lower = response.text.lower()[:500]
        if any(x in lower for x in ['not found', '404', 'page not found', 'does not exist']):
            return True

        return False

    # =============================================
    # DIRECTORY SCAN
    # =============================================

    def _scan_directories(self):
        """Bruteforce common directories"""
        print(f"{Fore.YELLOW}[*] Scanning directories ({len(self.COMMON_DIRECTORIES)})...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_path, directory, 'directory'): directory
                for directory in self.COMMON_DIRECTORIES
            }

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        if result['type'] == 'directory':
                            self.results['directories'].append(result)
                            color = Fore.GREEN if result['status'] == 200 else Fore.YELLOW
                            print(f"{color}  [+] [{result['status']}] /{result['path']}{Style.RESET_ALL}")
                except Exception:
                    pass

    # =============================================
    # SENSITIVE FILES SCAN
    # =============================================

    def _scan_sensitive_files(self):
        """Scan for sensitive files"""
        print(f"{Fore.YELLOW}[*] Scanning sensitive files ({len(self.SENSITIVE_FILES)})...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_path, file_path, 'file'): file_path
                for file_path in self.SENSITIVE_FILES
            }

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results['sensitive_files'].append(result)
                        print(f"{Fore.RED}  [!] [{result['status']}] {result['path']} ({result['size']} bytes){Style.RESET_ALL}")
                except Exception:
                    pass

    # =============================================
    # CHECK SINGLE PATH
    # =============================================

    def _check_path(self, path, path_type='directory'):
        """Check if a path exists"""
        try:
            url = urljoin(self.target + '/', path.lstrip('/'))
            r = self.session.get(url, timeout=self.timeout, allow_redirects=False, verify=False)

            # Filter false positives
            if r.status_code == 200 and self._is_false_positive(r):
                return None

            # Check interesting status codes
            if r.status_code in [200, 201, 301, 302, 401, 403, 500]:
                result = {
                    'path': path,
                    'url': url,
                    'status': r.status_code,
                    'size': len(r.content),
                    'type': path_type,
                    'content_type': r.headers.get('Content-Type', ''),
                }

                # Mark interesting files
                if path_type == 'file':
                    if any(k in path.lower() for k in ['.env', '.git', 'config', 'backup', '.sql', '.zip', 'phpinfo']):
                        result['interesting'] = True

                return result
        except Exception:
            pass

        return None

    # =============================================
    # HTTP METHODS
    # =============================================

    def _test_http_methods(self):
        """Test HTTP methods"""
        print(f"{Fore.YELLOW}[*] Testing HTTP methods...")

        for method in self.HTTP_METHODS:
            try:
                r = self.session.request(method, self.target, timeout=self.timeout, verify=False)

                method_info = {
                    'method': method,
                    'status': r.status_code,
                    'allowed': r.status_code < 400,
                    'size': len(r.content),
                }

                self.results['http_methods'].append(method_info)

                if r.status_code < 400:
                    # Dangerous methods
                    if method in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
                        print(f"{Fore.RED}  [!] {method}: {r.status_code} (DANGEROUS){Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}  [+] {method}: {r.status_code}{Style.RESET_ALL}")
            except Exception:
                pass

    # =============================================
    # PARAMETER DISCOVERY
    # =============================================

    def _discover_parameters(self):
        """Discover parameters from HTML"""
        print(f"{Fore.YELLOW}[*] Discovering parameters...")

        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)

            # Find URL parameters in HTML
            params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', r.text)
            unique_params = list(set(params))

            if unique_params:
                self.results['parameters'] = unique_params
                print(f"{Fore.GREEN}  [+] Found {len(unique_params)} parameters: {', '.join(unique_params[:10])}")
        except Exception:
            pass

    # =============================================
    # FORM DISCOVERY
    # =============================================

    def _discover_forms(self):
        """Discover HTML forms"""
        print(f"{Fore.YELLOW}[*] Discovering forms...")

        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)

            # Find all forms
            forms = re.findall(r'<form[^>]*>.*?</form>', r.text, re.IGNORECASE | re.DOTALL)

            for form in forms:
                # Extract action
                action_match = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
                action = action_match.group(1) if action_match else self.target

                # Extract method
                method_match = re.search(r'method=["\']([^"\']*)["\']', form, re.IGNORECASE)
                method = method_match.group(1).upper() if method_match else 'GET'

                # Extract inputs
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form, re.IGNORECASE)
                textareas = re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', form, re.IGNORECASE)
                selects = re.findall(r'<select[^>]*name=["\']([^"\']+)["\']', form, re.IGNORECASE)

                all_params = inputs + textareas + selects

                if all_params:
                    form_info = {
                        'action': action,
                        'method': method,
                        'params': all_params,
                        'url': urljoin(self.target + '/', action),
                    }
                    self.results['forms'].append(form_info)
                    print(f"{Fore.GREEN}  [+] Form: {method} {action} [{', '.join(all_params[:5])}]{Style.RESET_ALL}")
        except Exception:
            pass

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        r = self.results

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  WEB SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Target:           {r['target']}")
        print(f"{Fore.GREEN}[+] Directories:      {len(r['directories'])}")
        print(f"{Fore.RED}[+] Sensitive Files:  {len(r['sensitive_files'])}")
        print(f"{Fore.GREEN}[+] HTTP Methods:     {len(r['http_methods'])}")
        print(f"{Fore.GREEN}[+] Parameters:       {len(r['parameters'])}")
        print(f"{Fore.GREEN}[+] Forms:            {len(r['forms'])}")

        if r['sensitive_files']:
            print(f"\n{Fore.RED}[!] Sensitive Files Found:")
            for f in r['sensitive_files'][:10]:
                print(f"{Fore.RED}    - [{f['status']}] {f['path']} ({f['size']} bytes)")

        if r['directories']:
            print(f"\n{Fore.GREEN}[+] Interesting Directories:")
            for d in r['directories'][:10]:
                print(f"{Fore.GREEN}    - [{d['status']}] {d['path']}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["WebScanner"]