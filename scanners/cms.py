# scanners/cms.py
# BlackHunter Pro - CMS Detector
# Detects WordPress, Joomla, Craft CMS, Drupal, Magento and more

import re
import json
import requests
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class CMSDetector:
    """
    CMS Detection Module
    - Detects multiple CMS platforms
    - Identifies version
    - Finds admin panels
    - Enumerates plugins/themes
    - Checks for known vulnerabilities
    """

    # =============================================
    # CMS SIGNATURES
    # =============================================

    CMS_SIGNATURES = {
        "WordPress": {
            "paths": [
                "/wp-login.php", "/wp-admin/", "/wp-content/",
                "/wp-includes/", "/wp-json/", "/xmlrpc.php",
                "/readme.html", "/license.txt",
            ],
            "html": [
                "wp-content", "wp-includes", "wp-emoji",
                "wp-block-library", "wp-embed", "WordPress",
            ],
            "headers": ["X-Pingback", "Link: <.*wp-json.*>"],
            "meta": [r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']WordPress'],
        },
        "Joomla": {
            "paths": [
                "/administrator/", "/components/", "/modules/",
                "/templates/", "/language/", "/configuration.php",
                "/htaccess.txt", "/README.txt",
                "/administrator/manifests/files/joomla.xml",
            ],
            "html": [
                "joomla", "/media/jui/", "/media/system/",
                "option=com_", "Joomla!",
            ],
            "headers": ["X-Content-Encoded-By: Joomla"],
            "meta": [r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']Joomla'],
        },
        "Craft CMS": {
            "paths": [
                "/admin", "/admin/login", "/index.php/admin",
                "/cpresources/", "/.env", "/composer.json", "/storage/",
            ],
            "html": ["craftcms", "Craft CMS", "craft.app", "CRAFT_", "/cpresources/"],
            "headers": ["X-Powered-By: Craft CMS"],
            "meta": [r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']Craft'],
        },
        "Drupal": {
            "paths": [
                "/sites/default/", "/core/", "/modules/",
                "/themes/", "/user/login", "/user/register",
                "/CHANGELOG.txt", "/core/CHANGELOG.txt",
            ],
            "html": ["Drupal", "drupal.js", "/sites/default/files/", "Drupal.settings"],
            "headers": ["X-Generator: Drupal", "X-Drupal-Cache"],
            "meta": [r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']Drupal'],
        },
        "Magento": {
            "paths": [
                "/admin/", "/downloader/", "/app/etc/local.xml",
                "/js/mage/", "/skin/frontend/", "/media/", "/index.php/admin",
            ],
            "html": ["Magento", "mage/", "Mage.Cookies", "VarienForm", "js/mage"],
            "headers": ["X-Magento"],
            "cookies": ["frontend", "adminhtml"],
        },
        "PrestaShop": {
            "paths": [
                "/admin", "/modules/", "/themes/",
                "/config/", "/controllers/", "/classes/",
            ],
            "html": ["prestashop", "PrestaShop", "prestashop.com", "var prestashop"],
            "headers": ["X-Powered-By: PrestaShop"],
        },
        "Shopify": {
            "paths": [],
            "html": ["cdn.shopify.com", "shopify.com", "Shopify.theme", "shopify-buy"],
            "headers": ["X-ShopId", "X-Shopify", "X-Sorting-Hat-ShopId"],
        },
        "Squarespace": {
            "paths": [],
            "html": ["squarespace.com", "static.squarespace.com", "Squarespace", "sqs-"],
            "headers": ["X-ServedBy", "X-Squarespace"],
        },
        "Wix": {
            "paths": [],
            "html": ["wix.com", "wixstatic.com", "wix-image", "wixapps"],
            "headers": ["X-Wix-"],
        },
        "TYPO3": {
            "paths": ["/typo3/", "/typo3conf/", "/typo3temp/", "/fileadmin/", "/uploads/"],
            "html": ["TYPO3", "typo3conf", "typo3temp"],
            "headers": ["X-TYPO3"],
        },
        "MODX": {
            "paths": ["/manager/", "/connectors/", "/assets/", "/core/"],
            "html": ["MODX", "modx", "manager/media/"],
            "headers": ["X-Powered-By: MODX"],
        },
        "Ghost": {
            "paths": ["/ghost/", "/ghost/api/", "/content/", "/assets/"],
            "html": ["ghost.org", "ghost-", "Ghost"],
            "headers": ["X-Ghost-Cache-Status"],
        },
        "Concrete CMS": {
            "paths": ["/concrete/", "/application/", "/packages/", "/index.php/dashboard"],
            "html": ["concrete5", "concretecms", "ccm_"],
            "headers": ["X-Powered-By: Concrete CMS"],
        },
        "Bitrix": {
            "paths": ["/bitrix/", "/upload/", "/bitrix/admin/", "/bitrix/js/"],
            "html": ["bitrix", "Bitrix"],
            "headers": ["X-Powered-CMS: Bitrix"],
        },
    }

    # =============================================
    # COMMON ADMIN PATHS
    # =============================================

    COMMON_PATHS = [
        "/admin", "/administrator", "/login", "/wp-admin",
        "/wp-login.php", "/user/login", "/admin/login",
        "/dashboard", "/panel", "/cpanel", "/manage",
        "/management",
    ]

    # =============================================
    # CMS ADMIN PATHS
    # =============================================

    CMS_ADMIN_PATHS = {
        "WordPress": ["/wp-admin/", "/wp-login.php"],
        "Joomla": ["/administrator/", "/administrator/index.php"],
        "Craft CMS": ["/admin", "/admin/login"],
        "Drupal": ["/user/login", "/admin/", "/user"],
        "Magento": ["/admin/", "/index.php/admin"],
        "PrestaShop": ["/admin", "/admin123"],
        "TYPO3": ["/typo3/", "/typo3/login"],
        "Ghost": ["/ghost/", "/ghost/#/signin"],
    }

    # =============================================
    # INITIALIZATION
    # =============================================

    def __init__(self, target, timeout=10, user_agent=None):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        self.session.verify = False

        self.results = {
            'target': self.target,
            'detected': [],
            'primary_cms': None,
            'admin_panels': [],
            'versions': {},
            'plugins': [],
            'themes': [],
            'technologies': [],
            'vulnerabilities': [],
        }

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Run CMS detection"""
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print()

        # 1. Detect all CMS
        self._detect_all()

        # 2. Find admin panels
        self._find_admin_panels()

        # 3. Detect versions
        self._detect_versions()

        # 4. Enumerate plugins/themes
        self._enumerate_plugins()

        # 5. Check vulnerabilities
        self._check_vulnerabilities()

        return self.results

    # =============================================
    # DETECT ALL CMS
    # =============================================

    def _detect_all(self):
        """Detect all possible CMS"""
        print(f"{Fore.YELLOW}[*] Detecting CMS platforms...")

        for cms_name, signatures in self.CMS_SIGNATURES.items():
            score = 0
            evidence = []

            # 1. Check paths
            for path in signatures.get('paths', []):
                try:
                    url = urljoin(self.target + '/', path.lstrip('/'))
                    r = self.session.get(url, timeout=5, allow_redirects=False, verify=False)

                    if r.status_code in [200, 301, 302, 401, 403]:
                        score += 2
                        evidence.append(f"path:{path}")
                except:
                    pass

            # 2. Check HTML
            try:
                r = self.session.get(self.target, timeout=self.timeout, verify=False)
                html = r.text.lower()

                for sig in signatures.get('html', []):
                    if sig.lower() in html:
                        score += 3
                        evidence.append(f"html:{sig}")

                # 3. Check meta generator
                for pattern in signatures.get('meta', []):
                    if re.search(pattern, r.text, re.IGNORECASE):
                        score += 5
                        evidence.append("meta:generator")

                # 4. Check headers
                for header_pattern in signatures.get('headers', []):
                    header_str = str(r.headers)
                    if re.search(header_pattern, header_str, re.IGNORECASE):
                        score += 4
                        evidence.append(f"header:{header_pattern[:20]}")

                # 5. Check cookies
                for cookie_name in signatures.get('cookies', []):
                    if cookie_name in self.session.cookies:
                        score += 2
                        evidence.append(f"cookie:{cookie_name}")
            except:
                pass

            # Consider detected if score >= 3
            if score >= 3:
                detected = {
                    'name': cms_name,
                    'score': score,
                    'evidence': evidence,
                }
                self.results['detected'].append(detected)

                print(f"{Fore.GREEN}  [+] Detected: {cms_name} (score: {score})")

                # Set primary CMS
                if self.results['primary_cms'] is None or score > self.results['primary_cms']['score']:
                    self.results['primary_cms'] = detected

        if not self.results['detected']:
            print(f"{Fore.YELLOW}  [-] No CMS detected")

    # =============================================
    # FIND ADMIN PANELS
    # =============================================

    def _find_admin_panels(self):
        """Find admin panels"""
        print(f"{Fore.YELLOW}[*] Finding admin panels...")

        paths_to_check = list(self.COMMON_PATHS)

        if self.results['primary_cms']:
            cms_name = self.results['primary_cms']['name']
            if cms_name in self.CMS_ADMIN_PATHS:
                paths_to_check = self.CMS_ADMIN_PATHS[cms_name] + paths_to_check

        for path in set(paths_to_check):
            try:
                url = urljoin(self.target + '/', path.lstrip('/'))
                r = self.session.get(url, timeout=5, allow_redirects=True, verify=False)

                if r.status_code == 200:
                    html_lower = r.text.lower()
                    is_login = any(x in html_lower for x in [
                        'login', 'sign in', 'password', 'username',
                        'admin', 'dashboard', 'authenticate'
                    ])

                    if is_login:
                        self.results['admin_panels'].append({
                            'url': url,
                            'path': path,
                            'status': r.status_code,
                            'login': True,
                        })
                        print(f"{Fore.GREEN}  [+] Admin panel: {url}")
            except:
                continue

    # =============================================
    # DETECT VERSIONS
    # =============================================

    def _detect_versions(self):
        """Detect CMS versions"""
        print(f"{Fore.YELLOW}[*] Detecting versions...")

        if not self.results['primary_cms']:
            return

        cms_name = self.results['primary_cms']['name']

        version_paths = {
            "WordPress": ["/readme.html", "/wp-includes/version.php", "/feed/"],
            "Joomla": ["/administrator/manifests/files/joomla.xml", "/README.txt"],
            "Craft CMS": ["/composer.json", "/composer.lock", "/CHANGELOG.md"],
            "Drupal": ["/CHANGELOG.txt", "/core/CHANGELOG.txt"],
        }

        paths = version_paths.get(cms_name, [])

        for path in paths:
            try:
                url = urljoin(self.target + '/', path.lstrip('/'))
                r = self.session.get(url, timeout=self.timeout, verify=False)

                if r.status_code == 200:
                    version = self._extract_version(r.text, cms_name)
                    if version:
                        self.results['versions'][cms_name] = version
                        print(f"{Fore.GREEN}  [+] {cms_name} version: {version}")
                        return
            except:
                continue

        # Try meta generator
        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)
            version = self._extract_version(r.text, cms_name)
            if version:
                self.results['versions'][cms_name] = version
                print(f"{Fore.GREEN}  [+] {cms_name} version: {version}")
        except:
            pass

    def _extract_version(self, html, cms_name):
        """Extract version from HTML"""
        patterns = {
            "WordPress": [
                r'Version\s+([\d.]+)',
                r'WordPress\s+([\d.]+)',
                r'wp-emoji-release\.min\.js\?ver=([\d.]+)',
                r'"version":"([\d.]+)"',
            ],
            "Joomla": [
                r'<version>([\d.]+)</version>',
                r'Joomla!\s+([\d.]+)',
                r'version\s*=\s*["\']([\d.]+)["\']',
            ],
            "Craft CMS": [
                r'"version":\s*"([\d.]+)"',
                r'Craft CMS\s+([\d.]+)',
                r'craftcms/cms[":\s]+([\d.]+)',
            ],
            "Drupal": [
                r'Drupal\s+([\d.]+)',
                r'"version":\s*"([\d.]+)"',
                r'VERSION.*?([\d.]+)',
            ],
        }

        for pattern in patterns.get(cms_name, []):
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    # =============================================
    # ENUMERATE PLUGINS
    # =============================================

    def _enumerate_plugins(self):
        """Enumerate plugins and themes"""
        print(f"{Fore.YELLOW}[*] Enumerating plugins & themes...")

        if not self.results['primary_cms']:
            return

        cms_name = self.results['primary_cms']['name']

        if cms_name == "WordPress":
            self._enum_wordpress_plugins()
            self._enum_wordpress_themes()
        elif cms_name == "Joomla":
            self._enum_joomla_components()
        elif cms_name == "Craft CMS":
            self._enum_craft_plugins()

    def _enum_wordpress_plugins(self):
        """Enumerate WordPress plugins"""
        common_plugins = [
            "akismet", "jetpack", "wordpress-seo", "contact-form-7",
            "woocommerce", "elementor", "wpforms-lite", "wordfence",
            "really-simple-ssl", "all-in-one-wp-migration",
            "advanced-custom-fields", "buddypress", "bbpress",
            "wp-super-cache", "w3-total-cache", "duplicator",
            "backupwordpress", "updraftplus", "redirection",
        ]

        for plugin in common_plugins:
            paths = [
                f"/wp-content/plugins/{plugin}/readme.txt",
                f"/wp-content/plugins/{plugin}/README.txt",
                f"/wp-content/plugins/{plugin}/style.css",
            ]

            for path in paths:
                try:
                    url = urljoin(self.target + '/', path.lstrip('/'))
                    r = self.session.get(url, timeout=3, allow_redirects=False, verify=False)

                    if r.status_code == 200:
                        version = None
                        version_match = re.search(r'Stable tag:\s*([\d.]+)', r.text, re.IGNORECASE)
                        if version_match:
                            version = version_match.group(1)

                        plugin_info = {
                            'name': plugin,
                            'version': version or 'unknown',
                        }

                        self.results['plugins'].append(plugin_info)
                        print(f"{Fore.GREEN}  [+] Plugin: {plugin} v{version or '?'}")
                        break
                except:
                    continue

    def _enum_wordpress_themes(self):
        """Enumerate WordPress themes"""
        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)
            themes = re.findall(r'/wp-content/themes/([a-zA-Z0-9\-_]+)/', r.text)

            for theme in set(themes):
                self.results['themes'].append({'name': theme})
                print(f"{Fore.GREEN}  [+] Theme: {theme}")
        except:
            pass

    def _enum_joomla_components(self):
        """Enumerate Joomla components"""
        common_components = [
            "com_content", "com_users", "com_contact", "com_jce",
            "com_k2", "com_virtuemart", "com_hikashop", "com_akeeba",
        ]

        for component in common_components:
            paths = [
                f"/components/{component}/",
                f"/administrator/components/{component}/",
            ]

            for path in paths:
                try:
                    url = urljoin(self.target + '/', path.lstrip('/'))
                    r = self.session.get(url, timeout=3, allow_redirects=False, verify=False)

                    if r.status_code == 200:
                        self.results['plugins'].append({'name': component})
                        print(f"{Fore.GREEN}  [+] Component: {component}")
                        break
                except:
                    continue

    def _enum_craft_plugins(self):
        """Enumerate Craft CMS plugins"""
        try:
            url = urljoin(self.target + '/', "composer.json")
            r = self.session.get(url, timeout=self.timeout, verify=False)

            if r.status_code == 200:
                try:
                    data = json.loads(r.text)
                    for name, version in data.get('require', {}).items():
                        if 'craft' in name.lower() or 'cms' in name.lower():
                            self.results['plugins'].append({
                                'name': name,
                                'version': version,
                            })
                            print(f"{Fore.GREEN}  [+] Plugin: {name} {version}")
                except:
                    pass
        except:
            pass

    # =============================================
    # VULNERABILITY CHECK
    # =============================================

    def _check_vulnerabilities(self):
        """Check for known CMS vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Checking known vulnerabilities...")

        if not self.results['primary_cms']:
            return

        cms_name = self.results['primary_cms']['name']
        version = self.results['versions'].get(cms_name)

        if not version:
            return

        # Known CVEs database
        known_vulns = {
            "WordPress": {
                "6.4.3": [{"cve": "CVE-2024-4439", "severity": "HIGH", "desc": "Stored XSS in Avatar block"}],
                "5.0": [{"cve": "CVE-2019-8942", "severity": "CRITICAL", "desc": "RCE via image metadata"}],
            },
            "Joomla": {
                "3.9.14": [{"cve": "CVE-2020-XXXXX", "severity": "HIGH", "desc": "Various vulnerabilities"}],
                "4.2.7": [{"cve": "CVE-2023-23752", "severity": "CRITICAL", "desc": "Unauthorized access to WebService"}],
            },
            "Craft CMS": {
                "4.4.14": [{"cve": "CVE-2023-41892", "severity": "CRITICAL", "desc": "RCE via unauthenticated endpoint"}],
                "3.9.14": [{"cve": "CVE-2024-56145", "severity": "CRITICAL", "desc": "RCE via register_argc_argv"}],
            },
        }

        if cms_name in known_vulns:
            for vuln_version, vulns in known_vulns[cms_name].items():
                if version == vuln_version:
                    for vuln in vulns:
                        self.results['vulnerabilities'].append({
                            'cms': cms_name,
                            'version': version,
                            'cve': vuln['cve'],
                            'severity': vuln['severity'],
                            'description': vuln['desc'],
                        })
                        print(f"{Fore.RED}  [!] {vuln['cve']} - {vuln['desc']}")

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  CMS DETECTION SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        if self.results['detected']:
            print(f"{Fore.GREEN}[+] Detected CMS:")
            for cms in self.results['detected']:
                print(f"{Fore.GREEN}    - {cms['name']} (score: {cms['score']})")
        else:
            print(f"{Fore.YELLOW}[-] No CMS detected")

        if self.results['versions']:
            print(f"\n{Fore.GREEN}[+] Versions:")
            for cms, version in self.results['versions'].items():
                print(f"{Fore.GREEN}    - {cms}: {version}")

        if self.results['admin_panels']:
            print(f"\n{Fore.GREEN}[+] Admin Panels:")
            for panel in self.results['admin_panels']:
                print(f"{Fore.GREEN}    - {panel['url']}")

        if self.results['plugins']:
            print(f"\n{Fore.GREEN}[+] Plugins/Components: {len(self.results['plugins'])}")

        if self.results['themes']:
            print(f"\n{Fore.GREEN}[+] Themes: {len(self.results['themes'])}")

        if self.results['vulnerabilities']:
            print(f"\n{Fore.RED}[!] Vulnerabilities:")
            for vuln in self.results['vulnerabilities']:
                print(f"{Fore.RED}    - {vuln['cve']} ({vuln['severity']}): {vuln['description']}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["CMSDetector"]