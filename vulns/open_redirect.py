# vulns/open_redirect.py
# BlackHunter Pro - Open Redirect Scanner
# Detects: Open Redirect vulnerabilities

import re
import requests
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class RedirectScanner:
    """
    Open Redirect Scanner
    - Parameter-based redirection
    - Path-based redirection
    - JavaScript-based redirection
    - Meta refresh redirection
    - Header-based redirection
    - Filter bypass techniques
    """

    # =============================================
    # REDIRECT-PRONE PARAMETERS
    # =============================================

    REDIRECT_PARAMS = [
        'url', 'uri', 'link', 'redirect', 'redirect_url', 'redirect_uri',
        'redirect_to', 'redirectto', 'redirect_url', 'return', 'return_url',
        'return_to', 'returnto', 'returnurl', 'next', 'next_url', 'nexturl',
        'continue', 'continue_url', 'continue_to', 'goto', 'go', 'go_to',
        'target', 'target_url', 'targeturl', 'dest', 'destination',
        'destination_url', 'dest_url', 'redir', 'redirect_to_url',
        'out', 'out_url', 'view', 'view_url', 'site', 'site_url',
        'to', 'to_url', 'forward', 'forward_url', 'location', 'location_url',
        'ref', 'referer', 'referrer', 'reference', 'callback', 'callback_url',
        'return_path', 'returnpath', 'success', 'success_url', 'failure',
        'failure_url', 'error', 'error_url', 'logout', 'logout_url',
        'login', 'login_url', 'checkout', 'checkout_url', 'pay', 'pay_url',
        'payment', 'payment_url', 'confirm', 'confirm_url', 'verify',
        'verify_url', 'auth', 'auth_url', 'authorize', 'authorize_url',
    ]

    # =============================================
    # REDIRECT TEST PAYLOADS
    # =============================================

    PAYLOADS = [
        # External domains
        'https://evil.com',
        'http://evil.com',
        '//evil.com',
        '///evil.com',
        '////evil.com',
        'https://evil.com/',
        'http://evil.com/',
        'https://attacker.com',
        'http://attacker.com',
        'https://google.com',
        'http://google.com',

        # Protocol variations
        'https:evil.com',
        'http:evil.com',
        'https:/evil.com',
        'http:/evil.com',
        'https:\\evil.com',
        'http:\\evil.com',

        # User info bypass
        'https://evil.com@legitimate.com',
        'https://legitimate.com@evil.com',
        'http://evil.com#@legitimate.com',

        # Whitelist bypass
        'https://legitimate.com.evil.com',
        'https://evil.com.legitimate.com',
        'https://legitimate.com/evil.com',

        # URL encoding
        'https%3A%2F%2Fevil.com',
        '%2F%2Fevil.com',
        '%252F%252Fevil.com',
        'https%253A%252F%252Fevil.com',

        # Unicode/IDN
        'https://evil。com',
        'https://еѵil.com',  # Cyrillic

        # Newline/CRLF
        'https://legitimate.com%0d%0aLocation:https://evil.com',
        '\r\nhttps://evil.com',
        '\nhttps://evil.com',

        # Backslash
        '\\\\evil.com',
        '/\\evil.com',
        '\\/evil.com',

        # Data URI
        'data:text/html,<script>alert(1)</script>',
        'javascript:alert(1)',
        'vbscript:msgbox(1)',

        # File protocol
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
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
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        self.session.verify = False

        self.vulnerabilities = []

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute Open Redirect detection"""
        print(f"{Fore.CYAN}[*] Open Redirect Scanner started")
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print()

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            params = self._find_form_params()

        if not params:
            print(f"{Fore.YELLOW}  [-] No parameters found")
            return []

        # Filter redirect-prone params
        redirect_params = {k: v for k, v in params.items()
                           if any(name in k.lower() for name in self.REDIRECT_PARAMS)}

        if not redirect_params:
            redirect_params = params

        print(f"{Fore.CYAN}[*] Testing {len(redirect_params)} parameters: {', '.join(redirect_params.keys())}")
        print()

        for param in redirect_params.keys():
            print(f"{Fore.YELLOW}[*] Testing parameter: {param}")
            self._test_parameter(param)

        # Also test path-based
        self._test_path_based()

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
    # TEST PARAMETER
    # =============================================

    def _test_parameter(self, param):
        """Test single parameter for open redirect"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for payload in self.PAYLOADS:
            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload

                r = self.session.get(
                    base_url, params=test_params,
                    timeout=self.timeout, allow_redirects=False, verify=False
                )

                # Check for redirect
                if r.status_code in [301, 302, 303, 307, 308]:
                    location = r.headers.get('Location', '')

                    if self._is_redirect_to_external(location):
                        print(f"{Fore.RED}  [!] Open Redirect Found!")
                        print(f"{Fore.RED}      Param: {param}")
                        print(f"{Fore.RED}      Payload: {payload}")
                        print(f"{Fore.RED}      Location: {location}")

                        self.vulnerabilities.append({
                            'type': 'Open Redirect',
                            'url': r.url,
                            'param': param,
                            'payload': payload,
                            'location': location,
                            'severity': 'MEDIUM',
                        })
                        return

                # Check for meta refresh
                if r.status_code == 200:
                    meta = re.search(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']([^"\']*)["\']', r.text, re.IGNORECASE)
                    if meta:
                        content = meta.group(1)
                        if self._contains_external(content):
                            print(f"{Fore.RED}  [!] Meta Refresh Redirect!")
                            print(f"{Fore.RED}      Param: {param}")
                            print(f"{Fore.RED}      Content: {content[:80]}")

                            self.vulnerabilities.append({
                                'type': 'Open Redirect (Meta Refresh)',
                                'url': r.url,
                                'param': param,
                                'payload': payload,
                                'evidence': content[:200],
                                'severity': 'MEDIUM',
                            })
                            return

                    # Check for JS redirect
                    js_patterns = [
                        r'window\.location\s*=\s*["\']([^"\']+)',
                        r'document\.location\s*=\s*["\']([^"\']+)',
                        r'location\.href\s*=\s*["\']([^"\']+)',
                        r'location\.replace\s*\(\s*["\']([^"\']+)',
                        r'location\.assign\s*\(\s*["\']([^"\']+)',
                    ]

                    for pattern in js_patterns:
                        match = re.search(pattern, r.text, re.IGNORECASE)
                        if match:
                            target_url = match.group(1)
                            if self._contains_external(target_url):
                                print(f"{Fore.RED}  [!] JavaScript Redirect!")
                                print(f"{Fore.RED}      Param: {param}")
                                print(f"{Fore.RED}      Target: {target_url[:80]}")

                                self.vulnerabilities.append({
                                    'type': 'Open Redirect (JavaScript)',
                                    'url': r.url,
                                    'param': param,
                                    'payload': payload,
                                    'evidence': target_url[:200],
                                    'severity': 'MEDIUM',
                                })
                                return

            except Exception:
                continue

    # =============================================
    # PATH-BASED REDIRECT
    # =============================================

    def _test_path_based(self):
        """Test path-based redirects"""
        parsed = urlparse(self.target)

        test_paths = [
            '/redirect/evil.com',
            '/redirect?url=https://evil.com',
            '/go/evil.com',
            '/out/evil.com',
            '/link/evil.com',
            '/r/evil.com',
        ]

        for path in test_paths:
            try:
                url = f"{parsed.scheme}://{parsed.netloc}{path}"
                r = self.session.get(url, timeout=self.timeout, allow_redirects=False, verify=False)

                if r.status_code in [301, 302, 303, 307, 308]:
                    location = r.headers.get('Location', '')

                    if self._is_redirect_to_external(location):
                        print(f"{Fore.RED}  [!] Path-Based Open Redirect!")
                        print(f"{Fore.RED}      URL: {url}")
                        print(f"{Fore.RED}      Location: {location}")

                        self.vulnerabilities.append({
                            'type': 'Open Redirect (Path-Based)',
                            'url': url,
                            'location': location,
                            'severity': 'MEDIUM',
                        })
                        return
            except:
                continue

    # =============================================
    # HELPER FUNCTIONS
    # =============================================

    def _is_redirect_to_external(self, location):
        """Check if redirect target is external"""
        if not location:
            return False

        location_lower = location.lower()

        # External indicators
        external_indicators = [
            'evil.com', 'attacker.com', 'google.com',
            '//evil', '//attacker', '//google',
            'http://evil', 'https://evil',
            'http://attacker', 'https://attacker',
        ]

        for indicator in external_indicators:
            if indicator in location_lower:
                return True

        # Check if domain is different
        try:
            parsed_target = urlparse(self.target)
            target_host = parsed_target.netloc.lower()

            if location.startswith(('http://', 'https://', '//')):
                parsed_location = urlparse(location if location.startswith('http') else 'http:' + location)
                location_host = parsed_location.netloc.lower()

                if location_host and location_host != target_host:
                    return True
        except:
            pass

        return False

    def _contains_external(self, text):
        """Check if text contains external URL"""
        if not text:
            return False

        external_indicators = ['evil.com', 'attacker.com', '//evil', 'http://evil', 'https://evil']
        return any(ind in text.lower() for ind in external_indicators)

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  OPEN REDIRECT SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Vulnerabilities: {len(self.vulnerabilities)}")

        for v in self.vulnerabilities:
            print(f"{Fore.RED}[!] {v['type']} - {v.get('param', 'N/A')}")
            print(f"{Fore.RED}    → {v.get('location', 'N/A')[:60]}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["RedirectScanner"]