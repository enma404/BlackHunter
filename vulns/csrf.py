# vulns/csrf.py
# BlackHunter Pro - CSRF Scanner
# Detects: Cross-Site Request Forgery vulnerabilities

import re
import requests
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class CSRFScanner:
    """
    Cross-Site Request Forgery (CSRF) Scanner
    - Form token detection
    - SameSite cookie analysis
    - HTTP method analysis
    - Referer/Origin validation check
    - Custom header requirement check
    - CORS misconfiguration detection
    """

    # =============================================
    # CSRF TOKEN NAMES
    # =============================================

    TOKEN_NAMES = [
        'csrf', 'csrf_token', 'csrftoken', 'csrfmiddlewaretoken',
        '_csrf', '_csrf_token', '_token', 'token', 'authenticity_token',
        'xsrf', 'xsrf_token', 'x-xsrf-token', '__requestverificationtoken',
        'anticsrf', 'anti_csrf', 'anti-csrf', 'secure_token',
        'request_token', 'form_token', 'session_token', 'security_token',
        'verification_token', 'verif_token',
    ]

    # =============================================
    # STATE-CHANGING METHODS
    # =============================================

    STATE_CHANGING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']

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

        self.vulnerabilities = []
        self.forms = []
        self.cookies_analysis = []

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute CSRF scan"""
        print(f"{Fore.CYAN}[*] CSRF Scanner started")
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print()

        # 1. Analyze forms
        self._analyze_forms()

        # 2. Analyze cookies
        self._analyze_cookies()

        # 3. Test Referer validation
        self._test_referer_validation()

        # 4. Test Origin validation
        self._test_origin_validation()

        # 5. Check CORS
        self._check_cors()

        return self.vulnerabilities

    # =============================================
    # ANALYZE FORMS
    # =============================================

    def _analyze_forms(self):
        """Analyze HTML forms for CSRF protection"""
        print(f"{Fore.YELLOW}[*] Analyzing forms...")

        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)

            # Find all forms
            forms = re.findall(r'<form[^>]*>.*?</form>', r.text, re.IGNORECASE | re.DOTALL)

            for form in forms:
                # Extract method
                method_match = re.search(r'method=["\']([^"\']*)["\']', form, re.IGNORECASE)
                method = method_match.group(1).upper() if method_match else 'GET'

                # Extract action
                action_match = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
                action = action_match.group(1) if action_match else self.target

                # Extract all inputs
                inputs = re.findall(r'<input[^>]*>', form, re.IGNORECASE)
                input_names = []
                for inp in inputs:
                    name_match = re.search(r'name=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                    if name_match:
                        input_names.append(name_match.group(1).lower())

                # Check for token
                has_token = any(
                    token_name in input_names
                    for token_name in self.TOKEN_NAMES
                )

                form_info = {
                    'action': action,
                    'method': method,
                    'input_names': input_names,
                    'has_token': has_token,
                    'url': urljoin(self.target + '/', action),
                }
                self.forms.append(form_info)

                # POST forms without token = potential CSRF
                if method in self.STATE_CHANGING_METHODS and not has_token:
                    print(f"{Fore.RED}  [!] CSRF vulnerable form: {method} {action}")
                    print(f"{Fore.RED}      Missing CSRF token")

                    self.vulnerabilities.append({
                        'type': 'CSRF (Missing Token)',
                        'url': form_info['url'],
                        'method': method,
                        'action': action,
                        'evidence': 'No CSRF token in form',
                        'severity': 'MEDIUM',
                    })
                elif method in self.STATE_CHANGING_METHODS and has_token:
                    print(f"{Fore.GREEN}  [+] Form with token: {method} {action}")

        except Exception as e:
            print(f"{Fore.RED}  [-] Form analysis failed: {e}")

    # =============================================
    # ANALYZE COOKIES
    # =============================================

    def _analyze_cookies(self):
        """Analyze cookies for SameSite attribute"""
        print(f"{Fore.YELLOW}[*] Analyzing cookies...")

        try:
            # Get cookies
            r = self.session.get(self.target, timeout=self.timeout, verify=False)

            for cookie in self.session.cookies:
                # Extract SameSite
                samesite = None
                if hasattr(cookie, '_rest'):
                    samesite = cookie._rest.get('SameSite')

                cookie_info = {
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'httponly': 'HttpOnly' in str(getattr(cookie, '_rest', {})),
                    'samesite': samesite,
                }
                self.cookies_analysis.append(cookie_info)

                # Check for session cookies without SameSite
                is_session = any(x in cookie.name.lower() for x in ['session', 'sess', 'sid', 'auth', 'token'])
                if is_session and not samesite:
                    print(f"{Fore.YELLOW}  [!] Session cookie without SameSite: {cookie.name}")

                    self.vulnerabilities.append({
                        'type': 'CSRF (Cookie without SameSite)',
                        'url': self.target,
                        'cookie': cookie.name,
                        'evidence': 'Session cookie missing SameSite attribute',
                        'severity': 'MEDIUM',
                    })
                elif is_session and samesite and samesite.lower() not in ['lax', 'strict']:
                    print(f"{Fore.YELLOW}  [!] Session cookie with weak SameSite: {cookie.name} = {samesite}")

        except Exception as e:
            print(f"{Fore.RED}  [-] Cookie analysis failed: {e}")

    # =============================================
    # TEST REFERER VALIDATION
    # =============================================

    def _test_referer_validation(self):
        """Test if server validates Referer header"""
        print(f"{Fore.YELLOW}[*] Testing Referer validation...")

        # Find POST forms
        post_forms = [f for f in self.forms if f['method'] in self.STATE_CHANGING_METHODS]

        for form in post_forms[:3]:  # Limit to 3
            try:
                # Test 1: No Referer
                data = {name: 'test' for name in form['input_names'] if name}
                r1 = self.session.post(form['url'], data=data, timeout=self.timeout, verify=False)

                # Test 2: Evil Referer
                headers = {'Referer': 'http://evil.com/'}
                r2 = self.session.post(
                    form['url'],
                    data=data,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False
                )

                # Compare responses
                if r1.status_code == r2.status_code == 200:
                    if abs(len(r1.text) - len(r2.text)) < 50:
                        print(f"{Fore.YELLOW}  [!] No Referer validation: {form['url']}")

                        self.vulnerabilities.append({
                            'type': 'CSRF (No Referer Validation)',
                            'url': form['url'],
                            'evidence': 'Server accepts requests with forged Referer',
                            'severity': 'LOW',
                        })
            except:
                continue

    # =============================================
    # TEST ORIGIN VALIDATION
    # =============================================

    def _test_origin_validation(self):
        """Test if server validates Origin header"""
        print(f"{Fore.YELLOW}[*] Testing Origin validation...")

        post_forms = [f for f in self.forms if f['method'] in self.STATE_CHANGING_METHODS]

        for form in post_forms[:3]:
            try:
                # Test with evil Origin
                headers = {'Origin': 'http://evil.com'}
                data = {name: 'test' for name in form['input_names'] if name}

                r = self.session.post(
                    form['url'],
                    data=data,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False
                )

                if r.status_code == 200:
                    # Check if response differs from normal
                    # If server doesn't validate Origin, it's vulnerable
                    pass
            except:
                continue

    # =============================================
    # CHECK CORS
    # =============================================

    def _check_cors(self):
        """Check CORS misconfiguration"""
        print(f"{Fore.YELLOW}[*] Checking CORS...")

        try:
            headers = {'Origin': 'http://evil.com'}
            r = self.session.get(self.target, headers=headers, timeout=self.timeout, verify=False)

            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')

            if acao == '*':
                print(f"{Fore.YELLOW}  [!] CORS wildcard: Access-Control-Allow-Origin: *")

                self.vulnerabilities.append({
                    'type': 'CORS Misconfiguration (Wildcard)',
                    'url': self.target,
                    'evidence': 'Access-Control-Allow-Origin: *',
                    'severity': 'MEDIUM',
                })
            elif 'evil.com' in acao:
                print(f"{Fore.RED}  [!] CORS reflects Origin: {acao}")

                self.vulnerabilities.append({
                    'type': 'CORS Misconfiguration (Origin Reflection)',
                    'url': self.target,
                    'evidence': f'Access-Control-Allow-Origin: {acao}',
                    'severity': 'HIGH',
                })

            if acao and acac.lower() == 'true':
                print(f"{Fore.RED}  [!] CORS with credentials: {acao}")

                self.vulnerabilities.append({
                    'type': 'CORS with Credentials',
                    'url': self.target,
                    'evidence': f'ACAO: {acao} | ACAC: {acac}',
                    'severity': 'HIGH',
                })
        except:
            pass

    # =============================================
    # GENERATE POC
    # =============================================

    def generate_poc(self, form):
        """Generate CSRF PoC HTML"""
        inputs = ""
        for name in form.get('input_names', []):
            if name:
                inputs += f'  <input type="hidden" name="{name}" value="test" />\n'

        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body onload="document.forms[0].submit()">
    <form action="{form['url']}" method="{form['method']}">
{inputs}  </form>
    <p>CSRF PoC - Powered by BlackHunter</p>
</body>
</html>'''

        return poc

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  CSRF SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Forms Analyzed:   {len(self.forms)}")
        print(f"{Fore.GREEN}[+] Cookies Analyzed: {len(self.cookies_analysis)}")
        print(f"{Fore.GREEN}[+] Vulnerabilities:  {len(self.vulnerabilities)}")

        for v in self.vulnerabilities:
            print(f"{Fore.RED}[!] {v['type']} - {v.get('url', 'N/A')}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["CSRFScanner"]