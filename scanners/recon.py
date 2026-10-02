# scanners/recon.py
# BlackHunter Pro - Reconnaissance Scanner
# Information Gathering: DNS, WHOIS, Headers, Technologies, SSL, CMS

import re
import ssl
import socket
import requests
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")

# Optional imports (graceful fallback)
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


class Recon:
    """
    Reconnaissance Module
    - DNS Resolution (A, AAAA, MX, NS, TXT, CNAME, SOA)
    - WHOIS Lookup
    - HTTP Headers Analysis
    - Security Headers Check
    - Technology Detection
    - SSL/TLS Analysis
    - robots.txt & sitemap.xml
    - Cookies Analysis
    - Page Title
    - HTTP Methods
    """

    # =============================================
    # SECURITY HEADERS
    # =============================================

    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Content-Type-Options': 'MIME Sniffing Protection',
        'X-XSS-Protection': 'XSS Protection',
        'Referrer-Policy': 'Referrer Policy',
        'Permissions-Policy': 'Permissions Policy',
        'Feature-Policy': 'Feature Policy',
        'Cross-Origin-Embedder-Policy': 'COEP',
        'Cross-Origin-Opener-Policy': 'COOP',
        'Cross-Origin-Resource-Policy': 'CORP',
    }

    # =============================================
    # TECHNOLOGY SIGNATURES
    # =============================================

    TECH_SIGNATURES = {
        'JavaScript': {
            'jQuery': ['jquery', 'jquery.min.js', 'jquery.js'],
            'React': ['react.js', 'react.min.js', 'react-dom'],
            'Vue.js': ['vue.js', 'vue.min.js', 'vuejs'],
            'Angular': ['angular.js', 'angular.min.js', 'ng-app'],
            'Svelte': ['svelte', 'svelte.js'],
            'Next.js': ['next.js', '_next/'],
            'Nuxt.js': ['nuxt', '_nuxt/'],
            'Ember.js': ['ember.js', 'ember.min.js'],
            'Backbone.js': ['backbone.js', 'backbone.min.js'],
            'Moment.js': ['moment.js', 'moment.min.js'],
            'Lodash': ['lodash.js', 'lodash.min.js'],
            'Axios': ['axios.js', 'axios.min.js'],
            'D3.js': ['d3.js', 'd3.min.js'],
            'Three.js': ['three.js', 'three.min.js'],
            'Socket.io': ['socket.io'],
            'Alpine.js': ['alpine.js', 'alpinejs'],
            'HTMX': ['htmx', 'hx-get', 'hx-post'],
        },
        'CSS': {
            'Bootstrap': ['bootstrap.css', 'bootstrap.min.css'],
            'Tailwind CSS': ['tailwind'],
            'Bulma': ['bulma.css', 'bulma.min.css'],
            'Foundation': ['foundation.css'],
            'Materialize': ['materialize.css'],
            'Semantic UI': ['semantic.min.css'],
            'UIkit': ['uikit.css', 'uikit.min.css'],
            'Pure CSS': ['pure-min.css'],
        },
        'Analytics': {
            'Google Analytics': ['google-analytics.com', 'gtag', 'ga('],
            'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
            'Facebook Pixel': ['connect.facebook.net', 'fbq('],
            'Hotjar': ['hotjar', 'hj('],
            'Mixpanel': ['mixpanel'],
            'Matomo': ['matomo', 'piwik'],
            'Segment': ['segment.com', 'analytics.js'],
            'Heap': ['heap.io', 'heap.js'],
            'Plausible': ['plausible.io'],
        },
        'CDN': {
            'Cloudflare': ['cloudflare', 'cf-'],
            'Akamai': ['akamai'],
            'Fastly': ['fastly'],
            'Amazon CloudFront': ['cloudfront'],
            'Google Cloud CDN': ['googleusercontent'],
            'MaxCDN': ['maxcdn'],
            'jsDelivr': ['jsdelivr'],
            'unpkg': ['unpkg.com'],
        },
        'Languages': {
            'PHP': ['.php', 'PHPSESSID', 'X-Powered-By: PHP'],
            'ASP.NET': ['.aspx', 'ASP.NET', 'X-AspNet-Version'],
            'Java/JSP': ['.jsp', 'JSESSIONID', 'X-Powered-By: JSP'],
            'Python': ['X-Powered-By: Python', 'wsgi'],
            'Ruby': ['X-Powered-By: Ruby', 'X-Rack'],
            'Node.js': ['X-Powered-By: Express', 'X-Powered-By: Node'],
        },
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
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.session.verify = False

        self.results = {
            'target': self.target,
            'url': self.target,
            'domain': '',
            'ip': '',
            'port': 80,
            'protocol': 'http',
            'server': '',
            'status_code': 0,
            'title': '',
            'headers': {},
            'security_headers': {'present': [], 'missing': []},
            'technologies': [],
            'dns_records': {},
            'whois': {},
            'ssl_info': {},
            'cookies': [],
            'redirects': [],
            'robots_txt': {'found': False, 'disallowed': [], 'allowed': [], 'sitemaps': []},
            'sitemap': {'found': False, 'urls': []},
            'http_methods': [],
        }

        self._parse_target()

    # =============================================
    # PARSE TARGET
    # =============================================

    def _parse_target(self):
        """Parse target URL"""
        parsed = urlparse(self.target)
        self.results['protocol'] = parsed.scheme or 'http'
        self.results['domain'] = parsed.netloc.split(':')[0]
        self.results['port'] = parsed.port or (443 if parsed.scheme == 'https' else 80)

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute all reconnaissance steps"""
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print(f"{Fore.CYAN}[*] Domain: {self.results['domain']}")
        print()

        self._resolve_dns()
        self._get_whois()
        self._get_headers()
        self._check_security_headers()
        self._detect_technologies()
        self._check_robots()
        self._check_sitemap()
        self._check_ssl()
        self._get_title()
        self._analyze_cookies()
        self._test_http_methods()

        return self.results

    # =============================================
    # DNS RESOLUTION
    # =============================================

    def _resolve_dns(self):
        """Resolve DNS records"""
        print(f"{Fore.YELLOW}[*] Resolving DNS...")

        domain = self.results['domain']

        # A Record
        try:
            ip = socket.gethostbyname(domain)
            self.results['ip'] = ip
            self.results['dns_records']['A'] = [ip]
            print(f"{Fore.GREEN}  [+] A: {ip}")
        except Exception as e:
            print(f"{Fore.RED}  [-] A record failed: {e}")

        # Other records (requires dnspython)
        if HAS_DNSPYTHON:
            record_types = ['AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                    records = [str(r) for r in answers]
                    self.results['dns_records'][rtype] = records
                    if records:
                        print(f"{Fore.GREEN}  [+] {rtype}: {', '.join(records[:2])}")
                except Exception:
                    pass

    # =============================================
    # WHOIS LOOKUP
    # =============================================

    def _get_whois(self):
        """WHOIS lookup"""
        print(f"{Fore.YELLOW}[*] WHOIS lookup...")

        if not HAS_WHOIS:
            print(f"{Fore.YELLOW}  [!] python-whois not installed")
            return

        try:
            w = whois.whois(self.results['domain'])

            self.results['whois'] = {
                'registrar': str(w.registrar) if w.registrar else 'N/A',
                'creation_date': str(w.creation_date) if w.creation_date else 'N/A',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'N/A',
                'name_servers': w.name_servers if w.name_servers else [],
                'emails': w.emails if w.emails else [],
                'country': str(w.country) if w.country else 'N/A',
                'org': str(w.org) if w.org else 'N/A',
            }

            if self.results['whois']['registrar'] != 'N/A':
                print(f"{Fore.GREEN}  [+] Registrar: {self.results['whois']['registrar']}")
            if self.results['whois']['country'] != 'N/A':
                print(f"{Fore.GREEN}  [+] Country: {self.results['whois']['country']}")
            if self.results['whois']['org'] != 'N/A':
                print(f"{Fore.GREEN}  [+] Organization: {self.results['whois']['org']}")
        except Exception as e:
            print(f"{Fore.RED}  [-] WHOIS failed: {e}")

    # =============================================
    # HTTP HEADERS
    # =============================================

    def _get_headers(self):
        """Fetch HTTP headers"""
        print(f"{Fore.YELLOW}[*] Fetching HTTP headers...")

        try:
            r = self.session.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )

            self.results['status_code'] = r.status_code
            self.results['headers'] = dict(r.headers)
            self.results['server'] = r.headers.get('Server', 'Unknown')
            self.results['url'] = r.url

            # Track redirects
            if r.history:
                for resp in r.history:
                    self.results['redirects'].append({
                        'url': resp.url,
                        'status': resp.status_code
                    })
                print(f"{Fore.GREEN}  [+] Redirects: {len(r.history)}")

            print(f"{Fore.GREEN}  [+] Status: {r.status_code}")
            print(f"{Fore.GREEN}  [+] Server: {self.results['server']}")

            # X-Powered-By
            powered = r.headers.get('X-Powered-By')
            if powered:
                print(f"{Fore.GREEN}  [+] Powered by: {powered}")

        except Exception as e:
            print(f"{Fore.RED}  [-] Headers failed: {e}")

    # =============================================
    # SECURITY HEADERS
    # =============================================

    def _check_security_headers(self):
        """Check security headers"""
        headers = self.results['headers']

        for header, name in self.SECURITY_HEADERS.items():
            if header in headers:
                self.results['security_headers']['present'].append(name)
            else:
                self.results['security_headers']['missing'].append(name)

        missing = self.results['security_headers']['missing']
        if missing:
            print(f"{Fore.YELLOW}  [!] Missing headers: {', '.join(missing[:5])}")

    # =============================================
    # TECHNOLOGY DETECTION
    # =============================================

    def _detect_technologies(self):
        """Detect web technologies"""
        print(f"{Fore.YELLOW}[*] Detecting technologies...")

        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)
            html = r.text.lower()
            headers = r.headers

            detected = []
            seen = set()

            # Detect by category
            for category, techs in self.TECH_SIGNATURES.items():
                for tech_name, signatures in techs.items():
                    for sig in signatures:
                        if sig.lower() in html:
                            key = (category, tech_name)
                            if key not in seen:
                                seen.add(key)
                                detected.append({
                                    'category': category,
                                    'name': tech_name,
                                    'confidence': 'high'
                                })
                            break

            # Detect server software
            server = headers.get('Server', '')
            if server:
                detected.append({
                    'category': 'Server',
                    'name': server,
                    'confidence': 'high'
                })

            # Detect from X-Powered-By
            powered = headers.get('X-Powered-By', '')
            if powered:
                detected.append({
                    'category': 'Framework',
                    'name': powered,
                    'confidence': 'high'
                })

            self.results['technologies'] = detected

            for tech in detected[:10]:
                print(f"{Fore.GREEN}  [+] {tech['category']}: {tech['name']}")

        except Exception as e:
            print(f"{Fore.RED}  [-] Technology detection failed: {e}")

    # =============================================
    # ROBOTS.TXT
    # =============================================

    def _check_robots(self):
        """Check robots.txt"""
        print(f"{Fore.YELLOW}[*] Checking robots.txt...")

        try:
            url = urljoin(self.target + '/', 'robots.txt')
            r = self.session.get(url, timeout=self.timeout, verify=False)

            if r.status_code == 200:
                self.results['robots_txt']['found'] = True

                disallowed = []
                allowed = []
                sitemaps = []

                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            disallowed.append(path)
                    elif line.lower().startswith('allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            allowed.append(path)
                    elif line.lower().startswith('sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        sitemaps.append(sitemap)

                self.results['robots_txt'].update({
                    'disallowed': disallowed,
                    'allowed': allowed,
                    'sitemaps': sitemaps,
                })

                print(f"{Fore.GREEN}  [+] Disallowed: {len(disallowed)} paths")
                print(f"{Fore.GREEN}  [+] Allowed: {len(allowed)} paths")
                if sitemaps:
                    print(f"{Fore.GREEN}  [+] Sitemaps: {len(sitemaps)}")

                # Show sensitive paths
                for path in disallowed[:5]:
                    if any(k in path.lower() for k in ['admin', 'backup', 'config', 'private', 'api', 'db']):
                        print(f"{Fore.RED}      [!] Sensitive: {path}")
            else:
                print(f"{Fore.YELLOW}  [-] robots.txt not found")
        except Exception as e:
            print(f"{Fore.RED}  [-] robots.txt failed: {e}")

    # =============================================
    # SITEMAP
    # =============================================

    def _check_sitemap(self):
        """Check sitemap.xml"""
        print(f"{Fore.YELLOW}[*] Checking sitemap.xml...")

        sitemap_paths = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap-index.xml',
            '/sitemap/sitemap.xml',
        ]

        # Also check robots.txt for sitemaps
        sitemap_paths.extend(self.results['robots_txt'].get('sitemaps', []))

        for path in sitemap_paths:
            try:
                if path.startswith('http'):
                    url = path
                else:
                    url = urljoin(self.target + '/', path.lstrip('/'))

                r = self.session.get(url, timeout=self.timeout, verify=False)

                if r.status_code == 200 and ('<urlset' in r.text or '<sitemapindex' in r.text):
                    urls = re.findall(r'<loc>(.*?)</loc>', r.text)
                    self.results['sitemap'] = {
                        'found': True,
                        'url': url,
                        'urls': urls[:100]
                    }
                    print(f"{Fore.GREEN}  [+] Found {len(urls)} URLs in sitemap")
                    return
            except:
                continue

        if not self.results['sitemap']['found']:
            print(f"{Fore.YELLOW}  [-] sitemap.xml not found")

    # =============================================
    # SSL/TLS
    # =============================================

    def _check_ssl(self):
        """Check SSL/TLS certificate"""
        if self.results['protocol'] != 'https':
            return

        print(f"{Fore.YELLOW}[*] Checking SSL/TLS...")

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.results['domain'], self.results['port']), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.results['domain']) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    self.results['ssl_info'] = {
                        'version': version,
                        'cipher': cipher[0] if cipher else 'N/A',
                        'bits': cipher[2] if cipher else 0,
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'notBefore': cert.get('notBefore', ''),
                        'notAfter': cert.get('notAfter', ''),
                        'subjectAltName': cert.get('subjectAltName', []),
                    }

                    print(f"{Fore.GREEN}  [+] TLS: {version}")
                    print(f"{Fore.GREEN}  [+] Cipher: {cipher[0] if cipher else 'N/A'}")
                    print(f"{Fore.GREEN}  [+] Issuer: {self.results['ssl_info']['issuer'].get('organizationName', 'N/A')}")

                    # Check weak versions
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                        print(f"{Fore.RED}  [!] Weak TLS version!")
        except Exception as e:
            print(f"{Fore.RED}  [-] SSL check failed: {e}")

    # =============================================
    # PAGE TITLE
    # =============================================

    def _get_title(self):
        """Extract page title"""
        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)
            match = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
            if match:
                title = re.sub(r'\s+', ' ', match.group(1).strip())
                self.results['title'] = title[:150]
                print(f"{Fore.GREEN}[*] Title: {self.results['title']}")
        except:
            pass

    # =============================================
    # COOKIES
    # =============================================

    def _analyze_cookies(self):
        """Analyze cookies"""
        try:
            for cookie in self.session.cookies:
                self.results['cookies'].append({
                    'name': cookie.name,
                    'domain': cookie.domain,
                    'secure': cookie.secure,
                    'httponly': 'HttpOnly' in str(getattr(cookie, '_rest', {})),
                    'samesite': getattr(cookie, '_rest', {}).get('SameSite', 'None') if hasattr(cookie, '_rest') else 'None',
                })

            if self.results['cookies']:
                print(f"{Fore.GREEN}[*] Cookies: {len(self.results['cookies'])}")
        except:
            pass

    # =============================================
    # HTTP METHODS
    # =============================================

    def _test_http_methods(self):
        """Test HTTP methods"""
        print(f"{Fore.YELLOW}[*] Testing HTTP methods...")

        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'TRACE', 'HEAD']

        for method in methods:
            try:
                r = self.session.request(method, self.target, timeout=5, verify=False)

                method_info = {
                    'method': method,
                    'status': r.status_code,
                    'allowed': r.status_code < 400,
                }
                self.results['http_methods'].append(method_info)

                if r.status_code < 400:
                    if method in ['PUT', 'DELETE', 'TRACE']:
                        print(f"{Fore.RED}  [!] {method}: {r.status_code} (DANGEROUS){Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}  [+] {method}: {r.status_code}")
            except:
                pass

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        r = self.results

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  RECONNAISSANCE SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        print(f"{Fore.GREEN}[+] Target:       {r['target']}")
        print(f"{Fore.GREEN}[+] Domain:       {r['domain']}")
        print(f"{Fore.GREEN}[+] IP:           {r['ip'] or 'N/A'}")
        print(f"{Fore.GREEN}[+] Status:       {r['status_code']}")
        print(f"{Fore.GREEN}[+] Server:       {r['server']}")
        print(f"{Fore.GREEN}[+] Title:        {r['title'] or 'N/A'}")
        print(f"{Fore.GREEN}[+] Technologies: {len(r['technologies'])}")
        print(f"{Fore.GREEN}[+] Cookies:      {len(r['cookies'])}")

        if r['security_headers']['missing']:
            print(f"{Fore.YELLOW}[!] Missing Headers: {len(r['security_headers']['missing'])}")

        if r['robots_txt']['found']:
            print(f"{Fore.GREEN}[+] robots.txt: {len(r['robots_txt']['disallowed'])} disallowed paths")

        if r['sitemap']['found']:
            print(f"{Fore.GREEN}[+] sitemap.xml: {len(r['sitemap']['urls'])} URLs")

        if r['ssl_info']:
            print(f"{Fore.GREEN}[+] TLS: {r['ssl_info'].get('version', 'N/A')}")

        if r['whois'].get('registrar', 'N/A') != 'N/A':
            print(f"{Fore.GREEN}[+] Registrar: {r['whois']['registrar']}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["Recon"]