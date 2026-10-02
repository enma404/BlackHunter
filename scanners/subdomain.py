# scanners/subdomain.py
# BlackHunter Pro - Subdomain Scanner
# Discovers subdomains via DNS bruteforce + certificate transparency

import os
import re
import ssl
import json
import socket
import requests
import concurrent.futures
from urllib.parse import urlparse
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")

# Optional DNS
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


class SubdomainScanner:
    """
    Subdomain Enumeration Module
    - DNS Bruteforce (using wordlist)
    - Certificate Transparency (crt.sh)
    - Passive DNS sources
    - HTTP verification
    - Wildcard detection
    """

    # =============================================
    # DEFAULT SUBDOMAIN WORDLIST
    # =============================================

    DEFAULT_WORDLIST = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
        "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover",
        "autoconfig", "m", "imap", "test", "ns", "blog", "pop3",
        "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
        "mail2", "new", "mysql", "old", "lists", "support", "mobile",
        "mx", "static", "docs", "beta", "shop", "sql", "secure",
        "demo", "cp", "calendar", "wiki", "web", "media", "email",
        "images", "img", "download", "dns", "dns1", "dns2",
        "api", "app", "apps", "cdn", "cloud", "gateway", "proxy",
        "login", "portal", "my", "internal", "intranet", "extranet",
        "stage", "staging", "prod", "production", "staging",
        "test1", "test2", "dev1", "dev2", "qa", "uat", "sandbox",
        "jenkins", "gitlab", "github", "git", "svn", "jenkins",
        "jira", "confluence", "wiki", "redmine", "mantis", "bugzilla",
        "monitor", "monitoring", "nagios", "zabbix", "grafana",
        "kibana", "elastic", "elasticsearch", "logstash", "prometheus",
        "db", "database", "mysql", "postgres", "mongo", "redis",
        "cache", "memcache", "queue", "rabbitmq", "kafka",
        "storage", "backup", "backups", "files", "uploads",
        "assets", "static", "media", "img", "images", "video",
        "stream", "live", "rtmp", "rtsp", "webrtc", "chat",
        "webmail", "mail", "smtp", "pop", "imap", "exchange",
        "owa", "autodiscover", "autoconfig", "mx", "mailer",
        "vpn", "remote", "rdp", "ssh", "ftp", "sftp", "telnet",
    ]

    # =============================================
    # CT API ENDPOINTS
    # =============================================

    CT_ENDPOINTS = [
        "https://crt.sh/?q=%25.{domain}&output=json",
        "https://crt.sh/?q={domain}&output=json",
    ]

    # =============================================
    # INITIALIZATION
    # =============================================

    def __init__(self, target, timeout=5, threads=50, wordlist=None, user_agent=None):
        """
        Initialize subdomain scanner

        Args:
            target: Target URL or domain
            timeout: DNS/HTTP timeout
            threads: Concurrent threads
            wordlist: Custom subdomain list
            user_agent: Custom User-Agent
        """
        # Extract domain
        if '://' in target:
            parsed = urlparse(target)
            self.domain = parsed.netloc.split(':')[0]
        else:
            self.domain = target.split('/')[0].split(':')[0]

        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.wordlist = wordlist or self._load_wordlist()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36',
        })
        self.session.verify = False

        self.results = {
            'domain': self.domain,
            'subdomains': [],
            'wildcard': False,
            'total_found': 0,
            'ct_subdomains': [],
            'dns_bruteforce': [],
        }

    # =============================================
    # LOAD WORDLIST
    # =============================================

    def _load_wordlist(self):
        """Load wordlist from file or use default"""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        wordlist_path = os.path.join(base_dir, "wordlists", "subdomains.txt")

        if os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                if words:
                    return words
            except:
                pass

        return self.DEFAULT_WORDLIST

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute subdomain enumeration"""
        print(f"{Fore.CYAN}[*] Subdomain Scanner started")
        print(f"{Fore.CYAN}[*] Domain: {self.domain}")
        print(f"{Fore.CYAN}[*] Wordlist: {len(self.wordlist)} entries")
        print(f"{Fore.CYAN}[*] Threads: {self.threads}")
        print()

        # Check wildcard DNS
        self._check_wildcard()

        if self.results['wildcard']:
            print(f"{Fore.YELLOW}[!] Wildcard DNS detected - results may include false positives")

        # Certificate Transparency
        self._ct_lookup()

        # DNS Bruteforce
        self._dns_bruteforce()

        # Deduplicate
        self._deduplicate()

        return self.results

    # =============================================
    # WILDCARD CHECK
    # =============================================

    def _check_wildcard(self):
        """Check for wildcard DNS"""
        try:
            random_sub = f"random-{os.urandom(4).hex()}.{self.domain}"
            socket.gethostbyname(random_sub)
            self.results['wildcard'] = True
        except socket.gaierror:
            self.results['wildcard'] = False
        except:
            pass

    # =============================================
    # CERTIFICATE TRANSPARENCY
    # =============================================

    def _ct_lookup(self):
        """Query Certificate Transparency logs"""
        print(f"{Fore.YELLOW}[*] Querying Certificate Transparency...")

        for endpoint in self.CT_ENDPOINTS:
            try:
                url = endpoint.format(domain=self.domain)
                r = self.session.get(url, timeout=15)

                if r.status_code == 200:
                    data = r.json()

                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for sub in name_value.split('\n'):
                            sub = sub.strip().lower()
                            if sub and sub.endswith(self.domain) and not sub.startswith('*'):
                                if sub not in self.results['ct_subdomains']:
                                    self.results['ct_subdomains'].append(sub)

                    if self.results['ct_subdomains']:
                        print(f"{Fore.GREEN}  [+] Found {len(self.results['ct_subdomains'])} from CT")
                    return
            except Exception as e:
                continue

        if not self.results['ct_subdomains']:
            print(f"{Fore.YELLOW}  [-] No CT results")

    # =============================================
    # DNS BRUTEFORCE
    # =============================================

    def _dns_bruteforce(self):
        """Bruteforce subdomains via DNS"""
        print(f"{Fore.YELLOW}[*] DNS Bruteforce...")

        found = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_subdomain, sub): sub
                for sub in self.wordlist
            }

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results['dns_bruteforce'].append(result)
                        found += 1
                        print(f"{Fore.GREEN}  [+] {result['subdomain']} -> {result['ip']}")
                except:
                    pass

        print(f"{Fore.GREEN}[+] Found {found} subdomains via DNS")

    # =============================================
    # CHECK SUBDOMAIN
    # =============================================

    def _check_subdomain(self, sub):
        """Check a single subdomain"""
        subdomain = f"{sub}.{self.domain}"

        try:
            ip = socket.gethostbyname(subdomain)

            result = {
                'subdomain': subdomain,
                'ip': ip,
                'http_status': None,
                'https_status': None,
                'title': None,
            }

            # Try HTTP
            try:
                r = self.session.get(f"http://{subdomain}", timeout=3, allow_redirects=False)
                result['http_status'] = r.status_code
            except:
                pass

            # Try HTTPS
            try:
                r = self.session.get(f"https://{subdomain}", timeout=3, allow_redirects=False)
                result['https_status'] = r.status_code

                # Extract title
                title_match = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result['title'] = re.sub(r'\s+', ' ', title_match.group(1).strip())[:100]
            except:
                pass

            return result
        except:
            return None

    # =============================================
    # DEDUPLICATE
    # =============================================

    def _deduplicate(self):
        """Merge and deduplicate all subdomains"""
        all_subs = {}

        # From DNS bruteforce
        for sub in self.results['dns_bruteforce']:
            all_subs[sub['subdomain']] = sub

        # From CT
        for sub in self.results['ct_subdomains']:
            if sub not in all_subs:
                try:
                    ip = socket.gethostbyname(sub)
                    all_subs[sub] = {
                        'subdomain': sub,
                        'ip': ip,
                        'http_status': None,
                        'https_status': None,
                        'title': None,
                        'source': 'ct',
                    }
                except:
                    pass

        self.results['subdomains'] = list(all_subs.values())
        self.results['total_found'] = len(self.results['subdomains'])

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        r = self.results

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  SUBDOMAIN SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Domain:       {r['domain']}")
        print(f"{Fore.GREEN}[+] Total Found:  {r['total_found']}")
        print(f"{Fore.GREEN}[+] Wildcard:     {r['wildcard']}")

        if r['subdomains']:
            print(f"\n{Fore.GREEN}[+] Discovered Subdomains:")
            for sub in r['subdomains'][:20]:
                status = sub.get('https_status') or sub.get('http_status') or 'N/A'
                print(f"{Fore.GREEN}    - {sub['subdomain']:<40} [{status}] {sub['ip']}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["SubdomainScanner"]