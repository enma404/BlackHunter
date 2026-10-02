# scanners/dns_enum.py
# BlackHunter Pro - DNS Enumerator
# Comprehensive DNS records enumeration and analysis

import socket
import requests
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")

# Optional DNS
try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


class DNSEnumerator:
    """
    DNS Enumeration Module
    - All record types (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV)
    - Zone transfer attempt (AXFR)
    - Reverse DNS lookup
    - DKIM, DMARC, SPF detection
    - DNS server identification
    """

    # =============================================
    # COMMON SUBDOMAINS FOR SRV
    # =============================================

    SRV_RECORDS = [
        "_sip._tcp",
        "_sip._udp",
        "_sips._tcp",
        "_xmpp-client._tcp",
        "_xmpp-server._tcp",
        "_ldap._tcp",
        "_kerberos._tcp",
        "_kerberos._udp",
        "_gc._tcp",
        "_autodiscover._tcp",
        "_caldavs._tcp",
        "_carddavs._tcp",
        "_imap._tcp",
        "_imaps._tcp",
        "_pop3._tcp",
        "_pop3s._tcp",
        "_smtp._tcp",
        "_submission._tcp",
        "_vpn._tcp",
        "_ftp._tcp",
        "_http._tcp",
        "_https._tcp",
        "_minecraft._tcp",
        "_minecraft._udp",
        "_stun._udp",
        "_turn._udp",
    ]

    # =============================================
    # INITIALIZATION
    # =============================================

    def __init__(self, target, timeout=10, user_agent=None):
        self.target = target.rstrip('/')

        # Extract domain
        if '://' in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            self.domain = parsed.netloc.split(':')[0]
        else:
            self.domain = target.split('/')[0].split(':')[0]

        self.timeout = timeout
        self.results = {
            'domain': self.domain,
            'records': {},
            'reverse_dns': {},
            'zone_transfer': {'success': False, 'records': []},
            'nameservers': [],
            'mail_servers': [],
            'spf': None,
            'dmarc': None,
            'dkim': [],
            'dnssec': False,
        }

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute DNS enumeration"""
        print(f"{Fore.CYAN}[*] DNS Enumerator started")
        print(f"{Fore.CYAN}[*] Domain: {self.domain}")
        print()

        if not HAS_DNSPYTHON:
            print(f"{Fore.RED}[!] dnspython not installed")
            print(f"{Fore.YELLOW}[!] Install: pip install dnspython")
            # Basic A record via socket
            self._basic_lookup()
            return self.results

        self._resolve_all_records()
        self._reverse_lookup()
        self._check_spf()
        self._check_dmarc()
        self._check_dkim()
        self._check_dnssec()
        self._try_zone_transfer()
        self._enumerate_srv()

        return self.results

    # =============================================
    # BASIC LOOKUP
    # =============================================

    def _basic_lookup(self):
        """Basic DNS lookup with socket"""
        try:
            ip = socket.gethostbyname(self.domain)
            self.results['records']['A'] = [ip]
            print(f"{Fore.GREEN}  [+] A: {ip}")
        except Exception as e:
            print(f"{Fore.RED}  [-] Failed: {e}")

    # =============================================
    # ALL RECORDS
    # =============================================

    def _resolve_all_records(self):
        """Resolve all common DNS records"""
        print(f"{Fore.YELLOW}[*] Resolving DNS records...")

        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype, lifetime=5)
                records = [str(r) for r in answers]
                self.results['records'][rtype] = records

                if records:
                    preview = records[0][:60] if len(records[0]) > 60 else records[0]
                    print(f"{Fore.GREEN}  [+] {rtype}: {preview}")
                    if len(records) > 1:
                        print(f"{Fore.DIM}      (+{len(records)-1} more){Style.RESET_ALL}")

                # Store nameservers
                if rtype == 'NS':
                    self.results['nameservers'] = records

                # Store mail servers
                if rtype == 'MX':
                    self.results['mail_servers'] = records

            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            except Exception:
                pass

    # =============================================
    # REVERSE LOOKUP
    # =============================================

    def _reverse_lookup(self):
        """Reverse DNS lookup for A records"""
        print(f"{Fore.YELLOW}[*] Reverse DNS lookup...")

        a_records = self.results['records'].get('A', [])

        for ip in a_records[:5]:
            try:
                rev_name = dns.reversename.from_address(ip)
                answers = dns.resolver.resolve(rev_name, 'PTR', lifetime=5)
                ptr = [str(r) for r in answers]
                self.results['reverse_dns'][ip] = ptr

                if ptr:
                    print(f"{Fore.GREEN}  [+] {ip} -> {ptr[0]}")
            except:
                pass

    # =============================================
    # SPF CHECK
    # =============================================

    def _check_spf(self):
        """Check SPF record"""
        print(f"{Fore.YELLOW}[*] Checking SPF...")

        try:
            answers = dns.resolver.resolve(self.domain, 'TXT', lifetime=5)

            for record in answers:
                txt = str(record)
                if 'v=spf1' in txt:
                    self.results['spf'] = txt
                    print(f"{Fore.GREEN}  [+] SPF: {txt[:70]}")
                    return

            print(f"{Fore.YELLOW}  [-] No SPF record")
        except:
            print(f"{Fore.YELLOW}  [-] No SPF record")

    # =============================================
    # DMARC CHECK
    # =============================================

    def _check_dmarc(self):
        """Check DMARC record"""
        print(f"{Fore.YELLOW}[*] Checking DMARC...")

        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=5)

            for record in answers:
                txt = str(record)
                if 'v=DMARC1' in txt:
                    self.results['dmarc'] = txt
                    print(f"{Fore.GREEN}  [+] DMARC: {txt[:70]}")
                    return

            print(f"{Fore.YELLOW}  [-] No DMARC record")
        except:
            print(f"{Fore.YELLOW}  [-] No DMARC record")

    # =============================================
    # DKIM CHECK
    # =============================================

    def _check_dkim(self):
        """Check common DKIM selectors"""
        print(f"{Fore.YELLOW}[*] Checking DKIM...")

        selectors = [
            'default', 'mail', 'dkim', 'selector1', 'selector2',
            'google', 'k1', 's1', 's2', 'mandrill', 'sendgrid',
        ]

        found = 0
        for selector in selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{self.domain}"
                answers = dns.resolver.resolve(dkim_domain, 'TXT', lifetime=3)

                for record in answers:
                    txt = str(record)
                    if 'v=DKIM1' in txt or 'p=' in txt:
                        self.results['dkim'].append({
                            'selector': selector,
                            'record': txt[:100],
                        })
                        print(f"{Fore.GREEN}  [+] DKIM ({selector}): found")
                        found += 1
                        break
            except:
                continue

        if found == 0:
            print(f"{Fore.YELLOW}  [-] No DKIM records found")

    # =============================================
    # DNSSEC CHECK
    # =============================================

    def _check_dnssec(self):
        """Check DNSSEC"""
        print(f"{Fore.YELLOW}[*] Checking DNSSEC...")

        try:
            answers = dns.resolver.resolve(self.domain, 'DNSKEY', lifetime=5)
            if answers:
                self.results['dnssec'] = True
                print(f"{Fore.GREEN}  [+] DNSSEC: enabled")
                return
        except:
            pass

        print(f"{Fore.YELLOW}  [-] DNSSEC: not detected")

    # =============================================
    # ZONE TRANSFER
    # =============================================

    def _try_zone_transfer(self):
        """Attempt DNS zone transfer (AXFR)"""
        print(f"{Fore.YELLOW}[*] Attempting zone transfer...")

        nameservers = self.results.get('nameservers', [])

        if not nameservers:
            print(f"{Fore.YELLOW}  [-] No nameservers to test")
            return

        for ns in nameservers:
            # Clean NS record
            ns_host = str(ns).rstrip('.')

            try:
                # Get NS IP
                ns_ip = socket.gethostbyname(ns_host)

                # Try zone transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=10))

                if zone:
                    records = []
                    for name, node in zone.nodes.items():
                        records.append(str(name))

                    self.results['zone_transfer'] = {
                        'success': True,
                        'nameserver': ns_host,
                        'records': records,
                    }

                    print(f"{Fore.RED}  [!] ZONE TRANSFER SUCCESSFUL: {ns_host}")
                    print(f"{Fore.RED}      Records: {len(records)}")
                    return
            except Exception:
                continue

        print(f"{Fore.YELLOW}  [-] Zone transfer failed (good)")

    # =============================================
    # SRV ENUMERATION
    # =============================================

    def _enumerate_srv(self):
        """Enumerate common SRV records"""
        print(f"{Fore.YELLOW}[*] Enumerating SRV records...")

        found = 0

        for srv in self.SRV_RECORDS:
            try:
                srv_domain = f"{srv}.{self.domain}"
                answers = dns.resolver.resolve(srv_domain, 'SRV', lifetime=3)

                records = [str(r) for r in answers]
                if records:
                    if 'SRV' not in self.results['records']:
                        self.results['records']['SRV'] = []
                    self.results['records']['SRV'].extend(records)
                    print(f"{Fore.GREEN}  [+] {srv}: {records[0][:60]}")
                    found += 1
            except:
                continue

        if found == 0:
            print(f"{Fore.YELLOW}  [-] No SRV records found")

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        r = self.results

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  DNS ENUMERATION SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Domain:       {r['domain']}")

        # Records
        for rtype, records in r['records'].items():
            if records:
                print(f"{Fore.GREEN}[+] {rtype:<8} {len(records)} record(s)")

        # SPF/DMARC/DKIM
        if r['spf']:
            print(f"{Fore.GREEN}[+] SPF:      Yes")
        else:
            print(f"{Fore.YELLOW}[!] SPF:      No")

        if r['dmarc']:
            print(f"{Fore.GREEN}[+] DMARC:    Yes")
        else:
            print(f"{Fore.YELLOW}[!] DMARC:    No")

        if r['dkim']:
            print(f"{Fore.GREEN}[+] DKIM:     {len(r['dkim'])} selector(s)")

        # DNSSEC
        if r['dnssec']:
            print(f"{Fore.GREEN}[+] DNSSEC:   Enabled")
        else:
            print(f"{Fore.YELLOW}[!] DNSSEC:   Disabled")

        # Zone Transfer
        if r['zone_transfer']['success']:
            print(f"{Fore.RED}[!] ZONE TRANSFER: SUCCESSFUL!")
            print(f"{Fore.RED}    Nameserver: {r['zone_transfer']['nameserver']}")
        else:
            print(f"{Fore.GREEN}[+] Zone Transfer: Failed (good)")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["DNSEnumerator"]