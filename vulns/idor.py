# vulns/idor.py
# BlackHunter Pro - IDOR Scanner
# Detects: Insecure Direct Object Reference vulnerabilities

import re
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class IDORScanner:
    """
    Insecure Direct Object Reference (IDOR) Scanner
    - Numeric ID enumeration
    - UUID/GUID detection
    - Parameter tampering
    - Path-based IDOR
    - Horizontal privilege escalation
    - Vertical privilege escalation
    """

    # =============================================
    # IDOR-PRONE PARAMETERS
    # =============================================

    IDOR_PARAMS = [
        'id', 'user_id', 'userid', 'user', 'uid', 'account',
        'account_id', 'accountid', 'profile', 'profile_id',
        'customer', 'customer_id', 'customerid', 'client',
        'client_id', 'clientid', 'member', 'member_id',
        'order', 'order_id', 'orderid', 'invoice', 'invoice_id',
        'invoiceid', 'document', 'document_id', 'documentid',
        'file', 'file_id', 'fileid', 'filename', 'attachment',
        'attachment_id', 'resource', 'resource_id', 'item',
        'item_id', 'itemid', 'product', 'product_id', 'productid',
        'post', 'post_id', 'postid', 'article', 'article_id',
        'ticket', 'ticket_id', 'ticketid', 'message', 'message_id',
        'msg', 'msg_id', 'comment', 'comment_id', 'commentid',
        'report', 'report_id', 'reportid', 'session', 'session_id',
        'sessionid', 'token', 'key', 'uuid', 'guid', 'ref',
        'reference', 'number', 'num', 'no', 'group', 'group_id',
        'team', 'team_id', 'organization', 'organization_id',
        'org', 'org_id', 'company', 'company_id', 'project',
        'project_id', 'task', 'task_id', 'job', 'job_id',
    ]

    # =============================================
    # TEST VALUES
    # =============================================

    NUMERIC_TESTS = [
        '1', '2', '3', '4', '5', '10', '50', '100', '500', '1000',
        '0', '-1', '999999', '1000000',
    ]

    STRING_TESTS = [
        'admin', 'administrator', 'root', 'user', 'test', 'guest',
        'null', 'undefined', 'true', 'false', 'None', 'nil',
        '1', '0', '-1', '1.0', '1e1',
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
        self._baselines = {}

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute IDOR detection"""
        print(f"{Fore.CYAN}[*] IDOR Scanner started")
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print()

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            params = self._find_form_params()

        if not params:
            print(f"{Fore.YELLOW}  [-] No parameters found")
            return []

        # Filter IDOR-prone params
        idor_params = {k: v for k, v in params.items()
                       if any(name in k.lower() for name in self.IDOR_PARAMS)}

        if not idor_params:
            idor_params = params

        print(f"{Fore.CYAN}[*] Testing {len(idor_params)} parameters: {', '.join(idor_params.keys())}")
        print()

        # Get baseline
        self._get_baseline()

        for param in idor_params.keys():
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
            self._baselines['original'] = {
                'status': r.status_code,
                'length': len(r.text),
                'content': r.text[:500],
            }
        except:
            self._baselines['original'] = {'status': 0, 'length': 0, 'content': ''}

    # =============================================
    # TEST PARAMETER
    # =============================================

    def _test_parameter(self, param):
        """Test single parameter for IDOR"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        original_value = params.get(param, ['1'])[0]

        # Determine if original value is numeric
        if original_value.isdigit():
            self._test_numeric(param, base_url, params, int(original_value))
        else:
            self._test_string(param, base_url, params, original_value)

    # =============================================
    # NUMERIC TESTS
    # =============================================

    def _test_numeric(self, param, base_url, params, original):
        """Test numeric ID parameters"""
        responses = {}

        for test_val in self.NUMERIC_TESTS:
            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = test_val

                r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                responses[test_val] = {
                    'status': r.status_code,
                    'length': len(r.text),
                    'content': r.text[:500],
                }

                # Check for successful access
                if r.status_code == 200 and int(test_val) != original:
                    # If response differs from original significantly = potential IDOR
                    diff = abs(len(r.text) - self._baselines['original']['length'])
                    if diff > 100:
                        print(f"{Fore.RED}  [!] Potential IDOR!")
                        print(f"{Fore.RED}      Param: {param}")
                        print(f"{Fore.RED}      Original: {original} | Test: {test_val}")
                        print(f"{Fore.RED}      Response size: {len(r.text)} (original: {self._baselines['original']['length']})")

                        self.vulnerabilities.append({
                            'type': 'IDOR (Numeric ID Enumeration)',
                            'url': r.url,
                            'param': param,
                            'original_value': original,
                            'test_value': test_val,
                            'response_size': len(r.text),
                            'severity': 'HIGH',
                        })
                        return
            except:
                continue

    # =============================================
    # STRING TESTS
    # =============================================

    def _test_string(self, param, base_url, params, original):
        """Test string ID parameters"""
        for test_val in self.STRING_TESTS:
            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = test_val

                r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                # Successful access with different value
                if r.status_code == 200 and test_val != original:
                    diff = abs(len(r.text) - self._baselines['original']['length'])
                    if diff > 100:
                        print(f"{Fore.RED}  [!] Potential IDOR (String)")
                        print(f"{Fore.RED}      Param: {param}")
                        print(f"{Fore.RED}      Original: {original} | Test: {test_val}")

                        self.vulnerabilities.append({
                            'type': 'IDOR (String ID Manipulation)',
                            'url': r.url,
                            'param': param,
                            'original_value': original,
                            'test_value': test_val,
                            'severity': 'HIGH',
                        })
                        return
            except:
                continue

    # =============================================
    # PATH-BASED IDOR
    # =============================================

    def test_path_idor(self):
        """Test path-based IDOR (e.g., /user/1, /user/2)"""
        print(f"{Fore.YELLOW}[*] Testing path-based IDOR...")

        parsed = urlparse(self.target)
        path = parsed.path

        # Check if path ends with number
        match = re.search(r'/(\d+)(/?)$', path)

        if not match:
            print(f"{Fore.YELLOW}  [-] No numeric ID in path")
            return

        original_id = int(match.group(1))
        base_path = path[:match.start()]

        for test_id in [original_id + 1, original_id - 1, original_id + 100, 1, 0, 999999]:
            try:
                new_path = f"{base_path}/{test_id}{match.group(2)}"
                url = f"{parsed.scheme}://{parsed.netloc}{new_path}"

                r = self.session.get(url, timeout=self.timeout, verify=False)

                if r.status_code == 200:
                    diff = abs(len(r.text) - self._baselines['original']['length'])
                    if diff > 100:
                        print(f"{Fore.RED}  [!] Path-Based IDOR!")
                        print(f"{Fore.RED}      Original: {original_id} | Test: {test_id}")

                        self.vulnerabilities.append({
                            'type': 'IDOR (Path-Based)',
                            'url': url,
                            'original_id': original_id,
                            'test_id': test_id,
                            'severity': 'HIGH',
                        })
                        return
            except:
                continue

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  IDOR SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Vulnerabilities: {len(self.vulnerabilities)}")

        for v in self.vulnerabilities:
            print(f"{Fore.RED}[!] {v['type']} - {v.get('param', 'N/A')}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["IDORScanner"]