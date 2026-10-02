# core/runner.py
# BlackHunter Pro - Module Runner
# Orchestrates all scanners and exploits

import os
import sys
import time
import json
from datetime import datetime
from urllib.parse import urlparse

# Import utils
try:
    from .utils import (
        Colors as C,
        log_info, log_ok, log_warn, log_error, log_step,
        print_separator, print_header,
        validate_target, timestamp, ensure_dir,
        save_json, format_time, Timer,
    )
    from .config import get_config
    from .logger import get_logger
    from .banner import (
        show_banner, show_small_banner,
        show_completion_banner, show_error_banner,
        show_phase_header, show_section_header,
    )
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from utils import (
        Colors as C,
        log_info, log_ok, log_warn, log_error, log_step,
        print_separator, print_header,
        validate_target, timestamp, ensure_dir,
        save_json, format_time, Timer,
    )
    from config import get_config
    from logger import get_logger
    from banner import (
        show_banner, show_small_banner,
        show_completion_banner, show_error_banner,
        show_phase_header, show_section_header,
    )


class Runner:
    """
    Module Runner
    - Executes scanners and exploits
    - Aggregates results
    - Generates reports
    - Handles errors gracefully
    """

    def __init__(self, target, config=None):
        self.target = target.rstrip('/')
        self.config = config or get_config()
        self.logger = get_logger()
        self.timer = Timer()

        self.results = {
            'target': self.target,
            'started_at': datetime.now().isoformat(),
            'finished_at': None,
            'duration': 0,
            'recon': {},
            'port': {},
            'web': {},
            'cms': {},
            'subdomain': {},
            'vulnerabilities': [],
            'exploits': [],
            'errors': [],
            'report_json': None,
            'report_html': None,
        }

    # =============================================
    # MAIN RUN
    # =============================================

    def run(self, module='full'):
        """Run specified module"""
        self.timer.start()

        print(f"\n{C.CYAN}{'═'*60}")
        print(f"{C.WHITE}  BlackHunter Pro - {module.upper()} SCAN")
        print(f"{C.CYAN}{'═'*60}{C.RESET}")
        print(f"{C.GREEN}[+] Target:  {self.target}")
        print(f"{C.GREEN}[+] Module:  {module}")
        print(f"{C.GREEN}[+] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{C.CYAN}{'═'*60}{C.RESET}\n")

        # Log scan start
        self.logger.scan_start(self.target, module)

        try:
            if module == 'recon':
                self._run_recon()
            elif module == 'port':
                self._run_port()
            elif module == 'web':
                self._run_web()
            elif module == 'cms':
                self._run_cms()
            elif module == 'subdomain':
                self._run_subdomain()
            elif module == 'sqli':
                self._run_sqli()
            elif module == 'xss':
                self._run_xss()
            elif module == 'lfi':
                self._run_lfi()
            elif module == 'cmdi':
                self._run_cmdi()
            elif module == 'ssrf':
                self._run_ssrf()
            elif module == 'upload':
                self._run_upload()
            elif module == 'xxe':
                self._run_xxe()
            elif module == 'csrf':
                self._run_csrf()
            elif module == 'idor':
                self._run_idor()
            elif module == 'redirect':
                self._run_redirect()
            elif module == 'full':
                self._run_full()
            elif module == 'report':
                self._generate_report()
                return self.results
            else:
                log_error(f"Unknown module: {module}")
                return self.results

        except KeyboardInterrupt:
            log_warn("Scan interrupted by user")
            self.results['errors'].append("Interrupted by user")
        except Exception as e:
            log_error(f"Fatal error: {e}")
            self.results['errors'].append(str(e))

        # Finalize
        self.results['finished_at'] = datetime.now().isoformat()
        self.results['duration'] = self.timer.elapsed()

        # Log scan end
        self.logger.scan_end(
            self.target,
            len(self.results['vulnerabilities']),
            self.results['duration']
        )

        # Save report
        if module != 'report':
            self._generate_report()

        self._print_summary()

        return self.results

    # =============================================
    # RECON
    # =============================================

    def _run_recon(self):
        """Run reconnaissance"""
        show_phase_header(1, "Reconnaissance", 5)

        try:
            from scanners.recon import Recon

            recon = Recon(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            result = recon.run()
            self.results['recon'] = result

            if hasattr(recon, 'summary'):
                recon.summary()

            log_ok("Reconnaissance completed")

        except Exception as e:
            log_error(f"Recon failed: {e}")
            self.results['errors'].append(f"Recon: {e}")

    # =============================================
    # PORT
    # =============================================

    def _run_port(self):
        """Run port scan"""
        show_phase_header(2, "Port Scanning", 5)

        try:
            from scanners.port import PortScanner

            scanner = PortScanner(
                self.target,
                timeout=2,
                threads=self.config.threads
            )
            result = scanner.run()
            self.results['port'] = result

            if hasattr(scanner, 'summary'):
                scanner.summary()

            log_ok(f"Port scan completed: {len(result.get('open_ports', []))} open ports")

        except Exception as e:
            log_error(f"Port scan failed: {e}")
            self.results['errors'].append(f"Port: {e}")

    # =============================================
    # WEB
    # =============================================

    def _run_web(self):
        """Run web scan"""
        show_phase_header(3, "Web Scanning", 5)

        try:
            from scanners.web import WebScanner

            scanner = WebScanner(
                self.target,
                timeout=self.config.timeout,
                threads=self.config.threads,
                user_agent=self.config.user_agent
            )
            result = scanner.run()
            self.results['web'] = result

            if hasattr(scanner, 'summary'):
                scanner.summary()

            log_ok("Web scan completed")

        except Exception as e:
            log_error(f"Web scan failed: {e}")
            self.results['errors'].append(f"Web: {e}")

    # =============================================
    # CMS
    # =============================================

    def _run_cms(self):
        """Run CMS detection"""
        show_phase_header(4, "CMS Detection", 5)

        try:
            from scanners.cms import CMSDetector

            detector = CMSDetector(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            result = detector.run()
            self.results['cms'] = result

            if hasattr(detector, 'summary'):
                detector.summary()

            log_ok("CMS detection completed")

        except Exception as e:
            log_error(f"CMS detection failed: {e}")
            self.results['errors'].append(f"CMS: {e}")

    # =============================================
    # SUBDOMAIN
    # =============================================

    def _run_subdomain(self):
        """Run subdomain enumeration"""
        show_phase_header(5, "Subdomain Enumeration", 5)

        try:
            from scanners.subdomain import SubdomainScanner

            scanner = SubdomainScanner(
                self.target,
                timeout=self.config.timeout,
                threads=self.config.threads
            )
            result = scanner.run()
            self.results['subdomain'] = result

            if hasattr(scanner, 'summary'):
                scanner.summary()

            log_ok("Subdomain enumeration completed")

        except Exception as e:
            log_error(f"Subdomain enum failed: {e}")
            self.results['errors'].append(f"Subdomain: {e}")

    # =============================================
    # SQLi
    # =============================================

    def _run_sqli(self):
        """Run SQL Injection scan"""
        show_section_header("SQL Injection Scanner")

        try:
            from vulns.sqli import SQLiScanner

            scanner = SQLiScanner(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            vulns = scanner.run()

            for v in vulns:
                self.results['vulnerabilities'].append(v)
                self.logger.vulnerability_found(v)

            if hasattr(scanner, 'summary'):
                scanner.summary()

            log_ok(f"SQLi scan completed: {len(vulns)} findings")

        except Exception as e:
            log_error(f"SQLi failed: {e}")
            self.results['errors'].append(f"SQLi: {e}")

    # =============================================
    # XSS
    # =============================================

    def _run_xss(self):
        """Run XSS scan"""
        show_section_header("XSS Scanner")

        try:
            from vulns.xss import XSSScanner

            scanner = XSSScanner(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            vulns = scanner.run()

            for v in vulns:
                self.results['vulnerabilities'].append(v)
                self.logger.vulnerability_found(v)

            if hasattr(scanner, 'summary'):
                scanner.summary()

            log_ok(f"XSS scan completed: {len(vulns)} findings")

        except Exception as e:
            log_error(f"XSS failed: {e}")
            self.results['errors'].append(f"XSS: {e}")

    # =============================================
    # LFI
    # =============================================

    def _run_lfi(self):
        """Run LFI scan"""
        show_section_header("LFI/RFI Scanner")

        try:
            from vulns.lfi import LFIScanner

            scanner = LFIScanner(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            vulns = scanner.run()

            for v in vulns:
                self.results['vulnerabilities'].append(v)
                self.logger.vulnerability_found(v)

            if hasattr(scanner, 'summary'):
                scanner.summary()

            log_ok(f"LFI scan completed: {len(vulns)} findings")

        except Exception as e:
            log_error(f"LFI failed: {e}")
            self.results['errors'].append(f"LFI: {e}")

    # =============================================
    # CMDi
    # =============================================

    def _run_cmdi(self):
        """Run Command Injection scan"""
        show_section_header("Command Injection Scanner")

        try:
            from vulns.cmdi import CMDInjectScanner

            scanner = CMDInjectScanner(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            vulns = scanner.run()

            for v in vulns:
                self.results['vulnerabilities'].append(v)
                self.logger.vulnerability_found(v)

            if hasattr(scanner, 'summary'):
                scanner.summary()

            log_ok(f"CMDi scan completed: {len(vulns)} findings")

        except Exception as e:
            log_error(f"CMDi failed: {e}")
            self.results['errors'].append(f"CMDi: {e}")

    # =============================================
    # SSRF
    # =============================================

    def _run_ssrf(self):
        """Run SSRF scan"""
        show_section_header("SSRF Scanner")

        try:
            from vulns.ssrf import SSRFScanner

            scanner = SSRFScanner(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            vulns = scanner.run()

            for v in vulns:
                self.results['vulnerabilities'].append(v)
                self.logger.vulnerability_found(v)

            if hasattr(scanner, 'summary'):
                scanner.summary()

            log_ok(f"SSRF scan completed: {len(vulns)} findings")

        except Exception as e:
            log_error(f"SSRF failed: {e}")
            self.results['errors'].append(f"SSRF: {e}")

    # =============================================
    # UPLOAD
    # =============================================

    def _run_upload(self):
        """Run File Upload scan"""
        show_section_header("File Upload Scanner")

        try:
            from vulns.upload import UploadScanner

            scanner = UploadScanner(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            vulns = scanner.run()

            for v in vulns:
                self.results['vulnerabilities'].append(v)
                self.logger.vulnerability_found(v)

            if hasattr(scanner, 'summary'):
                scanner.summary()

            log_ok(f"Upload scan completed: {len(vulns)} findings")

        except Exception as e:
            log_error(f"Upload failed: {e}")
            self.results['errors'].append(f"Upload: {e}")

    # =============================================
    # XXE
    # =============================================

    def _run_xxe(self):
        """Run XXE scan"""
        show_section_header("XXE Scanner")

        try:
            from vulns.xxe import XXEScanner

            scanner = XXEScanner(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            vulns = scanner.run()

            for v in vulns:
                self.results['vulnerabilities'].append(v)
                self.logger.vulnerability_found(v)

            log_ok(f"XXE scan completed: {len(vulns)} findings")

        except Exception as e:
            log_error(f"XXE failed: {e}")
            self.results['errors'].append(f"XXE: {e}")

    # =============================================
    # CSRF
    # =============================================

    def _run_csrf(self):
        """Run CSRF scan"""
        show_section_header("CSRF Scanner")

        try:
            from vulns.csrf import CSRFScanner

            scanner = CSRFScanner(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            vulns = scanner.run()

            for v in vulns:
                self.results['vulnerabilities'].append(v)
                self.logger.vulnerability_found(v)

            log_ok(f"CSRF scan completed: {len(vulns)} findings")

        except Exception as e:
            log_error(f"CSRF failed: {e}")
            self.results['errors'].append(f"CSRF: {e}")

    # =============================================
    # IDOR
    # =============================================

    def _run_idor(self):
        """Run IDOR scan"""
        show_section_header("IDOR Scanner")

        try:
            from vulns.idor import IDORScanner

            scanner = IDORScanner(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            vulns = scanner.run()

            for v in vulns:
                self.results['vulnerabilities'].append(v)
                self.logger.vulnerability_found(v)

            log_ok(f"IDOR scan completed: {len(vulns)} findings")

        except Exception as e:
            log_error(f"IDOR failed: {e}")
            self.results['errors'].append(f"IDOR: {e}")

    # =============================================
    # REDIRECT
    # =============================================

    def _run_redirect(self):
        """Run Open Redirect scan"""
        show_section_header("Open Redirect Scanner")

        try:
            from vulns.open_redirect import RedirectScanner

            scanner = RedirectScanner(
                self.target,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent
            )
            vulns = scanner.run()

            for v in vulns:
                self.results['vulnerabilities'].append(v)
                self.logger.vulnerability_found(v)

            log_ok(f"Redirect scan completed: {len(vulns)} findings")

        except Exception as e:
            log_error(f"Redirect failed: {e}")
            self.results['errors'].append(f"Redirect: {e}")

    # =============================================
    # FULL SCAN
    # =============================================

    def _run_full(self):
        """Run full scan - all modules"""
        print(f"{C.MAGENTA}>>> FULL SCAN MODE - Running all modules <<<{C.RESET}\n")

        # Scanning phase
        print(f"\n{C.CYAN}{'─'*60}")
        print(f"{C.WHITE}  SCANNING PHASE")
        print(f"{C.CYAN}{'─'*60}{C.RESET}")

        self._run_recon()
        self._run_port()
        self._run_web()
        self._run_cms()

        # Vulnerability phase
        print(f"\n{C.CYAN}{'─'*60}")
        print(f"{C.WHITE}  VULNERABILITY DETECTION PHASE")
        print(f"{C.CYAN}{'─'*60}{C.RESET}")

        self._run_sqli()
        self._run_xss()
        self._run_lfi()
        self._run_cmdi()
        self._run_ssrf()
        self._run_upload()

        log_ok(f"Full scan completed: {len(self.results['vulnerabilities'])} vulnerabilities found")

    # =============================================
    # GENERATE REPORT
    # =============================================

    def _generate_report(self):
        """Generate JSON + HTML reports"""
        show_section_header("Generating Reports")

        try:
            report_dir = self.config.get_report_path()
            ensure_dir(report_dir)

            ts = timestamp()

            # JSON report
            json_dir = os.path.join(report_dir, "json")
            ensure_dir(json_dir)
            json_path = os.path.join(json_dir, f"report_{ts}.json")

            if save_json(json_path, self.results):
                log_ok(f"JSON: {json_path}")
                self.results['report_json'] = json_path

            # HTML report
            html_dir = os.path.join(report_dir, "html")
            ensure_dir(html_dir)
            html_path = os.path.join(html_dir, f"report_{ts}.html")

            html_content = self._build_html_report()

            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            log_ok(f"HTML: {html_path}")
            self.results['report_html'] = html_path

        except Exception as e:
            log_error(f"Report generation failed: {e}")
            self.results['errors'].append(f"Report: {e}")

    # =============================================
    # HTML REPORT
    # =============================================

    def _build_html_report(self):
        """Build HTML report"""
        vulns = self.results['vulnerabilities']
        critical = len([v for v in vulns if v.get('severity') == 'CRITICAL'])
        high = len([v for v in vulns if v.get('severity') == 'HIGH'])
        medium = len([v for v in vulns if v.get('severity') == 'MEDIUM'])
        low = len([v for v in vulns if v.get('severity') == 'LOW'])

        duration = format_time(self.results['duration'])

        # Build vulnerabilities HTML
        vulns_html = ""
        if vulns:
            for i, v in enumerate(vulns, 1):
                sev = v.get('severity', 'LOW')
                sev_class = sev.lower()
                vulns_html += f"""
                <div class="vuln {sev_class}">
                    <div class="vuln-header">
                        <span class="vuln-num">#{i}</span>
                        <span class="vuln-type">{v.get('type', 'Unknown')}</span>
                        <span class="severity {sev_class}">{sev}</span>
                    </div>
                    <div class="vuln-body">
                        <p><strong>URL:</strong> <code>{v.get('url', 'N/A')}</code></p>
                        <p><strong>Parameter:</strong> <code>{v.get('param', 'N/A')}</code></p>
                        <p><strong>Payload:</strong></p>
                        <pre>{v.get('payload', 'N/A')}</pre>
                        {f'<p><strong>Evidence:</strong></p><pre>{str(v.get("evidence", "N/A"))[:500]}</pre>' if v.get('evidence') else ''}
                    </div>
                </div>
                """
        else:
            vulns_html = '<p class="no-vulns">No vulnerabilities detected.</p>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlackHunter Report - {self.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, 'Segoe UI', Tahoma, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: linear-gradient(135deg, #e94560, #0f3460);
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        header h1 {{ color: #fff; font-size: 2.5em; margin-bottom: 8px; }}
        header p {{ color: rgba(255,255,255,0.9); }}
        h2 {{
            color: #e94560;
            margin: 30px 0 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e94560;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .info-card {{
            background: #161b22;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #58a6ff;
        }}
        .info-card label {{
            color: #8b949e;
            font-size: 0.85em;
            display: block;
            margin-bottom: 6px;
            text-transform: uppercase;
        }}
        .info-card value {{
            color: #fff;
            font-size: 1.1em;
            font-weight: 600;
            word-break: break-all;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }}
        .stat {{
            padding: 25px;
            border-radius: 10px;
            text-align: center;
        }}
        .stat-critical {{ background: linear-gradient(135deg, #7d1a1a, #a01515); }}
        .stat-high {{ background: linear-gradient(135deg, #8b4513, #b35a1a); }}
        .stat-medium {{ background: linear-gradient(135deg, #7d6608, #a38508); }}
        .stat-low {{ background: linear-gradient(135deg, #1a5d3a, #257a4d); }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #fff;
        }}
        .stat-label {{
            color: rgba(255,255,255,0.9);
            margin-top: 6px;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }}
        .vuln {{
            background: #161b22;
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
        }}
        .vuln.critical {{ border-left: 4px solid #f85149; }}
        .vuln.high {{ border-left: 4px solid #d29922; }}
        .vuln.medium {{ border-left: 4px solid #58a6ff; }}
        .vuln.low {{ border-left: 4px solid #3fb950; }}
        .vuln-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 15px;
        }}
        .vuln-num {{
            background: #21262d;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .vuln-type {{
            flex: 1;
            font-size: 1.15em;
            font-weight: 600;
            color: #fff;
        }}
        .severity {{
            padding: 4px 14px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .severity.critical {{ background: #f85149; color: #fff; }}
        .severity.high {{ background: #d29922; color: #fff; }}
        .severity.medium {{ background: #58a6ff; color: #fff; }}
        .severity.low {{ background: #3fb950; color: #fff; }}
        .vuln-body p {{ margin: 8px 0; }}
        .vuln-body strong {{ color: #8b949e; }}
        code {{
            background: #0d1117;
            padding: 2px 8px;
            border-radius: 4px;
            color: #7ee787;
            font-family: 'Courier New', monospace;
            word-break: break-all;
        }}
        pre {{
            background: #0d1117;
            padding: 12px;
            border-radius: 6px;
            color: #7ee787;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 8px 0;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .no-vulns {{
            color: #3fb950;
            padding: 20px;
            text-align: center;
            font-size: 1.1em;
        }}
        footer {{
            text-align: center;
            padding: 30px;
            color: #8b949e;
            margin-top: 40px;
            border-top: 1px solid #30363d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🎯 BlackHunter Report</h1>
            <p>Security Assessment Report</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <h2>📊 Scan Summary</h2>
        <div class="info-grid">
            <div class="info-card">
                <label>Target</label>
                <value>{self.target}</value>
            </div>
            <div class="info-card">
                <label>Duration</label>
                <value>{duration}</value>
            </div>
            <div class="info-card">
                <label>IP Address</label>
                <value>{self.results.get('recon', {}).get('ip', 'N/A')}</value>
            </div>
            <div class="info-card">
                <label>Server</label>
                <value>{self.results.get('recon', {}).get('server', 'N/A')}</value>
            </div>
        </div>

        <h2>🎯 Vulnerability Statistics</h2>
        <div class="stats">
            <div class="stat stat-critical">
                <div class="stat-number">{critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat stat-high">
                <div class="stat-number">{high}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat stat-medium">
                <div class="stat-number">{medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat stat-low">
                <div class="stat-number">{low}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>

        <h2>🔍 Discovered Vulnerabilities</h2>
        {vulns_html}

        <footer>
            <p>🎯 BlackHunter Pro v1.0.0 - Academic Penetration Testing Tool</p>
            <p>For isolated lab environment only</p>
        </footer>
    </div>
</body>
</html>"""

        return html

    # =============================================
    # SUMMARY
    # =============================================

    def _print_summary(self):
        """Print final summary"""
        vulns = self.results['vulnerabilities']

        critical = len([v for v in vulns if v.get('severity') == 'CRITICAL'])
        high = len([v for v in vulns if v.get('severity') == 'HIGH'])
        medium = len([v for v in vulns if v.get('severity') == 'MEDIUM'])
        low = len([v for v in vulns if v.get('severity') == 'LOW'])

        duration = format_time(self.results['duration'])

        print(f"\n{C.GREEN}{'═'*60}")
        print(f"{C.GREEN}  SCAN COMPLETE")
        print(f"{C.GREEN}{'═'*60}{C.RESET}")
        print(f"{C.CYAN}[+] Target:       {self.target}")
        print(f"{C.CYAN}[+] Duration:     {duration}")
        print(f"{C.CYAN}[+] Total Vulns:  {len(vulns)}")

        if critical:
            print(f"{C.RED}[!] CRITICAL:     {critical}")
        if high:
            print(f"{C.YELLOW}[!] HIGH:         {high}")
        if medium:
            print(f"{C.CYAN}[!] MEDIUM:       {medium}")
        if low:
            print(f"{C.GREEN}[+] LOW:          {low}")

        if self.results.get('report_json'):
            print(f"{C.GREEN}[+] JSON Report:  {self.results['report_json']}")
        if self.results.get('report_html'):
            print(f"{C.GREEN}[+] HTML Report:  {self.results['report_html']}")

        if self.results['errors']:
            print(f"{C.YELLOW}[!] Errors:       {len(self.results['errors'])}")

        print(f"{C.GREEN}{'═'*60}{C.RESET}\n")


# =============================================
# HELPER FUNCTIONS
# =============================================

def run_scan(target, module='full', config=None):
    """Convenience function to run a scan"""
    target = validate_target(target)
    if not target:
        log_error("Invalid target")
        return None

    runner = Runner(target, config=config)
    return runner.run(module=module)


def run_module(target, module, config=None):
    """Run a specific module"""
    return run_scan(target, module=module, config=config)


# =============================================
# CLI INTERFACE
# =============================================

def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="BlackHunter Pro - Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python runner.py -t http://target.com -m full
  python runner.py -t http://target.com -m recon
  python runner.py -t http://target.com -m sqli
  python runner.py -t http://target.com -m port
        """
    )

    parser.add_argument('-t', '--target', required=True, help="Target URL")
    parser.add_argument('-m', '--module', default='full',
                        choices=['recon', 'port', 'web', 'cms', 'subdomain',
                                 'sqli', 'xss', 'lfi', 'cmdi', 'ssrf', 'upload',
                                 'xxe', 'csrf', 'idor', 'redirect',
                                 'full', 'report'],
                        help="Scan module (default: full)")
    parser.add_argument('-c', '--config', help="Config file path")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    parser.add_argument('--no-exploit', action='store_true', help="Skip exploitation")

    args = parser.parse_args()

    # Load config
    config = get_config(args.config) if args.config else get_config()

    # Validate target
    target = validate_target(args.target)
    if not target:
        log_error(f"Invalid target: {args.target}")
        sys.exit(1)

    # Run
    runner = Runner(target, config=config)
    runner.run(module=args.module)


if __name__ == '__main__':
    main()


# =============================================
# EXPORTS
# =============================================

__all__ = [
    "Runner",
    "run_scan",
    "run_module",
    "main",
]