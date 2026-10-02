# core/logger.py
# BlackHunter Pro - Logger Module
# Handles logging for scans, vulnerabilities, and exploits

import os
import sys
import json
import logging
from datetime import datetime

# Import utils
try:
    from .utils import Colors as C, ensure_dir, timestamp
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from utils import Colors as C, ensure_dir, timestamp


# =============================================
# LOGGER CLASS
# =============================================

class Logger:
    """
    Logger Manager
    - Scan logs
    - Vulnerability logs
    - Exploit logs
    - Error logs
    - Console + File output
    """

    def __init__(self, log_dir=None):
        """Initialize logger"""
        # Determine log directory
        if log_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_dir = os.path.join(base_dir, "logs")

        self.log_dir = log_dir
        ensure_dir(self.log_dir)

        # Log file paths
        self.scan_log = os.path.join(self.log_dir, "scan.log")
        self.vuln_log = os.path.join(self.log_dir, "vulnerabilities.log")
        self.exploit_log = os.path.join(self.log_dir, "exploit.log")
        self.error_log = os.path.join(self.log_dir, "error.log")
        self.session_log = os.path.join(self.log_dir, "sessions.log")

        # Create logging handlers
        self._setup_python_logging()

    def _setup_python_logging(self):
        """Setup Python logging for internal use"""
        self.logger = logging.getLogger("BlackHunter")
        self.logger.setLevel(logging.DEBUG)

        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # Console handler
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(console)

    # =============================================
    # FILE WRITING
    # =============================================

    def _write(self, path, message):
        """Write message to file with timestamp"""
        try:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(path, 'a', encoding='utf-8') as f:
                f.write(f"[{ts}] {message}\n")
        except Exception:
            pass

    def _write_json(self, path, data):
        """Append JSON entry to file"""
        try:
            entry = {
                'timestamp': datetime.now().isoformat(),
                'data': data,
            }
            with open(path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            pass

    # =============================================
    # SCAN LOGGING
    # =============================================

    def scan_start(self, target, module="full"):
        """Log scan start"""
        msg = f"SCAN START | Target: {target} | Module: {module}"
        self._write(self.scan_log, msg)
        self.logger.info(f"{C.CYAN}[*]{C.RESET} {msg}")

    def scan_end(self, target, vuln_count, duration):
        """Log scan end"""
        msg = f"SCAN END | Target: {target} | Vulnerabilities: {vuln_count} | Duration: {duration:.2f}s"
        self._write(self.scan_log, msg)
        self.logger.info(f"{C.GREEN}[✓]{C.RESET} {msg}")

    def scan_phase(self, phase_name, message=""):
        """Log a scan phase"""
        msg = f"PHASE | {phase_name} | {message}"
        self._write(self.scan_log, msg)

    # =============================================
    # VULNERABILITY LOGGING
    # =============================================

    def vulnerability_found(self, vuln):
        """Log a vulnerability finding"""
        if isinstance(vuln, dict):
            vuln_type = vuln.get('type', 'Unknown')
            severity = vuln.get('severity', 'LOW')
            url = vuln.get('url', 'N/A')
            param = vuln.get('param', 'N/A')

            msg = f"VULN | {severity} | {vuln_type} | URL: {url} | Param: {param}"
            self._write(self.vuln_log, msg)
            self._write_json(self.vuln_log, vuln)

            # Console output with color
            colors = {
                'CRITICAL': C.RED,
                'HIGH': C.YELLOW,
                'MEDIUM': C.CYAN,
                'LOW': C.GREEN,
            }
            color = colors.get(severity.upper(), C.WHITE)
            self.logger.info(f"{color}[!]{C.RESET} {vuln_type} [{severity}] - {url}")
        else:
            self._write(self.vuln_log, str(vuln))

    def vulnerability_summary(self, vulns):
        """Log vulnerability summary"""
        if not vulns:
            return

        counts = {}
        for v in vulns:
            sev = v.get('severity', 'LOW')
            counts[sev] = counts.get(sev, 0) + 1

        msg = f"VULN SUMMARY | Total: {len(vulns)} | " + " | ".join(f"{k}: {v}" for k, v in counts.items())
        self._write(self.vuln_log, msg)

    # =============================================
    # EXPLOIT LOGGING
    # =============================================

    def exploit_start(self, exploit_type, target):
        """Log exploit start"""
        msg = f"EXPLOIT START | Type: {exploit_type} | Target: {target}"
        self._write(self.exploit_log, msg)
        self.logger.info(f"{C.MAGENTA}[⚔]{C.RESET} {msg}")

    def exploit_success(self, exploit_type, url, payload, evidence=""):
        """Log successful exploit"""
        msg = f"EXPLOIT SUCCESS | {exploit_type} | URL: {url} | Payload: {payload[:100]}"
        self._write(self.exploit_log, msg)
        self._write_json(self.exploit_log, {
            'type': exploit_type,
            'url': url,
            'payload': payload,
            'evidence': evidence,
            'success': True,
        })
        self.logger.info(f"{C.RED}[✓]{C.RESET} {msg}")

    def exploit_fail(self, exploit_type, url, reason=""):
        """Log failed exploit"""
        msg = f"EXPLOIT FAIL | {exploit_type} | URL: {url} | Reason: {reason}"
        self._write(self.exploit_log, msg)

    def shell_obtained(self, url, shell_type, cmd_output=""):
        """Log shell obtained"""
        msg = f"SHELL OBTAINED | {shell_type} | URL: {url}"
        self._write(self.exploit_log, msg)
        self._write_json(self.exploit_log, {
            'event': 'shell_obtained',
            'url': url,
            'shell_type': shell_type,
            'output': cmd_output[:500] if cmd_output else '',
        })
        self.logger.info(f"{C.RED}[⚔] SHELL: {url}{C.RESET}")

    # =============================================
    # ERROR LOGGING
    # =============================================

    def error(self, message, exception=None):
        """Log an error"""
        msg = f"ERROR | {message}"
        if exception:
            msg += f" | Exception: {str(exception)}"
        self._write(self.error_log, msg)
        self.logger.error(f"{C.RED}[✗]{C.RESET} {message}")

    def warning(self, message):
        """Log a warning"""
        self._write(self.error_log, f"WARNING | {message}")
        self.logger.warning(f"{C.YELLOW}[!]{C.RESET} {message}")

    def debug(self, message):
        """Log debug info"""
        self._write(self.scan_log, f"DEBUG | {message}")

    # =============================================
    # SESSION LOGGING
    # =============================================

    def session_start(self, session_id, target, module):
        """Log session start"""
        msg = f"SESSION START | ID: {session_id} | Target: {target} | Module: {module}"
        self._write(self.session_log, msg)
        self._write_json(self.session_log, {
            'event': 'start',
            'session_id': session_id,
            'target': target,
            'module': module,
        })

    def session_end(self, session_id, vuln_count, duration, status="completed"):
        """Log session end"""
        msg = f"SESSION END | ID: {session_id} | Status: {status} | Vulns: {vuln_count} | Duration: {duration:.2f}s"
        self._write(self.session_log, msg)
        self._write_json(self.session_log, {
            'event': 'end',
            'session_id': session_id,
            'status': status,
            'vulnerabilities': vuln_count,
            'duration': duration,
        })

    def session_command(self, session_id, command):
        """Log a command executed in session"""
        msg = f"SESSION CMD | ID: {session_id} | Command: {command[:100]}"
        self._write(self.session_log, msg)

    # =============================================
    # UTILITIES
    # =============================================

    def clear_logs(self):
        """Clear all log files"""
        logs = [
            self.scan_log,
            self.vuln_log,
            self.exploit_log,
            self.error_log,
            self.session_log,
        ]
        for log_path in logs:
            try:
                if os.path.exists(log_path):
                    os.remove(log_path)
            except Exception:
                pass
        self.logger.info(f"{C.GREEN}[✓]{C.RESET} All logs cleared")

    def get_log_size(self):
        """Get total log size"""
        total = 0
        for log_path in [self.scan_log, self.vuln_log, self.exploit_log, self.error_log]:
            if os.path.exists(log_path):
                total += os.path.getsize(log_path)
        return total

    def get_stats(self):
        """Get log statistics"""
        stats = {
            'scan_entries': 0,
            'vuln_entries': 0,
            'exploit_entries': 0,
            'error_entries': 0,
        }

        for key, path in [
            ('scan_entries', self.scan_log),
            ('vuln_entries', self.vuln_log),
            ('exploit_entries', self.exploit_log),
            ('error_entries', self.error_log),
        ]:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        stats[key] = sum(1 for _ in f)
                except Exception:
                    pass

        return stats


# =============================================
# GLOBAL LOGGER INSTANCE
# =============================================

_global_logger = None


def get_logger(log_dir=None):
    """Get global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = Logger(log_dir)
    return _global_logger


# =============================================
# CONVENIENCE FUNCTIONS
# =============================================

def log_scan_start(target, module="full"):
    """Log scan start"""
    get_logger().scan_start(target, module)


def log_scan_end(target, vuln_count, duration):
    """Log scan end"""
    get_logger().scan_end(target, vuln_count, duration)


def log_vulnerability(vuln):
    """Log vulnerability"""
    get_logger().vulnerability_found(vuln)


def log_exploit(exploit_type, url, payload, evidence=""):
    """Log exploit"""
    get_logger().exploit_success(exploit_type, url, payload, evidence)


def log_error(message, exception=None):
    """Log error (to file)"""
    get_logger().error(message, exception)


def log_warning(message):
    """Log warning"""
    get_logger().warning(message)


# =============================================
# EXPORTS
# =============================================

__all__ = [
    "Logger",
    "get_logger",
    "log_scan_start",
    "log_scan_end",
    "log_vulnerability",
    "log_exploit",
    "log_error",
    "log_warning",
]