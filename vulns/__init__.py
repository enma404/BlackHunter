# vulns/__init__.py
# BlackHunter Pro - Vulnerability Scanners Package
# Academic Penetration Testing Tool - Isolated Lab Only

__version__ = "1.0.0"
__author__ = "Academic Security Research Lab"
__description__ = "Vulnerability scanners for BlackHunter Pro"

# =============================================
# VULNERABILITY SCANNER MODULES
# =============================================

from .sqli import SQLiScanner
from .xss import XSSScanner
from .lfi import LFIScanner
from .cmdi import CMDInjectScanner
from .ssrf import SSRFScanner
from .upload import UploadScanner
from .xxe import XXEScanner
from .csrf import CSRFScanner
from .idor import IDORScanner
from .open_redirect import RedirectScanner

# =============================================
# EXPORTS
# =============================================

__all__ = [
    "SQLiScanner",
    "XSSScanner",
    "LFIScanner",
    "CMDInjectScanner",
    "SSRFScanner",
    "UploadScanner",
    "XXEScanner",
    "CSRFScanner",
    "IDORScanner",
    "RedirectScanner",
]

# =============================================
# SCANNER REGISTRY
# =============================================

SCANNER_REGISTRY = {
    "sqli": SQLiScanner,
    "xss": XSSScanner,
    "lfi": LFIScanner,
    "cmdi": CMDInjectScanner,
    "ssrf": SSRFScanner,
    "upload": UploadScanner,
    "xxe": XXEScanner,
    "csrf": CSRFScanner,
    "idor": IDORScanner,
    "redirect": RedirectScanner,
}

# =============================================
# SEVERITY MAP
# =============================================

SEVERITY_MAP = {
    "sqli": "CRITICAL",
    "xss": "MEDIUM",
    "lfi": "HIGH",
    "cmdi": "CRITICAL",
    "ssrf": "HIGH",
    "upload": "CRITICAL",
    "xxe": "HIGH",
    "csrf": "MEDIUM",
    "idor": "HIGH",
    "redirect": "LOW",
}

# =============================================
# HELPER FUNCTIONS
# =============================================

def get_scanner(name):
    """Get scanner class by name"""
    return SCANNER_REGISTRY.get(name.lower())


def list_scanners():
    """List all available scanners"""
    return list(SCANNER_REGISTRY.keys())


def get_severity(name):
    """Get severity level for scanner"""
    return SEVERITY_MAP.get(name.lower(), "MEDIUM")


def run_scanner(name, target, **kwargs):
    """Run a scanner by name"""
    scanner_class = get_scanner(name)
    if scanner_class is None:
        raise ValueError(f"Unknown scanner: {name}")

    scanner = scanner_class(target, **kwargs)
    return scanner.run()