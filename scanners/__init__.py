# scanners/__init__.py
# BlackHunter Pro - Scanners Package
# Reconnaissance, Port, Web, CMS, Subdomain, DNS scanning

__version__ = "1.0.0"
__author__ = "Academic Security Research Lab"
__description__ = "Scanning modules for BlackHunter Pro"

# =============================================
# SCANNER MODULES
# =============================================

from .recon import Recon
from .port import PortScanner
from .web import WebScanner
from .cms import CMSDetector
from .subdomain import SubdomainScanner
from .dns_enum import DNSEnumerator

# =============================================
# EXPORTS
# =============================================

__all__ = [
    "Recon",
    "PortScanner",
    "WebScanner",
    "CMSDetector",
    "SubdomainScanner",
    "DNSEnumerator",
]

# =============================================
# SCANNER REGISTRY
# =============================================

SCANNER_REGISTRY = {
    "recon": Recon,
    "port": PortScanner,
    "web": WebScanner,
    "cms": CMSDetector,
    "subdomain": SubdomainScanner,
    "dns": DNSEnumerator,
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


def run_scanner(name, target, **kwargs):
    """Run a scanner by name"""
    scanner_class = get_scanner(name)
    if scanner_class is None:
        raise ValueError(f"Unknown scanner: {name}")

    scanner = scanner_class(target, **kwargs)
    return scanner.run()