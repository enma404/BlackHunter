# core/config.py
# BlackHunter Pro - Configuration Manager
# Handle loading, saving, and managing configuration

import os
import json
import copy


# =============================================
# DEFAULT CONFIGURATION
# =============================================

DEFAULT_CONFIG = {
    "name": "BlackHunter",
    "version": "1.0.0",
    "description": "Academic Penetration Testing Tool - Isolated Lab Only",

    "scan_settings": {
        "timeout": 10,
        "threads": 10,
        "user_agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "max_redirects": 5,
        "verify_ssl": False,
        "follow_redirects": True,
        "retry_count": 2,
        "retry_delay": 1,
        "delay_between_requests": 0.1,
        "max_scan_time": 1200
    },

    "modules": {
        "recon": {"enabled": True},
        "port": {"enabled": True, "timeout": 2, "threads": 100},
        "web": {"enabled": True, "threads": 20},
        "cms": {"enabled": True},
        "subdomain": {"enabled": True},
        "sqli": {"enabled": True, "severity": "CRITICAL", "time_based_delay": 5},
        "xss": {"enabled": True, "severity": "MEDIUM"},
        "lfi": {"enabled": True, "severity": "HIGH"},
        "cmdi": {"enabled": True, "severity": "CRITICAL", "time_based_delay": 5},
        "ssrf": {"enabled": True, "severity": "HIGH"},
        "upload": {"enabled": True, "severity": "CRITICAL"},
        "xxe": {"enabled": True, "severity": "HIGH"},
        "csrf": {"enabled": True, "severity": "MEDIUM"},
        "idor": {"enabled": True, "severity": "HIGH"},
        "redirect": {"enabled": True, "severity": "LOW"}
    },

    "cms_scanners": {
        "wordpress": {
            "enabled": True,
            "enumerate_users": True,
            "enumerate_plugins": True,
            "enumerate_themes": True,
            "check_xmlrpc": True,
            "check_rest_api": True
        },
        "joomla": {
            "enabled": True,
            "enumerate_components": True,
            "enumerate_templates": True,
            "check_config_exposure": True
        },
        "craft": {
            "enabled": True,
            "enumerate_plugins": True,
            "check_env_exposure": True,
            "check_graphql": True
        },
        "drupal": {
            "enabled": True,
            "check_changelog": True,
            "enumerate_modules": True
        }
    },

    "exploitation": {
        "enabled": False,
        "require_confirmation": True,
        "isolated_lab_only": True,
        "save_loot": True,
        "loot_dir": "reports/loot",
        "max_exploit_attempts": 3
    },

    "c2_server": {
        "host": "0.0.0.0",
        "port": 4443,
        "use_tls": True,
        "cert_file": "c2_server/server.crt",
        "key_file": "c2_server/server.key",
        "web_ui_enabled": True,
        "web_ui_port": 8080,
        "max_clients": 50
    },

    "native_modules": {
        "port_scanner": "native/port_scanner",
        "banner_grabber": "native/banner_grabber",
        "payload_engine": "native/payload_engine",
        "hash_cracker": "native/hash_cracker",
        "packet_crafter": "native/packet_crafter"
    },

    "output": {
        "report_dir": "reports",
        "log_dir": "logs",
        "save_json": True,
        "save_html": True,
        "save_pdf": False,
        "verbose": True,
        "color_output": True,
        "show_progress": True
    },

    "payloads": {
        "payload_dir": "payloads",
        "use_custom_payloads": True,
        "max_payloads_per_param": 100,
        "waf_bypass": False
    },

    "stealth": {
        "randomize_user_agents": True,
        "randomize_delays": True,
        "min_delay": 0.1,
        "max_delay": 0.5,
        "use_proxies": False,
        "proxy_list": []
    },

    "wordlists": {
        "wordlist_dir": "wordlists",
        "directories": "directories.txt",
        "files": "files.txt",
        "parameters": "parameters.txt",
        "subdomains": "subdomains.txt",
        "passwords": "passwords.txt",
        "usernames": "usernames.txt"
    },

    "notifications": {
        "enabled": False,
        "webhook_url": "",
        "email": "",
        "slack_webhook": ""
    },

    "ethical_guardrails": {
        "require_authorization": True,
        "target_whitelist": [
            "127.0.0.1",
            "localhost",
            "testphp.vulnweb.com",
            "demo.testfire.net",
            "testhtml5.vulnweb.com",
            "juice-shop.herokuapp.com"
        ],
        "block_public_targets": True,
        "warn_on_exploitation": True,
        "max_scan_intensity": "medium"
    }
}


# =============================================
# CONFIG CLASS
# =============================================

class Config:
    """Configuration manager"""

    def __init__(self, config_path=None, auto_load=True):
        """
        Initialize config

        Args:
            config_path: Path to config file
            auto_load: Load config on init
        """
        # Determine paths
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        if config_path:
            self.config_path = config_path
        else:
            self.config_path = os.path.join(self.base_dir, "config", "config.json")

        # Set default config
        self.data = copy.deepcopy(DEFAULT_CONFIG)

        # Auto-load if file exists
        if auto_load and os.path.exists(self.config_path):
            self.load()

    # =============================================
    # LOAD / SAVE
    # =============================================

    def load(self):
        """Load configuration from file"""
        try:
            if not os.path.exists(self.config_path):
                self.save()
                return True

            with open(self.config_path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)

            # Merge with defaults
            self.data = self._merge_config(DEFAULT_CONFIG, loaded)
            return True

        except json.JSONDecodeError as e:
            print(f"[!] Config JSON error: {e}")
            print(f"[*] Using default config")
            self.data = copy.deepcopy(DEFAULT_CONFIG)
            return False

        except Exception as e:
            print(f"[!] Failed to load config: {e}")
            return False

    def save(self):
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)

            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=4, ensure_ascii=False)

            return True

        except Exception as e:
            print(f"[!] Failed to save config: {e}")
            return False

    def reload(self):
        """Reload configuration"""
        return self.load()

    def reset(self):
        """Reset to default configuration"""
        self.data = copy.deepcopy(DEFAULT_CONFIG)
        return self.save()

    def _merge_config(self, default, loaded):
        """Merge loaded config with defaults (recursive)"""
        result = copy.deepcopy(default)

        for key, value in loaded.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value

        return result

    # =============================================
    # GET VALUES
    # =============================================

    def get(self, key, default=None):
        """
        Get config value using dot notation

        Examples:
            config.get("scan_settings.timeout")
            config.get("modules.sqli.enabled")
        """
        if '.' in key:
            parts = key.split('.')
            value = self.data
            for part in parts:
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    return default
            return value

        return self.data.get(key, default)

    def get_section(self, section):
        """Get entire section"""
        return self.data.get(section, {})

    def get_scan_settings(self):
        """Get scan settings"""
        return self.data.get("scan_settings", {})

    def get_module_config(self, module):
        """Get module configuration"""
        return self.data.get("modules", {}).get(module, {})

    def is_module_enabled(self, module):
        """Check if module is enabled"""
        return self.get_module_config(module).get("enabled", True)

    # =============================================
    # SET VALUES
    # =============================================

    def set(self, key, value):
        """
        Set config value using dot notation

        Examples:
            config.set("scan_settings.timeout", 20)
            config.set("modules.sqli.enabled", False)
        """
        if '.' in key:
            parts = key.split('.')
            target = self.data

            for part in parts[:-1]:
                if part not in target:
                    target[part] = {}
                target = target[part]

            target[parts[-1]] = value
        else:
            self.data[key] = value

        return True

    def update(self, updates):
        """Bulk update config"""
        for key, value in updates.items():
            self.set(key, value)
        return True

    # =============================================
    # UTILITIES
    # =============================================

    def to_dict(self):
        """Return config as dictionary"""
        return copy.deepcopy(self.data)

    def to_json(self, indent=4):
        """Return config as JSON string"""
        return json.dumps(self.data, indent=indent, ensure_ascii=False)

    def exists(self):
        """Check if config file exists"""
        return os.path.exists(self.config_path)

    def get_path(self):
        """Get config file path"""
        return self.config_path

    # =============================================
    # CONVENIENCE PROPERTIES
    # =============================================

    @property
    def timeout(self):
        return self.get("scan_settings.timeout", 10)

    @property
    def threads(self):
        return self.get("scan_settings.threads", 10)

    @property
    def user_agent(self):
        return self.get("scan_settings.user_agent", "Mozilla/5.0")

    @property
    def verify_ssl(self):
        return self.get("scan_settings.verify_ssl", False)

    @property
    def follow_redirects(self):
        return self.get("scan_settings.follow_redirects", True)

    @property
    def report_dir(self):
        return self.get("output.report_dir", "reports")

    @property
    def log_dir(self):
        return self.get("output.log_dir", "logs")

    @property
    def verbose(self):
        return self.get("output.verbose", True)

    @property
    def payload_dir(self):
        return self.get("payloads.payload_dir", "payloads")

    @property
    def wordlist_dir(self):
        return self.get("wordlists.wordlist_dir", "wordlists")

    @property
    def c2_host(self):
        return self.get("c2_server.host", "0.0.0.0")

    @property
    def c2_port(self):
        return self.get("c2_server.port", 4443)

    # =============================================
    # ABSOLUTE PATHS
    # =============================================

    def get_abs_path(self, relative_path):
        """Convert relative path to absolute"""
        if os.path.isabs(relative_path):
            return relative_path
        return os.path.join(self.base_dir, relative_path)

    def get_report_path(self):
        """Get absolute report directory path"""
        return self.get_abs_path(self.report_dir)

    def get_log_path(self):
        """Get absolute log directory path"""
        return self.get_abs_path(self.log_dir)

    def get_payload_path(self):
        """Get absolute payload directory path"""
        return self.get_abs_path(self.payload_dir)

    def get_wordlist_path(self):
        """Get absolute wordlist directory path"""
        return self.get_abs_path(self.wordlist_dir)

    def get_native_path(self, module):
        """Get absolute path for native module"""
        path = self.get(f"native_modules.{module}", f"native/{module}")
        return self.get_abs_path(path)

    # =============================================
    # DIRECTORY MANAGEMENT
    # =============================================

    def ensure_directories(self):
        """Ensure all required directories exist"""
        dirs = [
            self.get_report_path(),
            os.path.join(self.get_report_path(), "json"),
            os.path.join(self.get_report_path(), "html"),
            os.path.join(self.get_report_path(), "pdf"),
            os.path.join(self.get_report_path(), "loot"),
            self.get_log_path(),
            self.get_payload_path(),
            self.get_wordlist_path(),
            self.get_abs_path("downloads"),
        ]

        for directory in dirs:
            os.makedirs(directory, exist_ok=True)

        return True

    # =============================================
    # VALIDATION
    # =============================================

    def validate(self):
        """Validate configuration"""
        errors = []

        # Check timeout
        if self.timeout < 1 or self.timeout > 300:
            errors.append("timeout must be between 1 and 300")

        # Check threads
        if self.threads < 1 or self.threads > 500:
            errors.append("threads must be between 1 and 500")

        # Check C2 port
        if self.c2_port < 1 or self.c2_port > 65535:
            errors.append("c2_port must be between 1 and 65535")

        # Check ethical guardrails
        if not self.get("ethical_guardrails.require_authorization", True):
            errors.append("require_authorization should be True for ethical use")

        return errors

    # =============================================
    # DISPLAY
    # =============================================

    def show(self):
        """Print configuration (pretty)"""
        print(self.to_json())

    def summary(self):
        """Print config summary"""
        print(f"""
Configuration Summary
─────────────────────────────────────────
  Config Path:     {self.config_path}
  Timeout:         {self.timeout}s
  Threads:         {self.threads}
  User Agent:      {self.user_agent[:50]}...
  SSL Verify:      {self.verify_ssl}
  Report Dir:      {self.report_dir}
  Log Dir:         {self.log_dir}
  Payload Dir:     {self.payload_dir}
  Wordlist Dir:    {self.wordlist_dir}
  C2 Server:       {self.c2_host}:{self.c2_port}
─────────────────────────────────────────
  Enabled Modules:
""")

        for module, settings in self.data.get("modules", {}).items():
            status = "✓" if settings.get("enabled", True) else "✗"
            print(f"    [{status}] {module}")

        print("─────────────────────────────────────────")


# =============================================
# GLOBAL CONFIG INSTANCE
# =============================================

_global_config = None


def get_config(config_path=None, reload=False):
    """
    Get global config instance

    Args:
        config_path: Custom config path (optional)
        reload: Force reload from disk

    Returns:
        Config instance
    """
    global _global_config

    if _global_config is None or reload:
        _global_config = Config(config_path)

    return _global_config


def load_config(config_path=None):
    """Load config (alias)"""
    return get_config(config_path, reload=True)


def save_config(config=None):
    """Save config"""
    if config is None:
        config = get_config()
    return config.save()


def reset_config():
    """Reset config to defaults"""
    config = get_config()
    return config.reset()


def show_config():
    """Show current config"""
    config = get_config()
    config.show()


def validate_config():
    """Validate current config"""
    config = get_config()
    errors = config.validate()

    if errors:
        print("[!] Config validation errors:")
        for error in errors:
            print(f"    - {error}")
        return False
    else:
        print("[✓] Config is valid")
        return True


# =============================================
# CLI MODE
# =============================================

def main():
    """CLI entry point for config"""
    import argparse

    parser = argparse.ArgumentParser(description="BlackHunter Pro - Config Manager")
    parser.add_argument('--show', action='store_true', help="Show current config")
    parser.add_argument('--summary', action='store_true', help="Show config summary")
    parser.add_argument('--reset', action='store_true', help="Reset to defaults")
    parser.add_argument('--validate', action='store_true', help="Validate config")
    parser.add_argument('--path', help="Custom config path")
    parser.add_argument('--get', help="Get a value by key")
    parser.add_argument('--set', nargs=2, metavar=('KEY', 'VALUE'), help="Set a value")

    args = parser.parse_args()

    config = get_config(args.path)

    if args.show:
        config.show()
    elif args.summary:
        config.summary()
    elif args.reset:
        config.reset()
        print("[✓] Config reset to defaults")
    elif args.validate:
        validate_config()
    elif args.get:
        value = config.get(args.get)
        print(f"{args.get} = {value}")
    elif args.set:
        key, value = args.set
        # Try to parse as JSON for proper type
        try:
            value = json.loads(value)
        except:
            pass
        config.set(key, value)
        config.save()
        print(f"[✓] Set {key} = {value}")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()


# =============================================
# EXPORTS
# =============================================

__all__ = [
    "Config",
    "DEFAULT_CONFIG",
    "get_config",
    "load_config",
    "save_config",
    "reset_config",
    "show_config",
    "validate_config",
    "main",
]