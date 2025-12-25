"""
WPHunter - Configuration Module
===============================
YAML-based configuration management with validation and profile support.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class ProxyConfig:
    """Proxy configuration for Burp Suite integration."""
    enabled: bool = False
    http: str = "http://127.0.0.1:8080"
    https: str = "http://127.0.0.1:8080"


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_second: int = 10
    burst: int = 20
    delay_between_modules: float = 1.0
    parallel_requests: int = 5


@dataclass
class ScanProfile:
    """Scan profile with speed/stealth settings."""
    requests_per_second: int
    delay_between_modules: float
    parallel_requests: int


@dataclass
class ScannerConfig:
    """Individual scanner configuration."""
    enabled: bool = True
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolConfig:
    """External tool configuration."""
    enabled: bool = False
    path: str = ""
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WPHunterConfig:
    """Main WPHunter configuration."""
    
    # Target settings
    timeout: int = 30
    max_retries: int = 3
    verify_ssl: bool = False
    
    # HTTP settings
    user_agents: List[str] = field(default_factory=list)
    
    # Proxy
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    
    # Rate limiting
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    
    # Scan profiles
    profiles: Dict[str, ScanProfile] = field(default_factory=dict)
    active_profile: str = "normal"
    
    # Scanners
    scanners: Dict[str, ScannerConfig] = field(default_factory=dict)
    
    # External tools
    tools: Dict[str, ToolConfig] = field(default_factory=dict)
    
    # Reporting
    output_dir: str = "./reports"
    report_formats: List[str] = field(default_factory=lambda: ["json", "html"])
    include_evidence: bool = True
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    colored_output: bool = True
    
    @classmethod
    def from_yaml(cls, config_path: str) -> "WPHunterConfig":
        """Load configuration from YAML file."""
        path = Path(config_path)
        
        if not path.exists():
            # Return default config if file doesn't exist
            return cls._default_config()
        
        with open(path, 'r') as f:
            data = yaml.safe_load(f) or {}
        
        return cls._parse_config(data)
    
    @classmethod
    def _default_config(cls) -> "WPHunterConfig":
        """Create default configuration."""
        config = cls()
        config.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        ]
        config.profiles = {
            "stealthy": ScanProfile(2, 5.0, 1),
            "normal": ScanProfile(10, 1.0, 5),
            "aggressive": ScanProfile(50, 0.0, 20),
        }
        config.scanners = {
            "xss": ScannerConfig(True, {"max_payloads": 50, "verify_dom": True}),
            "sqli": ScannerConfig(True, {"time_based_delay": 5}),
            "csrf": ScannerConfig(True, {}),
            "lfi": ScannerConfig(True, {"max_depth": 10}),
            "upload": ScannerConfig(True, {"test_extensions": [".php", ".phtml"]}),
        }
        config.tools = {
            "nuclei": ToolConfig(True, "nuclei", {"templates": ["wordpress/", "cves/"]}),
            "sqlmap": ToolConfig(False, "sqlmap", {"level": 3, "risk": 2}),
            "dalfox": ToolConfig(False, "dalfox", {}),
        }
        return config
    
    @classmethod
    def _parse_config(cls, data: Dict[str, Any]) -> "WPHunterConfig":
        """Parse configuration from dictionary."""
        config = cls()
        
        # Target settings
        target = data.get("target", {})
        config.timeout = target.get("timeout", config.timeout)
        config.max_retries = target.get("max_retries", config.max_retries)
        config.verify_ssl = target.get("verify_ssl", config.verify_ssl)
        
        # HTTP settings
        http = data.get("http", {})
        config.user_agents = http.get("user_agents", config.user_agents) or [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ]
        
        # Proxy settings
        proxy = data.get("proxy", {})
        config.proxy = ProxyConfig(
            enabled=proxy.get("enabled", False),
            http=proxy.get("http", "http://127.0.0.1:8080"),
            https=proxy.get("https", "http://127.0.0.1:8080"),
        )
        
        # Rate limiting
        rate = data.get("rate_limit", {})
        config.rate_limit = RateLimitConfig(
            requests_per_second=rate.get("requests_per_second", 10),
            burst=rate.get("burst", 20),
        )
        
        # Profiles
        profiles = data.get("profiles", {})
        config.profiles = {}
        for name, settings in profiles.items():
            config.profiles[name] = ScanProfile(
                requests_per_second=settings.get("requests_per_second", 10),
                delay_between_modules=settings.get("delay_between_modules", 1.0),
                parallel_requests=settings.get("parallel_requests", 5),
            )
        
        # Scanners
        scanners = data.get("scanners", {})
        for name, settings in scanners.items():
            if isinstance(settings, dict):
                enabled = settings.pop("enabled", True)
                config.scanners[name] = ScannerConfig(enabled, settings)
        
        # External tools
        tools = data.get("tools", {})
        for name, settings in tools.items():
            if isinstance(settings, dict):
                config.tools[name] = ToolConfig(
                    enabled=settings.get("enabled", False),
                    path=settings.get("path", name),
                    options={k: v for k, v in settings.items() if k not in ["enabled", "path"]},
                )
        
        # Reporting
        reports = data.get("reports", {})
        config.output_dir = reports.get("output_dir", config.output_dir)
        config.report_formats = reports.get("formats", config.report_formats)
        config.include_evidence = reports.get("include_evidence", config.include_evidence)
        
        # Logging
        logging_cfg = data.get("logging", {})
        config.log_level = logging_cfg.get("level", config.log_level)
        config.log_file = logging_cfg.get("file")
        config.colored_output = logging_cfg.get("colored", config.colored_output)
        
        return config
    
    def get_active_profile(self) -> ScanProfile:
        """Get the currently active scan profile."""
        return self.profiles.get(
            self.active_profile,
            ScanProfile(10, 1.0, 5)
        )
    
    def set_profile(self, profile_name: str):
        """Set the active scan profile."""
        if profile_name in self.profiles:
            self.active_profile = profile_name
        else:
            raise ValueError(f"Unknown profile: {profile_name}. Available: {list(self.profiles.keys())}")
    
    def is_scanner_enabled(self, scanner_name: str) -> bool:
        """Check if a specific scanner is enabled."""
        if scanner_name in self.scanners:
            return self.scanners[scanner_name].enabled
        return False
    
    def get_scanner_options(self, scanner_name: str) -> Dict[str, Any]:
        """Get options for a specific scanner."""
        if scanner_name in self.scanners:
            return self.scanners[scanner_name].options
        return {}
    
    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if an external tool is enabled."""
        if tool_name in self.tools:
            return self.tools[tool_name].enabled
        return False
    
    def get_tool_config(self, tool_name: str, default: Dict = None) -> Dict[str, Any]:
        """Get configuration for an external tool."""
        if tool_name in self.tools:
            tool = self.tools[tool_name]
            return {"enabled": tool.enabled, "path": tool.path, **tool.options}
        return default or {}
    
    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Get proxy dictionary for HTTP client."""
        if self.proxy.enabled:
            return {
                "http://": self.proxy.http,
                "https://": self.proxy.https,
            }
        return None
