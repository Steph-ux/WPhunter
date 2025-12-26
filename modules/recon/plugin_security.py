"""
WPHunter - Plugin Security Testing
===================================
Test plugins for common vulnerabilities and detect nulled/cracked versions.
"""

import re
from typing import Dict, List
from core.http_client import WPHttpClient
from core.logger import logger


class PluginVulnTester:
    """
    Test plugins for common vulnerabilities.
    
    Tests for:
    - Directory traversal / LFI
    - Unauthenticated file access
    - Common vulnerable endpoints
    - SQL injection indicators
    """
    
    # Common vulnerable plugin files/endpoints
    VULN_ENDPOINTS = [
        "readme.txt",  # Version disclosure
        "changelog.txt",
        "debug.log",
        "error_log",
        ".git/config",
        "composer.json",
        "package.json",
        "phpinfo.php",
        "test.php",
        "backup.sql",
        "database.sql",
    ]
    
    # LFI test payloads
    LFI_PAYLOADS = [
        "../../../wp-config.php",
        "....//....//....//wp-config.php",
        "..%2f..%2f..%2fwp-config.php",
        "/etc/passwd",
        "../../../../etc/passwd",
    ]
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
    
    async def test_plugin(self, slug: str, path: str) -> List[Dict]:
        """
        Test plugin for vulnerabilities.
        
        Args:
            slug: Plugin slug
            path: Plugin path (e.g., /wp-content/plugins/plugin-name/)
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Test 1: Exposed sensitive files
        for endpoint in self.VULN_ENDPOINTS:
            try:
                url = f"{path}{endpoint}"
                response = await self.http.get(url)
                
                if response.ok and len(response.text) > 0:
                    findings.append({
                        "type": "information_disclosure",
                        "severity": "medium",
                        "title": f"Exposed file: {endpoint}",
                        "url": url,
                        "evidence": response.text[:200]
                    })
            except:
                continue
        
        # Test 2: Directory listing
        try:
            response = await self.http.get(path)
            if response.ok and "Index of" in response.text:
                findings.append({
                    "type": "directory_listing",
                    "severity": "low",
                    "title": "Directory listing enabled",
                    "url": path,
                    "evidence": "Directory browsing is enabled"
                })
        except:
            pass
        
        # Test 3: Common LFI parameters (basic check)
        lfi_params = ["file", "path", "page", "include", "load"]
        for param in lfi_params:
            try:
                test_url = f"{path}?{param}=../../../wp-config.php"
                response = await self.http.get(test_url)
                
                if response.ok and ("DB_NAME" in response.text or "DB_PASSWORD" in response.text):
                    findings.append({
                        "type": "lfi",
                        "severity": "critical",
                        "title": f"Local File Inclusion via {param} parameter",
                        "url": test_url,
                        "evidence": "wp-config.php content exposed"
                    })
                    break  # Don't test more if we found one
            except:
                continue
        
        if findings:
            logger.warning(f"Found {len(findings)} potential vulnerabilities in {slug}")
        
        return findings


class NulledPluginDetector:
    """
    Detect nulled/cracked plugins with potential backdoors.
    
    Checks for:
    - Common nulled plugin signatures
    - Obfuscated code patterns
    - Known backdoor indicators
    - License bypass code
    """
    
    # Common indicators of nulled plugins
    NULLED_INDICATORS = [
        # Nulled plugin sites
        r"nulled\.to",
        r"null-24",
        r"gpldl\.com",
        r"codecanyon\.net/item/.*?/\d+\?ref=",  # Pirated CodeCanyon
        
        # Common backdoor patterns
        r"eval\s*\(\s*base64_decode",
        r"eval\s*\(\s*gzinflate",
        r"eval\s*\(\s*str_rot13",
        r"assert\s*\(\s*base64_decode",
        r"\$GLOBALS\[.*?\]\s*\(\s*base64_decode",
        
        # Suspicious functions
        r"system\s*\(",
        r"exec\s*\(",
        r"shell_exec\s*\(",
        r"passthru\s*\(",
        r"proc_open\s*\(",
        
        # License bypass
        r"license.*?check.*?bypass",
        r"remove.*?license.*?validation",
        r"crack.*?license",
    ]
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
    
    async def check_plugin(self, slug: str, path: str) -> Dict:
        """
        Check if plugin is nulled/cracked.
        
        Args:
            slug: Plugin slug
            path: Plugin path
        
        Returns:
            Dict with is_nulled, indicators_found, backdoor_suspected
        """
        indicators_found = []
        backdoor_suspected = False
        
        # Try to fetch main plugin file
        try:
            # Common plugin file patterns
            plugin_files = [
                f"{slug}.php",
                "index.php",
                "plugin.php",
            ]
            
            for filename in plugin_files:
                url = f"{path}{filename}"
                response = await self.http.get(url)
                
                if not response.ok:
                    continue
                
                content = response.text
                
                # Check for nulled indicators
                for pattern in self.NULLED_INDICATORS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        indicators_found.append({
                            "pattern": pattern,
                            "matches": len(matches),
                            "file": filename
                        })
                        
                        # Backdoor patterns are more serious
                        if any(x in pattern for x in ["eval", "base64_decode", "system", "exec"]):
                            backdoor_suspected = True
                
                # Only check first accessible file
                if indicators_found:
                    break
        
        except Exception as e:
            logger.debug(f"Error checking {slug} for nulled indicators: {e}")
        
        is_nulled = len(indicators_found) > 0
        
        if is_nulled:
            logger.warning(f"Plugin {slug} has {len(indicators_found)} nulled/backdoor indicators")
        
        return {
            "is_nulled": is_nulled,
            "indicators_found": indicators_found,
            "backdoor_suspected": backdoor_suspected
        }
