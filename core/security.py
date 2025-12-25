"""
WPHunter - Advanced Security Module
====================================
Centralized security features for bug bounty operations.

Features:
- Global rate limiting with semaphore and backoff
- WAF detection and evasion
- WPScan Vulnerability Database API integration
- Plugin vulnerability testing (LFI/RCE/SQLi)
- Nulled/cracked plugin detection
"""

import asyncio
import hashlib
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.logger import logger


# =============================================================================
# GLOBAL RATE LIMITER WITH SEMAPHORE
# =============================================================================

class GlobalRateLimiter:
    """
    Global rate limiter with semaphore and exponential backoff.
    
    Prevents IP bans by limiting concurrent requests and adding jitter.
    """
    
    _instance = None
    _lock = asyncio.Lock()
    
    def __new__(cls, *args, **kwargs):
        # Singleton pattern
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(
        self,
        max_concurrent: int = 3,
        min_delay: float = 0.5,
        max_delay: float = 2.0,
        backoff_factor: float = 2.0,
        max_backoff: float = 60.0
    ):
        if self._initialized:
            return
        
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
        
        self.last_request_time = 0.0
        self.consecutive_failures = 0
        self.total_requests = 0
        self.blocked_count = 0
        
        self._initialized = True
    
    async def acquire(self) -> None:
        """Acquire a request slot with rate limiting."""
        async with self.semaphore:
            # Calculate delay with jitter
            base_delay = random.uniform(self.min_delay, self.max_delay)
            
            # Add exponential backoff if experiencing failures
            if self.consecutive_failures > 0:
                backoff = min(
                    self.max_backoff,
                    base_delay * (self.backoff_factor ** self.consecutive_failures)
                )
                logger.debug(f"Backoff: {backoff:.1f}s (failures: {self.consecutive_failures})")
                await asyncio.sleep(backoff)
            else:
                # Ensure minimum delay between requests
                elapsed = time.time() - self.last_request_time
                if elapsed < base_delay:
                    await asyncio.sleep(base_delay - elapsed)
            
            self.last_request_time = time.time()
            self.total_requests += 1
    
    def on_success(self) -> None:
        """Reset failure counter on successful request."""
        self.consecutive_failures = max(0, self.consecutive_failures - 1)
    
    def on_failure(self, is_blocked: bool = False) -> None:
        """Increment failure counter."""
        self.consecutive_failures += 1
        if is_blocked:
            self.blocked_count += 1
            logger.warning(f"Blocked by target ({self.blocked_count} times)")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        return {
            "total_requests": self.total_requests,
            "blocked_count": self.blocked_count,
            "current_backoff": self.consecutive_failures,
        }


# =============================================================================
# WAF DETECTION AND STEALTH MODE
# =============================================================================

@dataclass
class WAFInfo:
    """WAF detection result."""
    detected: bool = False
    waf_name: Optional[str] = None
    confidence: str = "unknown"
    bypass_techniques: List[str] = field(default_factory=list)


class WAFDetector:
    """
    Detect and evade Web Application Firewalls.
    
    Identifies common WAFs and suggests bypass techniques.
    """
    
    # WAF signatures in headers/responses
    WAF_SIGNATURES = {
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
            "body": ["cloudflare", "attention required", "cf-browser-verification"],
            "status_codes": [403, 503],
        },
        "wordfence": {
            "headers": ["x-wordfence"],
            "body": ["blocked by wordfence", "wordfence security", "this is a security issue"],
            "status_codes": [403, 503],
        },
        "sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "body": ["sucuri website firewall", "access denied - sucuri"],
            "status_codes": [403],
        },
        "modsecurity": {
            "headers": ["mod_security", "modsec"],
            "body": ["mod_security", "modsecurity", "not acceptable"],
            "status_codes": [403, 406],
        },
        "akamai": {
            "headers": ["akamai"],
            "body": ["access denied", "akamai ghost"],
            "status_codes": [403],
        },
        "imperva": {
            "headers": ["x-iinfo"],
            "body": ["incapsula incident", "imperva"],
            "status_codes": [403],
        },
        "aws_waf": {
            "headers": ["x-amzn-requestid"],
            "body": ["request blocked", "aws waf"],
            "status_codes": [403],
        },
    }
    
    # Bypass techniques per WAF
    BYPASS_TECHNIQUES = {
        "cloudflare": [
            "Use origin IP bypass",
            "Try HTTP/1.0",
            "Add X-Forwarded-For with internal IPs",
        ],
        "wordfence": [
            "Use legitimate User-Agent",
            "Add delay between requests (>30s)",
            "Avoid SQL/XSS payloads in URL",
        ],
        "sucuri": [
            "Try origin IP bypass",
            "Use URL encoding",
            "Avoid common attack patterns",
        ],
        "modsecurity": [
            "Try parameter pollution",
            "Use double URL encoding",
            "Try case variation",
        ],
        "default": [
            "Rotate User-Agents",
            "Add random delays",
            "Use different IP/proxy",
        ],
    }
    
    @classmethod
    async def detect(cls, http_client, test_payloads: bool = True) -> WAFInfo:
        """Detect WAF on target."""
        info = WAFInfo()
        
        try:
            # Test 1: Normal request
            normal_response = await http_client.get("/")
            
            # Check headers for WAF signatures
            for waf_name, signatures in cls.WAF_SIGNATURES.items():
                for header in signatures["headers"]:
                    if header.lower() in [h.lower() for h in normal_response.headers.keys()]:
                        info.detected = True
                        info.waf_name = waf_name
                        info.confidence = "high"
                        break
            
            # Test 2: Trigger WAF with malicious payload
            if test_payloads and not info.detected:
                test_paths = [
                    "/?id=1'",
                    "/?id=<script>alert(1)</script>",
                    "/?file=../../etc/passwd",
                ]
                
                for path in test_paths:
                    try:
                        response = await http_client.get(path)
                        
                        # Check for block response
                        if response.status_code in [403, 406, 429, 503]:
                            content = response.text.lower()
                            
                            for waf_name, signatures in cls.WAF_SIGNATURES.items():
                                for body_sig in signatures["body"]:
                                    if body_sig.lower() in content:
                                        info.detected = True
                                        info.waf_name = waf_name
                                        info.confidence = "high"
                                        break
                                if info.detected:
                                    break
                            
                            if not info.detected:
                                info.detected = True
                                info.waf_name = "unknown"
                                info.confidence = "medium"
                            
                            break
                    except Exception:
                        continue
            
            # Add bypass techniques
            if info.detected:
                techniques = cls.BYPASS_TECHNIQUES.get(
                    info.waf_name, cls.BYPASS_TECHNIQUES["default"]
                )
                info.bypass_techniques = techniques
                logger.warning(f"WAF detected: {info.waf_name} ({info.confidence})")
            
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
        
        return info


class StealthMode:
    """Stealth request mode for evading detection."""
    
    # Legitimate User-Agents
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]
    
    @classmethod
    def get_headers(cls, referer: Optional[str] = None) -> Dict[str, str]:
        """Get stealth headers."""
        headers = {
            "User-Agent": random.choice(cls.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
        if referer:
            headers["Referer"] = referer
        return headers
    
    @classmethod
    def get_random_delay(cls, min_sec: float = 1.0, max_sec: float = 5.0) -> float:
        """Get random delay with jitter."""
        return random.uniform(min_sec, max_sec)


# =============================================================================
# WPSCAN API INTEGRATION
# =============================================================================

class WPScanAPI:
    """
    WPScan Vulnerability Database API client.
    
    Free tier: 25 requests/day
    Paid tier: Unlimited
    """
    
    API_BASE = "https://wpscan.com/api/v3"
    
    def __init__(self, api_token: Optional[str] = None):
        self.api_token = api_token
        self.requests_today = 0
        self.cache: Dict[str, Dict] = {}
    
    async def check_plugin(self, slug: str, version: Optional[str] = None) -> List[Dict]:
        """Check plugin against WPScan database."""
        if not self.api_token:
            logger.debug("WPScan API token not configured")
            return []
        
        # Check cache first
        cache_key = f"plugin:{slug}"
        if cache_key in self.cache:
            return self._filter_by_version(self.cache[cache_key], version)
        
        try:
            import aiohttp
            
            headers = {"Authorization": f"Token token={self.api_token}"}
            url = f"{self.API_BASE}/plugins/{slug}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.cache[cache_key] = data
                        self.requests_today += 1
                        
                        return self._filter_by_version(data, version)
                    elif response.status == 401:
                        logger.error("WPScan API: Invalid token")
                    elif response.status == 429:
                        logger.warning("WPScan API: Rate limit exceeded")
        except ImportError:
            logger.debug("aiohttp not installed for WPScan API")
        except Exception as e:
            logger.debug(f"WPScan API error: {e}")
        
        return []
    
    async def check_theme(self, slug: str, version: Optional[str] = None) -> List[Dict]:
        """Check theme against WPScan database."""
        if not self.api_token:
            return []
        
        cache_key = f"theme:{slug}"
        if cache_key in self.cache:
            return self._filter_by_version(self.cache[cache_key], version)
        
        try:
            import aiohttp
            
            headers = {"Authorization": f"Token token={self.api_token}"}
            url = f"{self.API_BASE}/themes/{slug}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.cache[cache_key] = data
                        self.requests_today += 1
                        return self._filter_by_version(data, version)
        except Exception as e:
            logger.debug(f"WPScan API error: {e}")
        
        return []
    
    def _filter_by_version(self, data: Dict, version: Optional[str]) -> List[Dict]:
        """Filter vulnerabilities by version."""
        vulns = []
        
        for vuln_id, vuln_data in data.get(data.get("slug", ""), {}).get("vulnerabilities", {}).items():
            # Check if version is affected
            fixed_in = vuln_data.get("fixed_in")
            
            if version and fixed_in:
                try:
                    from packaging import version as pkg_version
                    if pkg_version.parse(version) >= pkg_version.parse(fixed_in):
                        continue  # Version is patched
                except Exception:
                    pass  # Include if we can't compare
            
            vulns.append({
                "id": vuln_id,
                "title": vuln_data.get("title", "Unknown"),
                "severity": self._cvss_to_severity(vuln_data.get("cvss", {}).get("score", 0)),
                "fixed_in": fixed_in,
                "references": vuln_data.get("references", {}),
            })
        
        return vulns
    
    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        """Convert CVSS score to severity."""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        return "low"


# =============================================================================
# PLUGIN VULNERABILITY TESTING
# =============================================================================

class PluginVulnTester:
    """
    Test plugins for common vulnerabilities.
    
    Tests:
    - Local File Inclusion (LFI)
    - Remote Code Execution (RCE)
    - SQL Injection (SQLi)
    - Arbitrary File Upload
    - Authentication Bypass
    """
    
    # LFI payloads
    LFI_PAYLOADS = [
        ("../../../wp-config.php", "DB_PASSWORD"),
        ("....//....//....//etc/passwd", "root:x:"),
        ("..%2f..%2f..%2fwp-config.php", "DB_PASSWORD"),
        ("....//....//....//wp-config.php", "DB_PASSWORD"),
    ]
    
    # SQLi payloads
    SQLI_PAYLOADS = [
        ("1'", ["mysql_fetch", "SQL syntax", "mysqli", "SQLSTATE"]),
        ("1 OR 1=1--", ["mysql_fetch", "SQL syntax", "mysqli"]),
        ("1' AND '1'='1", ["mysql_fetch", "SQL syntax"]),
    ]
    
    # RCE indicators
    RCE_INDICATORS = [
        "eval(", "base64_decode(", "system(", "exec(",
        "passthru(", "shell_exec(", "popen(", "proc_open(",
    ]
    
    def __init__(self, http_client):
        self.http = http_client
        self.findings: List[Dict] = []
    
    async def test_plugin(self, slug: str, path: str) -> List[Dict]:
        """Run all vulnerability tests on a plugin."""
        self.findings = []
        
        await asyncio.gather(
            self._test_lfi(slug, path),
            self._test_sqli(slug, path),
            self._test_file_upload(slug, path),
            self._test_admin_bypass(slug, path),
            return_exceptions=True
        )
        
        return self.findings
    
    async def _test_lfi(self, slug: str, path: str):
        """Test for Local File Inclusion."""
        lfi_endpoints = [
            f"{path}download.php?file=",
            f"{path}includes/download.php?path=",
            f"{path}export.php?file=",
            f"?{slug}_file=",
        ]
        
        for endpoint in lfi_endpoints:
            for payload, signature in self.LFI_PAYLOADS:
                try:
                    url = endpoint + payload
                    response = await self.http.get(url)
                    
                    if response.ok and signature in response.text:
                        self.findings.append({
                            "type": "LFI",
                            "severity": "critical",
                            "plugin": slug,
                            "endpoint": url,
                            "evidence": signature,
                        })
                        logger.vuln("critical", f"LFI in {slug}: {url[:60]}...")
                        return  # One finding is enough
                except Exception:
                    continue
    
    async def _test_sqli(self, slug: str, path: str):
        """Test for SQL Injection."""
        sqli_endpoints = [
            f"{path}?id=",
            f"{path}?page=",
            f"{path}?user_id=",
            f"{path}admin/?action=edit&id=",
        ]
        
        for endpoint in sqli_endpoints:
            for payload, signatures in self.SQLI_PAYLOADS:
                try:
                    url = endpoint + payload
                    response = await self.http.get(url)
                    
                    for sig in signatures:
                        if sig in response.text:
                            self.findings.append({
                                "type": "SQLi",
                                "severity": "critical",
                                "plugin": slug,
                                "endpoint": url,
                                "evidence": sig,
                            })
                            logger.vuln("critical", f"SQLi in {slug}: {url[:60]}...")
                            return
                except Exception:
                    continue
    
    async def _test_file_upload(self, slug: str, path: str):
        """Test for unrestricted file upload."""
        upload_endpoints = [
            f"{path}upload.php",
            f"{path}includes/upload.php",
            f"{path}admin/upload.php",
            f"{path}ajax/upload.php",
        ]
        
        for endpoint in upload_endpoints:
            try:
                response = await self.http.get(endpoint)
                if response.ok and response.status_code != 404:
                    # Check if upload form exists
                    if 'enctype="multipart/form-data"' in response.text or "upload" in response.text.lower():
                        self.findings.append({
                            "type": "File Upload",
                            "severity": "high",
                            "plugin": slug,
                            "endpoint": endpoint,
                            "evidence": "Upload endpoint accessible",
                        })
                        logger.warning(f"Upload endpoint in {slug}: {endpoint}")
            except Exception:
                continue
    
    async def _test_admin_bypass(self, slug: str, path: str):
        """Test for authentication bypass."""
        admin_endpoints = [
            f"{path}admin/",
            f"{path}includes/admin.php",
            f"{path}settings.php",
            f"{path}config.php",
        ]
        
        for endpoint in admin_endpoints:
            try:
                response = await self.http.get(endpoint)
                
                # Check if admin accessible without redirect to login
                if response.ok and "wp-login" not in response.url:
                    admin_indicators = ["dashboard", "settings", "configuration", "admin panel"]
                    if any(ind in response.text.lower() for ind in admin_indicators):
                        self.findings.append({
                            "type": "Auth Bypass",
                            "severity": "high",
                            "plugin": slug,
                            "endpoint": endpoint,
                            "evidence": "Admin panel accessible without auth",
                        })
                        logger.vuln("high", f"Auth bypass in {slug}: {endpoint}")
            except Exception:
                continue


# =============================================================================
# NULLED PLUGIN DETECTION
# =============================================================================

class NulledPluginDetector:
    """
    Detect nulled/cracked/pirated plugins.
    
    These often contain backdoors and malware.
    """
    
    # Indicators of nulled plugins
    NULLED_INDICATORS = [
        # Common nulled signatures
        "nulled", "cracked", "leaked", "warez", "gpl-ghost",
        "nulledpremium", "gplvault", "gpldl", "themefores",
        "free download premium", "downloaded from",
        
        # Backdoor patterns
        "eval(base64_decode", "eval(gzinflate", "eval(str_rot13",
        "eval(gzuncompress", "preg_replace('/.*" + "/e'",
        "assert(base64_decode", "create_function(",
        
        # Obfuscation patterns
        r'\$[a-zA-Z]{1,2}\s*=\s*"[a-zA-Z0-9+/=]{100,}";',
        r'chr\(\d+\)\.chr\(\d+\)',
    ]
    
    # Files to check
    FILES_TO_CHECK = [
        "readme.txt",
        "{slug}.php",
        "includes/functions.php",
        "includes/class-{slug}.php",
        "admin/admin.php",
        "license.php",
    ]
    
    def __init__(self, http_client):
        self.http = http_client
    
    async def check_plugin(self, slug: str, path: str) -> Dict:
        """Check if plugin is nulled/cracked."""
        result = {
            "is_nulled": False,
            "indicators_found": [],
            "backdoor_suspected": False,
        }
        
        files = [f.format(slug=slug) for f in self.FILES_TO_CHECK]
        
        for file in files:
            try:
                response = await self.http.get(f"{path}{file}")
                
                if not response.ok:
                    continue
                
                content = response.text
                content_lower = content.lower()
                
                for indicator in self.NULLED_INDICATORS:
                    # Check if it's a regex pattern
                    if indicator.startswith(r'\$') or indicator.startswith(r'chr'):
                        if re.search(indicator, content):
                            result["is_nulled"] = True
                            result["backdoor_suspected"] = True
                            result["indicators_found"].append(f"Pattern: {indicator[:30]}...")
                    elif indicator.lower() in content_lower:
                        result["is_nulled"] = True
                        result["indicators_found"].append(indicator)
                        
                        # Check if it's a backdoor pattern
                        if "eval" in indicator or "base64" in indicator:
                            result["backdoor_suspected"] = True
                
                if result["is_nulled"]:
                    severity = "critical" if result["backdoor_suspected"] else "high"
                    logger.vuln(
                        severity,
                        f"Nulled plugin detected: {slug} ({', '.join(result['indicators_found'][:3])})"
                    )
                    return result
                    
            except Exception:
                continue
        
        return result


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_rate_limiter() -> GlobalRateLimiter:
    """Get the global rate limiter instance."""
    return GlobalRateLimiter()


async def check_waf(http_client) -> WAFInfo:
    """Quick WAF check."""
    return await WAFDetector.detect(http_client)


def get_stealth_headers(referer: Optional[str] = None) -> Dict[str, str]:
    """Get stealth mode headers."""
    return StealthMode.get_headers(referer)
