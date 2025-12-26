"""
WPHunter - Advanced Plugin Enumeration
========================================
Intelligent plugin detection with passive and active methods.

Enhanced with:
- Sourcemap analysis
- Error log detection
- Translation file parsing
- Update JSON discovery
- CSS/JS fingerprinting
- Sitemap/robots.txt analysis
- HTTP header detection
- HTML comment parsing
- Changelog/composer.json version detection
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from bs4 import BeautifulSoup
from packaging import version

from core.http_client import WPHttpClient, HTTPResponse
from core.logger import logger
from core.security import get_rate_limiter
from modules.scanners.waf import WAFDetector
from modules.integrations.wpscan_api import WPScanAPI
from modules.recon.plugin_security import PluginVulnTester, NulledPluginDetector


@dataclass
class PluginInfo:
    """Information about a detected plugin."""
    slug: str
    name: Optional[str] = None
    version: Optional[str] = None
    path: Optional[str] = None
    detection_method: str = "unknown"
    vulnerable: bool = False
    vulnerabilities: List[Dict] = field(default_factory=list)
    
    def __hash__(self):
        return hash(self.slug)


class VulnerabilityChecker:
    """Check plugins against known vulnerability database."""
    
    # Known vulnerabilities (version_range: vuln_info)
    KNOWN_VULNERABILITIES = {
        "contact-form-7": {
            "5.3.1": {"cve": "CVE-2020-35489", "severity": "high", 
                     "type": "Unrestricted File Upload"},
        },
        "elementor": {
            "3.6.0": {"cve": "CVE-2023-32243", "severity": "critical",
                     "type": "Authentication Bypass"},
        },
        "wp-file-manager": {
            "6.8": {"cve": "CVE-2020-25213", "severity": "critical",
                   "type": "Remote Code Execution", "exploited": True},
        },
        "revslider": {
            "4.2": {"cve": "CVE-2014-9735", "severity": "critical",
                   "type": "Arbitrary File Download"},
        },
        "duplicator": {
            "1.3.26": {"cve": "CVE-2020-11738", "severity": "critical",
                      "type": "Unauthenticated Arbitrary File Download"},
        },
        "loginizer": {
            "1.6.3": {"cve": "CVE-2020-27615", "severity": "critical",
                     "type": "SQL Injection"},
        },
        "js_composer": {
            "6.0.5": {"cve": "CVE-2021-24370", "severity": "high",
                     "type": "Stored XSS"},
        },
        "all-in-one-wp-migration": {
            "7.14": {"cve": "CVE-2020-28422", "severity": "high",
                    "type": "Arbitrary File Download"},
        },
        "ninja-forms": {
            "3.6.25": {"cve": "CVE-2023-37979", "severity": "critical",
                      "type": "PHP Object Injection"},
        },
    }
    
    @classmethod
    def check_plugin(cls, plugin: PluginInfo) -> bool:
        """Check if plugin version is vulnerable."""
        if not plugin.version or plugin.slug not in cls.KNOWN_VULNERABILITIES:
            return False
        
        vulns = cls.KNOWN_VULNERABILITIES[plugin.slug]
        
        for vuln_version, vuln_info in vulns.items():
            if cls._is_version_vulnerable(plugin.version, vuln_version):
                plugin.vulnerable = True
                plugin.vulnerabilities.append({
                    "cve": vuln_info.get("cve", "N/A"),
                    "severity": vuln_info["severity"],
                    "type": vuln_info["type"],
                    "fixed_in": vuln_version,
                    "exploited": vuln_info.get("exploited", False),
                })
                logger.vuln(
                    vuln_info["severity"],
                    f"{plugin.slug} v{plugin.version}: {vuln_info['type']} ({vuln_info.get('cve', 'N/A')})"
                )
                return True
        return False
    
    @staticmethod
    def _is_version_vulnerable(current: str, fixed: str) -> bool:
        """
        Check if current version is older than fixed version.
        
        Uses packaging.version for proper semver comparison.
        Handles versions like 1.0.0-beta, 2.1-rc1, etc.
        """
        try:
            return version.parse(current) < version.parse(fixed)
        except version.InvalidVersion:
            logger.debug(f"Invalid version format: {current} or {fixed}")
            return False  # Conservative: assume not vulnerable if can't parse


class PluginEnumerator:
    """
    Enumerate WordPress plugins using multiple techniques.
    
    Combines passive HTML analysis with targeted active enumeration
    to minimize requests while maximizing detection.
    """
    
    # Top plugins to check (commonly installed/vulnerable)
    TOP_PLUGINS = [
        # Security & Performance
        "wordfence", "ithemes-security", "sucuri-scanner", "wp-super-cache",
        "w3-total-cache", "wp-fastest-cache", "autoptimize", "litespeed-cache",
        # Form Builders (often vulnerable)
        "contact-form-7", "wpforms-lite", "ninja-forms", "formidable",
        # SEO
        "wordpress-seo", "all-in-one-seo-pack", "rank-math-seo",
        # Page Builders
        "elementor", "beaver-builder-lite-version", "siteorigin-panels",
        # E-commerce
        "woocommerce", "easy-digital-downloads",
        # Media & Gallery
        "nextgen-gallery", "envira-gallery-lite", "ml-slider",
        # Backup
        "updraftplus", "backwpup", "duplicator", "all-in-one-wp-migration",
        # Utilities
        "akismet", "jetpack", "really-simple-ssl", "redirection",
        "wp-mail-smtp", "advanced-custom-fields", "classic-editor",
        # Known Vulnerable (CVE history)
        "revslider", "js_composer", "LayerSlider", "wp-file-manager",
        "loginizer", "limit-login-attempts-reloaded", "simple-backup",
    ]
    
    # AJAX actions that bruteforce
    BRUTEFORCE_AJAX_ACTIONS = [
        "get_user_data", "update_profile", "upload_media", "delete_media",
        "install_plugin", "activate_plugin", "export_data", "import_data",
    ]
    
    def __init__(self, http_client: WPHttpClient, wordlist_path: Optional[str] = None):
        self.http = http_client
        self.detected_plugins: Dict[str, PluginInfo] = {}
        self.wordlist_path = wordlist_path
        self.enumeration_methods: List[str] = []
    
    async def enumerate(self, passive_only: bool = False) -> List[PluginInfo]:
        """Basic enumeration with passive + active methods."""
        logger.section("Plugin Enumeration")
        
        await self._passive_detect()
        logger.info(f"Passive detection found {len(self.detected_plugins)} plugins")
        
        if not passive_only:
            await self._active_enumerate()
            await self._detect_from_rest_api()
        
        await self._detect_versions()
        
        # Check for known vulnerabilities
        vuln_count = 0
        for plugin in self.detected_plugins.values():
            if VulnerabilityChecker.check_plugin(plugin):
                vuln_count += 1
        
        plugins = list(self.detected_plugins.values())
        logger.success(f"Total plugins: {len(plugins)} ({vuln_count} vulnerable)")
        
        return plugins
    
    async def comprehensive_enumeration(self, aggressive: bool = False) -> List[PluginInfo]:
        """Perform comprehensive plugin enumeration with all advanced methods."""
        logger.section("Advanced Plugin Enumeration")
        
        self.enumeration_methods = []
        
        # Basic enumeration first
        await self._passive_detect()
        await self._active_enumerate()
        await self._detect_from_rest_api()
        self.enumeration_methods.extend(["passive", "active", "rest_api"])
        
        # Advanced passive methods (low footprint)
        passive_tasks = [
            self._detect_from_sitemap_robots(),
            self._detect_from_html_comments(),
            self._detect_from_http_headers(),
        ]
        await asyncio.gather(*passive_tasks, return_exceptions=True)
        self.enumeration_methods.extend(["sitemap_robots", "html_comments", "http_headers"])
        
        # More intrusive methods if aggressive
        if aggressive:
            aggressive_tasks = [
                self._detect_from_error_logs(),
                self._detect_from_translations(),
                self._detect_from_sourcemaps(),
                self._detect_from_assets_fingerprinting(),
                self._detect_from_update_json(),
            ]
            await asyncio.gather(*aggressive_tasks, return_exceptions=True)
            self.enumeration_methods.extend([
                "error_logs", "translations", "sourcemaps", 
                "asset_fingerprinting", "update_json"
            ])
        
        # Version detection refinement
        await self._detect_versions()
        await self._refine_versions()
        
        plugins = list(self.detected_plugins.values())
        
        # Log summary
        with_version = len([p for p in plugins if p.version])
        logger.success(f"Total plugins: {len(plugins)} ({with_version} with version)")
        
        return plugins
    
    async def full_security_scan(
        self, 
        wpscan_token: Optional[str] = None,
        test_vulns: bool = True,
        check_nulled: bool = True
    ) -> Dict:
        """
        Comprehensive security scan with all advanced features.
        
        Features:
        - WAF detection before scanning
        - Global rate limiting to avoid bans
        - CVE database checking
        - WPScan API integration (if token provided)
        - LFI/RCE/SQLi vulnerability testing
        - Nulled/cracked plugin detection
        
        Args:
            wpscan_token: Optional WPScan API token
            test_vulns: Test plugins for LFI/RCE/SQLi
            check_nulled: Check for nulled/pirated plugins
        
        Returns:
            Comprehensive security report
        """
        logger.section("Full Plugin Security Scan")
        
        report = {
            "waf_detected": None,
            "plugins_found": 0,
            "vulnerable_plugins": [],
            "nulled_plugins": [],
            "vuln_findings": [],
            "wpscan_vulns": [],
        }
        
        # Step 1: WAF Detection
        logger.info("Checking for WAF...")
        waf_info = await WAFDetector.detect(self.http)
        report["waf_detected"] = waf_info.waf_name if waf_info.detected else None
        
        if waf_info.detected:
            logger.warning(f"WAF detected: {waf_info.waf_name}")
            for technique in waf_info.bypass_techniques[:3]:
                logger.info(f"  Bypass: {technique}")
        
        # Step 2: Plugin enumeration with rate limiting
        rate_limiter = get_rate_limiter()
        
        await self._passive_detect()
        await rate_limiter.acquire()
        await self._active_enumerate()
        await rate_limiter.acquire()
        await self._detect_from_rest_api()
        await self._detect_versions()
        
        report["plugins_found"] = len(self.detected_plugins)
        logger.info(f"Found {report['plugins_found']} plugins")
        
        # Step 3: CVE Database Check
        logger.info("Checking CVE database...")
        for plugin in self.detected_plugins.values():
            if VulnerabilityChecker.check_plugin(plugin):
                report["vulnerable_plugins"].append({
                    "slug": plugin.slug,
                    "version": plugin.version,
                    "vulnerabilities": plugin.vulnerabilities,
                })
        
        # Step 4: WPScan API Check (if token provided)
        if wpscan_token:
            logger.info("Checking WPScan database...")
            wpscan = WPScanAPI(wpscan_token)
            
            for plugin in list(self.detected_plugins.values())[:10]:  # Limit API calls
                await rate_limiter.acquire()
                vulns = await wpscan.check_plugin(plugin.slug, plugin.version)
                if vulns:
                    report["wpscan_vulns"].extend([
                        {"plugin": plugin.slug, **v} for v in vulns
                    ])
        
        # Step 5: Vulnerability Testing (LFI/RCE/SQLi)
        if test_vulns:
            logger.info("Testing for vulnerabilities...")
            vuln_tester = PluginVulnTester(self.http)
            
            for plugin in list(self.detected_plugins.values())[:15]:
                if not plugin.path:
                    continue
                await rate_limiter.acquire()
                findings = await vuln_tester.test_plugin(plugin.slug, plugin.path)
                if findings:
                    report["vuln_findings"].extend(findings)
                    plugin.vulnerable = True
        
        # Step 6: Nulled Plugin Detection
        if check_nulled:
            logger.info("Checking for nulled/cracked plugins...")
            nulled_detector = NulledPluginDetector(self.http)
            
            for plugin in list(self.detected_plugins.values())[:10]:
                if not plugin.path:
                    continue
                await rate_limiter.acquire()
                result = await nulled_detector.check_plugin(plugin.slug, plugin.path)
                if result["is_nulled"]:
                    report["nulled_plugins"].append({
                        "slug": plugin.slug,
                        "indicators": result["indicators_found"],
                        "backdoor_suspected": result["backdoor_suspected"],
                    })
        
        # Summary
        vuln_count = len(report["vulnerable_plugins"]) + len(report["vuln_findings"])
        nulled_count = len(report["nulled_plugins"])
        
        logger.success(f"Scan complete: {report['plugins_found']} plugins")
        if vuln_count > 0:
            logger.vuln("high", f"Vulnerable: {vuln_count} issues found")
        if nulled_count > 0:
            logger.vuln("critical", f"Nulled: {nulled_count} plugins (likely backdoored)")
        
        return report

    async def _passive_detect(self):
        """
        Enhanced passive plugin detection.
        
        Scans multiple pages to find plugins that may only load on specific pages.
        """
        # Pages to scan for plugin references
        pages_to_scan = [
            "/",
            "/wp-login.php",
            "/wp-admin/",
            "/?p=1",  # First post
            "/sample-page/",
            "/feed/",
            "/wp-json/",
        ]
        
        all_matches = set()
        
        for page in pages_to_scan:
            try:
                response = await self.http.get(page)
                
                if not response.ok:
                    continue
                
                # Pattern 1: Standard plugin paths
                matches = re.findall(r'/wp-content/plugins/([a-zA-Z0-9_-]+)/', response.text)
                all_matches.update(matches)
                
                # Pattern 2: Inline scripts and quotes
                script_matches = re.findall(r'["\']/wp-content/plugins/([a-zA-Z0-9_-]+)', response.text)
                all_matches.update(script_matches)
                
                # Pattern 3: Plugin version comments
                version_matches = re.findall(r'wp-content/plugins/([a-zA-Z0-9_-]+)/.*?ver=', response.text)
                all_matches.update(version_matches)
                
            except Exception as e:
                logger.debug(f"Error scanning {page}: {e}")
                continue
        
        # Add detected plugins
        for slug in all_matches:
            if slug not in self.detected_plugins:
                self.detected_plugins[slug] = PluginInfo(
                    slug=slug,
                    path=f"/wp-content/plugins/{slug}/",
                    detection_method="passive"
                )
        
        logger.info(f"Passive detection found {len(all_matches)} plugins")
    
    async def _active_enumerate(self):
        """Actively check for known plugins."""
        plugins_to_check = set(self.TOP_PLUGINS)
        
        if self.wordlist_path and Path(self.wordlist_path).exists():
            with open(self.wordlist_path, 'r') as f:
                for line in f:
                    plugin = line.strip()
                    if plugin and not plugin.startswith('#'):
                        plugins_to_check.add(plugin)
        
        plugins_to_check -= set(self.detected_plugins.keys())
        
        if not plugins_to_check:
            return
        
        logger.info(f"Checking {len(plugins_to_check)} plugins actively...")
        
        async def check_plugin(slug: str) -> Optional[PluginInfo]:
            path = f"/wp-content/plugins/{slug}/"
            try:
                exists = await self.http.check_path_exists(path)
                if exists:
                    return PluginInfo(slug=slug, path=path, detection_method="active")
            except Exception:
                pass
            return None
        
        semaphore = asyncio.Semaphore(10)
        
        async def check_with_semaphore(slug: str):
            async with semaphore:
                return await check_plugin(slug)
        
        tasks = [check_with_semaphore(slug) for slug in plugins_to_check]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                self.detected_plugins[result.slug] = result
    
    async def _detect_from_rest_api(self):
        """Try to enumerate plugins via REST API."""
        try:
            response = await self.http.get("/wp-json/wp/v2/plugins")
            
            if response.ok and response.is_json:
                plugins = response.json()
                
                if isinstance(plugins, list):
                    for plugin in plugins:
                        slug = plugin.get("textdomain") or plugin.get("plugin", "").split("/")[0]
                        if slug and slug not in self.detected_plugins:
                            self.detected_plugins[slug] = PluginInfo(
                                slug=slug,
                                name=plugin.get("name"),
                                version=plugin.get("version"),
                                detection_method="rest_api"
                            )
                    logger.info(f"REST API exposed {len(plugins)} plugins")
        except Exception:
            pass
    
    async def _detect_versions(self):
        """Detect version for each plugin via readme.txt and main PHP file."""
        async def get_version(slug: str) -> Optional[str]:
            # Method 1: readme.txt
            readme_path = f"/wp-content/plugins/{slug}/readme.txt"
            try:
                response = await self.http.get(readme_path)
                if response.ok:
                    match = re.search(r'Stable tag:\s*([\d.]+)', response.text, re.IGNORECASE)
                    if match:
                        return match.group(1)
                    match = re.search(r'Version:\s*([\d.]+)', response.text, re.IGNORECASE)
                    if match:
                        return match.group(1)
            except Exception:
                pass
            
            # Method 2: Main plugin PHP file
            main_file_path = f"/wp-content/plugins/{slug}/{slug}.php"
            try:
                response = await self.http.get(main_file_path)
                if response.ok:
                    match = re.search(r'Version:\s*([\d.]+)', response.text, re.IGNORECASE)
                    if match:
                        return match.group(1)
            except Exception:
                pass
            
            return None
        
        plugins_without_version = [
            slug for slug, info in self.detected_plugins.items()
            if info.version is None
        ]
        
        if plugins_without_version:
            logger.info(f"Detecting versions for {len(plugins_without_version)} plugins...")
            
            semaphore = asyncio.Semaphore(5)
            
            async def get_version_with_semaphore(slug: str):
                async with semaphore:
                    return slug, await get_version(slug)
            
            tasks = [get_version_with_semaphore(slug) for slug in plugins_without_version]
            results = await asyncio.gather(*tasks)
            
            for slug, version in results:
                if version:
                    self.detected_plugins[slug].version = version
    
    # ===== ADVANCED DETECTION METHODS =====
    
    async def _detect_from_sitemap_robots(self):
        """Detect plugins from sitemap.xml and robots.txt."""
        # Check robots.txt for disallowed plugin paths
        try:
            response = await self.http.get("/robots.txt")
            if response.ok:
                disallow_pattern = r'Disallow:\s*/wp-content/plugins/([a-zA-Z0-9_-]+)'
                matches = re.findall(disallow_pattern, response.text)
                
                for slug in matches:
                    if slug not in self.detected_plugins:
                        self.detected_plugins[slug] = PluginInfo(
                            slug=slug,
                            path=f"/wp-content/plugins/{slug}/",
                            detection_method="robots_txt"
                        )
        except Exception:
            pass
        
        # Check sitemap.xml for plugin URLs
        sitemap_urls = ["/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"]
        
        for sitemap_url in sitemap_urls:
            try:
                response = await self.http.get(sitemap_url)
                if response.ok:
                    plugin_pattern = r'/wp-content/plugins/([a-zA-Z0-9_-]+)'
                    matches = re.findall(plugin_pattern, response.text)
                    
                    for slug in set(matches):
                        if slug not in self.detected_plugins:
                            self.detected_plugins[slug] = PluginInfo(
                                slug=slug,
                                path=f"/wp-content/plugins/{slug}/",
                                detection_method="sitemap"
                            )
            except Exception:
                continue
    
    async def _detect_from_html_comments(self):
        """Detect plugins from HTML comments."""
        try:
            response = await self.http.get("/")
            if response.ok:
                # Look for plugin-specific comments
                comment_patterns = [
                    r'<!--\s*(?:Plugin|Generated by|Powered by):?\s*([^>]+?)\s*-->',
                    r'<!--\s*([a-zA-Z0-9_-]+)\s+v?([\d.]+)\s*-->',
                    r'<!--\s*Begin\s+([a-zA-Z0-9_-]+)\s*-->',
                ]
                
                for pattern in comment_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    
                    for match in matches:
                        if isinstance(match, tuple):
                            slug = match[0].lower().replace(' ', '-')
                            version = match[1] if len(match) > 1 else None
                        else:
                            slug = match.lower().replace(' ', '-')
                            version = None
                        
                        # Skip if it's a version number
                        if re.match(r'^[\d.]+$', slug):
                            continue
                        
                        if slug not in self.detected_plugins and len(slug) > 2:
                            self.detected_plugins[slug] = PluginInfo(
                                slug=slug,
                                version=version,
                                detection_method="html_comments"
                            )
        except Exception:
            pass
    
    async def _detect_from_http_headers(self):
        """Detect plugins from HTTP headers."""
        try:
            response = await self.http.get("/")
            
            headers = response.headers
            
            plugin_header_patterns = [
                r'X-Plugin-([a-zA-Z0-9_-]+)',
                r'X-([a-zA-Z0-9_-]+)-Version',
                r'X-Powered-By-([a-zA-Z0-9_-]+)',
            ]
            
            for header_name in headers.keys():
                for pattern in plugin_header_patterns:
                    match = re.match(pattern, header_name, re.IGNORECASE)
                    if match:
                        slug = match.group(1).lower()
                        if slug not in self.detected_plugins:
                            self.detected_plugins[slug] = PluginInfo(
                                slug=slug,
                                detection_method="http_headers"
                            )
                            
                            # Try to get version from header value
                            value = headers.get(header_name, "")
                            version_match = re.search(r'([\d.]+)', value)
                            if version_match:
                                self.detected_plugins[slug].version = version_match.group(1)
        except Exception:
            pass
    
    async def _detect_from_error_logs(self):
        """Detect plugins from PHP error logs (with size limit to prevent DoS)."""
        MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB max
        
        error_log_paths = [
            "/wp-content/debug.log",
            "/debug.log",
            "/error_log",
        ]
        
        for path in error_log_paths:
            try:
                # Check size first with HEAD request
                head_response = await self.http.head(path)
                
                if not head_response.ok:
                    continue
                
                # Check content-length header
                size = int(head_response.headers.get('content-length', 0))
                
                if size > MAX_LOG_SIZE:
                    logger.warning(f"Debug log too large ({size} bytes, max {MAX_LOG_SIZE}): {path}")
                    continue
                
                # Now safe to download
                response = await self.http.get(path)
                
                if response.ok and "PHP" in response.text:
                    logger.warning(f"Debug log exposed: {path}")
                    
                    # Extract plugin paths from errors
                    plugin_pattern = r'/wp-content/plugins/([a-zA-Z0-9_-]+)'
                    matches = re.findall(plugin_pattern, response.text)
                    
                    for slug in set(matches):
                        if slug not in self.detected_plugins:
                            self.detected_plugins[slug] = PluginInfo(
                                slug=slug,
                                path=f"/wp-content/plugins/{slug}/",
                                detection_method="error_log"
                            )
                    
                    break  # Found one, stop checking
            except Exception as e:
                logger.debug(f"Error checking {path}: {e}")
                continue
    
    async def _detect_from_translations(self):
        """Detect plugins from translation files."""
        try:
            # Check global translation directory
            response = await self.http.get("/wp-content/languages/plugins/")
            if response.ok:
                # Look for directory listing or file names
                po_pattern = r'([a-zA-Z0-9_-]+)-([\d.]+)[^"\']*\.(?:po|mo)'
                matches = re.findall(po_pattern, response.text)
                
                for slug, version in matches:
                    if slug not in self.detected_plugins:
                        self.detected_plugins[slug] = PluginInfo(
                            slug=slug,
                            version=version,
                            detection_method="translations"
                        )
                    elif not self.detected_plugins[slug].version:
                        self.detected_plugins[slug].version = version
        except Exception:
            pass
    
    async def _detect_from_sourcemaps(self):
        """Detect plugin versions from JavaScript sourcemaps."""
        for plugin_slug in list(self.detected_plugins.keys())[:15]:
            if self.detected_plugins[plugin_slug].version:
                continue  # Already have version
            
            sourcemap_paths = [
                f"/wp-content/plugins/{plugin_slug}/assets/js/main.js.map",
                f"/wp-content/plugins/{plugin_slug}/dist/main.js.map",
                f"/wp-content/plugins/{plugin_slug}/js/{plugin_slug}.min.js.map",
            ]
            
            for path in sourcemap_paths:
                try:
                    response = await self.http.get(path)
                    
                    if response.ok and '"sources"' in response.text:
                        # Look for version in sources
                        version_match = re.search(r'([\d]+\.[\d]+\.[\d]+)', response.text)
                        if version_match:
                            self.detected_plugins[plugin_slug].version = version_match.group(1)
                            break
                except Exception:
                    continue
    
    async def _detect_from_assets_fingerprinting(self):
        """Fingerprint plugins by analyzing CSS/JS assets."""
        for plugin_slug in list(self.detected_plugins.keys())[:15]:
            if self.detected_plugins[plugin_slug].version:
                continue
            
            asset_paths = [
                f"/wp-content/plugins/{plugin_slug}/assets/css/style.css",
                f"/wp-content/plugins/{plugin_slug}/css/{plugin_slug}.css",
                f"/wp-content/plugins/{plugin_slug}/assets/js/main.js",
                f"/wp-content/plugins/{plugin_slug}/js/{plugin_slug}.js",
            ]
            
            for path in asset_paths[:2]:  # Limit checks
                try:
                    response = await self.http.get(path)
                    if response.ok:
                        version_patterns = [
                            r'Version:\s*([\d.]+)',
                            r'@version\s+([\d.]+)',
                            r'/\*.*?v([\d.]+)',
                        ]
                        
                        for pattern in version_patterns:
                            match = re.search(pattern, response.text, re.IGNORECASE)
                            if match:
                                self.detected_plugins[plugin_slug].version = match.group(1)
                                break
                        
                        if self.detected_plugins[plugin_slug].version:
                            break
                except Exception:
                    continue
    
    async def _detect_from_update_json(self):
        """Detect plugins from update JSON files."""
        for plugin_slug in list(self.detected_plugins.keys())[:10]:
            if self.detected_plugins[plugin_slug].version:
                continue
            
            try:
                update_path = f"/wp-content/plugins/{plugin_slug}/update.json"
                response = await self.http.get(update_path)
                
                if response.ok and response.is_json:
                    data = response.json()
                    version = data.get('version') or data.get('new_version')
                    if version:
                        self.detected_plugins[plugin_slug].version = version
            except Exception:
                continue
    
    async def _refine_versions(self):
        """Refine version detection using additional sources."""
        for plugin_slug in list(self.detected_plugins.keys())[:20]:
            if self.detected_plugins[plugin_slug].version:
                continue
            
            # Try changelog
            version = await self._get_version_from_changelog(plugin_slug)
            if version:
                self.detected_plugins[plugin_slug].version = version
                continue
            
            # Try composer.json
            version = await self._get_version_from_composer(plugin_slug)
            if version:
                self.detected_plugins[plugin_slug].version = version
                continue
            
            # Try package.json
            version = await self._get_version_from_package_json(plugin_slug)
            if version:
                self.detected_plugins[plugin_slug].version = version
    
    async def _get_version_from_changelog(self, plugin_slug: str) -> Optional[str]:
        """Get version from changelog files."""
        changelog_paths = [
            f"/wp-content/plugins/{plugin_slug}/changelog.txt",
            f"/wp-content/plugins/{plugin_slug}/CHANGELOG.md",
            f"/wp-content/plugins/{plugin_slug}/CHANGES.md",
        ]
        
        for path in changelog_paths:
            try:
                response = await self.http.get(path)
                if response.ok:
                    version_match = re.search(r'[vV]?([\d]+\.[\d]+\.?[\d]*)', response.text[:500])
                    if version_match:
                        return version_match.group(1)
            except Exception:
                continue
        
        return None
    
    async def _get_version_from_composer(self, plugin_slug: str) -> Optional[str]:
        """Get version from composer.json."""
        try:
            path = f"/wp-content/plugins/{plugin_slug}/composer.json"
            response = await self.http.get(path)
            if response.ok and response.is_json:
                data = response.json()
                return data.get('version')
        except Exception:
            pass
        return None
    
    async def _get_version_from_package_json(self, plugin_slug: str) -> Optional[str]:
        """Get version from package.json."""
        try:
            path = f"/wp-content/plugins/{plugin_slug}/package.json"
            response = await self.http.get(path)
            if response.ok and response.is_json:
                data = response.json()
                return data.get('version')
        except Exception:
            pass
        return None
    
    def get_plugins_by_criticality(self) -> Dict[str, List[PluginInfo]]:
        """Get plugins organized by vulnerability criticality."""
        return {
            "critical": [p for p in self.detected_plugins.values() 
                        if p.vulnerable and any(v.get('severity') == 'critical' 
                        for v in p.vulnerabilities)],
            "high": [p for p in self.detected_plugins.values() 
                    if p.vulnerable and any(v.get('severity') == 'high' 
                    for v in p.vulnerabilities)],
            "medium": [p for p in self.detected_plugins.values() 
                      if p.vulnerable and any(v.get('severity') == 'medium' 
                      for v in p.vulnerabilities)],
            "low": [p for p in self.detected_plugins.values() 
                   if p.vulnerable and any(v.get('severity') == 'low' 
                   for v in p.vulnerabilities)],
        }
    
    def export_for_scanners(self) -> Dict[str, List[str]]:
        """Export plugin info for other scanner modules."""
        return {
            "plugin_slugs": list(self.detected_plugins.keys()),
            "plugin_paths": [p.path for p in self.detected_plugins.values() if p.path],
            "vulnerable_plugins": [p.slug for p in self.detected_plugins.values() if p.vulnerable],
        }
    
    def get_fuzzing_targets(self) -> List[Dict]:
        """Get plugin-specific fuzzing targets."""
        targets = []
        for plugin in self.detected_plugins.values():
            if plugin.path:
                targets.append({
                    "plugin": plugin.slug,
                    "base_path": plugin.path,
                    "common_files": [
                        f"{plugin.path}readme.txt",
                        f"{plugin.path}{plugin.slug}.php",
                        f"{plugin.path}includes/",
                        f"{plugin.path}admin/",
                    ],
                })
        return targets
    
    def get_summary(self) -> Dict:
        """Get summary of enumeration results."""
        plugins = list(self.detected_plugins.values())
        
        detection_breakdown = {}
        for p in plugins:
            method = p.detection_method
            detection_breakdown[method] = detection_breakdown.get(method, 0) + 1
        
        return {
            "total": len(plugins),
            "with_version": len([p for p in plugins if p.version]),
            "vulnerable": len([p for p in plugins if p.vulnerable]),
            "detection_methods": self.enumeration_methods,
            "detection_breakdown": detection_breakdown,
            "plugins": [
                {
                    "slug": p.slug,
                    "version": p.version,
                    "method": p.detection_method,
                }
                for p in plugins
            ]
        }
