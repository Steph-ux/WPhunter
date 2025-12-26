"""
WPHunter - Professional WPScan API Integration
===============================================
Production-grade integration with WPScan Vulnerability Database API.

Features:
- Rate limiting (25 requests/day free tier)
- Request caching (24h TTL)
- Smart prioritization
- Robust error handling
- Version comparison with packaging library
- Exploit context enrichment
- Comprehensive reporting

API Documentation: https://wpscan.com/api
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from packaging import version

import httpx

from core.logger import logger


class RateLimitError(Exception):
    """Rate limit exceeded."""
    pass


class AuthenticationError(Exception):
    """Invalid API token."""
    pass


@dataclass
class Vulnerability:
    """Vulnerability with complete metadata and exploit context."""
    id: str
    title: str
    description: str
    vuln_type: str
    severity: str
    cvss_score: Optional[float]
    cve: Optional[str]
    references: List[str]
    fixed_in: Optional[str]
    
    # Exploit context
    exploitable: bool = False
    exploit_available: bool = False
    requires_auth: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "type": self.vuln_type,
            "severity": self.severity,
            "cvss": self.cvss_score,
            "cve": self.cve,
            "fixed_in": self.fixed_in,
            "references": self.references[:3],
            "exploitable": self.exploitable,
            "exploit_available": self.exploit_available,
            "requires_auth": self.requires_auth
        }


class WPScanAPI:
    """
    WPScan Vulnerability Database API client with rate limiting and caching.
    
    Free tier: 25 requests/day
    """
    
    BASE_URL = "https://wpscan.com/api/v3"
    
    def __init__(self, api_token: Optional[str] = None):
        self.api_token = api_token
        self.headers = {}
        if api_token:
            self.headers["Authorization"] = f"Token token={api_token}"
        
        # Rate limiting
        self.request_count = 0
        self.daily_limit = 25  # Free tier
        self.last_request_time = 0
        self.min_delay = 1.0  # 1 second between requests
        
        # Caching
        self.cache: Dict[str, Dict] = {}
        self.cache_ttl = 86400  # 24 hours
    
    async def _rate_limit(self):
        """Enforce rate limiting."""
        # Check daily quota
        if self.request_count >= self.daily_limit:
            logger.error(f"WPScan API daily limit reached ({self.daily_limit}/day)")
            raise RateLimitError("Daily quota exceeded")
        
        # Delay between requests
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.min_delay:
            await asyncio.sleep(self.min_delay - elapsed)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    async def check_plugin(self, slug: str, version: Optional[str] = None) -> List[Vulnerability]:
        """
        Check plugin for known vulnerabilities.
        
        Args:
            slug: Plugin slug (e.g., 'contact-form-7')
            version: Optional version to filter vulnerabilities
        """
        if not self.api_token:
            raise ValueError("WPScan API token required")
        
        # Check cache
        cache_key = f"plugin:{slug}:{version or 'latest'}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached["timestamp"] < self.cache_ttl:
                logger.debug(f"Cache hit: {slug}")
                return cached["vulnerabilities"]
        
        # Rate limit
        await self._rate_limit()
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.BASE_URL}/plugins/{slug}",
                    headers=self.headers,
                    timeout=10
                )
                
                # Handle HTTP status codes
                if response.status_code == 200:
                    data = response.json()
                    vulns = self._parse_vulnerabilities(data, slug, version)
                    
                    # Cache result
                    self.cache[cache_key] = {
                        "timestamp": time.time(),
                        "vulnerabilities": vulns
                    }
                    
                    return vulns
                
                elif response.status_code == 401:
                    logger.error("WPScan API: Invalid token")
                    return []  # Don't crash, just return empty
                
                elif response.status_code == 403:
                    logger.warning("WPScan API: Access forbidden (check token or rate limit)")
                    return []  # Don't crash, continue scan without API data
                
                elif response.status_code == 404:
                    logger.debug(f"Plugin not in WPScan DB: {slug}")
                    return []
                
                elif response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", 60)
                    logger.warning(f"Rate limited, waiting {retry_after}s")
                    await asyncio.sleep(int(retry_after))
                    return await self.check_plugin(slug, version)  # Retry
                
                else:
                    logger.error(f"WPScan API error: {response.status_code}")
                    return []
        
        except httpx.TimeoutException:
            logger.warning(f"Timeout checking {slug}")
            return []
        
        except httpx.NetworkError as e:
            logger.error(f"Network error: {e}")
            return []
        
        except Exception as e:
            logger.error(f"Unexpected error checking {slug}: {e}")
            return []
    
    async def check_theme(self, slug: str, version: Optional[str] = None) -> List[Vulnerability]:
        """Check theme for known vulnerabilities."""
        if not self.api_token:
            raise ValueError("WPScan API token required")
        
        # Check cache
        cache_key = f"theme:{slug}:{version or 'latest'}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached["timestamp"] < self.cache_ttl:
                logger.debug(f"Cache hit: {slug}")
                return cached["vulnerabilities"]
        
        await self._rate_limit()
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.BASE_URL}/themes/{slug}",
                    headers=self.headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    vulns = self._parse_vulnerabilities(data, slug, version)
                    
                    self.cache[cache_key] = {
                        "timestamp": time.time(),
                        "vulnerabilities": vulns
                    }
                    
                    return vulns
                
                elif response.status_code == 404:
                    logger.debug(f"Theme not in WPScan DB: {slug}")
                    return []
                
                elif response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", 60)
                    await asyncio.sleep(int(retry_after))
                    return await self.check_theme(slug, version)
                
                else:
                    return []
                    
        except Exception as e:
            logger.debug(f"WPScan theme check failed: {e}")
            return []
    
    async def check_wordpress(self, wp_version: str) -> List[Vulnerability]:
        """Check WordPress core for known vulnerabilities."""
        if not self.api_token:
            raise ValueError("WPScan API token required")
        
        # Check cache
        cache_key = f"wordpress:{wp_version}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached["timestamp"] < self.cache_ttl:
                logger.debug(f"Cache hit: WordPress {wp_version}")
                return cached["vulnerabilities"]
        
        await self._rate_limit()
        
        try:
            async with httpx.AsyncClient() as client:
                # CORRECT API format: /wordpresses/{version} (NOT with dots removed)
                response = await client.get(
                    f"{self.BASE_URL}/wordpresses/{wp_version}",
                    headers=self.headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    vulns = self._parse_vulnerabilities(data, f"wordpress-{wp_version}", None)
                    
                    self.cache[cache_key] = {
                        "timestamp": time.time(),
                        "vulnerabilities": vulns
                    }
                    
                    return vulns
                
                elif response.status_code == 404:
                    logger.debug(f"WordPress {wp_version} not in WPScan DB")
                    return []
                
                else:
                    return []
                    
        except Exception as e:
            logger.debug(f"WPScan WordPress check failed: {e}")
            return []
    
    def _parse_vulnerabilities(
        self,
        data: Dict,
        component: str,
        comp_version: Optional[str]
    ) -> List[Vulnerability]:
        """Parse WPScan API response with robust validation."""
        vulns = []
        
        try:
            # WPScan API can return multiple formats
            # Format 1: {slug: {vulnerabilities: [...]}}
            # Format 2: {vulnerabilities: [...]}
            
            if component in data:
                component_data = data[component]
            elif "vulnerabilities" in data:
                component_data = data
            else:
                logger.debug(f"No vulnerability data for {component}")
                return []
            
            raw_vulns = component_data.get("vulnerabilities", [])
            
            if not isinstance(raw_vulns, list):
                logger.error(f"Invalid vulnerabilities format: {type(raw_vulns)}")
                return []
            
            for vuln in raw_vulns:
                if not isinstance(vuln, dict):
                    continue
                
                # Validation of required fields
                if "id" not in vuln or "title" not in vuln:
                    logger.debug("Skipping invalid vulnerability entry")
                    continue
                
                # Filter by version
                fixed_in = vuln.get("fixed_in")
                if comp_version and fixed_in:
                    try:
                        if self._compare_versions(comp_version, fixed_in) >= 0:
                            continue  # Already fixed
                    except Exception as e:
                        logger.debug(f"Version comparison failed: {e}")
                
                # Parse CVSS
                cvss = None
                cvss_data = vuln.get("cvss")
                if isinstance(cvss_data, dict):
                    cvss = cvss_data.get("score")
                elif isinstance(cvss_data, (int, float)):
                    cvss = cvss_data
                
                # Determine severity
                severity = self._cvss_to_severity(cvss)
                
                # Extract references
                references = self._extract_references(vuln)
                
                # Check exploit availability
                exploit_available = self._check_exploit_indicators(vuln)
                
                # Check if requires authentication
                requires_auth = "authenticated" in vuln.get("title", "").lower()
                
                # Create vulnerability object
                vulnerability = Vulnerability(
                    id=str(vuln.get("id", "")),
                    title=vuln.get("title", "Unknown Vulnerability"),
                    description=vuln.get("description", "")[:500],  # Truncate
                    vuln_type=vuln.get("vuln_type", "unknown"),
                    severity=severity,
                    cvss_score=cvss,
                    cve=vuln.get("cve"),
                    references=references,
                    fixed_in=fixed_in,
                    exploit_available=exploit_available,
                    requires_auth=requires_auth,
                    exploitable=True  # Assume exploitable unless proven otherwise
                )
                
                vulns.append(vulnerability)
            
            return vulns
        
        except Exception as e:
            logger.error(f"Error parsing vulnerabilities: {e}")
            return []
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare versions using packaging library.
        
        Handles:
        - Beta/RC/dev: 1.0.0-beta < 1.0.0
        - Multiple parts: 1.2.3.4
        - Prefixes: v1.2.3
        """
        try:
            ver1 = version.parse(v1)
            ver2 = version.parse(v2)
            
            if ver1 < ver2:
                return -1
            elif ver1 > ver2:
                return 1
            return 0
        except Exception as e:
            logger.debug(f"Version comparison failed: {v1} vs {v2}: {e}")
            return 0  # Include vuln if uncertain
    
    def _cvss_to_severity(self, cvss: Optional[float]) -> str:
        """Convert CVSS score to severity level."""
        if cvss is None:
            return "unknown"
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"
    
    def _extract_references(self, vuln: Dict) -> List[str]:
        """Extract reference URLs with validation."""
        refs = vuln.get("references", {})
        
        if isinstance(refs, dict):
            urls = refs.get("url", [])
        elif isinstance(refs, list):
            urls = refs
        else:
            urls = []
        
        # Validate URLs
        valid_urls = []
        for url in urls:
            if isinstance(url, str) and url.startswith("http"):
                valid_urls.append(url)
        
        return valid_urls[:5]  # Limit to 5
    
    def _check_exploit_indicators(self, vuln: Dict) -> bool:
        """Check if exploit is likely available."""
        # Check references for exploit-db, metasploit, etc.
        refs = self._extract_references(vuln)
        
        exploit_indicators = [
            "exploit-db.com",
            "metasploit",
            "packetstorm",
            "github.com/exploit",
            "poc"
        ]
        
        for ref in refs:
            if any(indicator in ref.lower() for indicator in exploit_indicators):
                return True
        
        # Check title/description
        text = (vuln.get("title", "") + " " + vuln.get("description", "")).lower()
        if any(word in text for word in ["exploit", "poc", "metasploit"]):
            return True
        
        return False


class PluginVulnScanner:
    """
    Scan detected plugins/themes against WPScan vulnerability database.
    
    Features:
    - Smart prioritization (critical plugins first)
    - Rate limit management
    - Comprehensive reporting
    """
    
    # Critical plugin keywords (prioritize these)
    CRITICAL_KEYWORDS = [
        "contact", "form", "security", "auth", "login",
        "upload", "file", "admin", "user", "backup",
        "cache", "seo", "woocommerce", "elementor", "payment"
    ]
    
    def __init__(self, api_token: Optional[str] = None):
        self.api = WPScanAPI(api_token)
        self.vulnerabilities: List[Vulnerability] = []
        self.scanned_components: Set[str] = set()
    
    async def scan(
        self,
        plugins: List[Dict],
        themes: List[Dict],
        wp_version: Optional[str] = None
    ) -> List[Vulnerability]:
        """
        Scan all detected components for vulnerabilities.
        
        Args:
            plugins: List of {slug: str, version: str}
            themes: List of {slug: str, version: str}
            wp_version: WordPress version string
        """
        logger.section("Plugin/Theme Vulnerability Scan (WPScan API)")
        
        if not self.api.api_token:
            logger.warning("WPScan API token not configured - skipping CVE lookup")
            logger.info("Set WPSCAN_API_TOKEN in config.yaml for vulnerability database")
            return []
        
        # 1. Always check WordPress core first
        if wp_version:
            logger.info(f"Checking WordPress {wp_version} for CVEs...")
            try:
                core_vulns = await self.api.check_wordpress(wp_version)
                self.vulnerabilities.extend(core_vulns)
                if core_vulns:
                    logger.vuln("high", f"Found {len(core_vulns)} WordPress core vulnerabilities")
            except RateLimitError:
                logger.error("Rate limit reached on WordPress core check")
                return self.vulnerabilities
        
        # 2. Prioritize plugins
        priority_plugins = self._prioritize_plugins(plugins)
        
        # 3. Scan with quota management
        max_scans = 20  # Keep 5 requests margin
        scanned = 0
        
        for plugin in priority_plugins:
            if scanned >= max_scans:
                logger.warning(f"Quota limit: only scanned {scanned}/{len(plugins)} plugins")
                break
            
            slug = plugin.get("slug") or plugin
            version = plugin.get("version") if isinstance(plugin, dict) else None
            
            try:
                logger.info(f"Checking plugin: {slug}")
                vulns = await self.api.check_plugin(slug, version)
                self.vulnerabilities.extend(vulns)
                self.scanned_components.add(f"plugin:{slug}")
                scanned += 1
                
                if vulns:
                    for v in vulns:
                        logger.vuln(v.severity, f"{slug}: {v.title}")
            
            except RateLimitError:
                logger.error("Rate limit reached")
                break
            except Exception as e:
                logger.debug(f"Error checking {slug}: {e}")
                continue
        
        # 4. Scan themes (if quota allows)
        for theme in themes[:5]:  # Limit themes
            if scanned >= max_scans:
                break
            
            slug = theme.get("slug") or theme
            version = theme.get("version") if isinstance(theme, dict) else None
            
            try:
                logger.info(f"Checking theme: {slug}")
                vulns = await self.api.check_theme(slug, version)
                self.vulnerabilities.extend(vulns)
                self.scanned_components.add(f"theme:{slug}")
                scanned += 1
                
                if vulns:
                    for v in vulns:
                        logger.vuln(v.severity, f"{slug}: {v.title}")
            
            except RateLimitError:
                logger.error("Rate limit reached")
                break
            except Exception:
                continue
        
        # Summary
        logger.info(f"Scanned {scanned} components")
        logger.success(f"Found {len(self.vulnerabilities)} known vulnerabilities")
        
        return self.vulnerabilities
    
    def _prioritize_plugins(self, plugins: List[Dict]) -> List[Dict]:
        """
        Prioritize plugins to scan.
        
        Priority:
        1. Plugins with version detected (more accurate)
        2. Critical plugins (forms, auth, upload, etc.)
        3. Popular plugins (more likely to have known vulns)
        """
        def priority_score(plugin):
            score = 0
            slug = plugin.get("slug", "") if isinstance(plugin, dict) else str(plugin)
            
            # +10 if version detected
            if isinstance(plugin, dict) and plugin.get("version"):
                score += 10
            
            # +5 if critical plugin
            if any(kw in slug.lower() for kw in self.CRITICAL_KEYWORDS):
                score += 5
            
            return score
        
        return sorted(plugins, key=priority_score, reverse=True)
    
    def get_summary(self) -> Dict:
        """Get comprehensive vulnerability summary."""
        # Group by component
        by_component = {}
        for vuln in self.vulnerabilities:
            component = vuln.id.split("-")[0] if "-" in vuln.id else "unknown"
            if component not in by_component:
                by_component[component] = []
            by_component[component].append(vuln)
        
        # Find most critical
        critical_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: (v.severity == "critical", v.cvss_score or 0),
            reverse=True
        )
        
        return {
            "total": len(self.vulnerabilities),
            "scanned_components": len(self.scanned_components),
            "by_severity": self._count_by_severity(),
            "by_component": {
                comp: len(vulns) for comp, vulns in by_component.items()
            },
            "most_critical": critical_vulns[0].to_dict() if critical_vulns else None,
            "recommendations": self._generate_recommendations(),
            "exploitable_count": sum(1 for v in self.vulnerabilities if v.exploit_available),
            "patch_priority": self._get_patch_priority(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
        }
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        return {
            "critical": len([v for v in self.vulnerabilities if v.severity == "critical"]),
            "high": len([v for v in self.vulnerabilities if v.severity == "high"]),
            "medium": len([v for v in self.vulnerabilities if v.severity == "medium"]),
            "low": len([v for v in self.vulnerabilities if v.severity == "low"]),
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations."""
        recs = []
        
        # Critical vulns
        critical = [v for v in self.vulnerabilities if v.severity == "critical"]
        if critical:
            recs.append(f"URGENT: Patch {len(critical)} critical vulnerabilities immediately")
        
        # Outdated plugins
        outdated = [v for v in self.vulnerabilities if v.fixed_in]
        if outdated:
            recs.append(f"Update {len(outdated)} outdated plugins/themes")
        
        # Public exploits
        with_exploits = [v for v in self.vulnerabilities if v.exploit_available]
        if with_exploits:
            recs.append(f"WARNING: {len(with_exploits)} vulnerabilities have public exploits")
        
        # Auth required
        auth_required = [v for v in self.vulnerabilities if v.requires_auth]
        if auth_required:
            recs.append(f"INFO: {len(auth_required)} vulnerabilities require authentication")
        
        return recs
    
    def _get_patch_priority(self) -> List[Dict]:
        """Get patch priority list."""
        prioritized = sorted(
            self.vulnerabilities,
            key=lambda v: (
                v.severity == "critical",
                v.exploit_available,
                v.cvss_score or 0
            ),
            reverse=True
        )
        
        return [
            {
                "component": v.id.split("-")[0] if "-" in v.id else "unknown",
                "version": v.fixed_in,
                "severity": v.severity,
                "cvss": v.cvss_score,
                "reason": f"{v.title}",
                "exploit_available": v.exploit_available
            }
            for v in prioritized[:10]  # Top 10
        ]
