"""
WPHunter - Advanced WordPress Version Detection
================================================
Multiple methods to accurately detect WordPress version with confidence scoring.

Enhanced Detection Methods:
1. wp-includes/version.php (most reliable if exposed)
2. REST API /wp-json/ 
3. Meta generator tag
4. readme.html file
5. RSS/Atom feeds (OPML, generator)
6. Login page asset versions
7. Static file hash fingerprinting
8. HTTP headers analysis
"""

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup

from core.http_client import WPHttpClient
from core.logger import logger


@dataclass
class VersionInfo:
    """WordPress version detection result."""
    version: Optional[str] = None
    method: Optional[str] = None
    confidence: str = "unknown"  # low, medium, high
    raw_source: Optional[str] = None
    all_detections: List[Dict] = field(default_factory=list)
    
    @property
    def is_detected(self) -> bool:
        return self.version is not None


class VersionDetector:
    """
    Advanced WordPress version detection with weighted confidence scoring.
    
    - Prioritizes reliable sources (version.php, JSON API, static hashes)
    - Cross-validates across multiple sources
    - Implements rate limiting to avoid bans
    - Validates version format to prevent false positives
    """
    
    # Detection method weights (higher = more reliable)
    METHOD_WEIGHTS = {
        "version_php": 5,
        "json_api": 4,
        "static_hash": 4,
        "readme_html": 3,
        "rss_feed": 2,
        "opml": 2,
        "meta_generator": 2,
        "login_page": 2,
        "http_headers": 1,
    }
    
    # Static file hashes for fingerprinting (extensible)
    # Format: { file_path: { hash: version } }
    STATIC_HASHES = {
        "/wp-includes/js/wp-emoji-release.min.js": {
            # Real hashes would be added here from WPScan DB
        },
        "/wp-includes/css/dashicons.min.css": {},
    }
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.detected_versions: List[Dict] = []
        self.rate_limit_delay = 0.3  # seconds between requests
    
    async def detect(self) -> VersionInfo:
        """Run all version detection methods with weighted scoring."""
        logger.section("WordPress Version Detection")
        
        # Methods ordered by reliability (most reliable first)
        methods = [
            ("version_php", self._detect_from_version_php),
            ("json_api", self._detect_from_json_api),
            ("meta_generator", self._detect_from_meta),
            ("readme_html", self._detect_from_readme),
            ("rss_feed", self._detect_from_feed),
            ("opml", self._detect_from_opml),
            ("login_page", self._detect_from_login),
            ("http_headers", self._detect_from_headers),
        ]
        
        for method_name, method_func in methods:
            try:
                version = await method_func()
                if version and self._validate_version(version):
                    weight = self.METHOD_WEIGHTS.get(method_name, 1)
                    self.detected_versions.append({
                        "version": version,
                        "method": method_name,
                        "weight": weight,
                    })
                    logger.info(f"[{method_name}] Version: {version} (weight: {weight})")
            except Exception as e:
                logger.debug(f"[{method_name}] Detection failed: {e}")
            
            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)
        
        return self._analyze_weighted_results()
    
    def _validate_version(self, version: str) -> bool:
        """Validate WordPress version format."""
        if not version:
            return False
        
        # Must match X.Y or X.Y.Z format
        if not re.match(r'^\d+\.\d+(\.\d+)?$', version):
            return False
        
        # WordPress versions range check (1.0 to ~10.x)
        try:
            major = int(version.split('.')[0])
            if major < 1 or major > 10:
                return False
        except ValueError:
            return False
        
        return True
    
    async def _detect_from_version_php(self) -> Optional[str]:
        """
        Detect from wp-includes/version.php (most reliable if exposed).
        
        Contains: $wp_version = '6.4.2';
        """
        try:
            response = await self.http.get("/wp-includes/version.php")
            if response.ok:
                match = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)", response.text)
                if match:
                    logger.warning("version.php exposed - HIGH confidence source")
                    return match.group(1)
        except Exception:
            pass
        return None
    
    async def _detect_from_json_api(self) -> Optional[str]:
        """
        Detect WordPress version from REST API.
        
        Uses multiple methods:
        1. oEmbed endpoint (most reliable)
        2. Generator field in responses
        3. Namespace analysis
        """
        try:
            # Method 1: oEmbed endpoint (most reliable)
            oembed_url = f"/wp-json/oembed/1.0/embed?url={self.http.base_url}"
            response = await self.http.get(oembed_url)
            
            if response.ok and response.is_json:
                data = response.json()
                if "version" in data:
                    return str(data["version"])
            
            # Method 2: Root endpoint with generator
            response = await self.http.get("/wp-json/")
            
            if response.ok and response.is_json:
                data = response.json()
                
                # Check for generator in routes
                routes = data.get("routes", {})
                for route_info in routes.values():
                    if isinstance(route_info, dict):
                        # Some routes expose version info
                        if "version" in route_info:
                            return str(route_info["version"])
                
                # Method 3: Infer from namespaces (less precise)
                namespaces = data.get("namespaces", [])
                if "wp/v2" in namespaces:
                    # wp/v2 introduced in WP 4.7
                    # Can't get exact version, but know it's 4.7+
                    pass
        
        except Exception as e:
            logger.debug(f"JSON API detection failed: {e}")
        
        return None
    
    async def _detect_from_meta(self) -> Optional[str]:
        """Detect from <meta name="generator"> tag."""
        try:
            response = await self.http.get("/")
            if response.ok:
                # Use BeautifulSoup for safe parsing
                soup = BeautifulSoup(response.text, 'lxml')
                meta = soup.find('meta', attrs={'name': 'generator'})
                if meta and meta.get('content'):
                    content = meta.get('content', '')
                    match = re.search(r'WordPress\s+([\d.]+)', content, re.IGNORECASE)
                    if match:
                        return match.group(1)
        except Exception:
            pass
        return None
    
    async def _detect_from_readme(self) -> Optional[str]:
        """Detect from /readme.html file."""
        try:
            response = await self.http.get("/readme.html")
            if response.ok:
                patterns = [
                    r'Version\s+([\d.]+)',
                    r'WordPress\s+([\d.]+)',
                ]
                for pattern in patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        return match.group(1)
        except Exception:
            pass
        return None
    
    async def _detect_from_feed(self) -> Optional[str]:
        """Detect from RSS/Atom feeds using safe parsing."""
        feed_paths = ['/feed/', '/feed/rss/', '/feed/atom/', '/?feed=rss2']
        
        for path in feed_paths:
            try:
                response = await self.http.get(path)
                if response.ok:
                    # Safe XML parsing with BeautifulSoup
                    soup = BeautifulSoup(response.text, 'xml')
                    generator = soup.find('generator')
                    if generator:
                        text = generator.get_text() or str(generator)
                        match = re.search(r'([\d]+\.[\d]+\.?[\d]*)', text)
                        if match:
                            return match.group(1)
            except Exception:
                continue
        return None
    
    async def _detect_from_opml(self) -> Optional[str]:
        """Detect from wp-links-opml.php."""
        try:
            response = await self.http.get("/wp-links-opml.php")
            if response.ok:
                match = re.search(r'generator="WordPress/([\d.]+)"', response.text)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return None
    
    async def _detect_from_login(self) -> Optional[str]:
        """Detect from wp-login.php CSS/JS version parameters."""
        try:
            response = await self.http.get("/wp-login.php")
            if response.ok:
                patterns = [
                    r'wp-admin/css/.*?\?ver=([\d.]+)',
                    r'wp-includes/.*?\?ver=([\d.]+)',
                ]
                all_versions = []
                for pattern in patterns:
                    matches = re.findall(pattern, response.text)
                    all_versions.extend(matches)
                
                if all_versions:
                    from collections import Counter
                    version_counts = Counter(all_versions)
                    return version_counts.most_common(1)[0][0]
        except Exception:
            pass
        return None
    
    async def _detect_from_headers(self) -> Optional[str]:
        """Detect from HTTP headers (Link, X-Powered-By, etc.)."""
        try:
            response = await self.http.get("/")
            headers = response.headers
            
            # Check Link header for REST API version
            if 'Link' in headers:
                match = re.search(r'wp-json.*?wp/v(\d+)', headers['Link'])
                if match:
                    # Only gives API version, not WP version
                    pass
            
            # Check X-Powered-By
            powered_by = headers.get('X-Powered-By', '')
            match = re.search(r'WordPress/([\d.]+)', powered_by)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None
    
    async def _detect_from_static_hash(self) -> Optional[str]:
        """Detect via static file hash fingerprinting."""
        for file_path, hash_map in self.STATIC_HASHES.items():
            if not hash_map:
                continue
            
            try:
                response = await self.http.get(file_path)
                if response.ok:
                    # Calculate MD5 hash
                    content_hash = hashlib.md5(response.text.encode()).hexdigest()
                    if content_hash in hash_map:
                        return hash_map[content_hash]
            except Exception:
                continue
        return None
    
    def _analyze_weighted_results(self) -> VersionInfo:
        """Analyze results with weighted confidence scoring."""
        if not self.detected_versions:
            logger.warning("Could not detect WordPress version")
            return VersionInfo()
        
        # Calculate weighted scores for each version
        version_scores: Dict[str, float] = {}
        version_methods: Dict[str, List[str]] = {}
        
        for detection in self.detected_versions:
            version = detection["version"]
            weight = detection["weight"]
            method = detection["method"]
            
            if version not in version_scores:
                version_scores[version] = 0
                version_methods[version] = []
            
            version_scores[version] += weight
            version_methods[version].append(method)
        
        # Get best version by weighted score
        best_version = max(version_scores.keys(), key=lambda v: version_scores[v])
        best_score = version_scores[best_version]
        best_methods = version_methods[best_version]
        
        # Determine confidence based on score and method count
        if best_score >= 8 or len(best_methods) >= 3:
            confidence = "high"
        elif best_score >= 4 or len(best_methods) >= 2:
            confidence = "medium"
        else:
            confidence = "low"
        
        result = VersionInfo(
            version=best_version,
            method=best_methods[0],  # Primary method
            confidence=confidence,
            raw_source=f"Score: {best_score}, Methods: {', '.join(best_methods)}",
            all_detections=self.detected_versions
        )
        
        logger.success(f"WordPress {best_version} (confidence: {confidence})")
        return result
    
    def get_summary(self) -> Dict:
        """Get detection summary."""
        return {
            "detected_count": len(self.detected_versions),
            "versions_found": list(set(d["version"] for d in self.detected_versions)),
            "methods_used": list(set(d["method"] for d in self.detected_versions)),
            "detections": self.detected_versions,
        }
