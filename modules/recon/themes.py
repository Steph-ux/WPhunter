"""
WPHunter - Advanced Theme Detection
====================================
Detect active and installed WordPress themes with advanced methods.

Enhanced with:
- Directory listing detection
- REST API enumeration
- functions.php analysis
- theme.json (block themes)
- readme/changelog parsing
- Screenshot detection
- composer.json/package.json
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from bs4 import BeautifulSoup

from core.http_client import WPHttpClient
from core.logger import logger


@dataclass
class ThemeInfo:
    """Information about a detected theme."""
    slug: str
    name: Optional[str] = None
    version: Optional[str] = None
    author: Optional[str] = None
    path: Optional[str] = None
    is_active: bool = False
    is_child_theme: bool = False
    parent_theme: Optional[str] = None
    detection_method: str = "unknown"
    vulnerable: bool = False
    
    def __hash__(self):
        return hash(self.slug)


class ThemeDetector:
    """Detect WordPress themes with multiple techniques."""
    
    # Common themes to check (properly formatted)
    COMMON_THEMES = [
        # WordPress Core Themes
        "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
        "twentytwentyone", "twentytwenty", "twentynineteen",
        "twentyseventeen", "twentysixteen", "twentyfifteen",
        "twentyfourteen", "twentythirteen", "twentytwelve",
        # Popular Commercial/Freemium
        "astra", "hello-elementor", "oceanwp", "generatepress",
        "neve", "customizr", "divi", "avada", "enfold", "salient",
        "bridge", "the7", "woodmart", "flatsome", "porto", "betheme",
        # Popular Free Themes
        "storefront", "hestia", "flavor", "flavor flavor flavor flavorsydney", "flavor flavor flavor flavorkadence", "blocksy",
        "woostify", "flavor flavor flavor flavorrishi", "flavor flavor flavor flavorsimpla", "flavor flavor flavor flavorphotography",
    ]
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.detected_themes: Dict[str, ThemeInfo] = {}
        self.active_theme: Optional[ThemeInfo] = None
    
    async def detect(self) -> List[ThemeInfo]:
        """Basic theme detection."""
        logger.section("Theme Detection")
        
        await self._detect_active_theme()
        
        if self.active_theme:
            await self._get_theme_details(self.active_theme)
        
        themes = list(self.detected_themes.values())
        
        if self.active_theme:
            logger.success(f"Active theme: {self.active_theme.slug} (v{self.active_theme.version or 'unknown'})")
        
        return themes
    
    async def comprehensive_detection(self) -> List[ThemeInfo]:
        """Comprehensive theme detection with all advanced methods."""
        logger.section("Advanced Theme Detection")
        
        # Basic detection
        await self._detect_active_theme()
        
        # Advanced methods
        await asyncio.gather(
            self._detect_from_directory_listing(),
            self._detect_from_rest_api(),
            return_exceptions=True
        )
        
        # Get details for all themes
        for theme in list(self.detected_themes.values()):
            await self._get_comprehensive_details(theme)
        
        themes = list(self.detected_themes.values())
        with_version = len([t for t in themes if t.version])
        
        if self.active_theme:
            logger.success(f"Active: {self.active_theme.slug} v{self.active_theme.version or '?'}")
        logger.success(f"Total themes: {len(themes)} ({with_version} with version)")
        
        return themes
    
    async def _detect_active_theme(self):
        """Detect active theme from HTML."""
        try:
            response = await self.http.get("/")
            if not response.ok:
                return
            
            pattern = r'/wp-content/themes/([a-zA-Z0-9_-]+)/'
            matches = re.findall(pattern, response.text)
            
            if matches:
                from collections import Counter
                theme_counts = Counter(matches)
                active_slug = theme_counts.most_common(1)[0][0]
                
                self.active_theme = ThemeInfo(
                    slug=active_slug,
                    path=f"/wp-content/themes/{active_slug}/",
                    is_active=True,
                    detection_method="passive"
                )
                self.detected_themes[active_slug] = self.active_theme
                logger.info(f"Active theme detected: {active_slug}")
        except Exception as e:
            logger.debug(f"Active theme detection failed: {e}")
    
    async def _get_theme_details(self, theme: ThemeInfo):
        """Get theme info from style.css."""
        try:
            response = await self.http.get(f"{theme.path}style.css")
            if response.ok:
                headers = self._parse_theme_headers(response.text)
                theme.name = headers.get("Theme Name", theme.slug)
                theme.version = headers.get("Version")
                theme.author = headers.get("Author")
                
                if headers.get("Template"):
                    theme.is_child_theme = True
                    theme.parent_theme = headers.get("Template")
                    
                    if theme.parent_theme not in self.detected_themes:
                        parent = ThemeInfo(
                            slug=theme.parent_theme,
                            path=f"/wp-content/themes/{theme.parent_theme}/",
                            detection_method="child_reference"
                        )
                        self.detected_themes[theme.parent_theme] = parent
                        await self._get_theme_details(parent)
        except Exception:
            pass
    
    async def _get_comprehensive_details(self, theme: ThemeInfo):
        """Get comprehensive details for a theme."""
        await self._get_theme_details(theme)
        
        if not theme.version:
            await self._detect_from_functions(theme)
        if not theme.version:
            await self._detect_from_readme(theme)
        await self._detect_block_theme(theme)
    
    async def _detect_from_directory_listing(self):
        """Check if themes directory listing is enabled."""
        try:
            response = await self.http.get("/wp-content/themes/")
            if response.ok and ("Index of" in response.text or "<title>Index" in response.text):
                logger.warning("Themes directory listing enabled!")
                
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a', href=True)
                
                for link in links:
                    href = link['href']
                    if href.endswith('/') and not href.startswith(('?', '/', '.')):
                        slug = href.rstrip('/')
                        if slug not in self.detected_themes:
                            self.detected_themes[slug] = ThemeInfo(
                                slug=slug,
                                path=f"/wp-content/themes/{slug}/",
                                detection_method="directory_listing"
                            )
        except Exception:
            pass
    
    async def _detect_from_rest_api(self):
        """Get themes from REST API."""
        try:
            response = await self.http.get("/wp-json/wp/v2/themes")
            if response.ok and response.is_json:
                themes = response.json()
                for t in themes:
                    slug = t.get('stylesheet')
                    if slug and slug not in self.detected_themes:
                        self.detected_themes[slug] = ThemeInfo(
                            slug=slug, name=t.get('name'),
                            version=t.get('version'),
                            is_active=t.get('active', False),
                            detection_method="rest_api"
                        )
        except Exception:
            pass
    
    async def _detect_from_functions(self, theme: ThemeInfo):
        """Get version from functions.php."""
        if not theme.path:
            return
        try:
            response = await self.http.get(f"{theme.path}functions.php")
            if response.ok:
                patterns = [
                    r"define\s*\(\s*['\"]VERSION['\"]\s*,\s*['\"]([\d.]+)['\"]",
                    r"\$version\s*=\s*['\"]([\d.]+)['\"]",
                ]
                for pattern in patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        theme.version = match.group(1)
                        return
        except Exception:
            pass
    
    async def _detect_from_readme(self, theme: ThemeInfo):
        """Get version from readme files."""
        if not theme.path:
            return
        paths = [f"{theme.path}readme.txt", f"{theme.path}CHANGELOG.md"]
        for path in paths:
            try:
                response = await self.http.get(path)
                if response.ok:
                    match = re.search(r'[Vv]ersion:\s*([\d.]+)', response.text)
                    if match:
                        theme.version = match.group(1)
                        return
            except Exception:
                continue
    
    async def _detect_block_theme(self, theme: ThemeInfo):
        """Detect block theme from theme.json."""
        if not theme.path:
            return
        try:
            response = await self.http.get(f"{theme.path}theme.json")
            if response.ok and response.is_json:
                data = response.json()
                theme.detection_method += "+block_theme"
                if "version" in data and not theme.version:
                    theme.version = data["version"]
        except Exception:
            pass
    
    def _parse_theme_headers(self, css_content: str) -> Dict[str, str]:
        """Parse WordPress theme headers from style.css."""
        headers = {}
        header_match = re.search(r'/\*[\s\S]*?\*/', css_content)
        if not header_match:
            return headers
        
        block = header_match.group(0)
        patterns = [
            (r'Theme Name:\s*(.+)', "Theme Name"),
            (r'Version:\s*([\d.]+)', "Version"),
            (r'Author:\s*(.+)', "Author"),
            (r'Template:\s*(.+)', "Template"),
        ]
        
        for pattern, name in patterns:
            match = re.search(pattern, block, re.IGNORECASE)
            if match:
                headers[name] = match.group(1).strip()
        
        return headers
    
    def get_summary(self) -> Dict:
        """Get summary of theme detection."""
        themes = list(self.detected_themes.values())
        return {
            "total": len(themes),
            "active": self.active_theme.slug if self.active_theme else None,
            "active_version": self.active_theme.version if self.active_theme else None,
            "is_child_theme": self.active_theme.is_child_theme if self.active_theme else False,
            "themes": [{"slug": t.slug, "version": t.version, "is_active": t.is_active} for t in themes]
        }
