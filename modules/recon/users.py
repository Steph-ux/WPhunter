"""
WPHunter - Advanced User Enumeration
=====================================
Comprehensive user enumeration with security analysis.

Enhanced Methods:
1. REST API (/wp-json/wp/v2/users)
2. Author archives (?author=N)
3. Login error messages
4. WordPress sitemap
5. RSS/Atom feeds
6. Comments API
7. Posts API with embedded data
8. oEmbed endpoint

Security Features:
- User role detection
- Bruteforce protection testing
- Email extraction
- Security issue analysis
- Username wordlist generation
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.http_client import WPHttpClient
from core.logger import logger
from core.security import get_rate_limiter


@dataclass
class UserInfo:
    """Information about a detected user."""
    id: int
    username: Optional[str] = None
    display_name: Optional[str] = None
    slug: Optional[str] = None
    email: Optional[str] = None
    avatar_url: Optional[str] = None
    detection_method: str = "unknown"
    roles: List[str] = field(default_factory=list)
    is_admin: bool = False
    possible_emails: List[str] = field(default_factory=list)
    
    def __hash__(self):
        return hash(self.id)


class UserEnumerator:
    """
    Comprehensive WordPress user enumeration.
    
    Uses multiple techniques to discover users and analyze
    security implications for bug bounty/pentesting.
    """
    
    # Common usernames to test via login error
    COMMON_USERNAMES = [
        "admin", "administrator", "root", "test", "demo",
        "user", "guest", "editor", "author", "blogger",
        "webmaster", "postmaster", "info", "support", "contact",
        "wordpress", "wp", "site", "web", "manager",
    ]
    
    def __init__(self, http_client: WPHttpClient, max_users: int = 50):
        self.http = http_client
        self.max_users = max_users
        self.detected_users: Dict[int, UserInfo] = {}
        self.rate_limiter = get_rate_limiter()
        self.login_protection = {}
    
    async def enumerate(self, comprehensive: bool = False) -> List[UserInfo]:
        """
        Run user enumeration.
        
        Args:
            comprehensive: If True, use all methods including intrusive ones
        """
        logger.section("User Enumeration")
        
        # === PASSIVE METHODS ===
        await asyncio.gather(
            self._enumerate_via_rest_api(),
            self._enumerate_via_wp_sitemap(),
            self._enumerate_via_rss_feed(),
            return_exceptions=True
        )
        
        # === SEMI-PASSIVE METHODS ===
        if len(self.detected_users) < self.max_users:
            await asyncio.gather(
                self._enumerate_via_author_archives(),
                self._enumerate_via_oembed(),
                self._enumerate_via_comments(),
                self._enumerate_via_posts_api(),
                return_exceptions=True
            )
        
        # === ACTIVE METHODS ===
        if comprehensive:
            await self._enumerate_via_login_error()
            await self._extract_user_emails()
            await self._detect_user_roles()
            
            # Test bruteforce protection
            if self.detected_users:
                first_user = list(self.detected_users.values())[0]
                self.login_protection = await self.test_login_protection(
                    first_user.username or "admin"
                )
        
        # === SECURITY ANALYSIS ===
        issues = self.analyze_security_issues()
        for severity, issue_list in issues.items():
            for issue in issue_list:
                logger.vuln(severity, issue)
        
        users = list(self.detected_users.values())
        logger.success(f"Total users: {len(users)}")
        
        for user in users[:5]:
            roles_str = f" [{', '.join(user.roles)}]" if user.roles else ""
            logger.info(f"  - ID {user.id}: {user.username or user.slug or 'unknown'}{roles_str}")
        
        return users
    
    # =========================================================================
    # ENUMERATION METHODS
    # =========================================================================
    
    async def _enumerate_via_rest_api(self):
        """Enumerate users via REST API."""
        try:
            response = await self.http.get("/wp-json/wp/v2/users?per_page=100")
            
            if response.ok and response.is_json:
                users = response.json()
                
                if isinstance(users, list):
                    for user_data in users:
                        user_id = user_data.get("id")
                        if user_id:
                            self.detected_users[user_id] = UserInfo(
                                id=user_id,
                                username=user_data.get("slug"),
                                display_name=user_data.get("name"),
                                slug=user_data.get("slug"),
                                avatar_url=user_data.get("avatar_urls", {}).get("96"),
                                detection_method="rest_api"
                            )
                    logger.info(f"REST API exposed {len(users)} users")
        except Exception as e:
            logger.debug(f"REST API enumeration failed: {e}")
    
    async def _enumerate_via_wp_sitemap(self):
        """Enumerate users from WordPress core sitemap (WP 5.5+)."""
        sitemap_urls = ["/wp-sitemap-users-1.xml", "/wp-sitemap.xml"]
        
        for sitemap_url in sitemap_urls:
            try:
                response = await self.http.get(sitemap_url)
                
                if response.ok and "<?xml" in response.text:
                    author_urls = re.findall(
                        r'<loc>([^<]*?/author/[^<]+)</loc>',
                        response.text
                    )
                    
                    for url in author_urls:
                        match = re.search(r'/author/([^/]+)/?', url)
                        if match:
                            username = match.group(1)
                            if not self._user_exists(username=username):
                                new_id = self._next_id()
                                self.detected_users[new_id] = UserInfo(
                                    id=new_id,
                                    username=username,
                                    slug=username,
                                    detection_method="sitemap"
                                )
                                logger.info(f"User in sitemap: {username}")
                    
                    if author_urls:
                        return
            except Exception:
                continue
    
    async def _enumerate_via_rss_feed(self):
        """Enumerate users from RSS/Atom feeds."""
        feed_urls = ["/feed/", "/feed/rss/", "/feed/atom/", "/?feed=rss2"]
        
        for feed_url in feed_urls:
            try:
                response = await self.http.get(feed_url)
                
                if response.ok and ("<?xml" in response.text or "<rss" in response.text):
                    patterns = [
                        r'<dc:creator>(?:<!\[CDATA\[)?([^<\]]+)',
                        r'<author>(?:<!\[CDATA\[)?([^<\]]+)',
                        r'<name>([^<]+)</name>',
                    ]
                    
                    authors = set()
                    for pattern in patterns:
                        matches = re.findall(pattern, response.text)
                        authors.update(matches)
                    
                    for author_name in authors:
                        if not self._user_exists(display_name=author_name):
                            new_id = self._next_id()
                            self.detected_users[new_id] = UserInfo(
                                id=new_id,
                                display_name=author_name,
                                detection_method="rss_feed"
                            )
                            logger.info(f"User in RSS: {author_name}")
                    return
            except Exception:
                continue
    
    async def _enumerate_via_author_archives(self):
        """Enumerate users via author archive pages."""
        logger.info("Enumerating via author archives...")
        
        async def check_author(author_id: int) -> Optional[UserInfo]:
            try:
                await self.rate_limiter.acquire()
                response = await self.http.get(f"/?author={author_id}", allow_redirects=True)
                
                if response.ok:
                    match = re.search(r'/author/([^/]+)/', response.url)
                    if match:
                        return UserInfo(
                            id=author_id,
                            username=match.group(1),
                            slug=match.group(1),
                            detection_method="author_archive"
                        )
            except Exception:
                pass
            return None
        
        ids_to_check = [i for i in range(1, min(self.max_users + 1, 21))
                       if i not in self.detected_users]
        
        semaphore = asyncio.Semaphore(3)
        
        async def check_with_sem(author_id):
            async with semaphore:
                return await check_author(author_id)
        
        tasks = [check_with_sem(i) for i in ids_to_check]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                self.detected_users[result.id] = result
    
    async def _enumerate_via_comments(self):
        """Enumerate users from WordPress comments."""
        try:
            response = await self.http.get("/wp-json/wp/v2/comments?per_page=100")
            
            if response.ok and response.is_json:
                comments = response.json()
                
                for comment in comments:
                    author_id = comment.get("author", 0)
                    if author_id > 0 and author_id not in self.detected_users:
                        self.detected_users[author_id] = UserInfo(
                            id=author_id,
                            display_name=comment.get("author_name"),
                            detection_method="comments"
                        )
                        logger.info(f"User in comments: {comment.get('author_name')}")
        except Exception as e:
            logger.debug(f"Comment enumeration failed: {e}")
    
    async def _enumerate_via_posts_api(self):
        """Enumerate users from posts API with embedded author."""
        try:
            response = await self.http.get("/wp-json/wp/v2/posts?per_page=50&_embed")
            
            if response.ok and response.is_json:
                posts = response.json()
                
                for post in posts:
                    if "_embedded" in post and "author" in post["_embedded"]:
                        for author in post["_embedded"]["author"]:
                            author_id = author.get("id")
                            if author_id and author_id not in self.detected_users:
                                self.detected_users[author_id] = UserInfo(
                                    id=author_id,
                                    username=author.get("slug"),
                                    display_name=author.get("name"),
                                    slug=author.get("slug"),
                                    detection_method="posts_api_embed"
                                )
        except Exception as e:
            logger.debug(f"Posts API enumeration failed: {e}")
    
    async def _enumerate_via_oembed(self):
        """Enumerate users via oEmbed endpoint."""
        try:
            response = await self.http.get("/")
            post_links = re.findall(r'href=["\']([^"\']+/\d{4}/\d{2}/[^"\']+)["\']', response.text)[:5]
            
            for post_url in post_links:
                try:
                    oembed_response = await self.http.get(
                        f"/wp-json/oembed/1.0/embed?url={post_url}"
                    )
                    
                    if oembed_response.ok and oembed_response.is_json:
                        data = oembed_response.json()
                        author_name = data.get("author_name")
                        
                        if author_name and not self._user_exists(display_name=author_name):
                            new_id = self._next_id()
                            self.detected_users[new_id] = UserInfo(
                                id=new_id,
                                display_name=author_name,
                                detection_method="oembed"
                            )
                except Exception:
                    continue
        except Exception:
            pass
    
    async def _enumerate_via_login_error(self):
        """Enumerate users via login error messages."""
        logger.info("Testing username existence via login errors...")
        
        # Add domain-specific usernames
        test_usernames = list(self.COMMON_USERNAMES)
        try:
            domain = urlparse(self.http.base_url).netloc
            parts = domain.replace('www.', '').split('.')
            test_usernames.extend([p for p in parts if len(p) > 2 and p not in ['com', 'net', 'org']])
        except Exception:
            pass
        
        for username in test_usernames[:15]:  # Limit to avoid ban
            if self._user_exists(username=username):
                continue
            
            try:
                await self.rate_limiter.acquire()
                response = await self.http.post(
                    "/wp-login.php",
                    data={
                        "log": username,
                        "pwd": "invalid_password_12345",
                        "wp-submit": "Log In",
                        "testcookie": "1"
                    }
                )
                
                if response.ok:
                    # WordPress reveals if username exists
                    if "incorrect password" in response.text.lower():
                        logger.warning(f"Valid username found: {username}")
                        new_id = self._next_id()
                        self.detected_users[new_id] = UserInfo(
                            id=new_id,
                            username=username,
                            detection_method="login_error"
                        )
            except Exception:
                continue
    
    # =========================================================================
    # SECURITY ANALYSIS
    # =========================================================================
    
    async def _detect_user_roles(self):
        """Detect user roles from REST API."""
        for user_id, user in list(self.detected_users.items())[:10]:
            try:
                response = await self.http.get(f"/wp-json/wp/v2/users/{user_id}?context=edit")
                
                if response.ok and response.is_json:
                    data = response.json()
                    roles = data.get("roles", [])
                    user.roles = roles
                    
                    if "administrator" in roles:
                        user.is_admin = True
                        logger.warning(f"Admin found: {user.username or user.display_name}")
            except Exception:
                continue
    
    async def _extract_user_emails(self):
        """Extract user emails from various sources."""
        domain = urlparse(self.http.base_url).netloc
        
        for user_id, user in self.detected_users.items():
            if user.email:
                continue
            
            # Try REST API (usually not exposed)
            try:
                response = await self.http.get(f"/wp-json/wp/v2/users/{user_id}")
                if response.ok and response.is_json:
                    data = response.json()
                    if "email" in data:
                        user.email = data["email"]
                        logger.warning(f"Email exposed: {user.email}")
                        continue
            except Exception:
                pass
            
            # Generate possible emails
            if user.username:
                user.possible_emails = [
                    f"{user.username}@{domain}",
                    f"admin@{domain}",
                    f"contact@{domain}",
                ]
    
    async def test_login_protection(self, username: str = "admin") -> Dict:
        """Test if site has login bruteforce protection."""
        logger.info("Testing login protection...")
        
        results = {
            "rate_limiting": False,
            "captcha": False,
            "lockout": False,
            "attempts_before_block": 0,
            "protection_plugins": []
        }
        
        for i in range(5):
            try:
                await asyncio.sleep(1)  # Delay between attempts
                response = await self.http.post(
                    "/wp-login.php",
                    data={
                        "log": username,
                        "pwd": f"test_password_{i}",
                        "wp-submit": "Log In",
                    }
                )
                
                if response.status_code == 429:
                    results["rate_limiting"] = True
                    results["attempts_before_block"] = i + 1
                    logger.warning(f"Rate limiting after {i+1} attempts")
                    break
                
                if "captcha" in response.text.lower() or "recaptcha" in response.text.lower():
                    results["captcha"] = True
                    logger.warning("CAPTCHA protection detected")
                    break
                
                lockout_indicators = ["locked", "blocked", "too many", "try again later"]
                if any(ind in response.text.lower() for ind in lockout_indicators):
                    results["lockout"] = True
                    results["attempts_before_block"] = i + 1
                    logger.warning(f"Lockout after {i+1} attempts")
                    break
                
                # Check for protection plugins
                plugin_indicators = {
                    "wordfence": "wordfence",
                    "limit-login-attempts": "limit login",
                    "loginizer": "loginizer",
                }
                for plugin, indicator in plugin_indicators.items():
                    if indicator in response.text.lower() and plugin not in results["protection_plugins"]:
                        results["protection_plugins"].append(plugin)
                        
            except Exception:
                break
        
        if not any([results["rate_limiting"], results["captcha"], results["lockout"]]):
            logger.vuln("high", "No bruteforce protection! Site vulnerable to password attacks")
        
        return results
    
    def analyze_security_issues(self) -> Dict[str, List[str]]:
        """Analyze detected users for security issues."""
        issues = {"critical": [], "high": [], "medium": [], "low": []}
        
        # Default admin username
        if any(u.username == "admin" for u in self.detected_users.values()):
            issues["high"].append("Default 'admin' username - easy bruteforce target")
        
        # REST API exposure
        rest_users = [u for u in self.detected_users.values() if u.detection_method == "rest_api"]
        if rest_users:
            issues["high"].append(f"REST API exposes {len(rest_users)} user accounts")
        
        # Email exposure
        users_with_emails = [u for u in self.detected_users.values() if u.email]
        if users_with_emails:
            issues["critical"].append(f"{len(users_with_emails)} user emails exposed")
        
        # Admin accounts
        admin_users = [u for u in self.detected_users.values() if u.is_admin]
        if admin_users:
            issues["medium"].append(f"{len(admin_users)} administrator account(s) enumerated")
        
        # Sequential IDs
        if 1 in self.detected_users:
            issues["medium"].append("User IDs start at 1 - allows complete enumeration")
        
        return issues
    
    def generate_username_wordlist(self, output_file: str = "usernames.txt") -> List[str]:
        """Generate wordlist of usernames for password attacks."""
        usernames = []
        
        for user in self.detected_users.values():
            if user.username:
                usernames.append(user.username)
            if user.slug and user.slug != user.username:
                usernames.append(user.slug)
            if user.display_name:
                display_lower = user.display_name.lower()
                usernames.extend([
                    display_lower,
                    display_lower.replace(' ', ''),
                    display_lower.replace(' ', '.'),
                    display_lower.replace(' ', '_'),
                ])
                if ' ' in display_lower:
                    usernames.append(display_lower.split()[0])
        
        usernames = list(set(filter(None, usernames)))
        
        with open(output_file, 'w') as f:
            for username in sorted(usernames):
                f.write(f"{username}\n")
        
        logger.success(f"Generated wordlist: {len(usernames)} usernames -> {output_file}")
        return usernames
    
    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    def _user_exists(self, username: str = None, display_name: str = None) -> bool:
        """Check if user already detected."""
        for user in self.detected_users.values():
            if username and user.username == username:
                return True
            if display_name and user.display_name == display_name:
                return True
        return False
    
    def _next_id(self) -> int:
        """Get next available user ID."""
        return max(self.detected_users.keys(), default=0) + 100
    
    def get_summary(self) -> Dict:
        """Get summary of user enumeration results."""
        users = list(self.detected_users.values())
        
        detection_breakdown = {}
        for u in users:
            method = u.detection_method
            detection_breakdown[method] = detection_breakdown.get(method, 0) + 1
        
        return {
            "total": len(users),
            "admins": len([u for u in users if u.is_admin]),
            "with_email": len([u for u in users if u.email]),
            "detection_methods": detection_breakdown,
            "login_protection": self.login_protection,
            "users": [
                {
                    "id": u.id,
                    "username": u.username,
                    "display_name": u.display_name,
                    "roles": u.roles,
                    "is_admin": u.is_admin,
                    "method": u.detection_method,
                }
                for u in users
            ]
        }
