"""
WPHunter - IDOR (Insecure Direct Object Reference) Scanner
==========================================================
Comprehensive IDOR detection for WordPress resources.

Tests:
1. User ID enumeration & access control
2. Post/Page ID enumeration
3. Order ID enumeration (WooCommerce)
4. Booking ID enumeration
5. Media attachment enumeration
6. Sequential vs random ID detection
7. Unauthorized access validation

CWE-639: Authorization Bypass Through User-Controlled Key
CWE-284: Improper Access Control
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from core.http_client import WPHttpClient
from core.logger import logger
from core.security import get_rate_limiter


@dataclass
class IDORFinding:
    """IDOR vulnerability finding."""
    resource_type: str  # user, post, order, booking, media
    resource_id: int
    url: str
    evidence: str
    severity: str = "high"
    cwe: str = "CWE-639"
    accessible_data: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        return {
            "type": "IDOR",
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "url": self.url,
            "evidence": self.evidence[:300],
            "severity": self.severity,
            "cwe": self.cwe,
            "data_exposed": bool(self.accessible_data)
        }


class IDORScanner:
    """
    Professional IDOR scanner for WordPress.
    
    Tests unauthorized access to resources via ID enumeration.
    """
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.findings: List[IDORFinding] = []
        self.rate_limiter = get_rate_limiter()
        self.id_pattern_cache: Dict[str, str] = {}  # sequential vs random
    
    async def scan(self) -> List[IDORFinding]:
        """Run comprehensive IDOR scan."""
        logger.section("IDOR Vulnerability Scan")
        
        # 1. User enumeration
        await self._scan_user_idor()
        
        # 2. Post/Page enumeration
        await self._scan_post_idor()
        
        # 3. WooCommerce orders
        await self._scan_order_idor()
        
        # 4. Media attachments
        await self._scan_media_idor()
        
        # 5. Bookings (if plugin detected)
        await self._scan_booking_idor()
        
        logger.success(f"IDOR scan: {len(self.findings)} findings")
        return self.findings
    
    async def _scan_user_idor(self):
        """Test user ID enumeration and unauthorized access."""
        logger.info("Testing user IDOR...")
        
        # Test REST API user enumeration
        test_ids = [1, 2, 3, 5, 10, 100]
        
        for user_id in test_ids:
            await self.rate_limiter.acquire()
            
            try:
                # Test 1: REST API /wp-json/wp/v2/users/{id}
                response = await self.http.get(f"/wp-json/wp/v2/users/{user_id}")
                
                if response.ok and response.is_json:
                    data = response.json()
                    
                    # Check if sensitive data exposed
                    sensitive_fields = ["email", "roles", "capabilities", "meta"]
                    exposed = [field for field in sensitive_fields if field in data]
                    
                    if exposed:
                        self.findings.append(IDORFinding(
                            resource_type="user",
                            resource_id=user_id,
                            url=f"/wp-json/wp/v2/users/{user_id}",
                            evidence=f"User data exposed via REST API: {', '.join(exposed)}",
                            severity="high" if "email" in exposed else "medium",
                            accessible_data=data
                        ))
                        logger.vuln("high", f"User IDOR: ID {user_id} - {exposed}")
                
                # Test 2: Author archive
                response = await self.http.get(f"/?author={user_id}")
                
                if response.ok and "author" in response.text.lower():
                    # Extract username from response
                    username = self._extract_username(response.text)
                    if username:
                        logger.info(f"User {user_id} enumerated: {username}")
                        
            except Exception as e:
                logger.debug(f"User IDOR test failed for ID {user_id}: {e}")
                continue
    
    async def _scan_post_idor(self):
        """Test post/page ID enumeration."""
        logger.info("Testing post/page IDOR...")
        
        # Detect ID pattern (sequential vs random)
        id_pattern = await self._detect_id_pattern("post")
        
        if id_pattern == "sequential":
            test_ids = range(1, 21)  # Test first 20
        else:
            test_ids = [1, 10, 100, 1000, 10000]  # Sample random IDs
        
        for post_id in test_ids:
            await self.rate_limiter.acquire()
            
            try:
                # Test 1: REST API
                response = await self.http.get(f"/wp-json/wp/v2/posts/{post_id}")
                
                if response.ok and response.is_json:
                    data = response.json()
                    
                    # Check if draft/private post accessible
                    status = data.get("status", "")
                    if status in ["draft", "private", "pending"]:
                        self.findings.append(IDORFinding(
                            resource_type="post",
                            resource_id=post_id,
                            url=f"/wp-json/wp/v2/posts/{post_id}",
                            evidence=f"Unauthorized access to {status} post",
                            severity="high",
                            accessible_data=data
                        ))
                        logger.vuln("high", f"Post IDOR: {status} post {post_id} accessible")
                
                # Test 2: Direct URL
                response = await self.http.get(f"/?p={post_id}")
                
                if response.ok and response.status_code == 200:
                    # Check if password-protected or private
                    if "password" in response.text.lower() or "private" in response.text.lower():
                        logger.debug(f"Post {post_id} is protected")
                        
            except Exception as e:
                logger.debug(f"Post IDOR test failed for ID {post_id}: {e}")
                continue
    
    async def _scan_order_idor(self):
        """Test WooCommerce order ID enumeration."""
        logger.info("Testing WooCommerce order IDOR...")
        
        # Check if WooCommerce is active
        wc_check = await self.http.get("/wp-json/wc/v3/orders")
        if wc_check.status_code == 404:
            logger.debug("WooCommerce not detected, skipping order IDOR")
            return
        
        test_ids = [1, 2, 3, 5, 10, 100, 1000]
        
        for order_id in test_ids:
            await self.rate_limiter.acquire()
            
            try:
                # Test 1: REST API (requires auth, but test anyway)
                response = await self.http.get(f"/wp-json/wc/v3/orders/{order_id}")
                
                if response.ok and response.is_json:
                    data = response.json()
                    
                    # If we can access order without auth = critical IDOR
                    self.findings.append(IDORFinding(
                        resource_type="order",
                        resource_id=order_id,
                        url=f"/wp-json/wc/v3/orders/{order_id}",
                        evidence="Order accessible without authentication",
                        severity="critical",
                        accessible_data=data
                    ))
                    logger.vuln("critical", f"Order IDOR: Order {order_id} accessible without auth")
                
                # Test 2: View order page
                response = await self.http.get(f"/my-account/view-order/{order_id}/")
                
                if response.ok and "order" in response.text.lower():
                    # Check if we can see order details without login
                    if "total" in response.text.lower() or "billing" in response.text.lower():
                        self.findings.append(IDORFinding(
                            resource_type="order",
                            resource_id=order_id,
                            url=f"/my-account/view-order/{order_id}/",
                            evidence="Order details accessible without authentication",
                            severity="critical"
                        ))
                        logger.vuln("critical", f"Order IDOR: Order {order_id} viewable without auth")
                        
            except Exception as e:
                logger.debug(f"Order IDOR test failed for ID {order_id}: {e}")
                continue
    
    async def _scan_media_idor(self):
        """Test media attachment enumeration."""
        logger.info("Testing media IDOR...")
        
        test_ids = [1, 2, 3, 5, 10, 50]
        
        for media_id in test_ids:
            await self.rate_limiter.acquire()
            
            try:
                # Test REST API
                response = await self.http.get(f"/wp-json/wp/v2/media/{media_id}")
                
                if response.ok and response.is_json:
                    data = response.json()
                    
                    # Check if private media exposed
                    media_url = data.get("source_url", "")
                    title = data.get("title", {}).get("rendered", "")
                    
                    # Try to access the media file
                    if media_url:
                        media_response = await self.http.get(media_url)
                        
                        if media_response.ok:
                            logger.info(f"Media {media_id} accessible: {title}")
                            
                            # Check if it's in a private directory
                            if "private" in media_url.lower() or "protected" in media_url.lower():
                                self.findings.append(IDORFinding(
                                    resource_type="media",
                                    resource_id=media_id,
                                    url=media_url,
                                    evidence="Private media file accessible",
                                    severity="medium",
                                    accessible_data=data
                                ))
                                logger.vuln("medium", f"Media IDOR: Private file {media_id} accessible")
                                
            except Exception as e:
                logger.debug(f"Media IDOR test failed for ID {media_id}: {e}")
                continue
    
    async def _scan_booking_idor(self):
        """Test booking plugin IDOR (if detected)."""
        logger.info("Testing booking IDOR...")
        
        # Common booking plugins
        booking_endpoints = [
            "/wp-json/bookly/v1/bookings",  # Bookly
            "/wp-json/wc-bookings/v1/bookings",  # WooCommerce Bookings
        ]
        
        for endpoint in booking_endpoints:
            check = await self.http.get(endpoint)
            
            if check.status_code != 404:
                logger.info(f"Booking endpoint found: {endpoint}")
                
                # Test ID enumeration
                test_ids = [1, 2, 3, 5, 10]
                
                for booking_id in test_ids:
                    await self.rate_limiter.acquire()
                    
                    try:
                        response = await self.http.get(f"{endpoint}/{booking_id}")
                        
                        if response.ok and response.is_json:
                            data = response.json()
                            
                            self.findings.append(IDORFinding(
                                resource_type="booking",
                                resource_id=booking_id,
                                url=f"{endpoint}/{booking_id}",
                                evidence="Booking accessible without authentication",
                                severity="high",
                                accessible_data=data
                            ))
                            logger.vuln("high", f"Booking IDOR: Booking {booking_id} accessible")
                            
                    except Exception:
                        continue
    
    async def _detect_id_pattern(self, resource_type: str) -> str:
        """Detect if IDs are sequential or random."""
        if resource_type in self.id_pattern_cache:
            return self.id_pattern_cache[resource_type]
        
        try:
            # Get first few IDs
            ids = []
            
            if resource_type == "post":
                response = await self.http.get("/wp-json/wp/v2/posts?per_page=10")
                if response.ok and response.is_json:
                    data = response.json()
                    ids = [post.get("id") for post in data if "id" in post]
            
            if len(ids) >= 3:
                # Check if sequential (difference of 1-5)
                diffs = [ids[i+1] - ids[i] for i in range(len(ids)-1)]
                avg_diff = sum(diffs) / len(diffs)
                
                pattern = "sequential" if avg_diff < 10 else "random"
                self.id_pattern_cache[resource_type] = pattern
                logger.debug(f"{resource_type} ID pattern: {pattern} (avg diff: {avg_diff:.1f})")
                return pattern
                
        except Exception as e:
            logger.debug(f"ID pattern detection failed: {e}")
        
        return "sequential"  # Default assumption
    
    def _extract_username(self, html: str) -> Optional[str]:
        """Extract username from HTML."""
        patterns = [
            r'author["\']?\s*:\s*["\']([^"\']+)',
            r'by\s+([a-zA-Z0-9_-]+)',
            r'class=["\']author["\'][^>]*>([^<]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return None
    
    def get_summary(self) -> Dict:
        """Get comprehensive summary."""
        by_resource = {}
        for finding in self.findings:
            res_type = finding.resource_type
            if res_type not in by_resource:
                by_resource[res_type] = []
            by_resource[res_type].append(finding)
        
        return {
            "total": len(self.findings),
            "by_severity": {
                "critical": len([f for f in self.findings if f.severity == "critical"]),
                "high": len([f for f in self.findings if f.severity == "high"]),
                "medium": len([f for f in self.findings if f.severity == "medium"]),
            },
            "by_resource": {res: len(findings) for res, findings in by_resource.items()},
            "findings": [f.to_dict() for f in self.findings]
        }
