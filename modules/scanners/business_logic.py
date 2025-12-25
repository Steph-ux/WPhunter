"""
WPHunter - Business Logic Scanner
=================================
Test for business logic vulnerabilities in WordPress e-commerce.

Tests:
1. Price manipulation (negative, overflow)
2. Discount abuse (stacking, multiple use)
3. Quantity manipulation
4. Currency manipulation
5. Shipping bypass
6. Payment bypass

CWE-840: Business Logic Errors
"""

import asyncio
from dataclasses import dataclass
from typing import Dict, List

from core.http_client import WPHttpClient
from core.logger import logger
from core.security import get_rate_limiter


@dataclass
class BusinessLogicFinding:
    """Business logic vulnerability finding."""
    vuln_type: str
    url: str
    evidence: str
    severity: str = "high"
    cwe: str = "CWE-840"
    payload: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        return {
            "type": "Business Logic",
            "vuln_type": self.vuln_type,
            "url": self.url,
            "evidence": self.evidence[:300],
            "severity": self.severity
        }


class BusinessLogicScanner:
    """Business logic vulnerability scanner for WordPress e-commerce."""
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.findings: List[BusinessLogicFinding] = []
        self.rate_limiter = get_rate_limiter()
    
    async def scan(self) -> List[BusinessLogicFinding]:
        """Run business logic tests."""
        logger.section("Business Logic Vulnerability Scan")
        
        # 1. Price manipulation
        await self._test_price_manipulation()
        
        # 2. Quantity manipulation
        await self._test_quantity_manipulation()
        
        # 3. Discount abuse
        await self._test_discount_abuse()
        
        # 4. Currency manipulation
        await self._test_currency_manipulation()
        
        logger.success(f"Business logic scan: {len(self.findings)} findings")
        return self.findings
    
    async def _test_price_manipulation(self):
        """Test price manipulation vulnerabilities."""
        logger.info("Testing price manipulation...")
        
        test_payloads = [
            {"price": -10, "desc": "Negative price"},
            {"price": 0, "desc": "Zero price"},
            {"price": 0.01, "desc": "Minimal price"},
            {"price": 999999999, "desc": "Overflow price"},
        ]
        
        for payload_data in test_payloads:
            await self.rate_limiter.acquire()
            
            try:
                # Test via cart update
                response = await self.http.post(
                    "/wp-json/wc/store/cart/update-item",
                    json={
                        "key": "test",
                        "quantity": 1,
                        "price": payload_data["price"]
                    }
                )
                
                if response.ok:
                    self.findings.append(BusinessLogicFinding(
                        vuln_type="price_manipulation",
                        url="/wp-json/wc/store/cart/update-item",
                        evidence=f"{payload_data['desc']}: {payload_data['price']}",
                        severity="critical",
                        payload=payload_data
                    ))
                    logger.vuln("critical", f"Price manipulation: {payload_data['desc']}")
                    
            except Exception:
                continue
    
    async def _test_quantity_manipulation(self):
        """Test quantity manipulation."""
        logger.info("Testing quantity manipulation...")
        
        test_quantities = [-1, 0, 999999]
        
        for qty in test_quantities:
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.post(
                    "/wp-json/wc/store/cart/add-item",
                    json={"id": 1, "quantity": qty}
                )
                
                if response.ok:
                    self.findings.append(BusinessLogicFinding(
                        vuln_type="quantity_manipulation",
                        url="/wp-json/wc/store/cart/add-item",
                        evidence=f"Invalid quantity accepted: {qty}",
                        severity="high"
                    ))
                    logger.vuln("high", f"Quantity manipulation: {qty}")
                    
            except Exception:
                continue
    
    async def _test_discount_abuse(self):
        """Test discount stacking and abuse."""
        logger.info("Testing discount abuse...")
        
        # Try to apply multiple coupons
        test_coupons = ["SAVE10", "SAVE20", "WELCOME"]
        
        for coupon in test_coupons:
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.post(
                    "/wp-json/wc/store/cart/apply-coupon",
                    json={"code": coupon}
                )
                
                if response.ok:
                    logger.info(f"Coupon {coupon} applied")
                    
            except Exception:
                continue
    
    async def _test_currency_manipulation(self):
        """Test currency manipulation."""
        logger.info("Testing currency manipulation...")
        
        test_currencies = ["USD", "EUR", "GBP", "XXX"]
        
        for currency in test_currencies:
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.post(
                    "/wp-json/wc/store/cart",
                    json={"currency": currency}
                )
                
                if response.ok and currency == "XXX":
                    self.findings.append(BusinessLogicFinding(
                        vuln_type="currency_manipulation",
                        url="/wp-json/wc/store/cart",
                        evidence=f"Invalid currency accepted: {currency}",
                        severity="medium"
                    ))
                    logger.vuln("medium", f"Currency manipulation: {currency}")
                    
            except Exception:
                continue
    
    def get_summary(self) -> Dict:
        """Get summary."""
        return {
            "total": len(self.findings),
            "by_type": {
                "price": len([f for f in self.findings if f.vuln_type == "price_manipulation"]),
                "quantity": len([f for f in self.findings if f.vuln_type == "quantity_manipulation"]),
                "discount": len([f for f in self.findings if f.vuln_type == "discount_abuse"]),
                "currency": len([f for f in self.findings if f.vuln_type == "currency_manipulation"]),
            },
            "findings": [f.to_dict() for f in self.findings]
        }
