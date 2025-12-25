"""
WPHunter - Dalfox Integration
=============================
Integration with Dalfox for XSS exploitation.
"""

import asyncio
import json
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.logger import logger


@dataclass
class DalfoxResult:
    url: str
    parameter: str
    payload: str
    evidence: str
    
    def to_dict(self) -> Dict:
        return {"url": self.url, "parameter": self.parameter,
                "payload": self.payload, "evidence": self.evidence[:200]}


class DalfoxIntegration:
    """Dalfox integration for XSS exploitation."""
    
    def __init__(self, dalfox_path: str = "dalfox", proxy: Optional[str] = None):
        self.dalfox_path = dalfox_path
        self.proxy = proxy
        self.results: List[DalfoxResult] = []
    
    async def scan(self, urls: List[str]) -> List[DalfoxResult]:
        """Run Dalfox scan on URLs."""
        logger.section("Dalfox Integration")
        
        for url in urls:
            await self._scan_url(url)
        
        logger.success(f"Dalfox found {len(self.results)} XSS")
        return self.results
    
    async def _scan_url(self, url: str):
        cmd = [self.dalfox_path, "url", url, "-o", "json", "--silence"]
        
        if self.proxy:
            cmd.extend(["--proxy", self.proxy])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            for line in stdout.decode().strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        if data.get("type") == "POC":
                            self.results.append(DalfoxResult(
                                url=url,
                                parameter=data.get("param", ""),
                                payload=data.get("data", ""),
                                evidence=data.get("evidence", "")
                            ))
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logger.debug(f"Dalfox error: {e}")
    
    def get_summary(self) -> Dict:
        return {"total": len(self.results), "findings": [r.to_dict() for r in self.results]}
