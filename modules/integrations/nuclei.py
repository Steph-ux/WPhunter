"""
WPHunter - Nuclei Integration
=============================
Integration with Nuclei scanner for WordPress templates.
"""

import asyncio
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from core.logger import logger


@dataclass
class NucleiResult:
    template_id: str
    name: str
    severity: str
    url: str
    matched_at: str
    extracted: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "template": self.template_id, "name": self.name,
            "severity": self.severity, "url": self.url, "matched_at": self.matched_at
        }


class NucleiIntegration:
    """Nuclei scanner integration for WordPress."""
    
    def __init__(self, nuclei_path: str = "nuclei", proxy: Optional[str] = None):
        self.nuclei_path = nuclei_path
        self.proxy = proxy
        self.results: List[NucleiResult] = []
    
    async def scan(self, target: str, templates: List[str] = None) -> List[NucleiResult]:
        """Run Nuclei scan with WordPress templates."""
        logger.section("Nuclei Integration Scan")
        
        if not self._check_nuclei():
            logger.warning("Nuclei not found, skipping")
            return []
        
        cmd = [self.nuclei_path, "-u", target, "-j", "-silent"]
        
        # Add WordPress-specific templates
        templates = templates or ["wordpress/", "cves/"]
        for tpl in templates:
            cmd.extend(["-t", tpl])
        
        if self.proxy:
            cmd.extend(["-proxy", self.proxy])
        
        try:
            logger.info(f"Running: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            # Parse JSON output
            for line in stdout.decode().strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        self.results.append(NucleiResult(
                            template_id=data.get("template-id", ""),
                            name=data.get("info", {}).get("name", ""),
                            severity=data.get("info", {}).get("severity", "unknown"),
                            url=data.get("host", target),
                            matched_at=data.get("matched-at", ""),
                        ))
                    except json.JSONDecodeError:
                        continue
            
            logger.success(f"Nuclei found {len(self.results)} issues")
            
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
        
        return self.results
    
    def _check_nuclei(self) -> bool:
        """Check if Nuclei is installed."""
        try:
            subprocess.run([self.nuclei_path, "-version"], capture_output=True)
            return True
        except FileNotFoundError:
            return False
    
    def get_summary(self) -> Dict:
        return {
            "total": len(self.results),
            "by_severity": {
                s: len([r for r in self.results if r.severity == s])
                for s in ["critical", "high", "medium", "low", "info"]
            },
            "findings": [r.to_dict() for r in self.results]
        }
