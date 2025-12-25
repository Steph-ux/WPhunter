"""
WPHunter - SQLMap Integration
=============================
Integration with SQLMap for SQL injection exploitation.
"""

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.logger import logger


@dataclass
class SQLMapResult:
    url: str
    parameter: str
    dbms: str
    injection_type: str
    payload: str
    
    def to_dict(self) -> Dict:
        return {"url": self.url, "parameter": self.parameter, "dbms": self.dbms,
                "type": self.injection_type, "payload": self.payload}


class SQLMapIntegration:
    """SQLMap integration for SQL injection exploitation."""
    
    def __init__(self, sqlmap_path: str = "sqlmap", level: int = 3, risk: int = 2):
        self.sqlmap_path = sqlmap_path
        self.level = level
        self.risk = risk
        self.results: List[SQLMapResult] = []
    
    async def scan(self, target: str, parameter: Optional[str] = None) -> List[SQLMapResult]:
        """Run SQLMap scan on target URL."""
        logger.section("SQLMap Integration")
        
        cmd = [
            "python3", self.sqlmap_path,
            "-u", target,
            "--level", str(self.level),
            "--risk", str(self.risk),
            "--batch", "--output-dir=/tmp/sqlmap_out"
        ]
        
        if parameter:
            cmd.extend(["-p", parameter])
        
        try:
            logger.info(f"Running SQLMap on {target}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            output = stdout.decode()
            
            # Parse output for injection findings
            if "is vulnerable" in output.lower():
                self.results.append(SQLMapResult(
                    url=target,
                    parameter=parameter or "auto",
                    dbms="detected",
                    injection_type="see output",
                    payload="see sqlmap output"
                ))
                logger.vuln("critical", f"SQLMap confirmed SQLi in {target}")
            
        except Exception as e:
            logger.error(f"SQLMap failed: {e}")
        
        return self.results
    
    def get_summary(self) -> Dict:
        return {"total": len(self.results), "findings": [r.to_dict() for r in self.results]}
