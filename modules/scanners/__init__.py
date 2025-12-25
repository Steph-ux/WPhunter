# WPHunter Scanners Module
from .xss import XSSScanner
from .sqli import SQLiScanner
from .csrf import CSRFScanner
from .lfi import LFIScanner
from .upload import UploadScanner
from .auth import AuthScanner
from .ssrf import SSRFScanner
from .waf import WAFDetector
from .nginx import NginxScanner

__all__ = [
    'XSSScanner',
    'SQLiScanner',
    'CSRFScanner',
    'LFIScanner',
    'UploadScanner',
    'AuthScanner',
    'SSRFScanner',
    'WAFDetector',
    'NginxScanner',
]
