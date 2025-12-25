"""
WPHunter - Utility Functions
============================
Common utilities for WordPress security testing.
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urljoin, urlparse


def normalize_url(url: str) -> str:
    """
    Normalize a URL to standard format.
    
    Args:
        url: Input URL
        
    Returns:
        Normalized URL with scheme
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    
    # Remove trailing slash from path (except for root)
    path = parsed.path.rstrip('/') if parsed.path != '/' else '/'
    
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    return parsed.netloc


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs belong to the same domain."""
    return extract_domain(url1) == extract_domain(url2)


def extract_paths_from_html(html: str, base_url: str) -> List[str]:
    """
    Extract all paths from HTML content.
    
    Args:
        html: HTML content
        base_url: Base URL for relative paths
        
    Returns:
        List of unique absolute URLs
    """
    paths = set()
    
    # Regex patterns for various HTML attributes containing URLs
    patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
        r'action=["\']([^"\']+)["\']',
        r'data-src=["\']([^"\']+)["\']',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in matches:
            if match.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
                continue
            
            # Convert relative to absolute
            absolute_url = urljoin(base_url, match)
            
            # Only include same-domain URLs
            if is_same_domain(absolute_url, base_url):
                paths.add(absolute_url)
    
    return list(paths)


def extract_forms(html: str) -> List[Dict[str, Any]]:
    """
    Extract form information from HTML.
    
    Args:
        html: HTML content
        
    Returns:
        List of form dictionaries with action, method, and inputs
    """
    from bs4 import BeautifulSoup
    
    soup = BeautifulSoup(html, 'lxml')
    forms = []
    
    for form in soup.find_all('form'):
        form_data = {
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'id': form.get('id', ''),
            'inputs': [],
        }
        
        # Extract input fields
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_data = {
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', ''),
                'required': input_tag.has_attr('required'),
            }
            if input_data['name']:
                form_data['inputs'].append(input_data)
        
        forms.append(form_data)
    
    return forms


def extract_wp_nonce(html: str) -> Optional[str]:
    """
    Extract WordPress nonce from HTML content.
    
    Args:
        html: HTML content
        
    Returns:
        Nonce value if found, None otherwise
    """
    patterns = [
        r'_wpnonce["\']?\s*[:=]\s*["\']([a-f0-9]+)["\']',
        r'wp_nonce["\']?\s*[:=]\s*["\']([a-f0-9]+)["\']',
        r'nonce["\']?\s*[:=]\s*["\']([a-f0-9]+)["\']',
        r'name=["\']_wpnonce["\']\s+value=["\']([a-f0-9]+)["\']',
        r'value=["\']([a-f0-9]+)["\']\s+name=["\']_wpnonce["\']',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None


def extract_ajax_actions(html: str) -> List[str]:
    """
    Extract WordPress AJAX action names from HTML/JS.
    
    Args:
        html: HTML/JS content
        
    Returns:
        List of AJAX action names
    """
    patterns = [
        r'action["\']?\s*[:=]\s*["\'](\w+)["\']',
        r'wp_ajax_(\w+)',
        r'wp_ajax_nopriv_(\w+)',
    ]
    
    actions = set()
    for pattern in patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        actions.update(matches)
    
    # Filter out common false positives
    false_positives = {'submit', 'click', 'change', 'input', 'focus', 'blur'}
    actions = {a for a in actions if a.lower() not in false_positives}
    
    return list(actions)


def extract_rest_namespaces(json_data: Dict) -> List[str]:
    """
    Extract REST API namespaces from /wp-json/ response.
    
    Args:
        json_data: JSON data from /wp-json/
        
    Returns:
        List of namespace strings
    """
    namespaces = []
    
    if isinstance(json_data, dict):
        namespaces = json_data.get('namespaces', [])
    
    return namespaces


def parse_version(version_str: str) -> Tuple[int, ...]:
    """
    Parse version string to tuple for comparison.
    
    Args:
        version_str: Version string like "6.4.2"
        
    Returns:
        Tuple of version numbers
    """
    # Remove any non-version characters
    version_str = re.sub(r'[^0-9.]', '', version_str)
    
    parts = version_str.split('.')
    return tuple(int(p) for p in parts if p.isdigit())


def version_compare(v1: str, v2: str) -> int:
    """
    Compare two version strings.
    
    Args:
        v1: First version
        v2: Second version
        
    Returns:
        -1 if v1 < v2, 0 if equal, 1 if v1 > v2
    """
    v1_tuple = parse_version(v1)
    v2_tuple = parse_version(v2)
    
    if v1_tuple < v2_tuple:
        return -1
    elif v1_tuple > v2_tuple:
        return 1
    return 0


def calculate_hash(content: str, algorithm: str = 'md5') -> str:
    """
    Calculate hash of content.
    
    Args:
        content: String content to hash
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hex digest of hash
    """
    if algorithm == 'md5':
        return hashlib.md5(content.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(content.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(content.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def is_wordpress_url(html: str) -> bool:
    """
    Check if HTML content appears to be from a WordPress site.
    
    Args:
        html: HTML content
        
    Returns:
        True if WordPress indicators found
    """
    indicators = [
        '/wp-content/',
        '/wp-includes/',
        '/wp-admin/',
        'wp-json',
        'wordpress',
        'generator" content="WordPress',
    ]
    
    html_lower = html.lower()
    return any(indicator.lower() in html_lower for indicator in indicators)


def sanitize_filename(filename: str) -> str:
    """Sanitize a string for use as filename."""
    # Remove or replace invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(' .')
    return sanitized or 'unnamed'


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate string with ellipsis if too long."""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + '...'


class WordPressPaths:
    """Common WordPress paths for scanning."""
    
    # Core WordPress files
    CORE_FILES = [
        '/wp-login.php',
        '/wp-admin/',
        '/wp-content/',
        '/wp-includes/',
        '/xmlrpc.php',
        '/wp-json/',
        '/readme.html',
        '/license.txt',
        '/wp-config.php',
        '/wp-config-sample.php',
        '/.htaccess',
        '/wp-cron.php',
    ]
    
    # Sensitive files
    SENSITIVE_FILES = [
        '/wp-config.php.bak',
        '/wp-config.php.old',
        '/wp-config.php.save',
        '/wp-config.php~',
        '/wp-config.bak',
        '/wp-config.old',
        '/.git/',
        '/.svn/',
        '/.env',
        '/debug.log',
        '/wp-content/debug.log',
        '/error_log',
        '/php_error.log',
    ]
    
    # REST API endpoints
    REST_ENDPOINTS = [
        '/wp-json/',
        '/wp-json/wp/v2/',
        '/wp-json/wp/v2/users',
        '/wp-json/wp/v2/posts',
        '/wp-json/wp/v2/pages',
        '/wp-json/wp/v2/media',
        '/wp-json/wp/v2/comments',
        '/wp-json/wp/v2/settings',
        '/wp-json/wp/v2/plugins',
        '/wp-json/wp/v2/themes',
        '/wp-json/oembed/1.0/',
    ]
    
    # User enumeration paths
    USER_ENUM_PATHS = [
        '/?author=1',
        '/?author=2',
        '/?author=3',
        '/wp-json/wp/v2/users',
        '/wp-json/wp/v2/users?per_page=100',
    ]
    
    # Common backup extensions
    BACKUP_EXTENSIONS = [
        '.bak', '.backup', '.old', '.save', '.swp',
        '.tmp', '.temp', '~', '.orig', '.copy'
    ]
