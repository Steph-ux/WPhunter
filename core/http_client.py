"""
WPHunter - HTTP Client Module
=============================
Async HTTP client with proxy support, rate limiting, and retry logic.
"""

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse

import httpx

from .config import WPHunterConfig
from .logger import logger


@dataclass
class HTTPResponse:
    """Wrapper for HTTP response with useful attributes."""
    url: str
    status_code: int
    headers: Dict[str, str]
    text: str
    elapsed: float
    
    @property
    def ok(self) -> bool:
        """Check if response is successful (2xx)."""
        return 200 <= self.status_code < 300
    
    @property
    def content_type(self) -> str:
        """Get content type from headers."""
        return self.headers.get("content-type", "")
    
    @property
    def is_html(self) -> bool:
        """Check if response is HTML."""
        return "text/html" in self.content_type
    
    @property
    def is_json(self) -> bool:
        """Check if response is JSON."""
        return "application/json" in self.content_type
    
    def json(self) -> Any:
        """Parse response as JSON."""
        import json
        return json.loads(self.text)


@dataclass
class RateLimiter:
    """Token bucket rate limiter."""
    tokens_per_second: float
    max_tokens: int
    tokens: float = field(init=False)
    last_update: float = field(init=False)
    _lock: asyncio.Lock = field(init=False, default_factory=asyncio.Lock)
    
    def __post_init__(self):
        self.tokens = float(self.max_tokens)
        self.last_update = time.monotonic()
    
    async def acquire(self):
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = time.monotonic()
            # Add tokens based on time passed
            elapsed = now - self.last_update
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.tokens_per_second)
            self.last_update = now
            
            if self.tokens < 1:
                # Wait for a token
                wait_time = (1 - self.tokens) / self.tokens_per_second
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class WPHttpClient:
    """
    Async HTTP client for WordPress security testing.
    
    Features:
    - Proxy support (Burp Suite integration)
    - Rate limiting with token bucket
    - Automatic retry with exponential backoff
    - User-Agent rotation
    - Cookie management
    """
    
    def __init__(self, config: WPHunterConfig, base_url: Optional[str] = None):
        self.config = config
        self.base_url = base_url.rstrip('/') if base_url else None
        self.user_agents = config.user_agents or ["WPHunter/1.0"]
        
        # Rate limiter
        profile = config.get_active_profile()
        self.rate_limiter = RateLimiter(
            tokens_per_second=profile.requests_per_second,
            max_tokens=config.rate_limit.burst
        )
        
        # HTTP client configuration
        self.client_kwargs = {
            "timeout": httpx.Timeout(config.timeout),
            "follow_redirects": True,
            "verify": config.verify_ssl,
        }
        
        # Proxy configuration
        if config.proxy.enabled:
            self.client_kwargs["proxies"] = config.get_proxy_dict()
            logger.info(f"Proxy enabled: {config.proxy.http}")
        
        # Session cookies
        self.cookies: Dict[str, str] = {}
        
        # Request counter for stats
        self.request_count = 0
        self.error_count = 0
    
    def _get_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Build request headers with random User-Agent."""
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if custom_headers:
            headers.update(custom_headers)
        return headers
    
    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        if path.startswith(('http://', 'https://')):
            return path
        if self.base_url:
            return urljoin(self.base_url + '/', path.lstrip('/'))
        raise ValueError("No base URL configured and path is not absolute")
    
    async def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> HTTPResponse:
        """
        Make an HTTP request with rate limiting and retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: URL path or full URL
            params: Query parameters
            data: Form data
            json_data: JSON body
            headers: Custom headers
            cookies: Custom cookies
            allow_redirects: Follow redirects
            
        Returns:
            HTTPResponse wrapper
        """
        url = self._build_url(path)
        request_headers = self._get_headers(headers)
        
        # Merge cookies
        request_cookies = {**self.cookies}
        if cookies:
            request_cookies.update(cookies)
        
        # Rate limiting
        await self.rate_limiter.acquire()
        
        # Retry logic with exponential backoff
        last_error = None
        for attempt in range(self.config.max_retries + 1):
            try:
                start_time = time.monotonic()
                
                async with httpx.AsyncClient(**self.client_kwargs) as client:
                    response = await client.request(
                        method=method.upper(),
                        url=url,
                        params=params,
                        data=data,
                        json=json_data,
                        headers=request_headers,
                        cookies=request_cookies,
                        follow_redirects=allow_redirects,
                    )
                
                elapsed = time.monotonic() - start_time
                self.request_count += 1
                
                # Update session cookies
                for cookie_name, cookie_value in response.cookies.items():
                    self.cookies[cookie_name] = cookie_value
                
                return HTTPResponse(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    text=response.text,
                    elapsed=elapsed,
                )
                
            except httpx.TimeoutException as e:
                last_error = e
                self.error_count += 1
                logger.warning(f"Timeout on {url} (attempt {attempt + 1}/{self.config.max_retries + 1})")
                
            except httpx.RequestError as e:
                last_error = e
                self.error_count += 1
                logger.warning(f"Request error on {url}: {e} (attempt {attempt + 1}/{self.config.max_retries + 1})")
            
            # Exponential backoff
            if attempt < self.config.max_retries:
                wait_time = (2 ** attempt) + random.uniform(0, 1)
                await asyncio.sleep(wait_time)
        
        # All retries failed
        raise httpx.RequestError(f"Failed after {self.config.max_retries + 1} attempts: {last_error}")
    
    async def get(self, path: str, **kwargs) -> HTTPResponse:
        """HTTP GET request."""
        return await self.request("GET", path, **kwargs)
    
    async def post(self, path: str, **kwargs) -> HTTPResponse:
        """HTTP POST request."""
        return await self.request("POST", path, **kwargs)
    
    async def head(self, path: str, **kwargs) -> HTTPResponse:
        """HTTP HEAD request."""
        return await self.request("HEAD", path, **kwargs)
    
    async def options(self, path: str, **kwargs) -> HTTPResponse:
        """HTTP OPTIONS request."""
        return await self.request("OPTIONS", path, **kwargs)
    
    async def check_path_exists(self, path: str) -> bool:
        """Check if a path exists (returns 2xx or 3xx)."""
        try:
            response = await self.head(path)
            return response.status_code < 400
        except httpx.RequestError:
            return False
    
    async def get_multiple(
        self,
        paths: List[str],
        concurrency: int = 5
    ) -> List[Union[HTTPResponse, Exception]]:
        """
        Fetch multiple paths concurrently with limited concurrency.
        
        Args:
            paths: List of paths to fetch
            concurrency: Maximum concurrent requests
            
        Returns:
            List of responses or exceptions
        """
        semaphore = asyncio.Semaphore(concurrency)
        
        async def fetch_with_semaphore(path: str) -> Union[HTTPResponse, Exception]:
            async with semaphore:
                try:
                    return await self.get(path)
                except Exception as e:
                    return e
        
        tasks = [fetch_with_semaphore(path) for path in paths]
        return await asyncio.gather(*tasks)
    
    def get_stats(self) -> Dict[str, int]:
        """Get request statistics."""
        return {
            "total_requests": self.request_count,
            "errors": self.error_count,
            "success_rate": f"{((self.request_count - self.error_count) / max(1, self.request_count)) * 100:.1f}%"
        }
    
    def set_cookie(self, name: str, value: str):
        """Set a session cookie."""
        self.cookies[name] = value
    
    def set_auth_cookies(self, cookies: Dict[str, str]):
        """Set authentication cookies (WordPress login)."""
        self.cookies.update(cookies)
        logger.info(f"Set {len(cookies)} auth cookies")
