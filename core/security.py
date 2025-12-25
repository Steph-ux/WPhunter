"""
WPHunter - Enhanced Rate Limiter
================================
Advanced rate limiting with daily limits, blacklist, and UA rotation.
"""

import asyncio
import time
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime, timedelta

from core.logger import logger


@dataclass
class RateLimitConfig:
    """Enhanced rate limiting configuration."""
    requests_per_second: int = 10
    burst: int = 20
    daily_limit: Optional[int] = None  # None = unlimited
    blacklist_duration: int = 300  # 5 minutes
    ua_rotation_interval: int = 50  # Rotate UA every N requests
    adaptive_throttling: bool = True


class EnhancedRateLimiter:
    """
    Enhanced rate limiter with advanced features.
    
    Features:
    - Global daily request limit
    - Temporary blacklist after ban detection
    - Automatic User-Agent rotation
    - Adaptive throttling based on response times
    """
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.burst)
        
        # Daily limit tracking
        self.daily_requests = 0
        self.daily_reset_time = datetime.now() + timedelta(days=1)
        
        # Blacklist tracking
        self.blacklisted_until: Optional[datetime] = None
        self.ban_count = 0
        
        # UA rotation
        self.request_count = 0
        self.current_ua_index = 0
        
        # Adaptive throttling
        self.response_times: List[float] = []
        self.current_delay = 1.0 / config.requests_per_second
        
        # Statistics
        self.total_requests = 0
        self.throttled_requests = 0
        self.blacklist_hits = 0
    
    async def acquire(self) -> str:
        """
        Acquire rate limit token.
        
        Returns: User-Agent to use for this request
        """
        # Check blacklist
        if self.blacklisted_until and datetime.now() < self.blacklisted_until:
            self.blacklist_hits += 1
            wait_time = (self.blacklisted_until - datetime.now()).total_seconds()
            logger.warning(f"Blacklisted - waiting {wait_time:.0f}s")
            await asyncio.sleep(wait_time)
            self.blacklisted_until = None
        
        # Check daily limit
        if self.config.daily_limit:
            if datetime.now() >= self.daily_reset_time:
                self.daily_requests = 0
                self.daily_reset_time = datetime.now() + timedelta(days=1)
                logger.info("Daily request limit reset")
            
            if self.daily_requests >= self.config.daily_limit:
                wait_time = (self.daily_reset_time - datetime.now()).total_seconds()
                logger.warning(f"Daily limit reached - waiting {wait_time:.0f}s")
                await asyncio.sleep(wait_time)
                self.daily_requests = 0
                self.daily_reset_time = datetime.now() + timedelta(days=1)
        
        # Acquire semaphore
        await self.semaphore.acquire()
        
        # Apply delay
        await asyncio.sleep(self.current_delay)
        
        # Update counters
        self.total_requests += 1
        self.daily_requests += 1
        self.request_count += 1
        
        # Rotate User-Agent
        if self.request_count % self.config.ua_rotation_interval == 0:
            self.current_ua_index = (self.current_ua_index + 1) % len(self.USER_AGENTS)
            logger.debug(f"Rotated User-Agent (request #{self.request_count})")
        
        return self.USER_AGENTS[self.current_ua_index]
    
    def release(self):
        """Release rate limit token."""
        self.semaphore.release()
    
    def record_response_time(self, response_time: float):
        """Record response time for adaptive throttling."""
        if not self.config.adaptive_throttling:
            return
        
        self.response_times.append(response_time)
        
        # Keep only last 20 response times
        if len(self.response_times) > 20:
            self.response_times.pop(0)
        
        # Adjust delay based on average response time
        if len(self.response_times) >= 10:
            avg_time = sum(self.response_times) / len(self.response_times)
            
            # If responses are slow, increase delay
            if avg_time > 2.0:
                self.current_delay = min(self.current_delay * 1.2, 5.0)
                logger.debug(f"Increased delay to {self.current_delay:.2f}s (slow responses)")
            
            # If responses are fast, decrease delay
            elif avg_time < 0.5 and self.current_delay > 0.1:
                self.current_delay = max(self.current_delay * 0.8, 0.1)
                logger.debug(f"Decreased delay to {self.current_delay:.2f}s (fast responses)")
    
    def report_ban(self, duration: Optional[int] = None):
        """
        Report that a ban was detected.
        
        Args:
            duration: Ban duration in seconds (None = use default)
        """
        self.ban_count += 1
        ban_duration = duration or self.config.blacklist_duration
        
        # Increase duration for repeated bans
        ban_duration *= (2 ** (self.ban_count - 1))
        ban_duration = min(ban_duration, 3600)  # Cap at 1 hour
        
        self.blacklisted_until = datetime.now() + timedelta(seconds=ban_duration)
        logger.error(f"Ban detected (#{self.ban_count}) - blacklisted for {ban_duration}s")
    
    def report_rate_limit(self, retry_after: Optional[int] = None):
        """
        Report that rate limiting was encountered.
        
        Args:
            retry_after: Retry-After header value in seconds
        """
        self.throttled_requests += 1
        
        if retry_after:
            self.blacklisted_until = datetime.now() + timedelta(seconds=retry_after)
            logger.warning(f"Rate limited - waiting {retry_after}s")
        else:
            # Adaptive backoff
            backoff = min(60 * (2 ** self.throttled_requests), 600)  # Cap at 10 minutes
            self.blacklisted_until = datetime.now() + timedelta(seconds=backoff)
            logger.warning(f"Rate limited - backing off {backoff}s")
    
    def get_current_ua(self) -> str:
        """Get current User-Agent."""
        return self.USER_AGENTS[self.current_ua_index]
    
    def get_stats(self) -> Dict:
        """Get rate limiter statistics."""
        return {
            "total_requests": self.total_requests,
            "daily_requests": self.daily_requests,
            "daily_limit": self.config.daily_limit,
            "throttled_requests": self.throttled_requests,
            "blacklist_hits": self.blacklist_hits,
            "ban_count": self.ban_count,
            "current_delay": round(self.current_delay, 3),
            "current_ua_index": self.current_ua_index,
            "is_blacklisted": self.blacklisted_until is not None and datetime.now() < self.blacklisted_until
        }


# Global instance
_global_rate_limiter: Optional[EnhancedRateLimiter] = None


def init_rate_limiter(config: RateLimitConfig):
    """Initialize global rate limiter."""
    global _global_rate_limiter
    _global_rate_limiter = EnhancedRateLimiter(config)


def get_rate_limiter() -> EnhancedRateLimiter:
    """Get global rate limiter instance."""
    global _global_rate_limiter
    if _global_rate_limiter is None:
        # Initialize with default config
        _global_rate_limiter = EnhancedRateLimiter(RateLimitConfig())
    return _global_rate_limiter
