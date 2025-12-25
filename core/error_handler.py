"""
WPHunter - Enhanced Error Handling
==================================
Professional error handling with statistics and context preservation.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, Optional
import httpx

from core.logger import logger


@dataclass
class ErrorStats:
    """Track error statistics during scanning."""
    timeouts: int = 0
    http_errors: int = 0
    network_errors: int = 0
    rate_limit_errors: int = 0
    auth_errors: int = 0
    unexpected_errors: int = 0
    total_requests: int = 0
    successful_requests: int = 0
    
    def get_error_rate(self) -> float:
        """Get overall error rate."""
        if self.total_requests == 0:
            return 0.0
        errors = (self.timeouts + self.http_errors + self.network_errors + 
                 self.rate_limit_errors + self.auth_errors + self.unexpected_errors)
        return errors / self.total_requests
    
    def should_abort(self) -> bool:
        """Determine if scan should be aborted due to excessive errors."""
        # Abort if >50% error rate and >20 requests
        if self.total_requests > 20 and self.get_error_rate() > 0.5:
            return True
        
        # Abort if too many timeouts
        if self.timeouts > 15:
            return True
        
        # Abort if rate limited multiple times
        if self.rate_limit_errors > 5:
            return True
        
        return False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "timeouts": self.timeouts,
            "http_errors": self.http_errors,
            "network_errors": self.network_errors,
            "rate_limit_errors": self.rate_limit_errors,
            "auth_errors": self.auth_errors,
            "unexpected_errors": self.unexpected_errors,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "error_rate": round(self.get_error_rate(), 3)
        }


class EnhancedErrorHandler:
    """
    Enhanced error handler with typed exceptions and automatic retry.
    
    Features:
    - Typed exception handling
    - Error statistics tracking
    - Automatic retry with exponential backoff
    - Context preservation
    """
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.stats = ErrorStats()
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.last_error_time: Dict[str, float] = {}
    
    async def execute_with_retry(self, func, *args, **kwargs):
        """
        Execute function with automatic retry and error handling.
        
        Returns: (success: bool, result: any, error: Optional[Exception])
        """
        self.stats.total_requests += 1
        
        for attempt in range(self.max_retries):
            try:
                result = await func(*args, **kwargs)
                self.stats.successful_requests += 1
                return True, result, None
                
            except httpx.TimeoutException as e:
                self.stats.timeouts += 1
                logger.debug(f"Timeout (attempt {attempt + 1}/{self.max_retries}): {e}")
                
                if self.stats.timeouts > 10:
                    logger.error("Too many timeouts, aborting scan")
                    return False, None, e
                
                if attempt < self.max_retries - 1:
                    await self._backoff(attempt)
                    continue
                else:
                    return False, None, e
            
            except httpx.HTTPStatusError as e:
                self.stats.http_errors += 1
                status = e.response.status_code
                
                # Rate limiting
                if status == 429:
                    self.stats.rate_limit_errors += 1
                    logger.warning(f"Rate limited (429) - backing off")
                    
                    # Extract retry-after header
                    retry_after = e.response.headers.get("Retry-After", "60")
                    try:
                        delay = int(retry_after)
                    except:
                        delay = 60
                    
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(delay)
                        continue
                    else:
                        return False, None, e
                
                # Authentication errors
                elif status in [401, 403]:
                    self.stats.auth_errors += 1
                    logger.warning(f"Authentication error ({status}): {e}")
                    return False, None, e  # Don't retry auth errors
                
                # Server errors (retry)
                elif status >= 500:
                    logger.warning(f"Server error ({status}): {e}")
                    
                    if attempt < self.max_retries - 1:
                        await self._backoff(attempt)
                        continue
                    else:
                        return False, None, e
                
                # Client errors (don't retry)
                else:
                    logger.debug(f"HTTP error ({status}): {e}")
                    return False, None, e
            
            except (httpx.NetworkError, httpx.ConnectError, httpx.ConnectTimeout) as e:
                self.stats.network_errors += 1
                logger.warning(f"Network error (attempt {attempt + 1}/{self.max_retries}): {type(e).__name__}")
                
                if attempt < self.max_retries - 1:
                    await self._backoff(attempt)
                    continue
                else:
                    return False, None, e
            
            except Exception as e:
                self.stats.unexpected_errors += 1
                logger.error(f"Unexpected error: {type(e).__name__}: {e}")
                return False, None, e
        
        return False, None, Exception("Max retries exceeded")
    
    async def _backoff(self, attempt: int):
        """Exponential backoff with jitter."""
        import random
        delay = self.base_delay * (2 ** attempt) + random.uniform(0, 1)
        await asyncio.sleep(min(delay, 30))  # Cap at 30 seconds
    
    def check_abort_conditions(self):
        """Check if scan should be aborted."""
        if self.stats.should_abort():
            error_summary = self.stats.to_dict()
            raise Exception(f"Scan aborted due to excessive errors: {error_summary}")
    
    def get_stats(self) -> Dict:
        """Get error statistics."""
        return self.stats.to_dict()
