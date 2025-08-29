"""Rate limiting implementation for MCP server with dynamic configuration."""

import os
import time
from typing import Dict, List, Tuple
from collections import defaultdict, deque
from threading import Lock
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """Token bucket rate limiter with sliding window."""
    
    def __init__(self):
        """Initialize rate limiter."""
        self._requests: Dict[str, deque] = defaultdict(deque)
        self._lock = Lock()
        
        # Cleanup old entries periodically with configurable interval
        self._last_cleanup = time.time()
        self._cleanup_interval = int(os.getenv("MCP_RATE_LIMITER_CLEANUP_INTERVAL", "300"))  # 5 minutes default
    
    def check_rate_limit(
        self, 
        client_id: str, 
        max_requests: int, 
        window_seconds: int
    ) -> bool:
        """
        Check if client is within rate limits.
        
        Args:
            client_id: Unique identifier for the client (IP, API key, etc.)
            max_requests: Maximum number of requests allowed
            window_seconds: Time window in seconds
            
        Returns:
            True if request is allowed, False if rate limited
        """
        current_time = time.time()
        
        with self._lock:
            # Cleanup old entries if needed
            if current_time - self._last_cleanup > self._cleanup_interval:
                self._cleanup_old_entries(current_time)
                self._last_cleanup = current_time
            
            # Get request history for this client
            client_requests = self._requests[client_id]
            
            # Remove requests outside the current window
            cutoff_time = current_time - window_seconds
            while client_requests and client_requests[0] < cutoff_time:
                client_requests.popleft()
            
            # Check if client has exceeded rate limit
            if len(client_requests) >= max_requests:
                logger.warning(f"Rate limit exceeded for client {client_id}: "
                             f"{len(client_requests)} requests in {window_seconds}s window")
                return False
            
            # Add current request
            client_requests.append(current_time)
            
            logger.debug(f"Rate limit check passed for client {client_id}: "
                        f"{len(client_requests)}/{max_requests} requests")
            return True
    
    def get_rate_limit_status(
        self, 
        client_id: str, 
        max_requests: int, 
        window_seconds: int
    ) -> Dict[str, any]:
        """
        Get current rate limit status for a client.
        
        Returns:
            Dictionary with rate limit information
        """
        current_time = time.time()
        
        with self._lock:
            client_requests = self._requests[client_id]
            
            # Remove requests outside the current window
            cutoff_time = current_time - window_seconds
            while client_requests and client_requests[0] < cutoff_time:
                client_requests.popleft()
            
            current_requests = len(client_requests)
            remaining_requests = max(0, max_requests - current_requests)
            
            # Calculate reset time (when oldest request will expire)
            reset_time = None
            if client_requests:
                oldest_request = client_requests[0]
                reset_time = oldest_request + window_seconds
            
            return {
                "limit": max_requests,
                "remaining": remaining_requests,
                "used": current_requests,
                "window_seconds": window_seconds,
                "reset_time": reset_time,
                "reset_in_seconds": max(0, reset_time - current_time) if reset_time else 0
            }
    
    def reset_client_limits(self, client_id: str) -> None:
        """Reset rate limits for a specific client."""
        with self._lock:
            if client_id in self._requests:
                del self._requests[client_id]
                logger.info(f"Reset rate limits for client: {client_id}")
    
    def get_all_clients_status(self) -> Dict[str, Dict[str, any]]:
        """Get rate limit status for all clients."""
        current_time = time.time()
        status = {}
        
        with self._lock:
            for client_id, requests in self._requests.items():
                if requests:  # Only include clients with recent requests
                    # Calculate requests in last minute as example
                    cutoff_time = current_time - 60
                    recent_requests = sum(1 for req_time in requests if req_time > cutoff_time)
                    
                    status[client_id] = {
                        "recent_requests_1min": recent_requests,
                        "total_tracked_requests": len(requests),
                        "oldest_request_age": current_time - requests[0] if requests else 0,
                        "newest_request_age": current_time - requests[-1] if requests else 0
                    }
        
        return status
    
    def _cleanup_old_entries(self, current_time: float) -> None:
        """Clean up old request entries to prevent memory leaks."""
        # Remove entries older than 1 hour
        cutoff_time = current_time - 3600
        clients_to_remove = []
        
        for client_id, requests in self._requests.items():
            # Remove old requests
            while requests and requests[0] < cutoff_time:
                requests.popleft()
            
            # Mark empty clients for removal
            if not requests:
                clients_to_remove.append(client_id)
        
        # Remove empty clients
        for client_id in clients_to_remove:
            del self._requests[client_id]
        
        if clients_to_remove:
            logger.debug(f"Cleaned up rate limiter: removed {len(clients_to_remove)} inactive clients")


class AdvancedRateLimiter:
    """Advanced rate limiter with multiple tiers and burst handling."""
    
    def __init__(self):
        """Initialize advanced rate limiter."""
        self.basic_limiter = RateLimiter()
        self._burst_allowances: Dict[str, Dict[str, any]] = defaultdict(dict)
        self._lock = Lock()
    
    def check_tiered_rate_limit(
        self, 
        client_id: str, 
        tier_limits: List[Tuple[int, int]]  # [(requests, seconds), ...]
    ) -> Tuple[bool, Dict[str, any]]:
        """
        Check rate limits across multiple tiers.
        
        Args:
            client_id: Client identifier
            tier_limits: List of (max_requests, window_seconds) tuples
            
        Returns:
            Tuple of (allowed, status_info)
        """
        status_info = {
            "tiers": [],
            "allowed": True,
            "limiting_tier": None
        }
        
        for i, (max_requests, window_seconds) in enumerate(tier_limits):
            tier_allowed = self.basic_limiter.check_rate_limit(
                f"{client_id}_tier_{i}", max_requests, window_seconds
            )
            
            tier_status = self.basic_limiter.get_rate_limit_status(
                f"{client_id}_tier_{i}", max_requests, window_seconds
            )
            
            tier_info = {
                "tier": i,
                "max_requests": max_requests,
                "window_seconds": window_seconds,
                "allowed": tier_allowed,
                "status": tier_status
            }
            
            status_info["tiers"].append(tier_info)
            
            if not tier_allowed:
                status_info["allowed"] = False
                status_info["limiting_tier"] = i
                break
        
        return status_info["allowed"], status_info
    
    def allow_burst(
        self, 
        client_id: str, 
        burst_requests: int, 
        burst_window: int,
        cooldown_seconds: int = 3600
    ) -> bool:
        """
        Allow burst requests for a client.
        
        Args:
            client_id: Client identifier
            burst_requests: Number of burst requests to allow
            burst_window: Time window for burst in seconds
            cooldown_seconds: Cooldown period before next burst
            
        Returns:
            True if burst is allowed
        """
        current_time = time.time()
        
        with self._lock:
            client_burst = self._burst_allowances[client_id]
            
            # Check if client is in cooldown
            last_burst = client_burst.get("last_burst_time", 0)
            if current_time - last_burst < cooldown_seconds:
                return False
            
            # Check burst rate limit
            burst_allowed = self.basic_limiter.check_rate_limit(
                f"{client_id}_burst", burst_requests, burst_window
            )
            
            if burst_allowed:
                client_burst["last_burst_time"] = current_time
                client_burst["burst_count"] = client_burst.get("burst_count", 0) + 1
                logger.info(f"Burst allowed for client {client_id}: "
                           f"burst #{client_burst['burst_count']}")
            
            return burst_allowed
    
    def get_client_burst_status(self, client_id: str) -> Dict[str, any]:
        """Get burst status for a client."""
        current_time = time.time()
        
        with self._lock:
            client_burst = self._burst_allowances.get(client_id, {})
            
            last_burst = client_burst.get("last_burst_time", 0)
            burst_count = client_burst.get("burst_count", 0)
            
            return {
                "last_burst_time": last_burst,
                "last_burst_ago_seconds": current_time - last_burst,
                "total_bursts": burst_count,
                "has_recent_burst": (current_time - last_burst) < 3600
            }


class IPRateLimiter:
    """IP-based rate limiter with subnet support."""
    
    def __init__(self):
        """Initialize IP rate limiter."""
        self.rate_limiter = RateLimiter()
        self._ip_classifications: Dict[str, str] = {}
        self._lock = Lock()
    
    def classify_ip(self, ip_address: str) -> str:
        """
        Classify IP address for different rate limit tiers.
        
        Returns:
            Classification: 'trusted', 'normal', 'suspicious', 'blocked'
        """
        with self._lock:
            if ip_address in self._ip_classifications:
                return self._ip_classifications[ip_address]
            
            # Default classification logic
            if ip_address in ["127.0.0.1", "::1"]:
                classification = "trusted"
            elif ip_address.startswith("192.168.") or ip_address.startswith("10."):
                classification = "trusted"  # Private networks
            else:
                classification = "normal"
            
            self._ip_classifications[ip_address] = classification
            return classification
    
    def check_ip_rate_limit(self, ip_address: str) -> Tuple[bool, Dict[str, any]]:
        """
        Check rate limit based on IP classification.
        
        Returns:
            Tuple of (allowed, status_info)
        """
        classification = self.classify_ip(ip_address)
        
        # Define rate limits per classification with environment variable support
        rate_limits = {
            "trusted": (
                int(os.getenv("MCP_RATE_LIMIT_TRUSTED_REQUESTS", "1000")),
                int(os.getenv("MCP_RATE_LIMIT_TRUSTED_WINDOW", "3600"))
            ),
            "normal": (
                int(os.getenv("MCP_RATE_LIMIT_NORMAL_REQUESTS", "100")),
                int(os.getenv("MCP_RATE_LIMIT_NORMAL_WINDOW", "3600"))
            ),
            "suspicious": (
                int(os.getenv("MCP_RATE_LIMIT_SUSPICIOUS_REQUESTS", "10")),
                int(os.getenv("MCP_RATE_LIMIT_SUSPICIOUS_WINDOW", "3600"))
            ),
            "blocked": (
                int(os.getenv("MCP_RATE_LIMIT_BLOCKED_REQUESTS", "0")),
                int(os.getenv("MCP_RATE_LIMIT_BLOCKED_WINDOW", "3600"))
            )
        }
        
        max_requests, window_seconds = rate_limits.get(classification, (100, 3600))
        
        if max_requests == 0:
            return False, {
                "classification": classification,
                "blocked": True,
                "reason": "IP address is blocked"
            }
        
        allowed = self.rate_limiter.check_rate_limit(
            ip_address, max_requests, window_seconds
        )
        
        status = self.rate_limiter.get_rate_limit_status(
            ip_address, max_requests, window_seconds
        )
        
        status.update({
            "classification": classification,
            "blocked": False
        })
        
        return allowed, status
    
    def update_ip_classification(self, ip_address: str, classification: str) -> None:
        """Update IP classification."""
        valid_classifications = ["trusted", "normal", "suspicious", "blocked"]
        
        if classification not in valid_classifications:
            raise ValueError(f"Invalid classification: {classification}")
        
        with self._lock:
            old_classification = self._ip_classifications.get(ip_address, "normal")
            self._ip_classifications[ip_address] = classification
            
            logger.info(f"Updated IP {ip_address} classification: "
                       f"{old_classification} -> {classification}")
    
    def get_ip_statistics(self) -> Dict[str, any]:
        """Get IP classification statistics."""
        with self._lock:
            stats = defaultdict(int)
            for classification in self._ip_classifications.values():
                stats[classification] += 1
            
            return {
                "total_ips": len(self._ip_classifications),
                "by_classification": dict(stats),
                "rate_limiter_clients": len(self.rate_limiter._requests)
            }