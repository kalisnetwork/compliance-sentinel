"""Cache invalidation strategies and management."""

import asyncio
import logging
import time
from typing import Dict, List, Set, Optional, Callable, Any, Pattern
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import re
import fnmatch

from .intelligent_cache import IntelligentCache, get_global_cache

logger = logging.getLogger(__name__)


class InvalidationTrigger(Enum):
    """Types of cache invalidation triggers."""
    TIME_BASED = "time_based"
    EVENT_BASED = "event_based"
    DEPENDENCY_BASED = "dependency_based"
    MANUAL = "manual"
    SIZE_BASED = "size_based"
    ACCESS_BASED = "access_based"


class InvalidationStrategy(Enum):
    """Cache invalidation strategies."""
    IMMEDIATE = "immediate"
    LAZY = "lazy"
    SCHEDULED = "scheduled"
    WRITE_THROUGH = "write_through"
    WRITE_BEHIND = "write_behind"


@dataclass
class InvalidationRule:
    """Rule for cache invalidation."""
    name: str
    trigger: InvalidationTrigger
    strategy: InvalidationStrategy
    pattern: str  # Pattern to match cache keys
    condition: Optional[Callable] = None  # Custom condition function
    max_age_seconds: Optional[int] = None
    max_access_count: Optional[int] = None
    dependencies: List[str] = field(default_factory=list)
    enabled: bool = True
    priority: int = 0  # Higher priority rules are processed first
    
    def matches_key(self, key: str) -> bool:
        """Check if rule matches a cache key."""
        if not self.enabled:
            return False
        
        # Check pattern match
        if not self._pattern_matches(key):
            return False
        
        # Check custom condition if provided
        if self.condition and not self.condition(key):
            return False
        
        return True
    
    def _pattern_matches(self, key: str) -> bool:
        """Check if pattern matches key."""
        # Support different pattern types
        if self.pattern.startswith("regex:"):
            pattern = self.pattern[6:]  # Remove "regex:" prefix
            return bool(re.match(pattern, key))
        elif self.pattern.startswith("glob:"):
            pattern = self.pattern[5:]  # Remove "glob:" prefix
            return fnmatch.fnmatch(key, pattern)
        else:
            # Default to glob pattern
            return fnmatch.fnmatch(key, self.pattern)


@dataclass
class InvalidationEvent:
    """Event that triggers cache invalidation."""
    event_type: str
    source: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    affected_keys: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            "event_type": self.event_type,
            "source": self.source,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "affected_keys": self.affected_keys
        }


@dataclass
class InvalidationResult:
    """Result of cache invalidation operation."""
    invalidated_keys: List[str] = field(default_factory=list)
    failed_keys: List[str] = field(default_factory=list)
    total_processed: int = 0
    duration_ms: float = 0.0
    strategy_used: Optional[InvalidationStrategy] = None
    trigger: Optional[InvalidationTrigger] = None
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate of invalidation."""
        if self.total_processed == 0:
            return 1.0
        return len(self.invalidated_keys) / self.total_processed
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "invalidated_keys": self.invalidated_keys,
            "failed_keys": self.failed_keys,
            "total_processed": self.total_processed,
            "success_rate": self.success_rate,
            "duration_ms": self.duration_ms,
            "strategy_used": self.strategy_used.value if self.strategy_used else None,
            "trigger": self.trigger.value if self.trigger else None
        }


class CacheInvalidationManager:
    """Manages cache invalidation rules and strategies."""
    
    def __init__(self, cache: Optional[IntelligentCache] = None):
        """Initialize cache invalidation manager."""
        self.cache = cache or get_global_cache()
        self.rules: Dict[str, InvalidationRule] = {}
        self.event_listeners: Dict[str, List[Callable]] = {}
        self.dependency_graph: Dict[str, Set[str]] = {}
        self.invalidation_history: List[InvalidationResult] = []
        self.scheduled_tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            "total_invalidations": 0,
            "successful_invalidations": 0,
            "failed_invalidations": 0,
            "rules_triggered": 0,
            "events_processed": 0
        }
        
        logger.info("Cache invalidation manager initialized")
    
    def add_rule(self, rule: InvalidationRule) -> None:
        """Add invalidation rule."""
        self.rules[rule.name] = rule
        logger.info(f"Added invalidation rule: {rule.name} ({rule.trigger.value})")
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove invalidation rule."""
        if rule_name in self.rules:
            del self.rules[rule_name]
            logger.info(f"Removed invalidation rule: {rule_name}")
            return True
        return False
    
    def get_rule(self, rule_name: str) -> Optional[InvalidationRule]:
        """Get invalidation rule by name."""
        return self.rules.get(rule_name)
    
    def list_rules(self) -> List[InvalidationRule]:
        """List all invalidation rules."""
        return list(self.rules.values())
    
    async def invalidate_by_pattern(
        self, 
        pattern: str, 
        strategy: InvalidationStrategy = InvalidationStrategy.IMMEDIATE
    ) -> InvalidationResult:
        """Invalidate cache entries matching pattern."""
        start_time = time.time()
        result = InvalidationResult(strategy_used=strategy, trigger=InvalidationTrigger.MANUAL)
        
        try:
            async with self._lock:
                all_keys = await self.cache.get_all_keys()
                matching_keys = []
                
                for key in all_keys:
                    if self._pattern_matches(key, pattern):
                        matching_keys.append(key)
                
                result.total_processed = len(matching_keys)
                
                if strategy == InvalidationStrategy.IMMEDIATE:
                    await self._invalidate_immediate(matching_keys, result)
                elif strategy == InvalidationStrategy.LAZY:
                    await self._invalidate_lazy(matching_keys, result)
                elif strategy == InvalidationStrategy.SCHEDULED:
                    await self._invalidate_scheduled(matching_keys, result)
                
                result.duration_ms = (time.time() - start_time) * 1000
                self._update_stats(result)
                self.invalidation_history.append(result)
                
                logger.info(f"Invalidated {len(result.invalidated_keys)} keys matching pattern: {pattern}")
                
        except Exception as e:
            logger.error(f"Error invalidating by pattern {pattern}: {e}")
            result.failed_keys = [pattern]  # Mark pattern as failed
        
        return result
    
    async def invalidate_by_keys(
        self, 
        keys: List[str], 
        strategy: InvalidationStrategy = InvalidationStrategy.IMMEDIATE
    ) -> InvalidationResult:
        """Invalidate specific cache keys."""
        start_time = time.time()
        result = InvalidationResult(strategy_used=strategy, trigger=InvalidationTrigger.MANUAL)
        result.total_processed = len(keys)
        
        try:
            if strategy == InvalidationStrategy.IMMEDIATE:
                await self._invalidate_immediate(keys, result)
            elif strategy == InvalidationStrategy.LAZY:
                await self._invalidate_lazy(keys, result)
            elif strategy == InvalidationStrategy.SCHEDULED:
                await self._invalidate_scheduled(keys, result)
            
            result.duration_ms = (time.time() - start_time) * 1000
            self._update_stats(result)
            self.invalidation_history.append(result)
            
            logger.info(f"Invalidated {len(result.invalidated_keys)} specific keys")
            
        except Exception as e:
            logger.error(f"Error invalidating keys: {e}")
            result.failed_keys = keys
        
        return result
    
    async def invalidate_by_dependencies(self, dependency: str) -> InvalidationResult:
        """Invalidate cache entries that depend on a specific dependency."""
        start_time = time.time()
        result = InvalidationResult(
            strategy_used=InvalidationStrategy.IMMEDIATE,
            trigger=InvalidationTrigger.DEPENDENCY_BASED
        )
        
        try:
            dependent_keys = self.dependency_graph.get(dependency, set())
            result.total_processed = len(dependent_keys)
            
            if dependent_keys:
                await self._invalidate_immediate(list(dependent_keys), result)
                
                # Also invalidate transitive dependencies
                for key in list(dependent_keys):
                    transitive_deps = self.dependency_graph.get(key, set())
                    if transitive_deps:
                        transitive_result = await self.invalidate_by_dependencies(key)
                        result.invalidated_keys.extend(transitive_result.invalidated_keys)
                        result.failed_keys.extend(transitive_result.failed_keys)
            
            result.duration_ms = (time.time() - start_time) * 1000
            self._update_stats(result)
            self.invalidation_history.append(result)
            
            logger.info(f"Invalidated {len(result.invalidated_keys)} keys dependent on: {dependency}")
            
        except Exception as e:
            logger.error(f"Error invalidating dependencies for {dependency}: {e}")
        
        return result
    
    async def process_event(self, event: InvalidationEvent) -> InvalidationResult:
        """Process invalidation event."""
        start_time = time.time()
        result = InvalidationResult(
            strategy_used=InvalidationStrategy.IMMEDIATE,
            trigger=InvalidationTrigger.EVENT_BASED
        )
        
        try:
            self.stats["events_processed"] += 1
            
            # Find matching rules
            matching_rules = []
            for rule in self.rules.values():
                if rule.trigger == InvalidationTrigger.EVENT_BASED and rule.enabled:
                    if self._rule_matches_event(rule, event):
                        matching_rules.append(rule)
            
            # Sort by priority
            matching_rules.sort(key=lambda r: r.priority, reverse=True)
            
            # Process rules
            all_keys_to_invalidate = set()
            for rule in matching_rules:
                keys = await self._get_keys_for_rule(rule)
                all_keys_to_invalidate.update(keys)
                self.stats["rules_triggered"] += 1
            
            # Add explicitly affected keys from event
            all_keys_to_invalidate.update(event.affected_keys)
            
            result.total_processed = len(all_keys_to_invalidate)
            
            if all_keys_to_invalidate:
                await self._invalidate_immediate(list(all_keys_to_invalidate), result)
            
            result.duration_ms = (time.time() - start_time) * 1000
            self._update_stats(result)
            self.invalidation_history.append(result)
            
            # Notify event listeners
            await self._notify_event_listeners(event.event_type, event)
            
            logger.info(f"Processed event {event.event_type}: invalidated {len(result.invalidated_keys)} keys")
            
        except Exception as e:
            logger.error(f"Error processing event {event.event_type}: {e}")
        
        return result
    
    async def schedule_invalidation(
        self, 
        pattern: str, 
        delay_seconds: int,
        task_name: Optional[str] = None
    ) -> str:
        """Schedule cache invalidation for later execution."""
        task_name = task_name or f"scheduled_invalidation_{int(time.time())}"
        
        async def delayed_invalidation():
            await asyncio.sleep(delay_seconds)
            await self.invalidate_by_pattern(pattern, InvalidationStrategy.SCHEDULED)
        
        task = asyncio.create_task(delayed_invalidation())
        self.scheduled_tasks[task_name] = task
        
        logger.info(f"Scheduled invalidation task '{task_name}' for pattern '{pattern}' in {delay_seconds} seconds")
        return task_name
    
    def cancel_scheduled_invalidation(self, task_name: str) -> bool:
        """Cancel scheduled invalidation task."""
        if task_name in self.scheduled_tasks:
            task = self.scheduled_tasks[task_name]
            if not task.done():
                task.cancel()
            del self.scheduled_tasks[task_name]
            logger.info(f"Cancelled scheduled invalidation task: {task_name}")
            return True
        return False
    
    def add_dependency(self, key: str, dependency: str) -> None:
        """Add dependency relationship for cache key."""
        if dependency not in self.dependency_graph:
            self.dependency_graph[dependency] = set()
        self.dependency_graph[dependency].add(key)
        logger.debug(f"Added dependency: {key} depends on {dependency}")
    
    def remove_dependency(self, key: str, dependency: str) -> None:
        """Remove dependency relationship."""
        if dependency in self.dependency_graph:
            self.dependency_graph[dependency].discard(key)
            if not self.dependency_graph[dependency]:
                del self.dependency_graph[dependency]
        logger.debug(f"Removed dependency: {key} no longer depends on {dependency}")
    
    def add_event_listener(self, event_type: str, listener: Callable) -> None:
        """Add event listener for specific event type."""
        if event_type not in self.event_listeners:
            self.event_listeners[event_type] = []
        self.event_listeners[event_type].append(listener)
        logger.debug(f"Added event listener for: {event_type}")
    
    def remove_event_listener(self, event_type: str, listener: Callable) -> None:
        """Remove event listener."""
        if event_type in self.event_listeners:
            self.event_listeners[event_type] = [
                l for l in self.event_listeners[event_type] if l != listener
            ]
    
    async def _invalidate_immediate(self, keys: List[str], result: InvalidationResult) -> None:
        """Immediately invalidate cache keys."""
        for key in keys:
            try:
                success = await self.cache.delete(key)
                if success:
                    result.invalidated_keys.append(key)
                else:
                    result.failed_keys.append(key)
            except Exception as e:
                logger.error(f"Error invalidating key {key}: {e}")
                result.failed_keys.append(key)
    
    async def _invalidate_lazy(self, keys: List[str], result: InvalidationResult) -> None:
        """Mark keys for lazy invalidation (invalidate on next access)."""
        # For lazy invalidation, we could mark entries as stale
        # This is a simplified implementation
        for key in keys:
            try:
                entry_info = await self.cache.get_entry_info(key)
                if entry_info:
                    # Mark as expired by setting expiration to now
                    # This would require extending the cache API
                    success = await self.cache.delete(key)
                    if success:
                        result.invalidated_keys.append(key)
                    else:
                        result.failed_keys.append(key)
                else:
                    result.failed_keys.append(key)
            except Exception as e:
                logger.error(f"Error lazy invalidating key {key}: {e}")
                result.failed_keys.append(key)
    
    async def _invalidate_scheduled(self, keys: List[str], result: InvalidationResult) -> None:
        """Schedule keys for invalidation."""
        # For scheduled invalidation, we immediately invalidate
        # In a more sophisticated implementation, this could be queued
        await self._invalidate_immediate(keys, result)
    
    def _pattern_matches(self, key: str, pattern: str) -> bool:
        """Check if key matches pattern."""
        if pattern.startswith("regex:"):
            pattern = pattern[6:]
            return bool(re.match(pattern, key))
        elif pattern.startswith("glob:"):
            pattern = pattern[5:]
            return fnmatch.fnmatch(key, pattern)
        else:
            return fnmatch.fnmatch(key, pattern)
    
    def _rule_matches_event(self, rule: InvalidationRule, event: InvalidationEvent) -> bool:
        """Check if rule matches event."""
        # Simple event matching - could be extended
        return rule.pattern in event.event_type or event.event_type in rule.pattern
    
    async def _get_keys_for_rule(self, rule: InvalidationRule) -> List[str]:
        """Get cache keys that match a rule."""
        all_keys = await self.cache.get_all_keys()
        matching_keys = []
        
        for key in all_keys:
            if rule.matches_key(key):
                # Additional checks based on rule conditions
                if rule.max_age_seconds or rule.max_access_count:
                    entry_info = await self.cache.get_entry_info(key)
                    if entry_info:
                        if rule.max_age_seconds and entry_info["age_seconds"] > rule.max_age_seconds:
                            matching_keys.append(key)
                        elif rule.max_access_count and entry_info["access_count"] > rule.max_access_count:
                            matching_keys.append(key)
                else:
                    matching_keys.append(key)
        
        return matching_keys
    
    async def _notify_event_listeners(self, event_type: str, event: InvalidationEvent) -> None:
        """Notify event listeners."""
        if event_type in self.event_listeners:
            for listener in self.event_listeners[event_type]:
                try:
                    if asyncio.iscoroutinefunction(listener):
                        await listener(event)
                    else:
                        listener(event)
                except Exception as e:
                    logger.error(f"Error in event listener: {e}")
    
    def _update_stats(self, result: InvalidationResult) -> None:
        """Update invalidation statistics."""
        self.stats["total_invalidations"] += 1
        if result.success_rate > 0.5:  # Consider successful if > 50% success rate
            self.stats["successful_invalidations"] += 1
        else:
            self.stats["failed_invalidations"] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get invalidation statistics."""
        return {
            **self.stats,
            "active_rules": len([r for r in self.rules.values() if r.enabled]),
            "total_rules": len(self.rules),
            "scheduled_tasks": len(self.scheduled_tasks),
            "dependency_relationships": sum(len(deps) for deps in self.dependency_graph.values()),
            "event_listeners": sum(len(listeners) for listeners in self.event_listeners.values()),
            "recent_invalidations": len(self.invalidation_history[-10:])  # Last 10
        }
    
    def get_invalidation_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent invalidation history."""
        return [result.to_dict() for result in self.invalidation_history[-limit:]]
    
    async def cleanup(self) -> None:
        """Cleanup resources and cancel scheduled tasks."""
        for task_name, task in self.scheduled_tasks.items():
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        self.scheduled_tasks.clear()
        logger.info("Cache invalidation manager cleaned up")


# Global invalidation manager
_global_invalidation_manager = CacheInvalidationManager()


def get_invalidation_manager() -> CacheInvalidationManager:
    """Get the global cache invalidation manager."""
    return _global_invalidation_manager


# Convenience functions for common invalidation patterns
async def invalidate_vulnerability_cache(package_name: str) -> InvalidationResult:
    """Invalidate vulnerability cache for a package."""
    pattern = f"vulns_{package_name}_*"
    return await _global_invalidation_manager.invalidate_by_pattern(pattern)


async def invalidate_compliance_cache(framework: str) -> InvalidationResult:
    """Invalidate compliance cache for a framework."""
    pattern = f"compliance_{framework}_*"
    return await _global_invalidation_manager.invalidate_by_pattern(pattern)


async def invalidate_search_cache(query: str) -> InvalidationResult:
    """Invalidate search cache for a query."""
    pattern = f"search_{query}"
    return await _global_invalidation_manager.invalidate_by_pattern(pattern)


def create_time_based_rule(
    name: str, 
    pattern: str, 
    max_age_seconds: int
) -> InvalidationRule:
    """Create time-based invalidation rule."""
    return InvalidationRule(
        name=name,
        trigger=InvalidationTrigger.TIME_BASED,
        strategy=InvalidationStrategy.IMMEDIATE,
        pattern=pattern,
        max_age_seconds=max_age_seconds
    )


def create_dependency_rule(
    name: str, 
    pattern: str, 
    dependencies: List[str]
) -> InvalidationRule:
    """Create dependency-based invalidation rule."""
    return InvalidationRule(
        name=name,
        trigger=InvalidationTrigger.DEPENDENCY_BASED,
        strategy=InvalidationStrategy.IMMEDIATE,
        pattern=pattern,
        dependencies=dependencies
    )