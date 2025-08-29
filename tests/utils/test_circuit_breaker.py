"""Tests for circuit breaker implementation."""

import asyncio
import pytest
from unittest.mock import AsyncMock, Mock
import time

from compliance_sentinel.utils.circuit_breaker import (
    CircuitBreaker, CircuitBreakerConfig, CircuitState,
    CircuitBreakerOpenException, CircuitBreakerManager,
    get_circuit_breaker, with_circuit_breaker, circuit_breaker
)


class TestCircuitBreakerConfig:
    """Test circuit breaker configuration."""
    
    def test_valid_config(self):
        """Test valid configuration."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=30,
            success_threshold=2,
            timeout=10.0
        )
        
        assert config.failure_threshold == 3
        assert config.recovery_timeout == 30
        assert config.success_threshold == 2
        assert config.timeout == 10.0
    
    def test_invalid_config(self):
        """Test invalid configuration values."""
        with pytest.raises(ValueError, match="failure_threshold must be at least 1"):
            CircuitBreakerConfig(failure_threshold=0)
        
        with pytest.raises(ValueError, match="recovery_timeout must be at least 1"):
            CircuitBreakerConfig(recovery_timeout=0)
        
        with pytest.raises(ValueError, match="success_threshold must be at least 1"):
            CircuitBreakerConfig(success_threshold=0)
        
        with pytest.raises(ValueError, match="timeout must be positive"):
            CircuitBreakerConfig(timeout=0)


class TestCircuitBreaker:
    """Test circuit breaker functionality."""
    
    def setup_method(self):
        """Set up test circuit breaker."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=1,  # Short timeout for testing
            success_threshold=2,
            timeout=1.0
        )
        self.circuit_breaker = CircuitBreaker("test-circuit", config)
    
    @pytest.mark.asyncio
    async def test_successful_calls(self):
        """Test successful calls keep circuit closed."""
        async def success_func():
            return "success"
        
        # Make several successful calls
        for _ in range(5):
            result = await self.circuit_breaker.call(success_func)
            assert result == "success"
        
        assert self.circuit_breaker.get_state() == CircuitState.CLOSED
        stats = self.circuit_breaker.get_stats()
        assert stats.total_calls == 5
        assert stats.successful_calls == 5
        assert stats.failed_calls == 0
    
    @pytest.mark.asyncio
    async def test_circuit_opens_on_failures(self):
        """Test circuit opens after threshold failures."""
        async def failing_func():
            raise Exception("Test failure")
        
        # Make calls that will fail
        for i in range(3):
            with pytest.raises(Exception, match="Test failure"):
                await self.circuit_breaker.call(failing_func)
            
            if i < 2:  # Circuit should still be closed
                assert self.circuit_breaker.get_state() == CircuitState.CLOSED
        
        # Circuit should now be open
        assert self.circuit_breaker.get_state() == CircuitState.OPEN
        
        # Next call should be rejected
        with pytest.raises(CircuitBreakerOpenException):
            await self.circuit_breaker.call(failing_func)
    
    @pytest.mark.asyncio
    async def test_circuit_recovery(self):
        """Test circuit recovery from open to closed."""
        async def failing_func():
            raise Exception("Test failure")
        
        async def success_func():
            return "success"
        
        # Open the circuit
        for _ in range(3):
            with pytest.raises(Exception):
                await self.circuit_breaker.call(failing_func)
        
        assert self.circuit_breaker.get_state() == CircuitState.OPEN
        
        # Wait for recovery timeout
        await asyncio.sleep(1.1)
        
        # First call should transition to half-open
        result = await self.circuit_breaker.call(success_func)
        assert result == "success"
        assert self.circuit_breaker.get_state() == CircuitState.HALF_OPEN
        
        # Second successful call should close the circuit
        result = await self.circuit_breaker.call(success_func)
        assert result == "success"
        assert self.circuit_breaker.get_state() == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_half_open_failure_reopens_circuit(self):
        """Test that failure in half-open state reopens circuit."""
        async def failing_func():
            raise Exception("Test failure")
        
        async def success_func():
            return "success"
        
        # Open the circuit
        for _ in range(3):
            with pytest.raises(Exception):
                await self.circuit_breaker.call(failing_func)
        
        # Wait for recovery timeout
        await asyncio.sleep(1.1)
        
        # First call transitions to half-open
        await self.circuit_breaker.call(success_func)
        assert self.circuit_breaker.get_state() == CircuitState.HALF_OPEN
        
        # Failure should reopen the circuit
        with pytest.raises(Exception):
            await self.circuit_breaker.call(failing_func)
        
        assert self.circuit_breaker.get_state() == CircuitState.OPEN
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Test timeout handling."""
        async def slow_func():
            await asyncio.sleep(2)  # Longer than circuit breaker timeout
            return "success"
        
        with pytest.raises(asyncio.TimeoutError):
            await self.circuit_breaker.call(slow_func)
        
        stats = self.circuit_breaker.get_stats()
        assert stats.failed_calls == 1
    
    @pytest.mark.asyncio
    async def test_sync_function_support(self):
        """Test support for synchronous functions."""
        def sync_func(value):
            return f"sync_{value}"
        
        result = await self.circuit_breaker.call(sync_func, "test")
        assert result == "sync_test"
    
    def test_state_change_listeners(self):
        """Test state change listeners."""
        state_changes = []
        
        def listener(name, old_state, new_state):
            state_changes.append((name, old_state, new_state))
        
        self.circuit_breaker.add_state_change_listener(listener)
        
        # Force state change
        self.circuit_breaker.force_open()
        
        assert len(state_changes) == 1
        assert state_changes[0] == ("test-circuit", CircuitState.CLOSED, CircuitState.OPEN)
    
    def test_reset(self):
        """Test circuit breaker reset."""
        # Force some failures
        self.circuit_breaker.stats.failed_calls = 5
        self.circuit_breaker.force_open()
        
        assert self.circuit_breaker.get_state() == CircuitState.OPEN
        
        # Reset
        self.circuit_breaker.reset()
        
        assert self.circuit_breaker.get_state() == CircuitState.CLOSED
        assert self.circuit_breaker.get_stats().failed_calls == 0
    
    def test_get_info(self):
        """Test getting circuit breaker info."""
        info = self.circuit_breaker.get_info()
        
        assert info["name"] == "test-circuit"
        assert info["state"] == "closed"
        assert "config" in info
        assert "stats" in info
        assert "call_permitted" in info


class TestCircuitBreakerManager:
    """Test circuit breaker manager."""
    
    def setup_method(self):
        """Set up test manager."""
        self.manager = CircuitBreakerManager()
    
    def test_get_circuit_breaker(self):
        """Test getting circuit breaker from manager."""
        cb1 = self.manager.get_circuit_breaker("test1")
        cb2 = self.manager.get_circuit_breaker("test1")  # Same name
        cb3 = self.manager.get_circuit_breaker("test2")  # Different name
        
        assert cb1 is cb2  # Should return same instance
        assert cb1 is not cb3  # Should be different instances
        assert cb1.name == "test1"
        assert cb3.name == "test2"
    
    def test_remove_circuit_breaker(self):
        """Test removing circuit breaker."""
        cb = self.manager.get_circuit_breaker("test")
        assert "test" in self.manager.circuit_breakers
        
        result = self.manager.remove_circuit_breaker("test")
        assert result is True
        assert "test" not in self.manager.circuit_breakers
        
        # Try to remove non-existent
        result = self.manager.remove_circuit_breaker("nonexistent")
        assert result is False
    
    def test_reset_all(self):
        """Test resetting all circuit breakers."""
        cb1 = self.manager.get_circuit_breaker("test1")
        cb2 = self.manager.get_circuit_breaker("test2")
        
        # Force some state
        cb1.force_open()
        cb2.force_open()
        
        assert cb1.get_state() == CircuitState.OPEN
        assert cb2.get_state() == CircuitState.OPEN
        
        # Reset all
        self.manager.reset_all()
        
        assert cb1.get_state() == CircuitState.CLOSED
        assert cb2.get_state() == CircuitState.CLOSED
    
    def test_global_state_change_listener(self):
        """Test global state change listener."""
        state_changes = []
        
        def listener(name, old_state, new_state):
            state_changes.append((name, old_state, new_state))
        
        self.manager.add_global_state_change_listener(listener)
        
        # Create circuit breaker and change state
        cb = self.manager.get_circuit_breaker("test")
        cb.force_open()
        
        assert len(state_changes) == 1
        assert state_changes[0][0] == "test"
    
    def test_system_stats(self):
        """Test system statistics."""
        cb1 = self.manager.get_circuit_breaker("test1")
        cb2 = self.manager.get_circuit_breaker("test2")
        
        cb1.force_open()  # One open
        # cb2 stays closed
        
        stats = self.manager.get_system_stats()
        
        assert stats["total_circuit_breakers"] == 2
        assert stats["open_breakers"] == 1
        assert stats["closed_breakers"] == 1
        assert stats["half_open_breakers"] == 0
        assert stats["system_health_percentage"] == 50.0


class TestCircuitBreakerDecorator:
    """Test circuit breaker decorator."""
    
    @pytest.mark.asyncio
    async def test_decorator_success(self):
        """Test decorator with successful function."""
        @circuit_breaker("test-decorator")
        async def test_func(value):
            return f"result_{value}"
        
        result = await test_func("test")
        assert result == "result_test"
    
    @pytest.mark.asyncio
    async def test_decorator_failure(self):
        """Test decorator with failing function."""
        @circuit_breaker("test-decorator-fail", CircuitBreakerConfig(failure_threshold=1))
        async def failing_func():
            raise Exception("Test failure")
        
        # First call should fail and open circuit
        with pytest.raises(Exception, match="Test failure"):
            await failing_func()
        
        # Second call should be rejected by circuit breaker
        with pytest.raises(CircuitBreakerOpenException):
            await failing_func()


class TestGlobalFunctions:
    """Test global convenience functions."""
    
    @pytest.mark.asyncio
    async def test_with_circuit_breaker(self):
        """Test with_circuit_breaker function."""
        async def test_func(value):
            return f"global_{value}"
        
        result = await with_circuit_breaker("global-test", test_func, "test")
        assert result == "global_test"
    
    def test_get_circuit_breaker(self):
        """Test get_circuit_breaker function."""
        cb1 = get_circuit_breaker("global-cb")
        cb2 = get_circuit_breaker("global-cb")
        
        assert cb1 is cb2
        assert cb1.name == "global-cb"


@pytest.mark.asyncio
async def test_integration_scenario():
    """Test realistic integration scenario."""
    # Simulate external service calls
    call_count = 0
    
    async def external_service_call():
        nonlocal call_count
        call_count += 1
        
        if call_count <= 3:
            raise Exception("Service unavailable")
        elif call_count <= 5:
            await asyncio.sleep(0.1)  # Simulate slow recovery
            return "recovered"
        else:
            return "healthy"
    
    config = CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=0.5,
        success_threshold=2,
        timeout=1.0
    )
    
    cb = CircuitBreaker("integration-test", config)
    
    # Phase 1: Service fails, circuit opens
    for i in range(3):
        with pytest.raises(Exception, match="Service unavailable"):
            await cb.call(external_service_call)
    
    assert cb.get_state() == CircuitState.OPEN
    
    # Phase 2: Circuit rejects calls
    with pytest.raises(CircuitBreakerOpenException):
        await cb.call(external_service_call)
    
    # Phase 3: Wait for recovery timeout
    await asyncio.sleep(0.6)
    
    # Phase 4: Service recovers, circuit closes
    result = await cb.call(external_service_call)
    assert result == "recovered"
    assert cb.get_state() == CircuitState.HALF_OPEN
    
    result = await cb.call(external_service_call)
    assert result == "healthy"
    assert cb.get_state() == CircuitState.CLOSED
    
    # Verify final stats
    stats = cb.get_stats()
    assert stats.total_calls == 6  # 3 failures + 1 rejection + 2 successes
    assert stats.successful_calls == 2
    assert stats.failed_calls == 3
    assert stats.rejected_calls == 1