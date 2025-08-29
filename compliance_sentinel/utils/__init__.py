"""Utility modules for Compliance Sentinel."""

from .resilient_error_handler import ResilientErrorHandler, ErrorContext, FallbackResult

def get_resilient_error_handler():
    """Get the global resilient error handler instance."""
    return ResilientErrorHandler()

__all__ = [
    'ResilientErrorHandler',
    'ErrorContext', 
    'FallbackResult',
    'get_resilient_error_handler'
]