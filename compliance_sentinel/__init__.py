"""
Compliance Sentinel - Proactive Security and Compliance Enforcement System

A sophisticated system that integrates with Kiro's agentic capabilities to provide
real-time security analysis, policy enforcement, and intelligent feedback during
the development workflow.
"""

__version__ = "0.1.0"
__author__ = "Compliance Sentinel Team"

# Basic imports that should always work
try:
    from .models.analysis import SecurityIssue, AnalysisRequest, AnalysisResponse, Severity
    from .models.config import SystemConfiguration
    
    __all__ = [
        "SecurityIssue",
        "AnalysisRequest",
        "AnalysisResponse", 
        "Severity",
        "SystemConfiguration"
    ]
except ImportError:
    # If imports fail, just provide version info
    __all__ = ["__version__", "__author__"]