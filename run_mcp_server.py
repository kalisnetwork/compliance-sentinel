#!/usr/bin/env python3
"""
Simple script to run the Compliance Sentinel MCP Server.
This script ensures proper environment setup and starts the MCP server.
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

def setup_environment():
    """Setup the environment for running the MCP server."""
    # Add current directory to Python path
    current_dir = Path(__file__).parent.absolute()
    if str(current_dir) not in sys.path:
        sys.path.insert(0, str(current_dir))
    
    # Set environment variables
    os.environ['PYTHONPATH'] = str(current_dir)
    os.environ.setdefault('LOG_LEVEL', 'INFO')
    
    print(f"Environment setup complete:")
    print(f"  PYTHONPATH: {os.environ['PYTHONPATH']}")
    print(f"  LOG_LEVEL: {os.environ['LOG_LEVEL']}")
    print(f"  Working Directory: {current_dir}")

def check_dependencies():
    """Check if required dependencies are installed."""
    try:
        import mcp
        print("✅ MCP library found")
    except ImportError:
        print("❌ MCP library not found. Please install with: pip install mcp")
        return False
    
    try:
        from compliance_sentinel.core.compliance_agent import ComplianceAgent
        print("✅ Compliance Sentinel package found")
    except ImportError as e:
        print(f"❌ Compliance Sentinel package not found: {e}")
        print("Please ensure the package is properly installed.")
        return False
    
    return True

def main():
    """Main entry point."""
    print("🔒 Starting Compliance Sentinel MCP Server")
    print("=" * 50)
    
    # Setup environment
    setup_environment()
    print()
    
    # Check dependencies
    if not check_dependencies():
        print("\n❌ Dependency check failed. Please install required packages.")
        sys.exit(1)
    
    print("\n🚀 Starting MCP server...")
    print("The server will communicate via stdio following the MCP protocol.")
    print("Press Ctrl+C to stop the server.")
    print("-" * 50)
    
    try:
        # Import and run the MCP server
        from mcp_server import main as mcp_main
        import asyncio
        asyncio.run(mcp_main())
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        logging.exception("MCP Server error")
        sys.exit(1)

if __name__ == "__main__":
    main()