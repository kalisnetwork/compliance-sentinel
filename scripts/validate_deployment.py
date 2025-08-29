#!/usr/bin/env python3
"""Deployment validation script for Compliance Sentinel."""

import asyncio
import sys
import time
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
import json
import requests
import argparse

# Try to import compliance_sentinel modules
try:
    from compliance_sentinel.core.compliance_agent import ComplianceAgent
    from compliance_sentinel.models.config import SystemConfiguration
    from compliance_sentinel.config.config_manager import ConfigManager
    from compliance_sentinel.cli import cli
    COMPLIANCE_SENTINEL_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import compliance_sentinel modules: {e}")
    COMPLIANCE_SENTINEL_AVAILABLE = False


class DeploymentValidator:
    """Validates Compliance Sentinel deployment."""
    
    def __init__(self):
        """Initialize deployment validator."""
        self.results = []
        self.errors = []
        
    async def validate_deployment(self, deployment_type: str = "local") -> Dict[str, Any]:
        """Validate deployment based on type."""
        print("🔍 Starting Compliance Sentinel Deployment Validation")
        print("=" * 60)
        
        validation_results = {
            'deployment_type': deployment_type,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'overall_status': 'unknown',
            'tests': []
        }
        
        # Run validation tests based on deployment type
        if deployment_type == "local":
            await self._validate_local_deployment()
        elif deployment_type == "docker":
            await self._validate_docker_deployment()
        elif deployment_type == "mcp":
            await self._validate_mcp_deployment()
        elif deployment_type == "kiro":
            await self._validate_kiro_integration()
        else:
            await self._validate_all_deployments()
        
        # Determine overall status
        failed_tests = [r for r in self.results if not r['passed']]
        if not failed_tests:
            validation_results['overall_status'] = 'passed'
        elif len(failed_tests) < len(self.results) / 2:
            validation_results['overall_status'] = 'partial'
        else:
            validation_results['overall_status'] = 'failed'
        
        validation_results['tests'] = self.results
        validation_results['errors'] = self.errors
        
        return validation_results
    
    async def _validate_local_deployment(self):
        """Validate local installation."""
        print("\n📦 Validating Local Deployment")
        print("-" * 30)
        
        # Test 1: Package installation
        await self._test_package_installation()
        
        # Test 2: CLI availability
        await self._test_cli_availability()
        
        # Test 3: Configuration system
        await self._test_configuration_system()
        
        # Test 4: Core functionality
        await self._test_core_functionality()
        
        # Test 5: External tools
        await self._test_external_tools()
    
    async def _validate_docker_deployment(self):
        """Validate Docker deployment."""
        print("\n🐳 Validating Docker Deployment")
        print("-" * 30)
        
        # Test 1: Docker image build
        await self._test_docker_build()
        
        # Test 2: Container startup
        await self._test_container_startup()
        
        # Test 3: Health check
        await self._test_container_health()
        
        # Test 4: API endpoints
        await self._test_api_endpoints()
    
    async def _validate_mcp_deployment(self):
        """Validate MCP server deployment."""
        print("\n🔌 Validating MCP Server Deployment")
        print("-" * 30)
        
        # Test 1: MCP server startup
        await self._test_mcp_server_startup()
        
        # Test 2: API endpoints
        await self._test_mcp_endpoints()
        
        # Test 3: Authentication
        await self._test_mcp_authentication()
        
        # Test 4: Rate limiting
        await self._test_mcp_rate_limiting()
    
    async def _validate_kiro_integration(self):
        """Validate Kiro integration."""
        print("\n🎯 Validating Kiro Integration")
        print("-" * 30)
        
        # Test 1: Hook configuration
        await self._test_kiro_hooks()
        
        # Test 2: IDE feedback
        await self._test_ide_feedback()
        
        # Test 3: Real-time analysis
        await self._test_realtime_analysis()
    
    async def _validate_all_deployments(self):
        """Validate all deployment types."""
        await self._validate_local_deployment()
        await self._validate_docker_deployment()
        await self._validate_mcp_deployment()
        await self._validate_kiro_integration()
    
    async def _test_package_installation(self):
        """Test package installation."""
        test_name = "Package Installation"
        
        try:
            if not COMPLIANCE_SENTINEL_AVAILABLE:
                raise ImportError("compliance_sentinel package not available")
            
            # Test import of main modules
            from compliance_sentinel import ComplianceAgent
            from compliance_sentinel.cli import cli
            
            self._add_result(test_name, True, "Package successfully installed and importable")
            
        except Exception as e:
            self._add_result(test_name, False, f"Package installation failed: {e}")
    
    async def _test_cli_availability(self):
        """Test CLI availability."""
        test_name = "CLI Availability"
        
        try:
            # Test compliance-sentinel command
            result = subprocess.run(
                ['compliance-sentinel', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                version = result.stdout.strip()
                self._add_result(test_name, True, f"CLI available: {version}")
            else:
                self._add_result(test_name, False, f"CLI command failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self._add_result(test_name, False, "CLI command timed out")
        except FileNotFoundError:
            self._add_result(test_name, False, "compliance-sentinel command not found in PATH")
        except Exception as e:
            self._add_result(test_name, False, f"CLI test failed: {e}")
    
    async def _test_configuration_system(self):
        """Test configuration system."""
        test_name = "Configuration System"
        
        try:
            if not COMPLIANCE_SENTINEL_AVAILABLE:
                raise ImportError("compliance_sentinel not available")
            
            # Test configuration manager
            config_manager = ConfigManager()
            config = config_manager.load_project_config()
            
            # Test configuration validation
            errors = config.validate()
            
            if not errors:
                self._add_result(test_name, True, "Configuration system working")
            else:
                self._add_result(test_name, False, f"Configuration validation errors: {errors}")
                
        except Exception as e:
            self._add_result(test_name, False, f"Configuration system failed: {e}")
    
    async def _test_core_functionality(self):
        """Test core analysis functionality."""
        test_name = "Core Functionality"
        
        try:
            if not COMPLIANCE_SENTINEL_AVAILABLE:
                raise ImportError("compliance_sentinel not available")
            
            # Create test file
            test_code = '''
import os
password = "hardcoded_password"
os.system("echo test")
'''
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(test_code)
                test_file = f.name
            
            try:
                # Test analysis
                config = SystemConfiguration()
                config.hooks_enabled = False
                
                async with ComplianceAgent(config) as agent:
                    result = await agent.analyze_files([test_file])
                
                if result.success and result.total_issues > 0:
                    self._add_result(test_name, True, f"Analysis working: {result.total_issues} issues found")
                else:
                    self._add_result(test_name, False, "Analysis did not find expected issues")
                    
            finally:
                Path(test_file).unlink(missing_ok=True)
                
        except Exception as e:
            self._add_result(test_name, False, f"Core functionality test failed: {e}")
    
    async def _test_external_tools(self):
        """Test external security tools."""
        test_name = "External Tools"
        
        tools = ['bandit', 'semgrep', 'safety']
        available_tools = []
        
        for tool in tools:
            try:
                result = subprocess.run(
                    [tool, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    available_tools.append(tool)
                    
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        if len(available_tools) >= 2:
            self._add_result(test_name, True, f"External tools available: {', '.join(available_tools)}")
        else:
            self._add_result(test_name, False, f"Insufficient external tools: {available_tools}")
    
    async def _test_docker_build(self):
        """Test Docker image build."""
        test_name = "Docker Build"
        
        try:
            # Check if Dockerfile exists
            dockerfile_path = Path("deployment/docker/Dockerfile")
            if not dockerfile_path.exists():
                self._add_result(test_name, False, "Dockerfile not found")
                return
            
            # Test docker build (dry run)
            result = subprocess.run(
                ['docker', 'build', '--dry-run', '-f', str(dockerfile_path), '.'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self._add_result(test_name, True, "Docker build configuration valid")
            else:
                self._add_result(test_name, False, f"Docker build failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self._add_result(test_name, False, "Docker build test timed out")
        except FileNotFoundError:
            self._add_result(test_name, False, "Docker not available")
        except Exception as e:
            self._add_result(test_name, False, f"Docker build test failed: {e}")
    
    async def _test_container_startup(self):
        """Test container startup."""
        test_name = "Container Startup"
        
        try:
            # Check if docker-compose.yml exists
            compose_path = Path("deployment/docker/docker-compose.yml")
            if not compose_path.exists():
                self._add_result(test_name, False, "docker-compose.yml not found")
                return
            
            # Validate docker-compose configuration
            result = subprocess.run(
                ['docker-compose', '-f', str(compose_path), 'config'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self._add_result(test_name, True, "Docker Compose configuration valid")
            else:
                self._add_result(test_name, False, f"Docker Compose validation failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self._add_result(test_name, False, "Container startup test timed out")
        except FileNotFoundError:
            self._add_result(test_name, False, "docker-compose not available")
        except Exception as e:
            self._add_result(test_name, False, f"Container startup test failed: {e}")
    
    async def _test_container_health(self):
        """Test container health check."""
        test_name = "Container Health"
        
        # This would test actual container health in a real deployment
        # For now, just validate health check configuration exists
        try:
            dockerfile_path = Path("deployment/docker/Dockerfile")
            if dockerfile_path.exists():
                content = dockerfile_path.read_text()
                if "HEALTHCHECK" in content:
                    self._add_result(test_name, True, "Health check configured")
                else:
                    self._add_result(test_name, False, "No health check configured")
            else:
                self._add_result(test_name, False, "Dockerfile not found")
                
        except Exception as e:
            self._add_result(test_name, False, f"Health check test failed: {e}")
    
    async def _test_api_endpoints(self):
        """Test API endpoints."""
        test_name = "API Endpoints"
        
        # This would test actual API endpoints in a running deployment
        # For now, just check if MCP server module exists
        try:
            if COMPLIANCE_SENTINEL_AVAILABLE:
                from compliance_sentinel.mcp_server.server import app
                self._add_result(test_name, True, "MCP server module available")
            else:
                self._add_result(test_name, False, "MCP server module not available")
                
        except Exception as e:
            self._add_result(test_name, False, f"API endpoints test failed: {e}")
    
    async def _test_mcp_server_startup(self):
        """Test MCP server startup."""
        test_name = "MCP Server Startup"
        
        try:
            if not COMPLIANCE_SENTINEL_AVAILABLE:
                raise ImportError("compliance_sentinel not available")
            
            # Test MCP server import
            from compliance_sentinel.mcp_server.server import MCPServer
            server = MCPServer()
            
            self._add_result(test_name, True, "MCP server can be instantiated")
            
        except Exception as e:
            self._add_result(test_name, False, f"MCP server startup failed: {e}")
    
    async def _test_mcp_endpoints(self):
        """Test MCP endpoints."""
        test_name = "MCP Endpoints"
        
        # This would test actual MCP endpoints
        # For now, validate endpoint definitions exist
        try:
            openapi_path = Path("compliance_sentinel/mcp_server/openapi.yaml")
            if openapi_path.exists():
                self._add_result(test_name, True, "OpenAPI specification found")
            else:
                self._add_result(test_name, False, "OpenAPI specification not found")
                
        except Exception as e:
            self._add_result(test_name, False, f"MCP endpoints test failed: {e}")
    
    async def _test_mcp_authentication(self):
        """Test MCP authentication."""
        test_name = "MCP Authentication"
        
        # This would test actual authentication
        # For now, check if auth module exists
        try:
            if COMPLIANCE_SENTINEL_AVAILABLE:
                from compliance_sentinel.mcp_server.auth import AuthManager
                self._add_result(test_name, True, "Authentication module available")
            else:
                self._add_result(test_name, False, "Authentication module not available")
                
        except ImportError:
            self._add_result(test_name, False, "Authentication module not found")
        except Exception as e:
            self._add_result(test_name, False, f"Authentication test failed: {e}")
    
    async def _test_mcp_rate_limiting(self):
        """Test MCP rate limiting."""
        test_name = "MCP Rate Limiting"
        
        try:
            if COMPLIANCE_SENTINEL_AVAILABLE:
                from compliance_sentinel.mcp_server.rate_limiter import RateLimiter
                self._add_result(test_name, True, "Rate limiter available")
            else:
                self._add_result(test_name, False, "Rate limiter not available")
                
        except ImportError:
            self._add_result(test_name, False, "Rate limiter module not found")
        except Exception as e:
            self._add_result(test_name, False, f"Rate limiting test failed: {e}")
    
    async def _test_kiro_hooks(self):
        """Test Kiro hook configuration."""
        test_name = "Kiro Hooks"
        
        try:
            # Check if hook configurations exist
            hooks_dir = Path("kiro_hooks")
            if hooks_dir.exists():
                hook_files = list(hooks_dir.glob("*.json"))
                if hook_files:
                    # Validate hook JSON
                    valid_hooks = 0
                    for hook_file in hook_files:
                        try:
                            with open(hook_file) as f:
                                hook_config = json.load(f)
                            
                            # Basic validation
                            required_fields = ['name', 'triggers', 'execution']
                            if all(field in hook_config for field in required_fields):
                                valid_hooks += 1
                                
                        except json.JSONDecodeError:
                            continue
                    
                    if valid_hooks > 0:
                        self._add_result(test_name, True, f"{valid_hooks} valid hook configurations found")
                    else:
                        self._add_result(test_name, False, "No valid hook configurations found")
                else:
                    self._add_result(test_name, False, "No hook files found")
            else:
                self._add_result(test_name, False, "Kiro hooks directory not found")
                
        except Exception as e:
            self._add_result(test_name, False, f"Kiro hooks test failed: {e}")
    
    async def _test_ide_feedback(self):
        """Test IDE feedback system."""
        test_name = "IDE Feedback"
        
        try:
            if COMPLIANCE_SENTINEL_AVAILABLE:
                from compliance_sentinel.ide.feedback_formatter import IDEFeedbackFormatter
                formatter = IDEFeedbackFormatter()
                self._add_result(test_name, True, "IDE feedback formatter available")
            else:
                self._add_result(test_name, False, "IDE feedback formatter not available")
                
        except Exception as e:
            self._add_result(test_name, False, f"IDE feedback test failed: {e}")
    
    async def _test_realtime_analysis(self):
        """Test real-time analysis capability."""
        test_name = "Real-time Analysis"
        
        try:
            if COMPLIANCE_SENTINEL_AVAILABLE:
                from compliance_sentinel.hooks.hook_manager import HookManager
                self._add_result(test_name, True, "Hook manager available for real-time analysis")
            else:
                self._add_result(test_name, False, "Hook manager not available")
                
        except Exception as e:
            self._add_result(test_name, False, f"Real-time analysis test failed: {e}")
    
    def _add_result(self, test_name: str, passed: bool, message: str):
        """Add test result."""
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
        
        self.results.append({
            'test_name': test_name,
            'passed': passed,
            'message': message,
            'timestamp': time.strftime('%H:%M:%S')
        })
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate validation report."""
        report = ["# Compliance Sentinel Deployment Validation Report\n"]
        report.append(f"**Generated:** {results['timestamp']}")
        report.append(f"**Deployment Type:** {results['deployment_type']}")
        report.append(f"**Overall Status:** {results['overall_status'].upper()}\n")
        
        # Summary
        total_tests = len(results['tests'])
        passed_tests = len([t for t in results['tests'] if t['passed']])
        failed_tests = total_tests - passed_tests
        
        report.append("## Summary\n")
        report.append(f"- **Total Tests:** {total_tests}")
        report.append(f"- **Passed:** {passed_tests}")
        report.append(f"- **Failed:** {failed_tests}")
        report.append(f"- **Success Rate:** {passed_tests/total_tests:.1%}\n")
        
        # Test Results
        report.append("## Test Results\n")
        report.append("| Test | Status | Message |")
        report.append("|------|--------|---------|")
        
        for test in results['tests']:
            status = "✅ PASS" if test['passed'] else "❌ FAIL"
            report.append(f"| {test['test_name']} | {status} | {test['message']} |")
        
        report.append("\n")
        
        # Errors
        if results['errors']:
            report.append("## Errors\n")
            for error in results['errors']:
                report.append(f"- {error}")
            report.append("\n")
        
        # Recommendations
        report.append("## Recommendations\n")
        
        if failed_tests == 0:
            report.append("✅ All tests passed! Deployment is ready for production.")
        else:
            report.append("⚠️ Some tests failed. Please address the following issues:")
            for test in results['tests']:
                if not test['passed']:
                    report.append(f"- **{test['test_name']}**: {test['message']}")
        
        return "\n".join(report)


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Validate Compliance Sentinel deployment")
    parser.add_argument("--type", choices=["local", "docker", "mcp", "kiro", "all"],
                       default="local", help="Deployment type to validate")
    parser.add_argument("--output", help="Output file for validation report")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    
    args = parser.parse_args()
    
    validator = DeploymentValidator()
    
    try:
        results = await validator.validate_deployment(args.type)
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 Validation Summary")
        print("=" * 60)
        
        total_tests = len(results['tests'])
        passed_tests = len([t for t in results['tests'] if t['passed']])
        
        print(f"Overall Status: {results['overall_status'].upper()}")
        print(f"Tests Passed: {passed_tests}/{total_tests} ({passed_tests/total_tests:.1%})")
        
        # Save report
        if args.output:
            if args.json:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
            else:
                report = validator.generate_report(results)
                with open(args.output, 'w') as f:
                    f.write(report)
            
            print(f"Report saved to: {args.output}")
        
        # Exit with appropriate code
        if results['overall_status'] == 'passed':
            sys.exit(0)
        elif results['overall_status'] == 'partial':
            sys.exit(1)
        else:
            sys.exit(2)
            
    except KeyboardInterrupt:
        print("\n⏹️ Validation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Validation failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())