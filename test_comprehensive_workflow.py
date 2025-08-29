#!/usr/bin/env python3
"""Comprehensive workflow test for Compliance Sentinel."""

import tempfile
import asyncio
from pathlib import Path
import time

async def test_end_to_end_workflow():
    """Test end-to-end analysis workflow."""
    print("🚀 Testing End-to-End Analysis Workflow")
    print("=" * 50)
    
    # Import TestDataManager for test data
    from compliance_sentinel.testing.test_data_manager import get_test_data_manager, require_test_environment
    
    try:
        # Ensure we're in a test environment
        require_test_environment("comprehensive_workflow_test")
        test_data_manager = get_test_data_manager()
        
        # Create test files with vulnerable code using TestDataManager
        vulnerable_code_samples = {
            "hardcoded_secrets.py": test_data_manager.create_test_file_content("python"),
        
        "sql_injection.py": '''
import sqlite3

def get_user_by_name(username):
    # SQL injection vulnerability
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def search_users(search_term):
    # Another SQL injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name LIKE '%{}%'".format(search_term)
    cursor.execute(query)
    return cursor.fetchall()
''',
        
        "command_injection.py": '''
import os
import subprocess

def process_file(filename):
    # Command injection vulnerability
    os.system(f"cat {filename}")
    
def list_directory(path):
    # Another command injection
    result = subprocess.run(f"ls -la {path}", shell=True, capture_output=True)
    return result.stdout
''',
        
        "clean_code.py": '''
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def safe_function(data: str) -> str:
    """A safe utility function."""
    if not isinstance(data, str):
        raise ValueError("Input must be a string")
    
    return data.strip().lower()

def get_config_value(key: str) -> Optional[str]:
    """Safely get configuration from environment."""
    return os.environ.get(key)
'''
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test files
        test_files = []
        for filename, content in vulnerable_code_samples.items():
            file_path = temp_path / filename
            file_path.write_text(content)
            test_files.append(str(file_path))
        
        print(f"📁 Created {len(test_files)} test files")
        
        # Test 1: Basic Analysis Request
        print("\n🔍 Test 1: Basic Analysis Request")
        try:
            from compliance_sentinel.models.analysis import AnalysisRequest, AnalysisType
            
            request = AnalysisRequest(
                file_paths=test_files,
                analysis_type=AnalysisType.SECURITY_SCAN
            )
            
            print(f"✅ Created analysis request for {len(request.file_paths)} files")
            print(f"   Request ID: {request.request_id}")
            print(f"   Analysis type: {request.analysis_type.value}")
            
        except Exception as e:
            print(f"❌ Analysis request failed: {e}")
            return False
        
        # Test 2: Security Issue Creation and Processing
        print("\n🔍 Test 2: Security Issue Processing")
        try:
            from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
            from datetime import datetime
            import uuid
            
            # Create sample security issues
            issues = []
            
            # Hardcoded secret issue
            issues.append(SecurityIssue(
                id=str(uuid.uuid4()),
                severity=Severity.CRITICAL,
                category=SecurityCategory.HARDCODED_SECRETS,
                file_path=str(temp_path / "hardcoded_secrets.py"),
                line_number=5,
                description="Hardcoded database password detected",
                rule_id="B105",
                confidence=0.95,
                remediation_suggestions=["Use environment variables for sensitive data"],
                created_at=datetime.now()
            ))
            
            # SQL injection issue
            issues.append(SecurityIssue(
                id=str(uuid.uuid4()),
                severity=Severity.HIGH,
                category=SecurityCategory.SQL_INJECTION,
                file_path=str(temp_path / "sql_injection.py"),
                line_number=7,
                description="SQL injection vulnerability in user query",
                rule_id="B608",
                confidence=0.9,
                remediation_suggestions=["Use parameterized queries"],
                created_at=datetime.now()
            ))
            
            # Command injection issue
            issues.append(SecurityIssue(
                id=str(uuid.uuid4()),
                severity=Severity.HIGH,
                category=SecurityCategory.INPUT_VALIDATION,
                file_path=str(temp_path / "command_injection.py"),
                line_number=5,
                description="Command injection via os.system",
                rule_id="B602",
                confidence=0.85,
                remediation_suggestions=["Use subprocess with argument lists"],
                created_at=datetime.now()
            ))
            
            print(f"✅ Created {len(issues)} security issues")
            
            # Count by severity
            severity_counts = {}
            for issue in issues:
                severity = issue.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            print(f"   Severity breakdown: {severity_counts}")
            
        except Exception as e:
            print(f"❌ Security issue processing failed: {e}")
            return False
        
        # Test 3: IDE Feedback Generation
        print("\n🔍 Test 3: IDE Feedback Generation")
        try:
            from compliance_sentinel.ide.feedback_formatter import IDEFeedbackFormatter, IDEType
            
            # Test different IDE formats
            ide_types = [IDEType.KIRO, IDEType.VSCODE, IDEType.GENERIC]
            
            for ide_type in ide_types:
                formatter = IDEFeedbackFormatter(ide_type)
                feedback = formatter.format_issues(issues)
                
                print(f"✅ {ide_type.value} IDE feedback:")
                print(f"   - {len(feedback.diagnostics)} diagnostics")
                print(f"   - {len(feedback.quick_fixes)} quick fixes")
                print(f"   - {len(feedback.code_actions)} code actions")
                
                if ide_type == IDEType.KIRO:
                    print(f"   - {len(feedback.hover_info)} hover info items")
            
        except Exception as e:
            print(f"❌ IDE feedback generation failed: {e}")
            return False
        
        # Test 4: Code Highlighting
        print("\n🔍 Test 4: Code Highlighting")
        try:
            from compliance_sentinel.ide.code_highlighter import CodeHighlighter
            
            highlighter = CodeHighlighter()
            highlights_by_file = highlighter.create_highlights(issues)
            
            total_highlights = sum(len(fh.highlights) for fh.highlights in highlights_by_file.values())
            total_annotations = sum(len(fh.line_annotations) for fh.highlights in highlights_by_file.values())
            
            print(f"✅ Code highlighting generated:")
            print(f"   - {len(highlights_by_file)} files with highlights")
            print(f"   - {total_highlights} total highlights")
            print(f"   - {total_annotations} line annotations")
            
        except Exception as e:
            print(f"❌ Code highlighting failed: {e}")
            return False
        
        # Test 5: Contextual Help
        print("\n🔍 Test 5: Contextual Help")
        try:
            from compliance_sentinel.ide.contextual_help import ContextualHelpProvider
            
            help_provider = ContextualHelpProvider()
            
            # Get help for each issue
            help_items = []
            for issue in issues:
                help_content = help_provider.get_help_for_issue(issue)
                help_items.append(help_content)
            
            print(f"✅ Contextual help generated:")
            print(f"   - {len(help_items)} help items")
            
            # Test search functionality
            search_results = help_provider.search_help("password")
            print(f"   - {len(search_results)} results for 'password' search")
            
        except Exception as e:
            print(f"❌ Contextual help failed: {e}")
            return False
        
        # Test 6: Configuration Management
        print("\n🔍 Test 6: Configuration Management")
        try:
            from compliance_sentinel.config.config_manager import ConfigManager
            
            config_manager = ConfigManager(temp_path / ".compliance-sentinel")
            
            # Create and save configuration
            config = config_manager.create_default_config("test-workflow")
            success = config_manager.save_project_config(config)
            
            if success:
                # Load and validate
                loaded_config = config_manager.load_project_config()
                
                print(f"✅ Configuration management:")
                print(f"   - Project: {loaded_config.project_name}")
                print(f"   - Custom rules: {len(loaded_config.custom_rules)}")
                print(f"   - MCP servers: {len(loaded_config.mcp_servers)}")
            else:
                print(f"❌ Configuration save failed")
                return False
            
        except Exception as e:
            print(f"❌ Configuration management failed: {e}")
            return False
        
        # Test 7: Progress Tracking
        print("\n🔍 Test 7: Progress Tracking")
        try:
            from compliance_sentinel.ide.progress_indicators import (
                ProgressTracker, ProgressType, ProgressStep, ProgressManager
            )
            
            # Test progress manager
            manager = ProgressManager()
            tracker = manager.create_tracker(
                "workflow-test",
                "Workflow Test",
                "Testing comprehensive workflow",
                ProgressType.DETERMINATE
            )
            
            # Add steps
            steps = [
                ProgressStep("analysis", "Security Analysis", "Running security analysis"),
                ProgressStep("feedback", "Feedback Generation", "Generating IDE feedback"),
                ProgressStep("reporting", "Report Generation", "Creating analysis report")
            ]
            tracker.add_steps(steps)
            
            # Simulate workflow
            tracker.start()
            
            for step in steps:
                tracker.start_step(step.id)
                await asyncio.sleep(0.05)  # Simulate work
                tracker.complete_step(step.id)
            
            tracker.complete()
            
            # Get final progress
            info = tracker.get_progress_info()
            
            print(f"✅ Progress tracking:")
            print(f"   - Progress: {info.percentage}%")
            print(f"   - Duration: {info.elapsed_time:.3f}s")
            print(f"   - Steps completed: {info.current_step}/{info.total_steps}")
            
        except Exception as e:
            print(f"❌ Progress tracking failed: {e}")
            return False
        
        print(f"\n🎉 End-to-End Workflow Test Completed Successfully!")
        return True

async def test_performance_workflow():
    """Test performance aspects of the workflow."""
    print("\n⚡ Testing Performance Workflow")
    print("=" * 40)
    
    try:
        # Test with larger dataset
        from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
        from compliance_sentinel.ide.feedback_formatter import IDEFeedbackFormatter, IDEType
        from datetime import datetime
        import uuid
        
        # Create many issues to test performance
        start_time = time.time()
        
        issues = []
        for i in range(100):  # Create 100 issues
            issues.append(SecurityIssue(
                id=str(uuid.uuid4()),
                severity=Severity.HIGH if i % 2 == 0 else Severity.MEDIUM,
                category=SecurityCategory.HARDCODED_SECRETS,
                file_path=f"test_file_{i}.py",
                line_number=i + 1,
                description=f"Test security issue {i}",
                rule_id=f"TEST-{i:03d}",
                confidence=0.8,
                remediation_suggestions=[f"Fix issue {i}"],
                created_at=datetime.now()
            ))
        
        creation_time = time.time() - start_time
        
        # Test feedback generation performance
        start_time = time.time()
        formatter = IDEFeedbackFormatter(IDEType.KIRO)
        feedback = formatter.format_issues(issues)
        formatting_time = time.time() - start_time
        
        print(f"✅ Performance test results:")
        print(f"   - Created {len(issues)} issues in {creation_time:.3f}s")
        print(f"   - Generated feedback in {formatting_time:.3f}s")
        print(f"   - {len(feedback.diagnostics)} diagnostics generated")
        print(f"   - {len(feedback.quick_fixes)} quick fixes generated")
        
        return True
        
    except Exception as e:
        print(f"❌ Performance test failed: {e}")
        return False

async def main():
    """Run comprehensive workflow tests."""
    print("🚀 Compliance Sentinel Comprehensive Workflow Test")
    print("=" * 60)
    
    start_time = time.time()
    
    # Run tests
    tests = [
        test_end_to_end_workflow(),
        test_performance_workflow(),
    ]
    
    results = await asyncio.gather(*tests, return_exceptions=True)
    
    # Calculate results
    total_time = time.time() - start_time
    passed = sum(1 for r in results if r is True)
    total = len(results)
    
    # Handle exceptions
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"❌ Test {i+1} crashed: {result}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 Comprehensive Workflow Test Summary")
    print("=" * 60)
    print(f"Tests Passed: {passed}/{total}")
    print(f"Success Rate: {passed/total:.1%}")
    print(f"Total Time: {total_time:.2f} seconds")
    
    if passed == total:
        print("\n🎉 All comprehensive workflow tests passed!")
        print("✅ Compliance Sentinel is fully functional!")
        return 0
    else:
        print(f"\n⚠️ {total - passed} test(s) failed.")
        return 1

if __name__ == "__main__":
    exit(asyncio.run(main()))