"""Integration tests for Compliance Sentinel."""

import pytest
import tempfile
import os
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
from compliance_sentinel.analyzers.languages.base import ProgrammingLanguage


class TestEndToEndWorkflow:
    """Test complete end-to-end workflows."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.test_project_files = {
            "src/main.py": '''
import os
import hashlib

# Hardcoded secret - should be detected
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

def authenticate_user(username, password):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    return execute_query(query)

def hash_password(password):
    # Weak cryptography
    return hashlib.md5(password.encode()).hexdigest()

def process_user_input(user_data):
    # Command injection risk
    os.system(f"echo {user_data}")
    return True
''',
            "src/utils.js": '''
function displayUserData(userData) {
    // XSS vulnerability
    document.getElementById("content").innerHTML = userData;
}

function makeApiCall(endpoint, data) {
    // Insecure HTTP usage
    fetch("http://api.example.com/" + endpoint, {
        method: "POST",
        body: JSON.stringify(data)
    });
}

// Hardcoded token
const AUTH_TOKEN = "bearer_token_12345";
''',
            "config/database.yml": '''
production:
  host: localhost
  username: admin
  password: "production_password_123"  # Should be detected
  database: myapp_production
''',
            "requirements.txt": '''
django==2.0.1  # Known vulnerability
requests==2.18.0  # Outdated version
flask==0.12.0  # Security issues
''',
            "README.md": '''
# Test Project

This is a test project for security scanning.
''',
            ".env.example": '''
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=your_api_key_here
SECRET_KEY=your_secret_key_here
'''
        }
    
    def test_complete_project_scan(self):
        """Test scanning a complete project structure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create project structure
            for file_path, content in self.test_project_files.items():
                full_path = Path(temp_dir) / file_path
                full_path.parent.mkdir(parents=True, exist_ok=True)
                with open(full_path, 'w') as f:
                    f.write(content)
            
            # Mock the main analyzer
            class MockProjectAnalyzer:
                def scan_project(self, project_path: str):
                    issues = []
                    
                    # Simulate finding various security issues
                    issues.extend([
                        SecurityIssue(
                            id="hardcoded_secret_001",
                            severity=Severity.HIGH,
                            category=SecurityCategory.HARDCODED_SECRETS,
                            file_path="src/main.py",
                            line_number=5,
                            description="Hardcoded API key detected",
                            rule_id="hardcoded_secrets",
                            confidence=0.95,
                            remediation_suggestions=["Use environment variables"],
                            created_at=datetime.now()
                        ),
                        SecurityIssue(
                            id="sql_injection_001",
                            severity=Severity.CRITICAL,
                            category=SecurityCategory.INJECTION,
                            file_path="src/main.py",
                            line_number=9,
                            description="SQL injection vulnerability",
                            rule_id="sql_injection",
                            confidence=0.9,
                            remediation_suggestions=["Use parameterized queries"],
                            created_at=datetime.now()
                        ),
                        SecurityIssue(
                            id="weak_crypto_001",
                            severity=Severity.MEDIUM,
                            category=SecurityCategory.INSECURE_CRYPTO,
                            file_path="src/main.py",
                            line_number=13,
                            description="Weak hashing algorithm (MD5)",
                            rule_id="weak_crypto",
                            confidence=0.85,
                            remediation_suggestions=["Use SHA-256 or stronger"],
                            created_at=datetime.now()
                        ),
                        SecurityIssue(
                            id="xss_001",
                            severity=Severity.HIGH,
                            category=SecurityCategory.XSS,
                            file_path="src/utils.js",
                            line_number=3,
                            description="XSS vulnerability in innerHTML",
                            rule_id="xss_detection",
                            confidence=0.8,
                            remediation_suggestions=["Use textContent or sanitize input"],
                            created_at=datetime.now()
                        ),
                        SecurityIssue(
                            id="insecure_transport_001",
                            severity=Severity.MEDIUM,
                            category=SecurityCategory.INSECURE_TRANSPORT,
                            file_path="src/utils.js",
                            line_number=8,
                            description="Insecure HTTP protocol usage",
                            rule_id="insecure_transport",
                            confidence=0.9,
                            remediation_suggestions=["Use HTTPS instead of HTTP"],
                            created_at=datetime.now()
                        )
                    ])
                    
                    return {
                        "issues": issues,
                        "summary": {
                            "total_issues": len(issues),
                            "critical": len([i for i in issues if i.severity == Severity.CRITICAL]),
                            "high": len([i for i in issues if i.severity == Severity.HIGH]),
                            "medium": len([i for i in issues if i.severity == Severity.MEDIUM]),
                            "low": len([i for i in issues if i.severity == Severity.LOW]),
                            "files_scanned": len(self.test_project_files),
                            "scan_duration": 2.5
                        }
                    }
            
            analyzer = MockProjectAnalyzer()
            results = analyzer.scan_project(temp_dir)
            
            # Verify scan results
            assert "issues" in results
            assert "summary" in results
            
            issues = results["issues"]
            summary = results["summary"]
            
            # Check issue counts
            assert len(issues) == 5
            assert summary["total_issues"] == 5
            assert summary["critical"] == 1
            assert summary["high"] == 2
            assert summary["medium"] == 2
            assert summary["low"] == 0
            
            # Verify issue categories
            categories = [issue.category for issue in issues]
            assert SecurityCategory.HARDCODED_SECRETS in categories
            assert SecurityCategory.INJECTION in categories
            assert SecurityCategory.INSECURE_CRYPTO in categories
            assert SecurityCategory.XSS in categories
            assert SecurityCategory.INSECURE_TRANSPORT in categories
            
            # Verify file coverage
            files_with_issues = set(issue.file_path for issue in issues)
            assert "src/main.py" in files_with_issues
            assert "src/utils.js" in files_with_issues
    
    def test_git_integration_workflow(self):
        """Test Git integration workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Initialize git repo
            os.system(f"cd {temp_dir} && git init")
            
            # Create test files
            test_file = Path(temp_dir) / "test.py"
            with open(test_file, 'w') as f:
                f.write('''
def login():
    password = "hardcoded_secret"  # Security issue
    return authenticate(password)
''')
            
            # Mock Git hook integration
            class MockGitHooks:
                def __init__(self, repo_path):
                    self.repo_path = repo_path
                    self.installed_hooks = []
                
                def install_pre_commit_hook(self):
                    hook_path = Path(self.repo_path) / ".git" / "hooks" / "pre-commit"
                    hook_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    hook_content = '''#!/bin/bash
# Compliance Sentinel pre-commit hook
python -m compliance_sentinel.git_integration.pre_commit_scan
'''
                    with open(hook_path, 'w') as f:
                        f.write(hook_content)
                    
                    os.chmod(hook_path, 0o755)
                    self.installed_hooks.append("pre-commit")
                    return True
                
                def scan_staged_files(self):
                    # Mock scanning staged files
                    return [
                        SecurityIssue(
                            id="git_scan_001",
                            severity=Severity.HIGH,
                            category=SecurityCategory.HARDCODED_SECRETS,
                            file_path="test.py",
                            line_number=3,
                            description="Hardcoded password in staged file",
                            rule_id="hardcoded_secrets",
                            confidence=0.9,
                            remediation_suggestions=["Use environment variables"],
                            created_at=datetime.now()
                        )
                    ]
            
            git_hooks = MockGitHooks(temp_dir)
            
            # Install hooks
            assert git_hooks.install_pre_commit_hook() is True
            assert "pre-commit" in git_hooks.installed_hooks
            
            # Verify hook file exists
            hook_file = Path(temp_dir) / ".git" / "hooks" / "pre-commit"
            assert hook_file.exists()
            assert os.access(hook_file, os.X_OK)  # Executable
            
            # Test staged file scanning
            issues = git_hooks.scan_staged_files()
            assert len(issues) == 1
            assert issues[0].category == SecurityCategory.HARDCODED_SECRETS
            assert issues[0].severity == Severity.HIGH
    
    def test_ci_cd_integration(self):
        """Test CI/CD pipeline integration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create project structure
            project_files = {
                "src/app.py": '''
import os
API_KEY = "sk-test-key-123"  # Hardcoded secret

def process_data(user_input):
    os.system(f"process {user_input}")  # Command injection
''',
                ".github/workflows/security.yml": '''
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Compliance Sentinel
        run: |
          pip install compliance-sentinel
          compliance-sentinel scan --format json --output security-report.json
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security-report.json
''',
                "Jenkinsfile": '''
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'compliance-sentinel scan --fail-on-high'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-report.json'
                }
            }
        }
    }
}
'''
            }
            
            for file_path, content in project_files.items():
                full_path = Path(temp_dir) / file_path
                full_path.parent.mkdir(parents=True, exist_ok=True)
                with open(full_path, 'w') as f:
                    f.write(content)
            
            # Mock CI/CD scanner
            class MockCIPipeline:
                def __init__(self, project_path):
                    self.project_path = project_path
                
                def run_security_scan(self, fail_on_high=False):
                    issues = [
                        SecurityIssue(
                            id="ci_scan_001",
                            severity=Severity.HIGH,
                            category=SecurityCategory.HARDCODED_SECRETS,
                            file_path="src/app.py",
                            line_number=2,
                            description="Hardcoded API key",
                            rule_id="hardcoded_secrets",
                            confidence=0.95,
                            remediation_suggestions=["Use environment variables"],
                            created_at=datetime.now()
                        ),
                        SecurityIssue(
                            id="ci_scan_002",
                            severity=Severity.CRITICAL,
                            category=SecurityCategory.INJECTION,
                            file_path="src/app.py",
                            line_number=5,
                            description="Command injection vulnerability",
                            rule_id="command_injection",
                            confidence=0.9,
                            remediation_suggestions=["Use subprocess with shell=False"],
                            created_at=datetime.now()
                        )
                    ]
                    
                    high_or_critical = [i for i in issues 
                                      if i.severity in [Severity.HIGH, Severity.CRITICAL]]
                    
                    if fail_on_high and high_or_critical:
                        return {
                            "success": False,
                            "issues": issues,
                            "exit_code": 1,
                            "message": f"Found {len(high_or_critical)} high/critical issues"
                        }
                    
                    return {
                        "success": True,
                        "issues": issues,
                        "exit_code": 0,
                        "message": "Scan completed successfully"
                    }
                
                def generate_report(self, issues, format="json"):
                    if format == "json":
                        return json.dumps({
                            "scan_results": {
                                "timestamp": datetime.now().isoformat(),
                                "total_issues": len(issues),
                                "issues": [
                                    {
                                        "id": issue.id,
                                        "severity": issue.severity.value,
                                        "category": issue.category.value,
                                        "file_path": issue.file_path,
                                        "line_number": issue.line_number,
                                        "description": issue.description,
                                        "rule_id": issue.rule_id,
                                        "confidence": issue.confidence
                                    }
                                    for issue in issues
                                ]
                            }
                        }, indent=2)
                    
                    return "Report format not supported"
            
            pipeline = MockCIPipeline(temp_dir)
            
            # Test successful scan
            result = pipeline.run_security_scan(fail_on_high=False)
            assert result["success"] is True
            assert result["exit_code"] == 0
            assert len(result["issues"]) == 2
            
            # Test failing scan with high severity issues
            result = pipeline.run_security_scan(fail_on_high=True)
            assert result["success"] is False
            assert result["exit_code"] == 1
            assert "high/critical issues" in result["message"]
            
            # Test report generation
            report = pipeline.generate_report(result["issues"], format="json")
            report_data = json.loads(report)
            
            assert "scan_results" in report_data
            assert report_data["scan_results"]["total_issues"] == 2
            assert len(report_data["scan_results"]["issues"]) == 2
    
    def test_real_time_monitoring(self):
        """Test real-time file monitoring."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock file watcher
            class MockFileWatcher:
                def __init__(self, watch_path):
                    self.watch_path = watch_path
                    self.watched_files = set()
                    self.scan_results = {}
                
                def add_watch(self, file_path):
                    self.watched_files.add(file_path)
                
                def simulate_file_change(self, file_path, content):
                    if file_path in self.watched_files:
                        # Simulate real-time scanning
                        issues = []
                        
                        if "password" in content.lower():
                            issues.append(SecurityIssue(
                                id=f"realtime_{hash(content) % 1000}",
                                severity=Severity.HIGH,
                                category=SecurityCategory.HARDCODED_SECRETS,
                                file_path=file_path,
                                line_number=1,
                                description="Potential hardcoded secret detected",
                                rule_id="realtime_secrets",
                                confidence=0.8,
                                remediation_suggestions=["Review and use environment variables"],
                                created_at=datetime.now()
                            ))
                        
                        self.scan_results[file_path] = issues
                        return issues
                    
                    return []
                
                def get_scan_results(self, file_path):
                    return self.scan_results.get(file_path, [])
            
            watcher = MockFileWatcher(temp_dir)
            
            # Add files to watch
            test_files = ["src/main.py", "src/utils.py", "config/settings.py"]
            for file_path in test_files:
                watcher.add_watch(file_path)
            
            assert len(watcher.watched_files) == 3
            
            # Simulate file changes
            safe_content = '''
def calculate_total(items):
    return sum(item.price for item in items)
'''
            
            unsafe_content = '''
def authenticate():
    password = "admin123"  # Hardcoded password
    return check_auth(password)
'''
            
            # Test safe content
            issues = watcher.simulate_file_change("src/main.py", safe_content)
            assert len(issues) == 0
            
            # Test unsafe content
            issues = watcher.simulate_file_change("src/utils.py", unsafe_content)
            assert len(issues) == 1
            assert issues[0].category == SecurityCategory.HARDCODED_SECRETS
            assert issues[0].severity == Severity.HIGH
            
            # Verify results are stored
            stored_results = watcher.get_scan_results("src/utils.py")
            assert len(stored_results) == 1
            assert stored_results[0].id == issues[0].id
    
    def test_configuration_management(self):
        """Test configuration management integration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create configuration files
            config_files = {
                "compliance_sentinel.yml": '''
scan:
  enabled_analyzers:
    - secrets
    - injection
    - xss
    - crypto
  severity_threshold: medium
  exclude_patterns:
    - "*.test.js"
    - "test_*.py"
    - "node_modules/**"
  
rules:
  hardcoded_secrets:
    enabled: true
    severity: high
    patterns:
      - "(password|secret|key|token)\\s*=\\s*[\"'][^\"']{3,}[\"']"
  
  sql_injection:
    enabled: true
    severity: critical
    patterns:
      - "SELECT.*\\+.*"
      - "INSERT.*\\+.*"

reporting:
  formats:
    - json
    - html
  output_directory: "./security-reports"
  include_remediation: true
''',
                "custom_rules.yml": '''
custom_rules:
  - id: "custom_api_key"
    name: "Custom API Key Detection"
    pattern: "api[_-]?key\\s*=\\s*[\"'][a-zA-Z0-9]{20,}[\"']"
    severity: "high"
    category: "hardcoded_secrets"
    description: "Custom API key pattern detected"
    remediation: "Store API keys in environment variables"
  
  - id: "custom_sql_pattern"
    name: "Custom SQL Injection Pattern"
    pattern: "execute\\(.*\\+.*\\)"
    severity: "critical"
    category: "injection"
    description: "Potential SQL injection in execute statement"
    remediation: "Use parameterized queries"
'''
            }
            
            for file_path, content in config_files.items():
                full_path = Path(temp_dir) / file_path
                with open(full_path, 'w') as f:
                    f.write(content)
            
            # Mock configuration manager
            class MockConfigManager:
                def __init__(self, config_path):
                    self.config_path = config_path
                    self.config = {}
                    self.custom_rules = []
                
                def load_config(self):
                    import yaml
                    
                    # Load main config
                    config_file = Path(self.config_path) / "compliance_sentinel.yml"
                    if config_file.exists():
                        with open(config_file, 'r') as f:
                            self.config = yaml.safe_load(f)
                    
                    # Load custom rules
                    rules_file = Path(self.config_path) / "custom_rules.yml"
                    if rules_file.exists():
                        with open(rules_file, 'r') as f:
                            rules_data = yaml.safe_load(f)
                            self.custom_rules = rules_data.get('custom_rules', [])
                    
                    return True
                
                def get_enabled_analyzers(self):
                    return self.config.get('scan', {}).get('enabled_analyzers', [])
                
                def get_severity_threshold(self):
                    threshold_str = self.config.get('scan', {}).get('severity_threshold', 'low')
                    threshold_map = {
                        'low': Severity.LOW,
                        'medium': Severity.MEDIUM,
                        'high': Severity.HIGH,
                        'critical': Severity.CRITICAL
                    }
                    return threshold_map.get(threshold_str, Severity.LOW)
                
                def get_exclude_patterns(self):
                    return self.config.get('scan', {}).get('exclude_patterns', [])
                
                def get_custom_rules(self):
                    return self.custom_rules
                
                def validate_config(self):
                    required_sections = ['scan', 'rules', 'reporting']
                    for section in required_sections:
                        if section not in self.config:
                            return False, f"Missing required section: {section}"
                    
                    return True, "Configuration is valid"
            
            config_manager = MockConfigManager(temp_dir)
            
            # Test configuration loading
            assert config_manager.load_config() is True
            
            # Test configuration access
            enabled_analyzers = config_manager.get_enabled_analyzers()
            assert 'secrets' in enabled_analyzers
            assert 'injection' in enabled_analyzers
            assert 'xss' in enabled_analyzers
            assert 'crypto' in enabled_analyzers
            
            # Test severity threshold
            threshold = config_manager.get_severity_threshold()
            assert threshold == Severity.MEDIUM
            
            # Test exclude patterns
            exclude_patterns = config_manager.get_exclude_patterns()
            assert "*.test.js" in exclude_patterns
            assert "test_*.py" in exclude_patterns
            assert "node_modules/**" in exclude_patterns
            
            # Test custom rules
            custom_rules = config_manager.get_custom_rules()
            assert len(custom_rules) == 2
            
            api_key_rule = next((r for r in custom_rules if r['id'] == 'custom_api_key'), None)
            assert api_key_rule is not None
            assert api_key_rule['severity'] == 'high'
            assert api_key_rule['category'] == 'hardcoded_secrets'
            
            # Test configuration validation
            is_valid, message = config_manager.validate_config()
            assert is_valid is True
            assert message == "Configuration is valid"


if __name__ == "__main__":
    pytest.main([__file__])