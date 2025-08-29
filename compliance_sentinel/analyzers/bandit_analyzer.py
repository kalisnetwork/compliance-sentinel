"""Bandit security analyzer integration for Python code analysis."""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import logging

from compliance_sentinel.core.interfaces import (
    SecurityAnalyzer,
    SecurityIssue,
    SecurityCategory,
    Severity
)
from compliance_sentinel.utils.error_handler import (
    get_global_error_handler,
    retry_with_backoff,
    RetryStrategy
)
from compliance_sentinel.utils.cache import get_global_cache
from compliance_sentinel.core.validation import InputSanitizer
from datetime import datetime


logger = logging.getLogger(__name__)


@dataclass
class BanditConfig:
    """Configuration for Bandit analyzer."""
    config_file: Optional[str] = None
    excluded_paths: List[str] = None
    skipped_tests: List[str] = None
    confidence_level: str = "low"  # low, medium, high
    severity_level: str = "low"    # low, medium, high
    format_output: str = "json"
    recursive: bool = True
    aggregate_results: bool = True
    
    def __post_init__(self):
        if self.excluded_paths is None:
            self.excluded_paths = [
                "*/tests/*", "*/test/*", "*_test.py", "test_*.py",
                "*/venv/*", "*/env/*", "*/.venv/*"
            ]
        
        if self.skipped_tests is None:
            # Skip some tests that might be too noisy
            self.skipped_tests = ["B101"]  # Skip assert_used test


class BanditAnalyzer(SecurityAnalyzer):
    """Bandit-based security analyzer for Python code."""
    
    # Mapping of Bandit test IDs to our security categories
    BANDIT_CATEGORY_MAPPING = {
        # Hardcoded secrets and passwords
        "B105": SecurityCategory.HARDCODED_SECRETS,  # hardcoded_password_string
        "B106": SecurityCategory.HARDCODED_SECRETS,  # hardcoded_password_funcarg
        "B107": SecurityCategory.HARDCODED_SECRETS,  # hardcoded_password_default
        
        # Cryptographic issues
        "B303": SecurityCategory.INSECURE_CRYPTO,    # md5
        "B324": SecurityCategory.INSECURE_CRYPTO,    # hashlib_new_insecure_functions
        "B325": SecurityCategory.INSECURE_CRYPTO,    # tempfile
        "B501": SecurityCategory.INSECURE_CRYPTO,    # request_with_no_cert_validation
        "B502": SecurityCategory.INSECURE_CRYPTO,    # ssl_with_bad_version
        "B503": SecurityCategory.INSECURE_CRYPTO,    # ssl_with_bad_defaults
        "B504": SecurityCategory.INSECURE_CRYPTO,    # ssl_with_no_version
        "B505": SecurityCategory.INSECURE_CRYPTO,    # weak_cryptographic_key
        "B506": SecurityCategory.INSECURE_CRYPTO,    # yaml_load
        "B507": SecurityCategory.INSECURE_CRYPTO,    # ssh_no_host_key_verification
        
        # SQL Injection
        "B608": SecurityCategory.SQL_INJECTION,      # hardcoded_sql_expressions
        
        # Input validation and injection
        "B102": SecurityCategory.INPUT_VALIDATION,   # exec_used
        "B301": SecurityCategory.INPUT_VALIDATION,   # pickle
        "B302": SecurityCategory.INPUT_VALIDATION,   # marshal
        "B307": SecurityCategory.INPUT_VALIDATION,   # eval
        "B308": SecurityCategory.INPUT_VALIDATION,   # mark_safe
        "B309": SecurityCategory.INPUT_VALIDATION,   # httpsconnection
        "B310": SecurityCategory.INPUT_VALIDATION,   # urllib_urlopen
        "B311": SecurityCategory.INPUT_VALIDATION,   # random
        "B312": SecurityCategory.INPUT_VALIDATION,   # telnetlib
        "B313": SecurityCategory.INPUT_VALIDATION,   # xml_bad_cElementTree
        "B314": SecurityCategory.INPUT_VALIDATION,   # xml_bad_ElementTree
        "B315": SecurityCategory.INPUT_VALIDATION,   # xml_bad_expatreader
        "B316": SecurityCategory.INPUT_VALIDATION,   # xml_bad_expatbuilder
        "B317": SecurityCategory.INPUT_VALIDATION,   # xml_bad_sax
        "B318": SecurityCategory.INPUT_VALIDATION,   # xml_bad_minidom
        "B319": SecurityCategory.INPUT_VALIDATION,   # xml_bad_pulldom
        "B320": SecurityCategory.INPUT_VALIDATION,   # xml_bad_etree
        
        # Authentication and authorization
        "B104": SecurityCategory.AUTHENTICATION,     # hardcoded_bind_all_interfaces
        "B108": SecurityCategory.AUTHENTICATION,     # hardcoded_tmp_directory
        "B109": SecurityCategory.AUTHENTICATION,     # password_config_option_not_marked_secret
        
        # Default fallback
        "default": SecurityCategory.INPUT_VALIDATION
    }
    
    # Mapping of Bandit severity to our severity levels
    BANDIT_SEVERITY_MAPPING = {
        "LOW": Severity.LOW,
        "MEDIUM": Severity.MEDIUM,
        "HIGH": Severity.HIGH,
        "UNDEFINED": Severity.LOW
    }
    
    def __init__(self, config: Optional[BanditConfig] = None):
        """Initialize Bandit analyzer with configuration."""
        self.config = config or BanditConfig()
        self.cache = get_global_cache()
        self.error_handler = get_global_error_handler()
        
        # Verify Bandit is available
        self._verify_bandit_installation()
        
        logger.info("Initialized Bandit analyzer")
    
    def _verify_bandit_installation(self) -> None:
        """Verify that Bandit is installed and accessible."""
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Bandit version: {result.stdout.strip()}")
            else:
                raise RuntimeError("Bandit not properly installed")
        except (subprocess.TimeoutExpired, FileNotFoundError, RuntimeError) as e:
            logger.error(f"Bandit installation check failed: {e}")
            raise RuntimeError(
                "Bandit is not installed or not accessible. "
                "Please install it with: pip install bandit[toml]"
            )
    
    def analyze_file(self, file_path: str) -> List[SecurityIssue]:
        """Analyze a single Python file for security issues."""
        file_path_obj = Path(file_path)
        
        # Validate file
        if not file_path_obj.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not file_path_obj.suffix == '.py':
            logger.warning(f"Bandit analyzer only supports Python files, skipping: {file_path}")
            return []
        
        # Check cache first
        cache_key = f"bandit_analysis:{file_path}:{file_path_obj.stat().st_mtime}"
        cached_result = self.cache.get(cache_key)
        if cached_result:
            logger.debug(f"Using cached Bandit results for {file_path}")
            return cached_result
        
        try:
            # Run Bandit analysis
            bandit_results = self._run_bandit_analysis(file_path)
            
            # Convert to SecurityIssue objects
            security_issues = self._convert_bandit_results(bandit_results, file_path)
            
            # Cache results
            self.cache.set(cache_key, security_issues, ttl=3600)  # Cache for 1 hour
            
            logger.info(f"Bandit analysis completed for {file_path}: {len(security_issues)} issues found")
            return security_issues
            
        except Exception as e:
            logger.error(f"Bandit analysis failed for {file_path}: {e}")
            self.error_handler.handle_analysis_error(e, f"bandit_analysis:{file_path}")
            return []
    
    @retry_with_backoff(
        strategy=RetryStrategy(max_attempts=2, base_delay=1.0),
        exceptions=(subprocess.TimeoutExpired, subprocess.CalledProcessError)
    )
    def _run_bandit_analysis(self, file_path: str) -> Dict[str, Any]:
        """Run Bandit analysis on a file and return results."""
        cmd = self._build_bandit_command(file_path)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,  # 1 minute timeout
                cwd=Path.cwd()
            )
            
            # Bandit returns non-zero exit code when issues are found
            # Only treat it as error if it's a real failure (exit code > 1)
            if result.returncode > 1:
                logger.error(f"Bandit command failed: {result.stderr}")
                raise subprocess.CalledProcessError(result.returncode, cmd, result.stderr)
            
            # Parse JSON output
            if result.stdout.strip():
                return json.loads(result.stdout)
            else:
                # No issues found
                return {"results": [], "metrics": {}}
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Bandit JSON output: {e}")
            logger.debug(f"Bandit stdout: {result.stdout}")
            logger.debug(f"Bandit stderr: {result.stderr}")
            raise
        except subprocess.TimeoutExpired:
            logger.warning(f"Bandit analysis timed out for {file_path}")
            raise
    
    def _build_bandit_command(self, file_path: str) -> List[str]:
        """Build Bandit command with appropriate options."""
        cmd = ["bandit"]
        
        # Output format
        cmd.extend(["-f", self.config.format_output])
        
        # Confidence and severity levels
        cmd.extend(["-i", self.config.confidence_level])
        cmd.extend(["-l", self.config.severity_level])
        
        # Skip tests if configured
        if self.config.skipped_tests:
            cmd.extend(["-s", ",".join(self.config.skipped_tests)])
        
        # Exclude paths if configured
        if self.config.excluded_paths:
            for exclude_path in self.config.excluded_paths:
                cmd.extend(["-x", exclude_path])
        
        # Configuration file
        if self.config.config_file and Path(self.config.config_file).exists():
            cmd.extend(["-c", self.config.config_file])
        
        # Recursive analysis
        if self.config.recursive:
            cmd.append("-r")
        
        # Aggregate results
        if self.config.aggregate_results:
            cmd.append("-a")
        
        # Target file
        cmd.append(file_path)
        
        logger.debug(f"Bandit command: {' '.join(cmd)}")
        return cmd
    
    def _convert_bandit_results(self, bandit_results: Dict[str, Any], file_path: str) -> List[SecurityIssue]:
        """Convert Bandit results to SecurityIssue objects."""
        security_issues = []
        
        results = bandit_results.get("results", [])
        
        for result in results:
            try:
                # Extract issue information
                test_id = result.get("test_id", "unknown")
                test_name = result.get("test_name", "Unknown Test")
                issue_severity = result.get("issue_severity", "LOW")
                issue_confidence = result.get("issue_confidence", "LOW")
                issue_text = result.get("issue_text", "Security issue detected")
                line_number = result.get("line_number", 1)
                line_range = result.get("line_range", [line_number])
                code = result.get("code", "")
                
                # Map to our categories and severity
                category = self.BANDIT_CATEGORY_MAPPING.get(test_id, SecurityCategory.INPUT_VALIDATION)
                severity = self.BANDIT_SEVERITY_MAPPING.get(issue_severity, Severity.LOW)
                
                # Calculate confidence score
                confidence = self._calculate_confidence_score(issue_confidence, test_id, code)
                
                # Generate remediation suggestions
                remediation_suggestions = self._generate_remediation_suggestions(test_id, test_name, code)
                
                # Create SecurityIssue
                security_issue = SecurityIssue(
                    id=f"BANDIT_{test_id}_{line_number}",
                    severity=severity,
                    category=category,
                    file_path=file_path,
                    line_number=line_number,
                    description=f"{test_name}: {issue_text}",
                    rule_id=f"BANDIT_{test_id}",
                    confidence=confidence,
                    remediation_suggestions=remediation_suggestions,
                    created_at=datetime.utcnow()
                )
                
                security_issues.append(security_issue)
                
            except Exception as e:
                logger.warning(f"Error processing Bandit result: {e}")
                logger.debug(f"Problematic result: {result}")
                continue
        
        return security_issues
    
    def _calculate_confidence_score(self, bandit_confidence: str, test_id: str, code: str) -> float:
        """Calculate confidence score based on Bandit confidence and context."""
        # Base confidence from Bandit
        base_confidence = {
            "HIGH": 0.9,
            "MEDIUM": 0.7,
            "LOW": 0.5,
            "UNDEFINED": 0.3
        }.get(bandit_confidence, 0.5)
        
        # Adjust based on test type reliability
        high_reliability_tests = ["B105", "B106", "B107", "B501", "B502"]  # Hardcoded secrets, SSL issues
        medium_reliability_tests = ["B303", "B324", "B608"]  # Crypto, SQL
        
        if test_id in high_reliability_tests:
            base_confidence += 0.1
        elif test_id in medium_reliability_tests:
            pass  # No adjustment
        else:
            base_confidence -= 0.1
        
        # Adjust based on code context
        if code:
            code_lower = code.lower()
            
            # Increase confidence for clear violations
            if any(keyword in code_lower for keyword in ['password', 'secret', 'key', 'token']):
                base_confidence += 0.1
            
            # Decrease confidence for test/example code
            if any(keyword in code_lower for keyword in ['test', 'example', 'demo', 'mock']):
                base_confidence -= 0.2
            
            # Decrease confidence for comments
            if code.strip().startswith('#'):
                base_confidence -= 0.3
        
        return max(0.1, min(1.0, base_confidence))
    
    def _generate_remediation_suggestions(self, test_id: str, test_name: str, code: str) -> List[str]:
        """Generate remediation suggestions based on Bandit test ID."""
        suggestions = []
        
        # Test-specific suggestions
        remediation_map = {
            "B105": [
                "Move hardcoded passwords to environment variables",
                "Use a secure secret management system like HashiCorp Vault",
                "Never commit secrets to version control"
            ],
            "B106": [
                "Avoid hardcoded passwords in function arguments",
                "Use configuration files or environment variables",
                "Implement proper secret injection mechanisms"
            ],
            "B107": [
                "Remove hardcoded password defaults",
                "Use None as default and require explicit configuration",
                "Implement secure password prompting"
            ],
            "B303": [
                "Replace MD5 with SHA-256 or stronger hash functions",
                "Use bcrypt, scrypt, or Argon2 for password hashing",
                "Consider cryptographic libraries like cryptography"
            ],
            "B324": [
                "Use secure hash functions (SHA-256, SHA-3)",
                "Avoid deprecated cryptographic functions",
                "Update to modern cryptographic libraries"
            ],
            "B501": [
                "Enable SSL certificate verification",
                "Set verify=True in requests",
                "Use proper CA certificate bundles"
            ],
            "B502": [
                "Use TLS 1.2 or higher",
                "Avoid deprecated SSL/TLS versions",
                "Configure secure SSL context"
            ],
            "B608": [
                "Use parameterized queries or prepared statements",
                "Validate and sanitize all user inputs",
                "Use ORM frameworks with built-in SQL injection protection"
            ],
            "B102": [
                "Avoid using exec() with user input",
                "Use safer alternatives like ast.literal_eval()",
                "Implement proper input validation and sanitization"
            ],
            "B307": [
                "Avoid using eval() with user input",
                "Use ast.literal_eval() for safe evaluation",
                "Implement proper parsing instead of evaluation"
            ]
        }
        
        if test_id in remediation_map:
            suggestions.extend(remediation_map[test_id][:2])  # Top 2 suggestions
        else:
            # Generic suggestions based on category
            suggestions.append(f"Review and fix the {test_name.lower()} issue")
            suggestions.append("Follow security best practices for this type of vulnerability")
        
        # Add general security suggestion
        suggestions.append("Refer to OWASP guidelines for secure coding practices")
        
        return suggestions[:3]  # Limit to 3 suggestions
    
    def get_supported_file_types(self) -> List[str]:
        """Return list of supported file extensions."""
        return ['.py']
    
    def configure_rules(self, rules: List[str]) -> None:
        """Configure custom Bandit rules."""
        # Update skipped tests based on rules
        if rules:
            # Rules format: ["skip:B101", "include:B105", "severity:high"]
            for rule in rules:
                if rule.startswith("skip:"):
                    test_id = rule[5:]
                    if test_id not in self.config.skipped_tests:
                        self.config.skipped_tests.append(test_id)
                elif rule.startswith("include:"):
                    test_id = rule[8:]
                    if test_id in self.config.skipped_tests:
                        self.config.skipped_tests.remove(test_id)
                elif rule.startswith("severity:"):
                    severity = rule[9:]
                    if severity in ["low", "medium", "high"]:
                        self.config.severity_level = severity
                elif rule.startswith("confidence:"):
                    confidence = rule[11:]
                    if confidence in ["low", "medium", "high"]:
                        self.config.confidence_level = confidence
        
        logger.info(f"Updated Bandit configuration with {len(rules)} rules")
    
    def analyze_directory(self, directory_path: str, file_patterns: List[str] = None) -> List[SecurityIssue]:
        """Analyze all Python files in a directory."""
        directory = Path(directory_path)
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Directory not found: {directory_path}")
        
        patterns = file_patterns or ["**/*.py"]
        all_issues = []
        
        for pattern in patterns:
            for file_path in directory.glob(pattern):
                if file_path.is_file() and file_path.suffix == '.py':
                    try:
                        issues = self.analyze_file(str(file_path))
                        all_issues.extend(issues)
                    except Exception as e:
                        logger.warning(f"Failed to analyze {file_path}: {e}")
                        continue
        
        logger.info(f"Bandit directory analysis completed: {len(all_issues)} issues found in {directory_path}")
        return all_issues
    
    def get_analyzer_info(self) -> Dict[str, Any]:
        """Get information about the analyzer."""
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            version = result.stdout.strip() if result.returncode == 0 else "unknown"
        except Exception:
            version = "unknown"
        
        return {
            "name": "Bandit",
            "version": version,
            "supported_languages": ["Python"],
            "supported_file_types": self.get_supported_file_types(),
            "configuration": {
                "confidence_level": self.config.confidence_level,
                "severity_level": self.config.severity_level,
                "skipped_tests": self.config.skipped_tests,
                "excluded_paths": self.config.excluded_paths
            }
        }