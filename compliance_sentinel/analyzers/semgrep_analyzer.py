"""Semgrep security analyzer integration for multi-language code analysis."""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
import logging
import yaml

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
class SemgrepConfig:
    """Configuration for Semgrep analyzer."""
    config_files: List[str] = field(default_factory=list)
    rulesets: List[str] = field(default_factory=lambda: ["auto"])  # auto, security, owasp-top-ten
    custom_rules: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    included_paths: List[str] = field(default_factory=list)
    max_target_bytes: int = 1000000  # 1MB max file size
    timeout: int = 30  # seconds
    jobs: int = 1  # parallel jobs
    verbose: bool = False
    strict: bool = False
    
    def __post_init__(self):
        if not self.excluded_paths:
            self.excluded_paths = [
                "tests/", "test/", "*_test.py", "test_*.py",
                "venv/", "env/", ".venv/", "node_modules/",
                ".git/", "__pycache__/", "*.pyc"
            ]


@dataclass
class SemgrepRule:
    """Represents a custom Semgrep rule."""
    id: str
    message: str
    languages: List[str]
    severity: str
    pattern: Optional[str] = None
    patterns: Optional[List[Dict[str, Any]]] = None
    pattern_either: Optional[List[Dict[str, Any]]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_yaml_dict(self) -> Dict[str, Any]:
        """Convert rule to YAML-compatible dictionary."""
        rule_dict = {
            "id": self.id,
            "message": self.message,
            "languages": self.languages,
            "severity": self.severity
        }
        
        if self.pattern:
            rule_dict["pattern"] = self.pattern
        elif self.patterns:
            rule_dict["patterns"] = self.patterns
        elif self.pattern_either:
            rule_dict["pattern-either"] = self.pattern_either
        
        if self.metadata:
            rule_dict["metadata"] = self.metadata
        
        return rule_dict


class SemgrepAnalyzer(SecurityAnalyzer):
    """Semgrep-based security analyzer for multi-language code analysis."""
    
    # Mapping of Semgrep severity to our severity levels
    SEMGREP_SEVERITY_MAPPING = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW
    }
    
    # Language to file extension mapping
    LANGUAGE_EXTENSIONS = {
        "python": [".py"],
        "javascript": [".js", ".jsx"],
        "typescript": [".ts", ".tsx"],
        "java": [".java"],
        "go": [".go"],
        "php": [".php"],
        "ruby": [".rb"],
        "c": [".c", ".h"],
        "cpp": [".cpp", ".cc", ".cxx", ".hpp"],
        "csharp": [".cs"],
        "kotlin": [".kt"],
        "scala": [".scala"],
        "rust": [".rs"],
        "swift": [".swift"],
        "yaml": [".yml", ".yaml"],
        "json": [".json"],
        "dockerfile": ["Dockerfile", ".dockerfile"],
        "terraform": [".tf"],
        "html": [".html", ".htm"],
        "xml": [".xml"]
    }
    
    def __init__(self, config: Optional[SemgrepConfig] = None):
        """Initialize Semgrep analyzer with configuration."""
        self.config = config or SemgrepConfig()
        self.cache = get_global_cache()
        self.error_handler = get_global_error_handler()
        self.custom_rules_file = None
        
        # Verify Semgrep is available
        self._verify_semgrep_installation()
        
        # Load custom rules if provided
        if self.config.custom_rules:
            self._create_custom_rules_file()
        
        logger.info("Initialized Semgrep analyzer")
    
    def _verify_semgrep_installation(self) -> None:
        """Verify that Semgrep is installed and accessible."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Semgrep version: {result.stdout.strip()}")
            else:
                raise RuntimeError("Semgrep not properly installed")
        except (subprocess.TimeoutExpired, FileNotFoundError, RuntimeError) as e:
            logger.error(f"Semgrep installation check failed: {e}")
            raise RuntimeError(
                "Semgrep is not installed or not accessible. "
                "Please install it with: pip install semgrep"
            )
    
    def _create_custom_rules_file(self) -> None:
        """Create a temporary file with custom Semgrep rules."""
        try:
            # Create temporary file for custom rules
            temp_file = tempfile.NamedTemporaryFile(
                mode='w', suffix='.yml', delete=False
            )
            
            # Convert custom rules to YAML format
            rules_data = {"rules": []}
            
            for rule_yaml in self.config.custom_rules:
                try:
                    rule_dict = yaml.safe_load(rule_yaml)
                    if isinstance(rule_dict, dict) and "id" in rule_dict:
                        rules_data["rules"].append(rule_dict)
                except yaml.YAMLError as e:
                    logger.warning(f"Invalid custom rule YAML: {e}")
                    continue
            
            # Write rules to file
            yaml.dump(rules_data, temp_file, default_flow_style=False)
            temp_file.close()
            
            self.custom_rules_file = temp_file.name
            logger.info(f"Created custom rules file: {self.custom_rules_file}")
            
        except Exception as e:
            logger.error(f"Failed to create custom rules file: {e}")
            self.custom_rules_file = None
    
    def analyze_file(self, file_path: str) -> List[SecurityIssue]:
        """Analyze a single file for security issues."""
        file_path_obj = Path(file_path)
        
        # Validate file
        if not file_path_obj.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Check if file type is supported
        if not self._is_supported_file(file_path_obj):
            logger.debug(f"File type not supported by Semgrep: {file_path}")
            return []
        
        # Check cache first
        cache_key = f"semgrep_analysis:{file_path}:{file_path_obj.stat().st_mtime}"
        cached_result = self.cache.get(cache_key)
        if cached_result:
            logger.debug(f"Using cached Semgrep results for {file_path}")
            return cached_result
        
        try:
            # Run Semgrep analysis
            semgrep_results = self._run_semgrep_analysis(file_path)
            
            # Convert to SecurityIssue objects
            security_issues = self._convert_semgrep_results(semgrep_results, file_path)
            
            # Cache results
            self.cache.set(cache_key, security_issues, ttl=3600)  # Cache for 1 hour
            
            logger.info(f"Semgrep analysis completed for {file_path}: {len(security_issues)} issues found")
            return security_issues
            
        except Exception as e:
            logger.error(f"Semgrep analysis failed for {file_path}: {e}")
            self.error_handler.handle_analysis_error(e, f"semgrep_analysis:{file_path}")
            return []
    
    def _is_supported_file(self, file_path: Path) -> bool:
        """Check if file type is supported by Semgrep."""
        file_extension = file_path.suffix.lower()
        file_name = file_path.name.lower()
        
        # Check extensions
        for extensions in self.LANGUAGE_EXTENSIONS.values():
            if file_extension in extensions or file_name in extensions:
                return True
        
        return False
    
    @retry_with_backoff(
        strategy=RetryStrategy(max_attempts=2, base_delay=1.0),
        exceptions=(subprocess.TimeoutExpired, subprocess.CalledProcessError)
    )
    def _run_semgrep_analysis(self, file_path: str) -> Dict[str, Any]:
        """Run Semgrep analysis on a file and return results."""
        cmd = self._build_semgrep_command(file_path)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
                cwd=Path.cwd()
            )
            
            # Semgrep returns non-zero exit code when issues are found
            # Only treat it as error if it's a real failure (exit code > 2)
            if result.returncode > 2:
                logger.error(f"Semgrep command failed: {result.stderr}")
                raise subprocess.CalledProcessError(result.returncode, cmd, result.stderr)
            
            # Parse JSON output
            if result.stdout.strip():
                return json.loads(result.stdout)
            else:
                # No issues found
                return {"results": [], "errors": []}
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep JSON output: {e}")
            logger.debug(f"Semgrep stdout: {result.stdout}")
            logger.debug(f"Semgrep stderr: {result.stderr}")
            raise
        except subprocess.TimeoutExpired:
            logger.warning(f"Semgrep analysis timed out for {file_path}")
            raise
    
    def _build_semgrep_command(self, file_path: str) -> List[str]:
        """Build Semgrep command with appropriate options."""
        cmd = ["semgrep"]
        
        # Output format
        cmd.extend(["--json", "--no-git-ignore"])
        
        # Rulesets
        for ruleset in self.config.rulesets:
            cmd.extend(["--config", ruleset])
        
        # Custom rules file
        if self.custom_rules_file:
            cmd.extend(["--config", self.custom_rules_file])
        
        # Configuration files
        for config_file in self.config.config_files:
            if Path(config_file).exists():
                cmd.extend(["--config", config_file])
        
        # Excluded paths
        for exclude_path in self.config.excluded_paths:
            cmd.extend(["--exclude", exclude_path])
        
        # Included paths
        for include_path in self.config.included_paths:
            cmd.extend(["--include", include_path])
        
        # Performance options
        cmd.extend(["--max-target-bytes", str(self.config.max_target_bytes)])
        cmd.extend(["--timeout", str(self.config.timeout)])
        cmd.extend(["--jobs", str(self.config.jobs)])
        
        # Verbosity
        if self.config.verbose:
            cmd.append("--verbose")
        
        # Strict mode
        if self.config.strict:
            cmd.append("--strict")
        
        # Target file
        cmd.append(file_path)
        
        logger.debug(f"Semgrep command: {' '.join(cmd)}")
        return cmd
    
    def _convert_semgrep_results(self, semgrep_results: Dict[str, Any], file_path: str) -> List[SecurityIssue]:
        """Convert Semgrep results to SecurityIssue objects."""
        security_issues = []
        
        results = semgrep_results.get("results", [])
        
        for result in results:
            try:
                # Extract issue information
                check_id = result.get("check_id", "unknown")
                message = result.get("message", "Security issue detected")
                severity = result.get("extra", {}).get("severity", "INFO")
                
                # Location information
                start_info = result.get("start", {})
                end_info = result.get("end", {})
                line_number = start_info.get("line", 1)
                
                # Code snippet
                extra = result.get("extra", {})
                lines = extra.get("lines", "")
                
                # Metadata
                metadata = extra.get("metadata", {})
                
                # Map to our categories and severity
                category = self._determine_category(check_id, message, metadata)
                mapped_severity = self.SEMGREP_SEVERITY_MAPPING.get(severity, Severity.LOW)
                
                # Calculate confidence score
                confidence = self._calculate_confidence_score(severity, check_id, metadata)
                
                # Generate remediation suggestions
                remediation_suggestions = self._generate_remediation_suggestions(
                    check_id, message, metadata
                )
                
                # Create SecurityIssue
                security_issue = SecurityIssue(
                    id=f"SEMGREP_{check_id}_{line_number}",
                    severity=mapped_severity,
                    category=category,
                    file_path=file_path,
                    line_number=line_number,
                    description=f"Semgrep: {message}",
                    rule_id=f"SEMGREP_{check_id}",
                    confidence=confidence,
                    remediation_suggestions=remediation_suggestions,
                    created_at=datetime.utcnow()
                )
                
                security_issues.append(security_issue)
                
            except Exception as e:
                logger.warning(f"Error processing Semgrep result: {e}")
                logger.debug(f"Problematic result: {result}")
                continue
        
        return security_issues
    
    def _determine_category(self, check_id: str, message: str, metadata: Dict[str, Any]) -> SecurityCategory:
        """Determine security category based on Semgrep rule information."""
        check_id_lower = check_id.lower()
        message_lower = message.lower()
        
        # Check metadata for category hints
        category_hint = metadata.get("category", "").lower()
        owasp_category = metadata.get("owasp", "").lower()
        
        # SQL Injection
        if any(keyword in check_id_lower for keyword in ["sql", "injection", "sqli"]):
            return SecurityCategory.SQL_INJECTION
        if any(keyword in message_lower for keyword in ["sql injection", "sqli"]):
            return SecurityCategory.SQL_INJECTION
        
        # XSS
        if any(keyword in check_id_lower for keyword in ["xss", "cross-site"]):
            return SecurityCategory.XSS
        if any(keyword in message_lower for keyword in ["xss", "cross-site scripting"]):
            return SecurityCategory.XSS
        
        # Hardcoded secrets
        if any(keyword in check_id_lower for keyword in ["secret", "password", "key", "token", "credential"]):
            return SecurityCategory.HARDCODED_SECRETS
        if any(keyword in message_lower for keyword in ["hardcoded", "secret", "password", "api key"]):
            return SecurityCategory.HARDCODED_SECRETS
        
        # Cryptographic issues
        if any(keyword in check_id_lower for keyword in ["crypto", "hash", "ssl", "tls", "cipher"]):
            return SecurityCategory.INSECURE_CRYPTO
        if any(keyword in message_lower for keyword in ["weak", "insecure", "crypto", "ssl", "tls"]):
            return SecurityCategory.INSECURE_CRYPTO
        
        # Authentication/Authorization
        if any(keyword in check_id_lower for keyword in ["auth", "login", "session", "jwt"]):
            return SecurityCategory.AUTHENTICATION
        if any(keyword in message_lower for keyword in ["authentication", "authorization", "session"]):
            return SecurityCategory.AUTHENTICATION
        
        # Default to input validation
        return SecurityCategory.INPUT_VALIDATION
    
    def _calculate_confidence_score(self, severity: str, check_id: str, metadata: Dict[str, Any]) -> float:
        """Calculate confidence score based on Semgrep rule information."""
        # Base confidence from severity
        base_confidence = {
            "ERROR": 0.9,
            "WARNING": 0.7,
            "INFO": 0.5
        }.get(severity, 0.5)
        
        # Adjust based on rule source
        if "owasp" in check_id.lower():
            base_confidence += 0.1
        elif "security" in check_id.lower():
            base_confidence += 0.05
        
        # Adjust based on metadata confidence
        metadata_confidence = metadata.get("confidence", "").lower()
        if metadata_confidence == "high":
            base_confidence += 0.1
        elif metadata_confidence == "low":
            base_confidence -= 0.1
        
        # Adjust based on rule maturity
        if metadata.get("likelihood") == "HIGH":
            base_confidence += 0.05
        elif metadata.get("likelihood") == "LOW":
            base_confidence -= 0.05
        
        return max(0.1, min(1.0, base_confidence))
    
    def _generate_remediation_suggestions(self, check_id: str, message: str, metadata: Dict[str, Any]) -> List[str]:
        """Generate remediation suggestions based on Semgrep rule information."""
        suggestions = []
        
        # Use metadata references if available
        references = metadata.get("references", [])
        if references:
            suggestions.append(f"See: {references[0]}")
        
        # Category-specific suggestions
        check_id_lower = check_id.lower()
        message_lower = message.lower()
        
        if "sql" in check_id_lower or "injection" in message_lower:
            suggestions.extend([
                "Use parameterized queries or prepared statements",
                "Validate and sanitize all user inputs",
                "Use ORM frameworks with built-in protection"
            ])
        elif "xss" in check_id_lower or "cross-site" in message_lower:
            suggestions.extend([
                "Sanitize and encode all user inputs before output",
                "Use Content Security Policy (CSP) headers",
                "Avoid dynamic HTML generation with user input"
            ])
        elif any(keyword in check_id_lower for keyword in ["secret", "password", "key"]):
            suggestions.extend([
                "Move secrets to environment variables",
                "Use secure secret management systems",
                "Never commit secrets to version control"
            ])
        elif "crypto" in check_id_lower or "ssl" in check_id_lower:
            suggestions.extend([
                "Use strong encryption algorithms",
                "Enable proper certificate verification",
                "Update to secure cryptographic libraries"
            ])
        else:
            # Generic suggestions
            suggestions.extend([
                "Review the code for security vulnerabilities",
                "Follow secure coding best practices",
                "Validate all inputs and sanitize outputs"
            ])
        
        # Add OWASP reference if applicable
        if metadata.get("owasp"):
            suggestions.append(f"Refer to OWASP guidelines: {metadata['owasp']}")
        
        return suggestions[:3]  # Limit to 3 suggestions
    
    def get_supported_file_types(self) -> List[str]:
        """Return list of supported file extensions."""
        extensions = set()
        for lang_extensions in self.LANGUAGE_EXTENSIONS.values():
            extensions.update(lang_extensions)
        return sorted(list(extensions))
    
    def configure_rules(self, rules: List[str]) -> None:
        """Configure custom Semgrep rules."""
        # Update custom rules
        self.config.custom_rules = rules
        
        # Recreate custom rules file
        if rules:
            self._create_custom_rules_file()
        
        logger.info(f"Updated Semgrep configuration with {len(rules)} custom rules")
    
    def analyze_with_custom_rules(self, file_path: str, rules: List[str]) -> List[SecurityIssue]:
        """Analyze file with specific custom rules."""
        # Temporarily update configuration
        original_rules = self.config.custom_rules.copy()
        original_rules_file = self.custom_rules_file
        
        try:
            # Set custom rules
            self.config.custom_rules = rules
            self._create_custom_rules_file()
            
            # Run analysis
            return self.analyze_file(file_path)
            
        finally:
            # Restore original configuration
            self.config.custom_rules = original_rules
            self.custom_rules_file = original_rules_file
    
    def load_organizational_rules(self) -> List[SemgrepRule]:
        """Load organizational rules from configuration."""
        rules = []
        
        # Example organizational rules
        organizational_rules = [
            SemgrepRule(
                id="org.hardcoded-secrets",
                message="Hardcoded secret detected in organizational code",
                languages=["python", "javascript", "java"],
                severity="ERROR",
                pattern='$VAR = "..."',
                metadata={
                    "category": "security",
                    "confidence": "high",
                    "owasp": "A02:2021 – Cryptographic Failures"
                }
            ),
            SemgrepRule(
                id="org.sql-injection",
                message="Potential SQL injection vulnerability",
                languages=["python", "java", "php"],
                severity="ERROR",
                patterns=[
                    {"pattern": "execute($QUERY)"},
                    {"pattern-not": "execute(...)"}
                ],
                metadata={
                    "category": "security",
                    "confidence": "high",
                    "owasp": "A03:2021 – Injection"
                }
            )
        ]
        
        return organizational_rules
    
    def validate_rule_syntax(self, rule: str) -> bool:
        """Validate Semgrep rule syntax."""
        try:
            rule_dict = yaml.safe_load(rule)
            
            # Basic validation
            required_fields = ["id", "message", "languages", "severity"]
            for field in required_fields:
                if field not in rule_dict:
                    logger.error(f"Missing required field in rule: {field}")
                    return False
            
            # Pattern validation
            pattern_fields = ["pattern", "patterns", "pattern-either"]
            if not any(field in rule_dict for field in pattern_fields):
                logger.error("Rule must have at least one pattern field")
                return False
            
            return True
            
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML syntax in rule: {e}")
            return False
        except Exception as e:
            logger.error(f"Rule validation error: {e}")
            return False
    
    def get_analyzer_info(self) -> Dict[str, Any]:
        """Get information about the analyzer."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            version = result.stdout.strip() if result.returncode == 0 else "unknown"
        except Exception:
            version = "unknown"
        
        return {
            "name": "Semgrep",
            "version": version,
            "supported_languages": list(self.LANGUAGE_EXTENSIONS.keys()),
            "supported_file_types": self.get_supported_file_types(),
            "configuration": {
                "rulesets": self.config.rulesets,
                "custom_rules_count": len(self.config.custom_rules),
                "excluded_paths": self.config.excluded_paths,
                "timeout": self.config.timeout,
                "max_target_bytes": self.config.max_target_bytes
            }
        }
    
    def __del__(self):
        """Cleanup temporary files."""
        if self.custom_rules_file and Path(self.custom_rules_file).exists():
            try:
                Path(self.custom_rules_file).unlink()
            except Exception:
                pass  # Ignore cleanup errors