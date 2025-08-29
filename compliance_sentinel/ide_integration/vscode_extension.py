"""Visual Studio Code extension for real-time security feedback."""

import json
import asyncio
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import logging
import os
from pathlib import Path

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
# from compliance_sentinel.core.analyzer import ComplianceSentinel


logger = logging.getLogger(__name__)


class DiagnosticSeverity(Enum):
    """VS Code diagnostic severity levels."""
    ERROR = 0
    WARNING = 1
    INFORMATION = 2
    HINT = 3


@dataclass
class VSCodePosition:
    """Position in VS Code editor."""
    line: int
    character: int


@dataclass
class VSCodeRange:
    """Range in VS Code editor."""
    start: VSCodePosition
    end: VSCodePosition


@dataclass
class VSCodeDiagnostic:
    """VS Code diagnostic message."""
    range: VSCodeRange
    message: str
    severity: DiagnosticSeverity
    code: str
    source: str = "Compliance Sentinel"
    tags: List[int] = None
    related_information: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.related_information is None:
            self.related_information = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to VS Code diagnostic format."""
        return {
            'range': {
                'start': {'line': self.range.start.line, 'character': self.range.start.character},
                'end': {'line': self.range.end.line, 'character': self.range.end.character}
            },
            'message': self.message,
            'severity': self.severity.value,
            'code': self.code,
            'source': self.source,
            'tags': self.tags,
            'relatedInformation': self.related_information
        }


@dataclass
class CodeAction:
    """VS Code code action for quick fixes."""
    title: str
    kind: str
    diagnostics: List[VSCodeDiagnostic]
    edit: Dict[str, Any]
    command: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to VS Code code action format."""
        action = {
            'title': self.title,
            'kind': self.kind,
            'diagnostics': [d.to_dict() for d in self.diagnostics],
            'edit': self.edit
        }
        if self.command:
            action['command'] = self.command
        return action


@dataclass
class CompletionItem:
    """VS Code completion item with security guidance."""
    label: str
    kind: int
    detail: str
    documentation: str
    insert_text: str
    filter_text: Optional[str] = None
    sort_text: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to VS Code completion item format."""
        item = {
            'label': self.label,
            'kind': self.kind,
            'detail': self.detail,
            'documentation': self.documentation,
            'insertText': self.insert_text
        }
        if self.filter_text:
            item['filterText'] = self.filter_text
        if self.sort_text:
            item['sortText'] = self.sort_text
        return item


class VSCodeExtension:
    """VS Code extension for Compliance Sentinel integration."""
    
    def __init__(self, workspace_path: str):
        """Initialize VS Code extension."""
        self.workspace_path = workspace_path
        self.logger = logging.getLogger(f"{__name__}.vscode")
        # self.analyzer = ComplianceSentinel()  # Would be initialized in real implementation
        self.diagnostics_cache: Dict[str, List[VSCodeDiagnostic]] = {}
        self.settings = self._load_settings()
        
        # Security-focused completion items
        self.security_completions = self._initialize_security_completions()
    
    def _load_settings(self) -> Dict[str, Any]:
        """Load extension settings."""
        settings_path = Path(self.workspace_path) / ".vscode" / "settings.json"
        default_settings = {
            "complianceSentinel.enabled": True,
            "complianceSentinel.realTimeAnalysis": True,
            "complianceSentinel.severityLevel": "medium",
            "complianceSentinel.autoFix": True,
            "complianceSentinel.showSecurityHints": True,
            "complianceSentinel.excludePatterns": ["node_modules/**", "*.min.js"],
            "complianceSentinel.frameworks": ["soc2", "pci_dss", "hipaa"]
        }
        
        try:
            if settings_path.exists():
                with open(settings_path, 'r') as f:
                    user_settings = json.load(f)
                    # Merge with defaults
                    for key, value in user_settings.items():
                        if key.startswith("complianceSentinel."):
                            default_settings[key] = value
        except Exception as e:
            self.logger.warning(f"Failed to load settings: {e}")
        
        return default_settings
    
    def _initialize_security_completions(self) -> List[CompletionItem]:
        """Initialize security-focused code completions."""
        return [
            # Secure authentication patterns
            CompletionItem(
                label="secure_jwt_auth",
                kind=9,  # Snippet
                detail="Secure JWT Authentication",
                documentation="Generate secure JWT authentication with proper validation and expiration",
                insert_text="""import jwt
import os
from datetime import datetime, timedelta

def generate_jwt_token(user_id: str, roles: list = None) -> str:
    payload = {
        'user_id': user_id,
        'roles': roles or [],
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, os.getenv('JWT_SECRET'), algorithm='HS256')

def verify_jwt_token(token: str) -> dict:
    try:
        return jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")"""
            ),
            
            # Secure password hashing
            CompletionItem(
                label="secure_password_hash",
                kind=9,
                detail="Secure Password Hashing",
                documentation="Hash passwords securely using bcrypt with proper salt rounds",
                insert_text="""import bcrypt

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))"""
            ),
            
            # Input validation
            CompletionItem(
                label="secure_input_validation",
                kind=9,
                detail="Secure Input Validation",
                documentation="Validate and sanitize user inputs to prevent injection attacks",
                insert_text="""import re
import html

def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def sanitize_input(user_input: str) -> str:
    # HTML escape to prevent XSS
    sanitized = html.escape(user_input)
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>\"\\']', '', sanitized)
    return sanitized.strip()"""
            ),
            
            # Secure database queries
            CompletionItem(
                label="secure_db_query",
                kind=9,
                detail="Secure Database Query",
                documentation="Use parameterized queries to prevent SQL injection",
                insert_text="""def get_user_by_id(cursor, user_id: int):
    # Use parameterized query to prevent SQL injection
    query = "SELECT id, username, email FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

def create_user(cursor, username: str, email: str, password_hash: str):
    query = "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)"
    cursor.execute(query, (username, email, password_hash))"""
            ),
            
            # Secure file operations
            CompletionItem(
                label="secure_file_upload",
                kind=9,
                detail="Secure File Upload",
                documentation="Secure file upload with validation and sanitization",
                insert_text="""import os
import mimetypes
from pathlib import Path

ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def secure_file_upload(file_path: str, upload_dir: str) -> str:
    file_path = Path(file_path)
    
    # Validate file extension
    if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("File type not allowed")
    
    # Validate file size
    if file_path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError("File too large")
    
    # Sanitize filename
    safe_filename = "".join(c for c in file_path.name if c.isalnum() or c in '._-')
    
    # Create secure path
    upload_path = Path(upload_dir) / safe_filename
    return str(upload_path)"""
            )
        ]
    
    async def analyze_document(self, file_path: str, content: str) -> List[VSCodeDiagnostic]:
        """Analyze document and return VS Code diagnostics."""
        if not self.settings.get("complianceSentinel.enabled", True):
            return []
        
        try:
            # Run security analysis (mock for demo)
            issues = self._mock_analyze_file(file_path, content)
            
            # Convert to VS Code diagnostics
            diagnostics = []
            min_severity = self._get_min_severity()
            
            for issue in issues:
                if self._should_include_issue(issue, min_severity):
                    diagnostic = self._create_diagnostic(issue)
                    diagnostics.append(diagnostic)
            
            # Cache diagnostics
            self.diagnostics_cache[file_path] = diagnostics
            
            self.logger.info(f"Analyzed {file_path}: {len(diagnostics)} diagnostics")
            return diagnostics
        
        except Exception as e:
            self.logger.error(f"Analysis failed for {file_path}: {e}")
            return []
    
    def _get_min_severity(self) -> Severity:
        """Get minimum severity level from settings."""
        severity_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL
        }
        
        level = self.settings.get("complianceSentinel.severityLevel", "medium")
        return severity_map.get(level, Severity.MEDIUM)
    
    def _should_include_issue(self, issue: SecurityIssue, min_severity: Severity) -> bool:
        """Check if issue should be included based on settings."""
        # Check severity threshold
        severity_levels = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if severity_levels.index(issue.severity) < severity_levels.index(min_severity):
            return False
        
        # Check exclude patterns
        exclude_patterns = self.settings.get("complianceSentinel.excludePatterns", [])
        for pattern in exclude_patterns:
            if self._matches_pattern(issue.file_path, pattern):
                return False
        
        return True
    
    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """Check if file path matches exclude pattern."""
        import fnmatch
        return fnmatch.fnmatch(file_path, pattern)
    
    def _create_diagnostic(self, issue: SecurityIssue) -> VSCodeDiagnostic:
        """Create VS Code diagnostic from security issue."""
        # Map severity
        severity_map = {
            Severity.LOW: DiagnosticSeverity.HINT,
            Severity.MEDIUM: DiagnosticSeverity.INFORMATION,
            Severity.HIGH: DiagnosticSeverity.WARNING,
            Severity.CRITICAL: DiagnosticSeverity.ERROR
        }
        
        # Create range (VS Code uses 0-based line numbers)
        start_line = max(0, issue.line_number - 1)
        range_obj = VSCodeRange(
            start=VSCodePosition(line=start_line, character=0),
            end=VSCodePosition(line=start_line, character=100)  # End of line
        )
        
        # Create diagnostic message
        message = f"{issue.description}"
        if issue.remediation_suggestions:
            message += f"\\n\\nSuggested fixes:\\n" + "\\n".join(f"• {fix}" for fix in issue.remediation_suggestions)
        
        # Add tags for deprecated/unnecessary code
        tags = []
        if issue.category == SecurityCategory.HARDCODED_SECRETS:
            tags.append(1)  # Unnecessary tag
        
        return VSCodeDiagnostic(
            range=range_obj,
            message=message,
            severity=severity_map.get(issue.severity, DiagnosticSeverity.WARNING),
            code=issue.rule_id,
            source="Compliance Sentinel",
            tags=tags
        )
    
    def get_code_actions(self, file_path: str, diagnostics: List[VSCodeDiagnostic]) -> List[CodeAction]:
        """Get code actions (quick fixes) for diagnostics."""
        if not self.settings.get("complianceSentinel.autoFix", True):
            return []
        
        actions = []
        
        for diagnostic in diagnostics:
            # Generate quick fixes based on diagnostic code
            if "hardcoded_secrets" in diagnostic.code:
                actions.append(self._create_env_var_fix(diagnostic))
            elif "sql_injection" in diagnostic.code:
                actions.append(self._create_parameterized_query_fix(diagnostic))
            elif "xss" in diagnostic.code:
                actions.append(self._create_xss_fix(diagnostic))
        
        return actions
    
    def _create_env_var_fix(self, diagnostic: VSCodeDiagnostic) -> CodeAction:
        """Create quick fix for hardcoded secrets."""
        return CodeAction(
            title="Replace with environment variable",
            kind="quickfix",
            diagnostics=[diagnostic],
            edit={
                "changes": {
                    # This would contain the actual text edits
                    "file_uri": [
                        {
                            "range": diagnostic.range.to_dict() if hasattr(diagnostic.range, 'to_dict') else diagnostic.range,
                            "newText": 'os.getenv("SECRET_KEY", "")'
                        }
                    ]
                }
            }
        )
    
    def _create_parameterized_query_fix(self, diagnostic: VSCodeDiagnostic) -> CodeAction:
        """Create quick fix for SQL injection."""
        return CodeAction(
            title="Use parameterized query",
            kind="quickfix",
            diagnostics=[diagnostic],
            edit={
                "changes": {
                    "file_uri": [
                        {
                            "range": diagnostic.range.to_dict() if hasattr(diagnostic.range, 'to_dict') else diagnostic.range,
                            "newText": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
                        }
                    ]
                }
            }
        )
    
    def _create_xss_fix(self, diagnostic: VSCodeDiagnostic) -> CodeAction:
        """Create quick fix for XSS vulnerabilities."""
        return CodeAction(
            title="Use safe DOM manipulation",
            kind="quickfix",
            diagnostics=[diagnostic],
            edit={
                "changes": {
                    "file_uri": [
                        {
                            "range": diagnostic.range.to_dict() if hasattr(diagnostic.range, 'to_dict') else diagnostic.range,
                            "newText": 'element.textContent = userInput'
                        }
                    ]
                }
            }
        )
    
    def get_completions(self, file_path: str, position: VSCodePosition, context: Dict[str, Any]) -> List[CompletionItem]:
        """Get security-focused code completions."""
        if not self.settings.get("complianceSentinel.showSecurityHints", True):
            return []
        
        # Filter completions based on context
        trigger_character = context.get("triggerCharacter")
        trigger_kind = context.get("triggerKind")
        
        # Return security completions for relevant contexts
        if trigger_character in [".", "(", " "] or trigger_kind == 2:  # Invoke completion
            return self.security_completions
        
        return []
    
    def get_hover_information(self, file_path: str, position: VSCodePosition) -> Optional[Dict[str, Any]]:
        """Get hover information with security guidance."""
        # Check if position corresponds to a security issue
        diagnostics = self.diagnostics_cache.get(file_path, [])
        
        for diagnostic in diagnostics:
            if self._position_in_range(position, diagnostic.range):
                return {
                    "contents": [
                        {
                            "language": "markdown",
                            "value": f"**Security Issue: {diagnostic.code}**\\n\\n{diagnostic.message}"
                        }
                    ]
                }
        
        return None
    
    def _position_in_range(self, position: VSCodePosition, range_obj: VSCodeRange) -> bool:
        """Check if position is within range."""
        if position.line < range_obj.start.line or position.line > range_obj.end.line:
            return False
        
        if position.line == range_obj.start.line and position.character < range_obj.start.character:
            return False
        
        if position.line == range_obj.end.line and position.character > range_obj.end.character:
            return False
        
        return True
    
    def get_document_symbols(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Get document symbols with security annotations."""
        symbols = []
        
        # Analyze for security-relevant symbols
        lines = content.split('\\n')
        for line_num, line in enumerate(lines):
            # Look for security-relevant patterns
            if 'password' in line.lower() or 'secret' in line.lower():
                symbols.append({
                    "name": "Security Sensitive Code",
                    "kind": 13,  # Variable
                    "location": {
                        "uri": f"file://{file_path}",
                        "range": {
                            "start": {"line": line_num, "character": 0},
                            "end": {"line": line_num, "character": len(line)}
                        }
                    },
                    "detail": "Contains security-sensitive information"
                })
        
        return symbols
    
    def generate_extension_manifest(self) -> Dict[str, Any]:
        """Generate VS Code extension manifest (package.json)."""
        return {
            "name": "compliance-sentinel",
            "displayName": "Compliance Sentinel",
            "description": "Real-time security analysis and compliance checking",
            "version": "1.0.0",
            "publisher": "compliance-sentinel",
            "engines": {
                "vscode": "^1.60.0"
            },
            "categories": ["Linters", "Other"],
            "keywords": ["security", "compliance", "analysis", "vulnerabilities"],
            "activationEvents": [
                "onLanguage:python",
                "onLanguage:javascript",
                "onLanguage:typescript",
                "onLanguage:java",
                "onLanguage:csharp",
                "onLanguage:go",
                "onLanguage:rust",
                "onLanguage:php"
            ],
            "main": "./out/extension.js",
            "contributes": {
                "configuration": {
                    "type": "object",
                    "title": "Compliance Sentinel",
                    "properties": {
                        "complianceSentinel.enabled": {
                            "type": "boolean",
                            "default": True,
                            "description": "Enable Compliance Sentinel analysis"
                        },
                        "complianceSentinel.realTimeAnalysis": {
                            "type": "boolean",
                            "default": True,
                            "description": "Enable real-time analysis as you type"
                        },
                        "complianceSentinel.severityLevel": {
                            "type": "string",
                            "enum": ["low", "medium", "high", "critical"],
                            "default": "medium",
                            "description": "Minimum severity level to show"
                        },
                        "complianceSentinel.autoFix": {
                            "type": "boolean",
                            "default": True,
                            "description": "Enable automatic fix suggestions"
                        },
                        "complianceSentinel.frameworks": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["soc2", "pci_dss", "hipaa", "gdpr", "iso27001"]
                            },
                            "default": ["soc2"],
                            "description": "Compliance frameworks to check"
                        }
                    }
                },
                "commands": [
                    {
                        "command": "complianceSentinel.analyzeFile",
                        "title": "Analyze Current File",
                        "category": "Compliance Sentinel"
                    },
                    {
                        "command": "complianceSentinel.analyzeWorkspace",
                        "title": "Analyze Entire Workspace",
                        "category": "Compliance Sentinel"
                    },
                    {
                        "command": "complianceSentinel.generateReport",
                        "title": "Generate Security Report",
                        "category": "Compliance Sentinel"
                    }
                ],
                "menus": {
                    "editor/context": [
                        {
                            "command": "complianceSentinel.analyzeFile",
                            "group": "navigation"
                        }
                    ],
                    "explorer/context": [
                        {
                            "command": "complianceSentinel.analyzeWorkspace",
                            "group": "navigation"
                        }
                    ]
                }
            },
            "scripts": {
                "vscode:prepublish": "npm run compile",
                "compile": "tsc -p ./",
                "watch": "tsc -watch -p ./"
            },
            "devDependencies": {
                "@types/vscode": "^1.60.0",
                "@types/node": "14.x",
                "typescript": "^4.4.4"
            }
        }
    
    def _mock_analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Mock security analysis for demo purposes."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for hardcoded passwords
            if 'password' in line.lower() and ('=' in line or ':' in line) and ('"' in line or "'" in line):
                issues.append(SecurityIssue(
                    id=f"hardcoded_password_{line_num}",
                    severity=Severity.HIGH,
                    category=SecurityCategory.HARDCODED_SECRETS,
                    file_path=file_path,
                    line_number=line_num,
                    description="Hardcoded password detected",
                    rule_id="hardcoded_secrets",
                    confidence=0.9,
                    remediation_suggestions=["Use environment variables for secrets"],
                    created_at=datetime.now()
                ))
            
            # Check for SQL injection
            if 'execute' in line.lower() and ('f"' in line or "f'" in line or '+' in line):
                issues.append(SecurityIssue(
                    id=f"sql_injection_{line_num}",
                    severity=Severity.HIGH,
                    category=SecurityCategory.INJECTION,
                    file_path=file_path,
                    line_number=line_num,
                    description="Potential SQL injection vulnerability",
                    rule_id="sql_injection",
                    confidence=0.8,
                    remediation_suggestions=["Use parameterized queries"],
                    created_at=datetime.now()
                ))
        
        return issues
    
    def get_extension_statistics(self) -> Dict[str, Any]:
        """Get extension usage statistics."""
        total_diagnostics = sum(len(diags) for diags in self.diagnostics_cache.values())
        
        return {
            "files_analyzed": len(self.diagnostics_cache),
            "total_diagnostics": total_diagnostics,
            "security_completions": len(self.security_completions),
            "settings": self.settings,
            "workspace_path": self.workspace_path
        }


# Global VS Code extension instance
_global_vscode_extension: Optional[VSCodeExtension] = None


def get_vscode_extension(workspace_path: str = ".") -> VSCodeExtension:
    """Get global VS Code extension instance."""
    global _global_vscode_extension
    if _global_vscode_extension is None:
        _global_vscode_extension = VSCodeExtension(workspace_path)
    return _global_vscode_extension


def reset_vscode_extension() -> None:
    """Reset global VS Code extension (for testing)."""
    global _global_vscode_extension
    _global_vscode_extension = None