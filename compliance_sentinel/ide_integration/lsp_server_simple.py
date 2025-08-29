"""Simplified Language Server Protocol implementation for universal IDE support."""

import json
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory


logger = logging.getLogger(__name__)


class DiagnosticSeverity(Enum):
    """LSP diagnostic severity levels."""
    ERROR = 1
    WARNING = 2
    INFORMATION = 3
    HINT = 4


@dataclass
class LSPPosition:
    """LSP position (0-based)."""
    line: int
    character: int


@dataclass
class LSPRange:
    """LSP range."""
    start: LSPPosition
    end: LSPPosition


@dataclass
class LSPDiagnostic:
    """LSP diagnostic."""
    range: LSPRange
    severity: DiagnosticSeverity
    code: Optional[str]
    source: str
    message: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to LSP format."""
        return {
            'range': {
                'start': {'line': self.range.start.line, 'character': self.range.start.character},
                'end': {'line': self.range.end.line, 'character': self.range.end.character}
            },
            'severity': self.severity.value,
            'message': self.message,
            'source': self.source,
            'code': self.code or ""
        }


class LanguageServerProtocol:
    """Simplified Language Server Protocol implementation for Compliance Sentinel."""
    
    def __init__(self):
        """Initialize LSP server."""
        self.logger = logging.getLogger(f"{__name__}.lsp_server")
        self.documents: Dict[str, str] = {}
        self.diagnostics: Dict[str, List[LSPDiagnostic]] = {}
        self.capabilities = self._get_server_capabilities()
    
    def _get_server_capabilities(self) -> Dict[str, Any]:
        """Get server capabilities."""
        return {
            "textDocumentSync": {"openClose": True, "change": 2},
            "diagnosticProvider": {"interFileDependencies": False},
            "completionProvider": {"triggerCharacters": [".", "(", " "]},
            "hoverProvider": True,
            "codeActionProvider": {"codeActionKinds": ["quickfix"]},
            "documentSymbolProvider": True
        }
    
    async def handle_message(self, message: str) -> Optional[str]:
        """Handle incoming LSP message."""
        try:
            data = json.loads(message)
            method = data.get("method")
            
            if method == "initialize":
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": data.get("id"),
                    "result": {
                        "capabilities": self.capabilities,
                        "serverInfo": {"name": "Compliance Sentinel LSP", "version": "1.0.0"}
                    }
                })
            
            elif method == "textDocument/didOpen":
                params = data.get("params", {})
                text_doc = params.get("textDocument", {})
                uri = text_doc.get("uri", "")
                content = text_doc.get("text", "")
                
                self.documents[uri] = content
                await self._analyze_document(uri, content)
            
            elif method == "textDocument/completion":
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": data.get("id"),
                    "result": {
                        "isIncomplete": False,
                        "items": self._get_security_completions()
                    }
                })
            
            return None
        
        except Exception as e:
            self.logger.error(f"Message handling error: {e}")
            return None
    
    def _get_security_completions(self) -> List[Dict[str, Any]]:
        """Get security-focused completion items."""
        return [
            {
                "label": "secure_hash_password",
                "kind": 3,
                "detail": "Secure password hashing",
                "documentation": "Hash password using bcrypt",
                "insertText": "bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
            },
            {
                "label": "validate_input", 
                "kind": 3,
                "detail": "Input validation",
                "documentation": "Validate and sanitize user input",
                "insertText": "html.escape(user_input).strip()"
            }
        ]
    
    async def _analyze_document(self, uri: str, content: str) -> None:
        """Analyze document and update diagnostics."""
        try:
            issues = self._mock_analyze_file(uri, content)
            diagnostics = [self._create_lsp_diagnostic(issue) for issue in issues]
            self.diagnostics[uri] = diagnostics
            self.logger.info(f"Analyzed {uri}: {len(diagnostics)} issues found")
        except Exception as e:
            self.logger.error(f"Document analysis failed: {e}")
    
    def _mock_analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Mock security analysis for demo purposes."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if any(keyword in line.lower() for keyword in ['password', 'secret', 'key']) and ('=' in line):
                issues.append(SecurityIssue(
                    id=f"hardcoded_secret_{line_num}",
                    severity=Severity.HIGH,
                    category=SecurityCategory.HARDCODED_SECRETS,
                    file_path=file_path,
                    line_number=line_num,
                    description="Hardcoded secret detected",
                    rule_id="hardcoded_secrets",
                    confidence=0.9,
                    remediation_suggestions=["Use environment variables"],
                    created_at=None
                ))
        
        return issues
    
    def _create_lsp_diagnostic(self, issue: SecurityIssue) -> LSPDiagnostic:
        """Create LSP diagnostic from security issue."""
        severity_map = {
            Severity.LOW: DiagnosticSeverity.HINT,
            Severity.MEDIUM: DiagnosticSeverity.INFORMATION,
            Severity.HIGH: DiagnosticSeverity.WARNING,
            Severity.CRITICAL: DiagnosticSeverity.ERROR
        }
        
        start_line = max(0, issue.line_number - 1)
        range_obj = LSPRange(
            start=LSPPosition(line=start_line, character=0),
            end=LSPPosition(line=start_line, character=100)
        )
        
        return LSPDiagnostic(
            range=range_obj,
            severity=severity_map.get(issue.severity, DiagnosticSeverity.WARNING),
            code=issue.rule_id,
            source="Compliance Sentinel",
            message=issue.description
        )


# Global LSP server instance
_global_lsp_server: Optional[LanguageServerProtocol] = None


def get_lsp_server() -> LanguageServerProtocol:
    """Get global LSP server instance."""
    global _global_lsp_server
    if _global_lsp_server is None:
        _global_lsp_server = LanguageServerProtocol()
    return _global_lsp_server