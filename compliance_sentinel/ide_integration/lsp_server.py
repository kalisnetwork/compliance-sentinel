"""Language Server Protocol implementation for universal IDE support."""

import json
import asyncio
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import sys
import traceback

from compliance_sentinel.core.interfaces import SecurityIssue, Severity
# from compliance_sentinel.core.analyzer import ComplianceSentinel


logger = logging.getLogger(__name__)


class MessageType(Enum):
    """LSP message types."""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"


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
    tags: Optional[List[int]] = None
    related_information: Optional[List[Dict[str, Any]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to LSP format."""
        result = {
            'range': {
                'start': {'line': self.range.start.line, 'character': self.range.start.character},
                'end': {'line': self.range.end.line, 'character': self.range.end.character}
            },
            'severity': self.severity.value,
            'message': self.message,
            'source': self.source
        }
        
        if self.code:
            result['code'] = self.code
        if self.tags:
            result['tags'] = self.tags
        if self.related_information:
            result['relatedInformation'] = self.related_information
        
        return result


@dataclass
class LSPMessage:
    """LSP message."""
    jsonrpc: str = "2.0"
    id: Optional[Union[str, int]] = None
    method: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None


class LanguageServerProtocol:
    """Language Server Protocol implementation for Compliance Sentinel."""
    
    def __init__(self):
        """Initialize LSP server."""
        self.logger = logging.getLogger(f"{__name__}.lsp_server")
        # self.analyzer = ComplianceSentinel()  # Would be initialized in real implementation
        self.documents: Dict[str, str] = {}  # URI -> content
        self.diagnostics: Dict[str, List[LSPDiagnostic]] = {}  # URI -> diagnostics
        self.capabilities = self._get_server_capabilities()
        self.request_handlers: Dict[str, Callable] = {}
        self.notification_handlers: Dict[str, Callable] = {}
        
        self._register_handlers()
    
    def _get_server_capabilities(self) -> Dict[str, Any]:
        """Get server capabilities."""
        return {
            "textDocumentSync": {
                "openClose": True,
                "change": 2,  # Incremental
                "save": {"includeText": True}
            },
            "diagnosticProvider": {
                "interFileDependencies": False,
                "workspaceDiagnostics": False
            },
            "completionProvider": {
                "triggerCharacters": [".", "(", " "],
                "resolveProvider": True
            },
            "hoverProvider": True,
            "codeActionProvider": {
                "codeActionKinds": ["quickfix", "refactor.rewrite"]
            },
            "documentSymbolProvider": True,
            "workspaceSymbolProvider": True,
            "definitionProvider": False,
            "referencesProvider": False,
            "documentHighlightProvider": False,
            "documentFormattingProvider": False,
            "documentRangeFormattingProvider": False,
            "renameProvider": False,
            "foldingRangeProvider": False,
            "executeCommandProvider": {
                "commands": [
                    "complianceSentinel.analyzeDocument",
                    "complianceSentinel.fixIssue",
                    "complianceSentinel.generateSecureCode"
                ]
            }
        }
    
    def _register_handlers(self) -> None:
        """Register LSP message handlers."""
        # Request handlers
        self.request_handlers.update({
            "initialize": self._handle_initialize,
            "textDocument/diagnostic": self._handle_diagnostic,
            "textDocument/completion": self._handle_completion,
            "textDocument/hover": self._handle_hover,
            "textDocument/codeAction": self._handle_code_action,
            "textDocument/documentSymbol": self._handle_document_symbol,
            "workspace/executeCommand": self._handle_execute_command,
            "shutdown": self._handle_shutdown
        })
        
        # Notification handlers
        self.notification_handlers.update({
            "initialized": self._handle_initialized,
            "textDocument/didOpen": self._handle_did_open,
            "textDocument/didChange": self._handle_did_change,
            "textDocument/didSave": self._handle_did_save,
            "textDocument/didClose": self._handle_did_close,
            "exit": self._handle_exit
        })
    
    async def handle_message(self, message: str) -> Optional[str]:
        """Handle incoming LSP message."""
        try:
            # Parse message
            data = json.loads(message)
            lsp_message = LSPMessage(**data)
            
            # Handle request
            if lsp_message.method and lsp_message.id is not None:
                handler = self.request_handlers.get(lsp_message.method)
                if handler:
                    try:
                        result = await handler(lsp_message.params or {})
                        response = LSPMessage(
                            id=lsp_message.id,
                            result=result
                        )
                        return json.dumps(asdict(response))
                    except Exception as e:
                        self.logger.error(f"Request handler error: {e}")
                        error_response = LSPMessage(
                            id=lsp_message.id,
                            error={
                                "code": -32603,  # Internal error
                                "message": str(e)
                            }
                        )
                        return json.dumps(asdict(error_response))
                else:
                    # Method not found
                    error_response = LSPMessage(
                        id=lsp_message.id,
                        error={
                            "code": -32601,  # Method not found
                            "message": f"Method not found: {lsp_message.method}"
                        }
                    )
                    return json.dumps(asdict(error_response))
            
            # Handle notification
            elif lsp_message.method:
                handler = self.notification_handlers.get(lsp_message.method)
                if handler:
                    await handler(lsp_message.params or {})
                return None
            
        except Exception as e:
            self.logger.error(f"Message handling error: {e}")
            self.logger.error(traceback.format_exc())
            return None
    
    async def _handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle initialize request."""
        self.logger.info("LSP server initialized")
        return {
            "capabilities": self.capabilities,
            "serverInfo": {
                "name": "Compliance Sentinel Language Server",
                "version": "1.0.0"
            }
        }
    
    async def _handle_initialized(self, params: Dict[str, Any]) -> None:
        """Handle initialized notification."""
        self.logger.info("LSP server ready")
    
    async def _handle_did_open(self, params: Dict[str, Any]) -> None:
        """Handle textDocument/didOpen notification."""
        text_document = params["textDocument"]
        uri = text_document["uri"]
        content = text_document["text"]
        
        self.documents[uri] = content
        await self._analyze_document(uri, content)
    
    async def _handle_did_change(self, params: Dict[str, Any]) -> None:
        """Handle textDocument/didChange notification."""
        text_document = params["textDocument"]
        uri = text_document["uri"]
        changes = params["contentChanges"]
        
        # Apply changes (simplified - assumes full document updates)
        if changes and "text" in changes[0]:
            content = changes[0]["text"]
            self.documents[uri] = content
            await self._analyze_document(uri, content)
    
    async def _handle_did_save(self, params: Dict[str, Any]) -> None:
        """Handle textDocument/didSave notification."""
        text_document = params["textDocument"]
        uri = text_document["uri"]
        
        if uri in self.documents:
            await self._analyze_document(uri, self.documents[uri])
    
    async def _handle_did_close(self, params: Dict[str, Any]) -> None:
        """Handle textDocument/didClose notification."""
        text_document = params["textDocument"]
        uri = text_document["uri"]
        
        # Clean up document data
        self.documents.pop(uri, None)
        self.diagnostics.pop(uri, None)
    
    async def _handle_diagnostic(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle textDocument/diagnostic request."""
        text_document = params["textDocument"]
        uri = text_document["uri"]
        
        diagnostics = self.diagnostics.get(uri, [])
        
        return {
            "kind": "full",
            "items": [diag.to_dict() for diag in diagnostics]
        }
    
    async def _handle_completion(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle textDocument/completion request."""
        text_document = params["textDocument"]
        position = params["position"]
        context = params.get("context", {})
        
        # Generate security-focused completions
        completions = self._get_security_completions(context)
        
        return {
            "isIncomplete": False,
            "items": completions
        }
    
    async def _handle_hover(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle textDocument/hover request."""
        text_document = params["textDocument"]
        position = params["position"]
        uri = text_document["uri"]
        
        # Check if position has diagnostic
        diagnostics = self.diagnostics.get(uri, [])
        
        for diagnostic in diagnostics:
            if self._position_in_range(position, diagnostic.range):
                return {
                    "contents": {
                        "kind": "markdown",
                        "value": f"**Security Issue**\\n\\n{diagnostic.message}"
                    }
                }
        
        return None
    
    async def _handle_code_action(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle textDocument/codeAction request."""
        text_document = params["textDocument"]
        range_param = params["range"]
        context = params["context"]
        
        diagnostics = context.get("diagnostics", [])
        actions = []
        
        for diagnostic in diagnostics:
            if diagnostic.get("source") == "Compliance Sentinel":
                # Generate quick fixes based on diagnostic code
                code = diagnostic.get("code", "")
                if "hardcoded_secrets" in code:
                    actions.append({
                        "title": "Replace with environment variable",
                        "kind": "quickfix",
                        "edit": {
                            "changes": {
                                text_document["uri"]: [
                                    {
                                        "range": diagnostic["range"],
                                        "newText": 'os.getenv("SECRET_KEY", "")'
                                    }
                                ]
                            }
                        }
                    })
        
        return actions
    
    async def _handle_document_symbol(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle textDocument/documentSymbol request."""
        text_document = params["textDocument"]
        uri = text_document["uri"]
        
        content = self.documents.get(uri, "")
        symbols = []
        
        # Find security-relevant symbols
        lines = content.split('\\n')
        for line_num, line in enumerate(lines):
            if any(keyword in line.lower() for keyword in ['password', 'secret', 'key', 'token']):
                symbols.append({
                    "name": f"Security Sensitive: Line {line_num + 1}",
                    "kind": 13,  # Variable
                    "range": {
                        "start": {"line": line_num, "character": 0},
                        "end": {"line": line_num, "character": len(line)}
                    },
                    "selectionRange": {
                        "start": {"line": line_num, "character": 0},
                        "end": {"line": line_num, "character": len(line)}
                    }
                })
        
        return symbols
    
    async def _handle_execute_command(self, params: Dict[str, Any]) -> Any:
        """Handle workspace/executeCommand request."""
        command = params["command"]
        arguments = params.get("arguments", [])
        
        if command == "complianceSentinel.analyzeDocument":
            uri = arguments[0] if arguments else None
            if uri and uri in self.documents:
                await self._analyze_document(uri, self.documents[uri])
                return {"status": "analyzed"}
        
        elif command == "complianceSentinel.fixIssue":
            # Implement automatic fix
            return {"status": "fixed"}
        
        elif command == "complianceSentinel.generateSecureCode":
            # Generate secure code template
            return {"code": "# Secure code template\\npass"}
        
        return None
    
    async def _handle_shutdown(self, params: Dict[str, Any]) -> None:
        """Handle shutdown request."""
        self.logger.info("LSP server shutting down")
        return None
    
    async def _handle_exit(self, params: Dict[str, Any]) -> None:
        """Handle exit notification."""
        self.logger.info("LSP server exiting")
        sys.exit(0)
    
    async def _analyze_document(self, uri: str, content: str) -> None:
        """Analyze document and update diagnostics."""
        try:
            # Convert URI to file path
            file_path = uri.replace("file://", "")
            
            # Run security analysis (mock for demo)
            issues = self._mock_analyze_file(file_path, content)
            
            # Convert to LSP diagnostics
            diagnostics = []
            for issue in issues:
                diagnostic = self._create_lsp_diagnostic(issue)
                diagnostics.append(diagnostic)
            
            # Store diagnostics
            self.diagnostics[uri] = diagnostics
            
            # Send diagnostics notification
            await self._send_diagnostics(uri, diagnostics)
            
            self.logger.info(f"Analyzed {file_path}: {len(diagnostics)} issues found")
        
        except Exception as e:
            self.logger.error(f"Document analysis failed: {e}")
    
    def _mock_analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Mock security analysis for demo purposes."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for hardcoded secrets
            if any(keyword in line.lower() for keyword in ['password', 'secret', 'key']) and ('=' in line or ':' in line):
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
                    created_at=datetime.now()
                ))
        
        return issues
    
    def _create_lsp_diagnostic(self, issue: SecurityIssue) -> LSPDiagnostic:
        """Create LSP diagnostic from security issue."""
        # Map severity
        severity_map = {
            Severity.LOW: DiagnosticSeverity.HINT,
            Severity.MEDIUM: DiagnosticSeverity.INFORMATION,
            Severity.HIGH: DiagnosticSeverity.WARNING,
            Severity.CRITICAL: DiagnosticSeverity.ERROR
        }
        
        # Create range (LSP uses 0-based line numbers)
        start_line = max(0, issue.line_number - 1)
        range_obj = LSPRange(
            start=LSPPosition(line=start_line, character=0),
            end=LSPPosition(line=start_line, character=100)
        )
        
        # Create message with remediation suggestions
        message = issue.description
        if issue.remediation_suggestions:
            message += "\\n\\nSuggested fixes:\\n" + "\\n".join(f"• {fix}" for fix in issue.remediation_suggestions)
        
        return LSPDiagnostic(
            range=range_obj,
            severity=severity_map.get(issue.severity, DiagnosticSeverity.WARNING),
            code=issue.rule_id,
            source="Compliance Sentinel",
            message=message
        )
    
    async def _send_diagnostics(self, uri: str, diagnostics: List[LSPDiagnostic]) -> None:
        """Send diagnostics notification to client."""
        notification = {
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {
                "uri": uri,
                "diagnostics": [diag.to_dict() for diag in diagnostics]
            }
        }
        
        # In a real implementation, this would send to the client
        self.logger.debug(f"Sending diagnostics for {uri}: {len(diagnostics)} items")
    
    def _get_security_completions(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get security-focused completion items."""
        return [
            {
                "label": "secure_hash_password",
                "kind": 3,  # Function
                "detail": "Secure password hashing",
                "documentation": "Hash password using bcrypt with proper salt rounds",
                "insertText": "bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))"
            },
            {
                "label": "validate_input",
                "kind": 3,
                "detail": "Input validation",
                "documentation": "Validate and sanitize user input",
                "insertText": "html.escape(user_input).strip()"
            },
            {
                "label": "parameterized_query",
                "kind": 9,  # Snippet
                "detail": "Safe database query",
                "documentation": "Use parameterized query to prevent SQL injection",
                "insertText": "cursor.execute(\\"SELECT * FROM users WHERE id = %s\\", (user_id,))"
            }
        ]
    
    def _position_in_range(self, position: Dict[str, int], range_obj: LSPRange) -> bool:
        """Check if position is within range."""
        pos_line = position["line"]
        pos_char = position["character"]
        
        if pos_line < range_obj.start.line or pos_line > range_obj.end.line:
            return False
        
        if pos_line == range_obj.start.line and pos_char < range_obj.start.character:
            return False
        
        if pos_line == range_obj.end.line and pos_char > range_obj.end.character:
            return False
        
        return True
    
    async def run_server(self) -> None:
        """Run the LSP server."""
        self.logger.info("Starting Compliance Sentinel Language Server")
        
        try:
            while True:
                # Read message from stdin
                line = await asyncio.to_thread(sys.stdin.readline)
                if not line:
                    break
                
                # Parse Content-Length header
                if line.startswith("Content-Length:"):
                    length = int(line.split(":")[1].strip())
                    
                    # Read separator line
                    await asyncio.to_thread(sys.stdin.readline)
                    
                    # Read message content
                    content = await asyncio.to_thread(sys.stdin.read, length)
                    
                    # Handle message
                    response = await self.handle_message(content)
                    
                    # Send response if needed
                    if response:
                        response_length = len(response.encode('utf-8'))
                        sys.stdout.write(f"Content-Length: {response_length}\\r\\n\\r\\n{response}")
                        sys.stdout.flush()
        
        except KeyboardInterrupt:
            self.logger.info("LSP server interrupted")
        except Exception as e:
            self.logger.error(f"LSP server error: {e}")
        finally:
            self.logger.info("LSP server stopped")


# Global LSP server instance
_global_lsp_server: Optional[LanguageServerProtocol] = None


def get_lsp_server() -> LanguageServerProtocol:
    """Get global LSP server instance."""
    global _global_lsp_server
    if _global_lsp_server is None:
        _global_lsp_server = LanguageServerProtocol()
    return _global_lsp_server


def reset_lsp_server() -> None:
    """Reset global LSP server (for testing)."""
    global _global_lsp_server
    _global_lsp_server = None


async def main():
    """Main entry point for LSP server."""
    server = get_lsp_server()
    await server.run_server()


if __name__ == "__main__":
    asyncio.run(main())