"""Contextual help and documentation system for security issues."""

import json
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from pathlib import Path
import logging

from compliance_sentinel.models.analysis import SecurityIssue, Severity


logger = logging.getLogger(__name__)


@dataclass
class HelpContent:
    """Help content for a security issue or concept."""
    title: str
    description: str
    explanation: str
    examples: List[Dict[str, str]] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)
    best_practices: List[str] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)
    related_topics: List[str] = field(default_factory=list)
    code_samples: Dict[str, str] = field(default_factory=dict)
    severity_info: Optional[Dict[str, str]] = None
    cwe_info: Optional[Dict[str, str]] = None


@dataclass
class InteractiveExample:
    """Interactive code example with before/after."""
    title: str
    description: str
    vulnerable_code: str
    secure_code: str
    language: str
    explanation: str
    key_changes: List[str] = field(default_factory=list)


@dataclass
class QuickReference:
    """Quick reference card for security concepts."""
    topic: str
    summary: str
    do_list: List[str] = field(default_factory=list)
    dont_list: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    checklist: List[str] = field(default_factory=list)


class ContextualHelpProvider:
    """Provides contextual help and documentation for security issues."""
    
    def __init__(self):
        """Initialize contextual help provider."""
        self.help_database = self._load_help_database()
        self.cwe_database = self._load_cwe_database()
        self.examples_database = self._load_examples_database()
        self.quick_references = self._load_quick_references()
    
    def get_help_for_issue(self, issue: SecurityIssue) -> HelpContent:
        """Get contextual help for a specific security issue."""
        # Try to find specific help for the rule ID
        if issue.rule_id in self.help_database:
            help_content = self.help_database[issue.rule_id]
        else:
            # Generate help based on issue characteristics
            help_content = self._generate_help_from_issue(issue)
        
        # Enhance with CWE information if available
        if issue.cwe_id and issue.cwe_id in self.cwe_database:
            help_content.cwe_info = self.cwe_database[issue.cwe_id]
        
        # Add severity-specific information
        help_content.severity_info = self._get_severity_info(issue.severity)
        
        return help_content
    
    def get_interactive_example(self, rule_id: str, language: str = "python") -> Optional[InteractiveExample]:
        """Get interactive example for a rule."""
        key = f"{rule_id}_{language}"
        if key in self.examples_database:
            return self.examples_database[key]
        
        # Try generic rule ID
        if rule_id in self.examples_database:
            return self.examples_database[rule_id]
        
        return None
    
    def get_quick_reference(self, topic: str) -> Optional[QuickReference]:
        """Get quick reference for a security topic."""
        return self.quick_references.get(topic)
    
    def search_help(self, query: str) -> List[HelpContent]:
        """Search help content by query."""
        results = []
        query_lower = query.lower()
        
        for rule_id, help_content in self.help_database.items():
            if (query_lower in help_content.title.lower() or
                query_lower in help_content.description.lower() or
                query_lower in help_content.explanation.lower()):
                results.append(help_content)
        
        return results[:10]  # Limit to top 10 results
    
    def get_related_help(self, issue: SecurityIssue) -> List[HelpContent]:
        """Get help for related security issues."""
        related_help = []
        
        # Find help for related topics
        main_help = self.get_help_for_issue(issue)
        for related_topic in main_help.related_topics:
            if related_topic in self.help_database:
                related_help.append(self.help_database[related_topic])
        
        # Find help for same CWE category
        if issue.cwe_id:
            for rule_id, help_content in self.help_database.items():
                if (help_content.cwe_info and 
                    help_content.cwe_info.get('id') == issue.cwe_id and
                    rule_id != issue.rule_id):
                    related_help.append(help_content)
        
        return related_help[:5]  # Limit to top 5 related items
    
    def format_help_for_ide(self, help_content: HelpContent, format_type: str = "markdown") -> str:
        """Format help content for IDE display."""
        if format_type == "markdown":
            return self._format_markdown_help(help_content)
        elif format_type == "html":
            return self._format_html_help(help_content)
        else:
            return self._format_plain_text_help(help_content)
    
    def _load_help_database(self) -> Dict[str, HelpContent]:
        """Load help database with security issue documentation."""
        # In a real implementation, this would load from files or database
        return {
            "B101": HelpContent(
                title="Hardcoded Password",
                description="Password or secret key is hardcoded in the source code",
                explanation="Hardcoding passwords, API keys, or other secrets in source code is a serious security vulnerability. These secrets can be easily discovered by anyone with access to the code, including in version control systems.",
                examples=[
                    {
                        "title": "Vulnerable Code",
                        "code": 'password = "admin123"'
                    },
                    {
                        "title": "Secure Code", 
                        "code": 'password = os.environ.get("PASSWORD")'
                    }
                ],
                remediation_steps=[
                    "Remove hardcoded secrets from source code",
                    "Use environment variables for configuration",
                    "Implement secure secret management system",
                    "Rotate any exposed secrets immediately"
                ],
                best_practices=[
                    "Never commit secrets to version control",
                    "Use secret management tools (HashiCorp Vault, AWS Secrets Manager)",
                    "Implement secret rotation policies",
                    "Use different secrets for different environments"
                ],
                references=[
                    {"title": "OWASP Hardcoded Credentials", "url": "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials"},
                    {"title": "CWE-798", "url": "https://cwe.mitre.org/data/definitions/798.html"}
                ],
                related_topics=["B102", "B103", "secret-management"],
                code_samples={
                    "python": "password = os.environ.get('PASSWORD')",
                    "javascript": "const password = process.env.PASSWORD",
                    "java": "String password = System.getenv(\"PASSWORD\")"
                }
            ),
            
            "B608": HelpContent(
                title="SQL Injection",
                description="Possible SQL injection vulnerability due to string formatting in SQL queries",
                explanation="SQL injection occurs when user input is directly concatenated or formatted into SQL queries without proper sanitization. This allows attackers to manipulate the query structure and potentially access, modify, or delete data.",
                examples=[
                    {
                        "title": "Vulnerable Code",
                        "code": 'query = f"SELECT * FROM users WHERE name = \'{user_input}\'"'
                    },
                    {
                        "title": "Secure Code",
                        "code": 'cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))'
                    }
                ],
                remediation_steps=[
                    "Use parameterized queries or prepared statements",
                    "Validate and sanitize all user inputs",
                    "Use ORM frameworks with built-in protection",
                    "Implement input validation and output encoding"
                ],
                best_practices=[
                    "Always use parameterized queries",
                    "Apply principle of least privilege to database accounts",
                    "Use stored procedures when appropriate",
                    "Implement proper error handling to avoid information disclosure"
                ],
                references=[
                    {"title": "OWASP SQL Injection", "url": "https://owasp.org/www-community/attacks/SQL_Injection"},
                    {"title": "CWE-89", "url": "https://cwe.mitre.org/data/definitions/89.html"}
                ],
                related_topics=["B609", "input-validation", "database-security"],
                code_samples={
                    "python": "cursor.execute('SELECT * FROM users WHERE name = ?', (user_input,))",
                    "java": "PreparedStatement stmt = conn.prepareStatement('SELECT * FROM users WHERE name = ?'); stmt.setString(1, userInput);",
                    "php": "$stmt = $pdo->prepare('SELECT * FROM users WHERE name = ?'); $stmt->execute([$userInput]);"
                }
            ),
            
            "B102": HelpContent(
                title="Command Injection",
                description="Possible command injection vulnerability",
                explanation="Command injection occurs when user input is passed to system commands without proper validation. This allows attackers to execute arbitrary commands on the host system.",
                examples=[
                    {
                        "title": "Vulnerable Code",
                        "code": 'os.system(f"ls -la {user_input}")'
                    },
                    {
                        "title": "Secure Code",
                        "code": 'subprocess.run(["ls", "-la", user_input], check=True)'
                    }
                ],
                remediation_steps=[
                    "Use subprocess with argument lists instead of shell=True",
                    "Validate and sanitize all user inputs",
                    "Use allowlists for permitted commands and arguments",
                    "Avoid system() and similar functions"
                ],
                best_practices=[
                    "Never pass user input directly to system commands",
                    "Use subprocess.run() with argument lists",
                    "Implement strict input validation",
                    "Run with minimal privileges"
                ],
                references=[
                    {"title": "OWASP Command Injection", "url": "https://owasp.org/www-community/attacks/Command_Injection"},
                    {"title": "CWE-78", "url": "https://cwe.mitre.org/data/definitions/78.html"}
                ],
                related_topics=["B603", "B605", "input-validation"],
                code_samples={
                    "python": "subprocess.run(['ls', '-la', user_input], check=True)",
                    "java": "ProcessBuilder pb = new ProcessBuilder('ls', '-la', userInput); pb.start();",
                    "nodejs": "const { spawn } = require('child_process'); spawn('ls', ['-la', userInput]);"
                }
            )
        }
    
    def _load_cwe_database(self) -> Dict[str, Dict[str, str]]:
        """Load CWE (Common Weakness Enumeration) database."""
        return {
            "798": {
                "id": "798",
                "name": "Use of Hard-coded Credentials",
                "description": "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
                "impact": "Hard-coded credentials typically create a significant hole that allows an attacker to bypass the authentication that has been configured by the software administrator.",
                "likelihood": "High"
            },
            "89": {
                "id": "89", 
                "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
                "impact": "Confidentiality, Integrity, Availability, Access Control",
                "likelihood": "High"
            },
            "78": {
                "id": "78",
                "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
                "impact": "Confidentiality, Integrity, Availability",
                "likelihood": "High"
            }
        }
    
    def _load_examples_database(self) -> Dict[str, InteractiveExample]:
        """Load interactive examples database."""
        return {
            "B101_python": InteractiveExample(
                title="Fixing Hardcoded Password",
                description="Learn how to replace hardcoded passwords with environment variables",
                vulnerable_code='''# Vulnerable: Password is hardcoded
DATABASE_PASSWORD = "admin123"
connection = connect_to_db("localhost", "admin", DATABASE_PASSWORD)''',
                secure_code='''# Secure: Password from environment variable
import os
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
if not DATABASE_PASSWORD:
    raise ValueError("DATABASE_PASSWORD environment variable not set")
connection = connect_to_db("localhost", "admin", DATABASE_PASSWORD)''',
                language="python",
                explanation="The secure version loads the password from an environment variable, which keeps secrets out of the source code.",
                key_changes=[
                    "Import os module to access environment variables",
                    "Use os.environ.get() to retrieve password",
                    "Add validation to ensure password is provided",
                    "Remove hardcoded password string"
                ]
            ),
            
            "B608_python": InteractiveExample(
                title="Preventing SQL Injection",
                description="Learn how to use parameterized queries to prevent SQL injection",
                vulnerable_code='''# Vulnerable: String formatting in SQL query
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()''',
                secure_code='''# Secure: Parameterized query
def get_user(username):
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()''',
                language="python",
                explanation="The secure version uses parameterized queries where the SQL structure is separated from the data, preventing injection attacks.",
                key_changes=[
                    "Replace f-string with parameterized query",
                    "Use ? placeholder for parameter",
                    "Pass username as tuple parameter",
                    "Remove direct string concatenation"
                ]
            )
        }
    
    def _load_quick_references(self) -> Dict[str, QuickReference]:
        """Load quick reference cards."""
        return {
            "input-validation": QuickReference(
                topic="Input Validation",
                summary="Best practices for validating user input to prevent security vulnerabilities",
                do_list=[
                    "Validate all input on the server side",
                    "Use allowlists instead of blocklists",
                    "Sanitize input before processing",
                    "Use parameterized queries for database operations",
                    "Encode output appropriately for the context"
                ],
                dont_list=[
                    "Trust client-side validation alone",
                    "Use string concatenation for SQL queries",
                    "Rely on blocklists for input filtering",
                    "Skip validation for 'trusted' sources",
                    "Use eval() or exec() with user input"
                ],
                tools=[
                    "OWASP Validation Regex Repository",
                    "Input validation libraries",
                    "Parameterized query frameworks",
                    "Output encoding libraries"
                ],
                checklist=[
                    "All user inputs are validated",
                    "Validation happens on server side",
                    "Appropriate data types are enforced",
                    "Length limits are applied",
                    "Special characters are handled safely"
                ]
            ),
            
            "secret-management": QuickReference(
                topic="Secret Management",
                summary="Best practices for handling secrets, passwords, and API keys securely",
                do_list=[
                    "Use environment variables for secrets",
                    "Implement secret rotation policies",
                    "Use dedicated secret management tools",
                    "Encrypt secrets at rest and in transit",
                    "Audit secret access regularly"
                ],
                dont_list=[
                    "Hardcode secrets in source code",
                    "Commit secrets to version control",
                    "Share secrets via email or chat",
                    "Use the same secret across environments",
                    "Store secrets in plain text files"
                ],
                tools=[
                    "HashiCorp Vault",
                    "AWS Secrets Manager",
                    "Azure Key Vault",
                    "Kubernetes Secrets",
                    "Docker Secrets"
                ],
                checklist=[
                    "No secrets in source code",
                    "Secrets are encrypted at rest",
                    "Access to secrets is logged",
                    "Secrets are rotated regularly",
                    "Different secrets per environment"
                ]
            )
        }
    
    def _generate_help_from_issue(self, issue: SecurityIssue) -> HelpContent:
        """Generate help content from issue characteristics."""
        return HelpContent(
            title=issue.title,
            description=issue.description,
            explanation=f"This issue was detected by rule {issue.rule_id}. {issue.description}",
            remediation_steps=[issue.remediation] if issue.remediation else [],
            references=[{"title": ref, "url": ref} for ref in issue.references],
            code_samples={}
        )
    
    def _get_severity_info(self, severity: Severity) -> Dict[str, str]:
        """Get information about severity level."""
        severity_info = {
            Severity.CRITICAL: {
                "level": "Critical",
                "description": "Immediate action required. This vulnerability poses a severe risk and should be fixed immediately.",
                "timeline": "Fix within 24 hours",
                "impact": "High risk of system compromise, data breach, or service disruption"
            },
            Severity.HIGH: {
                "level": "High", 
                "description": "High priority issue that should be addressed quickly.",
                "timeline": "Fix within 1 week",
                "impact": "Significant security risk that could lead to unauthorized access or data exposure"
            },
            Severity.MEDIUM: {
                "level": "Medium",
                "description": "Moderate security issue that should be addressed in the next development cycle.",
                "timeline": "Fix within 1 month",
                "impact": "Moderate security risk that could be exploited under certain conditions"
            },
            Severity.LOW: {
                "level": "Low",
                "description": "Low priority security issue that should be addressed when convenient.",
                "timeline": "Fix when convenient",
                "impact": "Minor security concern with limited exploitability"
            },
            Severity.INFO: {
                "level": "Informational",
                "description": "Informational finding that may indicate a potential security concern.",
                "timeline": "Review and consider",
                "impact": "No immediate security risk, but worth reviewing"
            }
        }
        
        return severity_info.get(severity, severity_info[Severity.INFO])
    
    def _format_markdown_help(self, help_content: HelpContent) -> str:
        """Format help content as Markdown."""
        markdown = f"# {help_content.title}\n\n"
        markdown += f"{help_content.description}\n\n"
        
        if help_content.explanation:
            markdown += f"## Explanation\n\n{help_content.explanation}\n\n"
        
        if help_content.severity_info:
            markdown += f"## Severity: {help_content.severity_info['level']}\n\n"
            markdown += f"{help_content.severity_info['description']}\n\n"
            markdown += f"**Timeline:** {help_content.severity_info['timeline']}\n\n"
            markdown += f"**Impact:** {help_content.severity_info['impact']}\n\n"
        
        if help_content.examples:
            markdown += "## Examples\n\n"
            for example in help_content.examples:
                markdown += f"### {example['title']}\n\n"
                markdown += f"```\n{example['code']}\n```\n\n"
        
        if help_content.remediation_steps:
            markdown += "## How to Fix\n\n"
            for i, step in enumerate(help_content.remediation_steps, 1):
                markdown += f"{i}. {step}\n"
            markdown += "\n"
        
        if help_content.best_practices:
            markdown += "## Best Practices\n\n"
            for practice in help_content.best_practices:
                markdown += f"- {practice}\n"
            markdown += "\n"
        
        if help_content.code_samples:
            markdown += "## Code Examples\n\n"
            for language, code in help_content.code_samples.items():
                markdown += f"### {language.title()}\n\n"
                markdown += f"```{language}\n{code}\n```\n\n"
        
        if help_content.references:
            markdown += "## References\n\n"
            for ref in help_content.references:
                markdown += f"- [{ref['title']}]({ref['url']})\n"
            markdown += "\n"
        
        if help_content.cwe_info:
            markdown += "## CWE Information\n\n"
            markdown += f"**CWE-{help_content.cwe_info['id']}:** {help_content.cwe_info['name']}\n\n"
            markdown += f"{help_content.cwe_info['description']}\n\n"
        
        return markdown
    
    def _format_html_help(self, help_content: HelpContent) -> str:
        """Format help content as HTML."""
        # Implementation would create HTML formatted help
        return self._format_markdown_help(help_content)  # Simplified for now
    
    def _format_plain_text_help(self, help_content: HelpContent) -> str:
        """Format help content as plain text."""
        text = f"{help_content.title}\n"
        text += "=" * len(help_content.title) + "\n\n"
        text += f"{help_content.description}\n\n"
        
        if help_content.explanation:
            text += f"Explanation:\n{help_content.explanation}\n\n"
        
        if help_content.remediation_steps:
            text += "How to Fix:\n"
            for i, step in enumerate(help_content.remediation_steps, 1):
                text += f"{i}. {step}\n"
            text += "\n"
        
        return text