"""Test data manager for comprehensive testing framework."""

import logging
import json
import hashlib
import random
import string
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
import tempfile
import os

from compliance_sentinel.core.interfaces import SecurityIssue, Severity


logger = logging.getLogger(__name__)


class TestDataType(Enum):
    """Types of test data."""
    VULNERABLE_CODE = "vulnerable_code"
    SECURE_CODE = "secure_code"
    MALICIOUS_PAYLOAD = "malicious_payload"
    CONFIGURATION_FILE = "configuration_file"
    DEPENDENCY_FILE = "dependency_file"
    COMPLIANCE_SAMPLE = "compliance_sample"
    PERFORMANCE_DATA = "performance_data"
    ML_TRAINING_DATA = "ml_training_data"


class ProgrammingLanguage(Enum):
    """Supported programming languages."""
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    PYTHON = "python"
    JAVA = "java"
    CSHARP = "csharp"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    CPP = "cpp"
    C = "c"


@dataclass
class TestDataSample:
    """Represents a test data sample."""
    
    sample_id: str
    name: str
    description: str
    data_type: TestDataType
    
    # Content
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Classification
    language: Optional[ProgrammingLanguage] = None
    vulnerability_types: List[str] = field(default_factory=list)
    severity: Optional[Severity] = None
    
    # Test expectations
    expected_issues: List[str] = field(default_factory=list)
    expected_patterns: List[str] = field(default_factory=list)
    
    # Metadata
    tags: Set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert sample to dictionary."""
        return {
            'sample_id': self.sample_id,
            'name': self.name,
            'description': self.description,
            'data_type': self.data_type.value,
            'language': self.language.value if self.language else None,
            'vulnerability_types': self.vulnerability_types,
            'severity': self.severity.value if self.severity else None,
            'expected_issues': self.expected_issues,
            'expected_patterns': self.expected_patterns,
            'tags': list(self.tags),
            'created_at': self.created_at.isoformat(),
            'content_length': len(self.content),
            'metadata': self.metadata
        }


class TestDataManager:
    """Manages test data for comprehensive testing framework."""
    
    def __init__(self, storage_path: str = "test_data"):
        """Initialize test data manager."""
        self.logger = logging.getLogger(__name__)
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        # Data storage
        self.samples = {}
        self.datasets = {}
        
        # Load built-in test data
        self._load_builtin_samples()
    
    def _load_builtin_samples(self):
        """Load built-in test data samples."""
        
        # JavaScript/TypeScript vulnerable samples
        self._add_javascript_samples()
        
        # Python vulnerable samples
        self._add_python_samples()
        
        # Java vulnerable samples
        self._add_java_samples()
        
        # Configuration samples
        self._add_configuration_samples()
        
        # Dependency samples
        self._add_dependency_samples()
        
        # Performance test data
        self._add_performance_samples()
        
        # ML training data
        self._add_ml_samples()
    
    def _add_javascript_samples(self):
        """Add JavaScript/TypeScript test samples."""
        
        # XSS vulnerability
        self.add_sample(TestDataSample(
            sample_id="js_xss_dom",
            name="DOM-based XSS",
            description="JavaScript code vulnerable to DOM-based XSS attacks",
            data_type=TestDataType.VULNERABLE_CODE,
            language=ProgrammingLanguage.JAVASCRIPT,
            content="""
function updateContent(userInput) {
    document.getElementById('content').innerHTML = userInput;
}

function displayMessage() {
    var message = location.hash.substring(1);
    document.write(message);
}

function processUserData(data) {
    var output = '<div>' + data + '</div>';
    document.body.innerHTML += output;
}
            """,
            vulnerability_types=["xss", "dom_manipulation"],
            severity=Severity.HIGH,
            expected_issues=["xss_dom_manipulation", "dangerous_innerHTML", "document_write"],
            tags={"javascript", "xss", "dom", "client_side"}
        ))
        
        # Prototype pollution
        self.add_sample(TestDataSample(
            sample_id="js_prototype_pollution",
            name="Prototype Pollution",
            description="JavaScript code vulnerable to prototype pollution",
            data_type=TestDataType.VULNERABLE_CODE,
            language=ProgrammingLanguage.JAVASCRIPT,
            content="""
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

function processConfig(userConfig) {
    let config = {};
    merge(config, JSON.parse(userConfig));
    return config;
}

function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
}
            """,
            vulnerability_types=["prototype_pollution", "object_manipulation"],
            severity=Severity.HIGH,
            expected_issues=["prototype_pollution", "unsafe_merge"],
            tags={"javascript", "prototype_pollution", "object_manipulation"}
        ))
        
        # Secure JavaScript sample
        self.add_sample(TestDataSample(
            sample_id="js_secure_dom",
            name="Secure DOM Manipulation",
            description="Secure JavaScript code for DOM manipulation",
            data_type=TestDataType.SECURE_CODE,
            language=ProgrammingLanguage.JAVASCRIPT,
            content="""
function updateContent(userInput) {
    // Use textContent instead of innerHTML
    document.getElementById('content').textContent = userInput;
}

function displayMessage() {
    var message = location.hash.substring(1);
    // Sanitize and use textContent
    document.getElementById('message').textContent = sanitizeInput(message);
}

function sanitizeInput(input) {
    return input.replace(/[<>\"'&]/g, function(match) {
        return {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        }[match];
    });
}
            """,
            vulnerability_types=[],
            expected_issues=[],
            tags={"javascript", "secure", "dom", "sanitization"}
        ))
    
    def _add_python_samples(self):
        """Add Python test samples."""
        
        # SQL injection vulnerability
        self.add_sample(TestDataSample(
            sample_id="py_sql_injection",
            name="SQL Injection",
            description="Python code vulnerable to SQL injection",
            data_type=TestDataType.VULNERABLE_CODE,
            language=ProgrammingLanguage.PYTHON,
            content="""
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: string concatenation
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    
    return cursor.fetchone()

def search_users(search_term):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: string formatting
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    
    return cursor.fetchall()

def update_user(user_id, name):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: % formatting
    query = "UPDATE users SET name = '%s' WHERE id = %s" % (name, user_id)
    cursor.execute(query)
    conn.commit()
            """,
            vulnerability_types=["sql_injection", "database"],
            severity=Severity.HIGH,
            expected_issues=["sql_injection", "string_concatenation_sql"],
            tags={"python", "sql_injection", "database"}
        ))
        
        # Command injection vulnerability
        self.add_sample(TestDataSample(
            sample_id="py_command_injection",
            name="Command Injection",
            description="Python code vulnerable to command injection",
            data_type=TestDataType.VULNERABLE_CODE,
            language=ProgrammingLanguage.PYTHON,
            content="""
import os
import subprocess

def process_file(filename):
    # Vulnerable: shell=True with user input
    command = f"cat {filename} | grep 'pattern'"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def backup_file(filename):
    # Vulnerable: os.system with user input
    os.system(f"cp {filename} /backup/")

def list_directory(path):
    # Vulnerable: string concatenation in shell command
    output = os.popen("ls -la " + path).read()
    return output
            """,
            vulnerability_types=["command_injection", "shell_injection"],
            severity=Severity.CRITICAL,
            expected_issues=["command_injection", "shell_true", "os_system"],
            tags={"python", "command_injection", "shell"}
        ))
        
        # Secure Python sample
        self.add_sample(TestDataSample(
            sample_id="py_secure_sql",
            name="Secure SQL Operations",
            description="Secure Python code for SQL operations",
            data_type=TestDataType.SECURE_CODE,
            language=ProgrammingLanguage.PYTHON,
            content="""
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Secure: parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    
    return cursor.fetchone()

def search_users(search_term):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Secure: parameterized query with LIKE
    query = "SELECT * FROM users WHERE name LIKE ?"
    cursor.execute(query, (f'%{search_term}%',))
    
    return cursor.fetchall()

def update_user(user_id, name):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Secure: parameterized query
    query = "UPDATE users SET name = ? WHERE id = ?"
    cursor.execute(query, (name, user_id))
    conn.commit()
            """,
            vulnerability_types=[],
            expected_issues=[],
            tags={"python", "secure", "sql", "parameterized"}
        ))
    
    def _add_java_samples(self):
        """Add Java test samples."""
        
        # Deserialization vulnerability
        self.add_sample(TestDataSample(
            sample_id="java_deserialization",
            name="Unsafe Deserialization",
            description="Java code vulnerable to deserialization attacks",
            data_type=TestDataType.VULNERABLE_CODE,
            language=ProgrammingLanguage.JAVA,
            content="""
import java.io.*;
import java.util.Base64;

public class UserService {
    
    public Object deserializeUser(byte[] data) throws Exception {
        // Vulnerable: unrestricted deserialization
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
    
    public void processUserData(String serializedData) throws Exception {
        byte[] data = Base64.getDecoder().decode(serializedData);
        Object user = deserializeUser(data);
        // Process user object
    }
    
    public Object loadFromFile(String filename) throws Exception {
        // Vulnerable: deserializing from file
        FileInputStream fis = new FileInputStream(filename);
        ObjectInputStream ois = new ObjectInputStream(fis);
        return ois.readObject();
    }
}
            """,
            vulnerability_types=["deserialization", "object_injection"],
            severity=Severity.CRITICAL,
            expected_issues=["unsafe_deserialization", "object_input_stream"],
            tags={"java", "deserialization", "rce"}
        ))
        
        # XXE vulnerability
        self.add_sample(TestDataSample(
            sample_id="java_xxe",
            name="XML External Entity (XXE)",
            description="Java code vulnerable to XXE attacks",
            data_type=TestDataType.VULNERABLE_CODE,
            language=ProgrammingLanguage.JAVA,
            content="""
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.io.*;

public class XMLProcessor {
    
    public Document parseXML(String xmlContent) throws Exception {
        // Vulnerable: XXE enabled by default
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        
        return builder.parse(new ByteArrayInputStream(xmlContent.getBytes()));
    }
    
    public void processXMLFile(String filename) throws Exception {
        // Vulnerable: processing external XML
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        
        Document doc = builder.parse(new File(filename));
        // Process document
    }
}
            """,
            vulnerability_types=["xxe", "xml_injection"],
            severity=Severity.HIGH,
            expected_issues=["xxe_vulnerability", "unsafe_xml_parsing"],
            tags={"java", "xxe", "xml"}
        ))
    
    def _add_configuration_samples(self):
        """Add configuration file samples."""
        
        # Insecure Docker configuration
        self.add_sample(TestDataSample(
            sample_id="docker_insecure",
            name="Insecure Dockerfile",
            description="Dockerfile with security vulnerabilities",
            data_type=TestDataType.CONFIGURATION_FILE,
            content="""
FROM ubuntu:latest

# Vulnerable: running as root
USER root

# Vulnerable: installing unnecessary packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim \
    sudo \
    ssh

# Vulnerable: hardcoded secrets
ENV API_KEY=sk-1234567890abcdef
ENV DATABASE_PASSWORD=admin123

# Vulnerable: exposing unnecessary ports
EXPOSE 22
EXPOSE 3306

# Vulnerable: copying entire context
COPY . /app

# Vulnerable: running with privileged access
RUN chmod 777 /app

WORKDIR /app
CMD ["python", "app.py"]
            """,
            vulnerability_types=["container_security", "privilege_escalation", "secret_exposure"],
            severity=Severity.HIGH,
            expected_issues=["root_user", "hardcoded_secrets", "unnecessary_packages"],
            tags={"docker", "container", "configuration"}
        ))
        
        # Secure Docker configuration
        self.add_sample(TestDataSample(
            sample_id="docker_secure",
            name="Secure Dockerfile",
            description="Secure Dockerfile configuration",
            data_type=TestDataType.CONFIGURATION_FILE,
            content="""
FROM python:3.9-slim

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install only necessary packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appuser src/ .

# Switch to non-root user
USER appuser

# Expose only necessary port
EXPOSE 8080

# Use exec form for CMD
CMD ["python", "-m", "app"]
            """,
            vulnerability_types=[],
            expected_issues=[],
            tags={"docker", "secure", "configuration"}
        ))
    
    def _add_dependency_samples(self):
        """Add dependency file samples."""
        
        # Vulnerable package.json
        self.add_sample(TestDataSample(
            sample_id="package_json_vulnerable",
            name="Vulnerable package.json",
            description="Node.js package.json with vulnerable dependencies",
            data_type=TestDataType.DEPENDENCY_FILE,
            content="""
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.16.0",
    "lodash": "4.17.4",
    "moment": "2.19.3",
    "request": "2.88.0",
    "jquery": "3.3.1",
    "bootstrap": "3.3.7",
    "handlebars": "4.0.12",
    "marked": "0.3.6",
    "serialize-javascript": "1.4.0",
    "node-sass": "4.5.3"
  },
  "devDependencies": {
    "webpack": "4.29.0",
    "babel-core": "6.26.0"
  }
}
            """,
            vulnerability_types=["vulnerable_dependencies", "supply_chain"],
            severity=Severity.HIGH,
            expected_issues=["vulnerable_lodash", "vulnerable_handlebars", "vulnerable_marked"],
            tags={"nodejs", "dependencies", "vulnerable"}
        ))
        
        # Vulnerable requirements.txt
        self.add_sample(TestDataSample(
            sample_id="requirements_vulnerable",
            name="Vulnerable requirements.txt",
            description="Python requirements.txt with vulnerable dependencies",
            data_type=TestDataType.DEPENDENCY_FILE,
            content="""
Django==2.0.1
Flask==0.12.2
requests==2.18.4
Pillow==5.0.0
PyYAML==3.12
Jinja2==2.9.6
SQLAlchemy==1.1.15
cryptography==2.1.4
paramiko==2.0.0
lxml==4.1.1
            """,
            vulnerability_types=["vulnerable_dependencies", "supply_chain"],
            severity=Severity.HIGH,
            expected_issues=["vulnerable_django", "vulnerable_pyyaml", "vulnerable_pillow"],
            tags={"python", "dependencies", "vulnerable"}
        ))
    
    def _add_performance_samples(self):
        """Add performance test data samples."""
        
        # Large dataset for performance testing
        large_code_sample = self._generate_large_code_sample(1000)
        
        self.add_sample(TestDataSample(
            sample_id="perf_large_file",
            name="Large Code File",
            description="Large code file for performance testing",
            data_type=TestDataType.PERFORMANCE_DATA,
            language=ProgrammingLanguage.JAVASCRIPT,
            content=large_code_sample,
            metadata={"lines_of_code": 1000, "file_size_kb": len(large_code_sample) / 1024},
            tags={"performance", "large_file", "javascript"}
        ))
        
        # Complex nested code
        complex_code = self._generate_complex_code_sample()
        
        self.add_sample(TestDataSample(
            sample_id="perf_complex_code",
            name="Complex Nested Code",
            description="Complex code with deep nesting for performance testing",
            data_type=TestDataType.PERFORMANCE_DATA,
            language=ProgrammingLanguage.PYTHON,
            content=complex_code,
            metadata={"complexity_level": "high", "nesting_depth": 10},
            tags={"performance", "complex", "python"}
        ))
    
    def _add_ml_samples(self):
        """Add ML training data samples."""
        
        # Positive samples (vulnerable code)
        vulnerable_samples = [
            "eval(user_input)",
            "exec(user_data)",
            "document.write(untrusted_data)",
            "innerHTML = user_content",
            "SELECT * FROM users WHERE id = '" + user_id + "'",
            "os.system(user_command)",
            "subprocess.call(shell_command, shell=True)"
        ]
        
        # Negative samples (secure code)
        secure_samples = [
            "json.loads(user_input)",
            "ast.literal_eval(user_data)",
            "document.textContent = trusted_data",
            "textContent = sanitized_content",
            "SELECT * FROM users WHERE id = ?",
            "subprocess.run([command, arg1, arg2])",
            "subprocess.call(command_list)"
        ]
        
        # Create ML training dataset
        ml_dataset = {
            "positive_samples": vulnerable_samples,
            "negative_samples": secure_samples,
            "features": ["ast_patterns", "string_patterns", "function_calls"],
            "labels": [1] * len(vulnerable_samples) + [0] * len(secure_samples)
        }
        
        self.add_sample(TestDataSample(
            sample_id="ml_training_basic",
            name="Basic ML Training Data",
            description="Basic training data for ML security models",
            data_type=TestDataType.ML_TRAINING_DATA,
            content=json.dumps(ml_dataset, indent=2),
            metadata={
                "positive_samples": len(vulnerable_samples),
                "negative_samples": len(secure_samples),
                "total_samples": len(vulnerable_samples) + len(secure_samples)
            },
            tags={"ml", "training", "security"}
        ))
    
    def _generate_large_code_sample(self, lines: int) -> str:
        """Generate large code sample for performance testing."""
        
        code_lines = []
        
        for i in range(lines):
            if i % 10 == 0:
                code_lines.append(f"// Function {i // 10}")
                code_lines.append(f"function processData{i // 10}(input) {{")
            elif i % 10 == 9:
                code_lines.append("}")
                code_lines.append("")
            else:
                code_lines.append(f"    var result{i} = input.map(item => item.value * {i});")
        
        return "\n".join(code_lines)
    
    def _generate_complex_code_sample(self) -> str:
        """Generate complex nested code sample."""
        
        return """
def complex_function(data):
    if data:
        for item in data:
            if item.get('type') == 'user':
                for permission in item.get('permissions', []):
                    if permission.get('level') > 5:
                        for resource in permission.get('resources', []):
                            if resource.get('sensitive'):
                                for action in resource.get('actions', []):
                                    if action.get('dangerous'):
                                        for audit in action.get('audit_logs', []):
                                            if audit.get('failed'):
                                                for retry in audit.get('retries', []):
                                                    if retry.get('count') > 3:
                                                        for alert in retry.get('alerts', []):
                                                            if alert.get('critical'):
                                                                return process_critical_alert(alert)
    return None
        """
    
    def add_sample(self, sample: TestDataSample):
        """Add a test data sample."""
        self.samples[sample.sample_id] = sample
        self.logger.debug(f"Added test sample: {sample.sample_id}")
    
    def get_sample(self, sample_id: str) -> Optional[TestDataSample]:
        """Get a test data sample by ID."""
        return self.samples.get(sample_id)
    
    def get_samples_by_type(self, data_type: TestDataType) -> List[TestDataSample]:
        """Get all samples of a specific type."""
        return [sample for sample in self.samples.values() if sample.data_type == data_type]
    
    def get_samples_by_language(self, language: ProgrammingLanguage) -> List[TestDataSample]:
        """Get all samples for a specific language."""
        return [sample for sample in self.samples.values() if sample.language == language]
    
    def get_samples_by_vulnerability(self, vulnerability_type: str) -> List[TestDataSample]:
        """Get all samples containing a specific vulnerability type."""
        return [
            sample for sample in self.samples.values()
            if vulnerability_type in sample.vulnerability_types
        ]
    
    def get_samples_by_tags(self, tags: Set[str]) -> List[TestDataSample]:
        """Get all samples matching any of the provided tags."""
        return [
            sample for sample in self.samples.values()
            if sample.tags.intersection(tags)
        ]
    
    def create_dataset(self, 
                      dataset_name: str,
                      sample_ids: List[str],
                      description: str = "") -> Dict[str, Any]:
        """Create a named dataset from sample IDs."""
        
        dataset = {
            'name': dataset_name,
            'description': description,
            'sample_ids': sample_ids,
            'created_at': datetime.now().isoformat(),
            'sample_count': len(sample_ids)
        }
        
        self.datasets[dataset_name] = dataset
        return dataset
    
    def get_dataset(self, dataset_name: str) -> Optional[Dict[str, Any]]:
        """Get a dataset by name."""
        return self.datasets.get(dataset_name)
    
    def get_dataset_samples(self, dataset_name: str) -> List[TestDataSample]:
        """Get all samples in a dataset."""
        dataset = self.get_dataset(dataset_name)
        if not dataset:
            return []
        
        return [
            self.samples[sample_id] 
            for sample_id in dataset['sample_ids']
            if sample_id in self.samples
        ]
    
    def export_samples(self, 
                      sample_ids: Optional[List[str]] = None,
                      output_path: Optional[str] = None) -> str:
        """Export samples to JSON file."""
        
        if sample_ids is None:
            samples_to_export = list(self.samples.values())
        else:
            samples_to_export = [
                self.samples[sample_id] 
                for sample_id in sample_ids 
                if sample_id in self.samples
            ]
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'sample_count': len(samples_to_export),
            'samples': [sample.to_dict() for sample in samples_to_export]
        }
        
        if output_path is None:
            output_path = self.storage_path / f"export_{int(datetime.now().timestamp())}.json"
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        self.logger.info(f"Exported {len(samples_to_export)} samples to {output_path}")
        return str(output_path)
    
    def import_samples(self, import_path: str) -> int:
        """Import samples from JSON file."""
        
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
            
            imported_count = 0
            
            for sample_dict in import_data.get('samples', []):
                # Reconstruct sample object
                sample = TestDataSample(
                    sample_id=sample_dict['sample_id'],
                    name=sample_dict['name'],
                    description=sample_dict['description'],
                    data_type=TestDataType(sample_dict['data_type']),
                    content=sample_dict.get('content', ''),
                    metadata=sample_dict.get('metadata', {}),
                    language=ProgrammingLanguage(sample_dict['language']) if sample_dict.get('language') else None,
                    vulnerability_types=sample_dict.get('vulnerability_types', []),
                    severity=Severity(sample_dict['severity']) if sample_dict.get('severity') else None,
                    expected_issues=sample_dict.get('expected_issues', []),
                    expected_patterns=sample_dict.get('expected_patterns', []),
                    tags=set(sample_dict.get('tags', [])),
                    created_at=datetime.fromisoformat(sample_dict.get('created_at', datetime.now().isoformat()))
                )
                
                self.add_sample(sample)
                imported_count += 1
            
            self.logger.info(f"Imported {imported_count} samples from {import_path}")
            return imported_count
            
        except Exception as e:
            self.logger.error(f"Error importing samples: {e}")
            return 0
    
    def generate_synthetic_samples(self, 
                                 language: ProgrammingLanguage,
                                 vulnerability_type: str,
                                 count: int = 10) -> List[TestDataSample]:
        """Generate synthetic test samples."""
        
        synthetic_samples = []
        
        for i in range(count):
            sample_id = f"synthetic_{language.value}_{vulnerability_type}_{i}"
            
            # Generate synthetic content based on patterns
            content = self._generate_synthetic_content(language, vulnerability_type, i)
            
            sample = TestDataSample(
                sample_id=sample_id,
                name=f"Synthetic {vulnerability_type} Sample {i}",
                description=f"Synthetically generated {vulnerability_type} sample for {language.value}",
                data_type=TestDataType.VULNERABLE_CODE,
                language=language,
                content=content,
                vulnerability_types=[vulnerability_type],
                severity=Severity.MEDIUM,
                expected_issues=[vulnerability_type],
                tags={"synthetic", language.value, vulnerability_type}
            )
            
            synthetic_samples.append(sample)
            self.add_sample(sample)
        
        return synthetic_samples
    
    def _generate_synthetic_content(self, 
                                  language: ProgrammingLanguage,
                                  vulnerability_type: str,
                                  index: int) -> str:
        """Generate synthetic code content."""
        
        templates = {
            ProgrammingLanguage.JAVASCRIPT: {
                "xss": [
                    f"document.getElementById('output{index}').innerHTML = userInput{index};",
                    f"document.write(userData{index});",
                    f"element{index}.outerHTML = content{index};"
                ],
                "prototype_pollution": [
                    f"function merge{index}(target, source) {{ for (let key in source) target[key] = source[key]; }}",
                    f"Object.assign(config{index}, userInput{index});",
                    f"_.merge(obj{index}, untrustedData{index});"
                ]
            },
            ProgrammingLanguage.PYTHON: {
                "sql_injection": [
                    f"cursor.execute('SELECT * FROM table WHERE id = ' + user_id{index})",
                    f"query{index} = f'SELECT * FROM users WHERE name = {{name{index}}}'",
                    f"db.execute('UPDATE table SET value = %s' % value{index})"
                ],
                "command_injection": [
                    f"os.system('ls ' + directory{index})",
                    f"subprocess.call(f'cat {{filename{index}}}', shell=True)",
                    f"os.popen('grep pattern ' + file{index}).read()"
                ]
            }
        }
        
        if language in templates and vulnerability_type in templates[language]:
            patterns = templates[language][vulnerability_type]
            return patterns[index % len(patterns)]
        
        # Fallback generic content
        return f"// Synthetic {vulnerability_type} sample {index} for {language.value}"
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about test data."""
        
        stats = {
            'total_samples': len(self.samples),
            'total_datasets': len(self.datasets),
            'by_type': {},
            'by_language': {},
            'by_severity': {},
            'by_vulnerability': {}
        }
        
        # Count by type
        for data_type in TestDataType:
            count = len(self.get_samples_by_type(data_type))
            stats['by_type'][data_type.value] = count
        
        # Count by language
        for language in ProgrammingLanguage:
            count = len(self.get_samples_by_language(language))
            if count > 0:
                stats['by_language'][language.value] = count
        
        # Count by severity
        for severity in Severity:
            count = len([s for s in self.samples.values() if s.severity == severity])
            if count > 0:
                stats['by_severity'][severity.value] = count
        
        # Count by vulnerability type
        all_vuln_types = set()
        for sample in self.samples.values():
            all_vuln_types.update(sample.vulnerability_types)
        
        for vuln_type in all_vuln_types:
            count = len(self.get_samples_by_vulnerability(vuln_type))
            stats['by_vulnerability'][vuln_type] = count
        
        return stats


# Utility functions

def create_test_data_report(manager: TestDataManager) -> str:
    """Create comprehensive test data report."""
    
    stats = manager.get_statistics()
    
    report = f"""
# Test Data Management Report

## Overview
- **Total Samples**: {stats['total_samples']}
- **Total Datasets**: {stats['total_datasets']}

## Samples by Type
"""
    
    for data_type, count in stats['by_type'].items():
        if count > 0:
            report += f"- **{data_type.replace('_', ' ').title()}**: {count}\n"
    
    report += "\n## Samples by Language\n"
    for language, count in stats['by_language'].items():
        report += f"- **{language.title()}**: {count}\n"
    
    report += "\n## Samples by Severity\n"
    for severity, count in stats['by_severity'].items():
        report += f"- **{severity.title()}**: {count}\n"
    
    report += "\n## Top Vulnerability Types\n"
    sorted_vulns = sorted(stats['by_vulnerability'].items(), key=lambda x: x[1], reverse=True)
    for vuln_type, count in sorted_vulns[:10]:
        report += f"- **{vuln_type.replace('_', ' ').title()}**: {count}\n"
    
    return report


def setup_comprehensive_test_data() -> TestDataManager:
    """Set up comprehensive test data for testing framework."""
    
    manager = TestDataManager()
    
    # Generate additional synthetic samples
    languages = [ProgrammingLanguage.JAVASCRIPT, ProgrammingLanguage.PYTHON, ProgrammingLanguage.JAVA]
    vulnerabilities = ["xss", "sql_injection", "command_injection"]
    
    for language in languages:
        for vuln_type in vulnerabilities:
            if (language == ProgrammingLanguage.JAVASCRIPT and vuln_type == "xss") or \
               (language == ProgrammingLanguage.PYTHON and vuln_type in ["sql_injection", "command_injection"]) or \
               (language == ProgrammingLanguage.JAVA and vuln_type == "sql_injection"):
                manager.generate_synthetic_samples(language, vuln_type, 5)
    
    # Create predefined datasets
    manager.create_dataset(
        "javascript_security",
        [s.sample_id for s in manager.get_samples_by_language(ProgrammingLanguage.JAVASCRIPT)],
        "JavaScript security test samples"
    )
    
    manager.create_dataset(
        "python_security",
        [s.sample_id for s in manager.get_samples_by_language(ProgrammingLanguage.PYTHON)],
        "Python security test samples"
    )
    
    manager.create_dataset(
        "high_severity",
        [s.sample_id for s in manager.samples.values() if s.severity == Severity.HIGH],
        "High severity vulnerability samples"
    )
    
    return manager