"""Vulnerable code samples for testing security analysis."""

from typing import Dict, List
from dataclasses import dataclass


@dataclass
class VulnerableCodeSample:
    """Represents a vulnerable code sample for testing."""
    name: str
    language: str
    code: str
    expected_issues: List[str]  # Expected rule IDs
    description: str
    severity_levels: List[str]
    cwe_ids: List[str] = None


class VulnerableCodeSamples:
    """Collection of vulnerable code samples for testing."""
    
    @staticmethod
    def get_python_samples() -> List[VulnerableCodeSample]:
        """Get Python vulnerable code samples."""
        return [
            VulnerableCodeSample(
                name="hardcoded_secrets",
                language="python",
                code='''
import os
import requests

# Hardcoded secrets - multiple types
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
SECRET_KEY = "my-secret-key-12345"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
JWT_SECRET = "jwt-secret-key"

def connect_to_database():
    connection_string = f"postgresql://admin:{DATABASE_PASSWORD}@localhost/mydb"
    return connection_string

def call_api():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get("https://api.example.com/data", headers=headers)
    return response.json()

class Config:
    SECRET_KEY = "hardcoded-flask-secret"
    DATABASE_URL = "mysql://root:password123@localhost/app"
''',
                expected_issues=["B105", "B106", "B107"],
                description="Multiple types of hardcoded secrets and credentials",
                severity_levels=["critical", "high"],
                cwe_ids=["798"]
            ),
            
            VulnerableCodeSample(
                name="sql_injection",
                language="python",
                code='''
import sqlite3
import mysql.connector

def get_user_by_name(username):
    # SQL injection via string formatting
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def get_user_by_id(user_id):
    # SQL injection via % formatting
    conn = mysql.connector.connect(host='localhost', database='app')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    return cursor.fetchone()

def search_users(search_term):
    # SQL injection via .format()
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name LIKE '%{}%'".format(search_term)
    cursor.execute(query)
    return cursor.fetchall()

def complex_query(table, column, value):
    # Complex SQL injection
    query = f"SELECT * FROM {table} WHERE {column} = '{value}' ORDER BY created_at"
    return execute_query(query)
''',
                expected_issues=["B608", "B609"],
                description="Various SQL injection vulnerabilities",
                severity_levels=["critical", "high"],
                cwe_ids=["89"]
            ),
            
            VulnerableCodeSample(
                name="command_injection",
                language="python",
                code='''
import os
import subprocess
import shlex

def process_file(filename):
    # Command injection via os.system
    os.system(f"cat {filename}")
    
def list_directory(path):
    # Command injection via subprocess with shell=True
    result = subprocess.run(f"ls -la {path}", shell=True, capture_output=True)
    return result.stdout

def compress_file(filename, output):
    # Command injection via os.popen
    cmd = f"gzip -c {filename} > {output}"
    os.popen(cmd)

def search_files(pattern, directory):
    # Command injection via subprocess.call
    subprocess.call(f"find {directory} -name '{pattern}'", shell=True)

def backup_database(db_name, backup_path):
    # Even with shlex, still vulnerable if not used properly
    cmd = f"mysqldump {db_name} > {backup_path}"
    subprocess.run(shlex.split(cmd))  # Still vulnerable
''',
                expected_issues=["B602", "B603", "B605", "B607"],
                description="Command injection vulnerabilities",
                severity_levels=["critical", "high"],
                cwe_ids=["78"]
            ),
            
            VulnerableCodeSample(
                name="weak_cryptography",
                language="python",
                code='''
import hashlib
import random
import string
from Crypto.Cipher import DES
import ssl

def weak_password_hash(password):
    # Weak hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()

def another_weak_hash(data):
    # SHA1 is also weak for passwords
    return hashlib.sha1(data.encode()).hexdigest()

def weak_random_token():
    # Weak random number generation
    return ''.join(random.choice(string.ascii_letters) for _ in range(32))

def weak_encryption(data, key):
    # Weak encryption algorithm
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

def insecure_ssl_context():
    # Insecure SSL context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

class WeakCrypto:
    def __init__(self):
        # Hardcoded encryption key
        self.key = b"12345678"  # DES key
        
    def encrypt(self, data):
        cipher = DES.new(self.key, DES.MODE_ECB)
        return cipher.encrypt(data)
''',
                expected_issues=["B303", "B324", "B501", "B502"],
                description="Weak cryptographic practices",
                severity_levels=["high", "medium"],
                cwe_ids=["327", "330"]
            ),
            
            VulnerableCodeSample(
                name="deserialization_attacks",
                language="python",
                code='''
import pickle
import yaml
import json
import marshal

def unsafe_pickle_load(data):
    # Unsafe deserialization with pickle
    return pickle.loads(data)

def unsafe_yaml_load(yaml_string):
    # Unsafe YAML loading
    return yaml.load(yaml_string)

def unsafe_marshal_load(data):
    # Unsafe marshal loading
    return marshal.loads(data)

def process_user_data(serialized_data, format_type):
    # Dynamic deserialization based on user input
    if format_type == "pickle":
        return pickle.loads(serialized_data)
    elif format_type == "yaml":
        return yaml.load(serialized_data)
    elif format_type == "json":
        return json.loads(serialized_data)  # This one is actually safe
    
def load_config_file(filename):
    with open(filename, 'rb') as f:
        # Unsafe pickle loading from file
        return pickle.load(f)
''',
                expected_issues=["B301", "B302", "B506"],
                description="Unsafe deserialization vulnerabilities",
                severity_levels=["critical", "high"],
                cwe_ids=["502"]
            ),
            
            VulnerableCodeSample(
                name="path_traversal",
                language="python",
                code='''
import os
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route('/download')
def download_file():
    # Path traversal vulnerability
    filename = request.args.get('filename')
    return send_file(f"/uploads/{filename}")

def read_user_file(filename):
    # Path traversal via direct file access
    with open(f"/data/{filename}", 'r') as f:
        return f.read()

def save_uploaded_file(filename, content):
    # Path traversal in file writing
    filepath = f"/uploads/{filename}"
    with open(filepath, 'w') as f:
        f.write(content)

def get_template(template_name):
    # Path traversal in template loading
    template_path = f"templates/{template_name}.html"
    with open(template_path, 'r') as f:
        return f.read()

def backup_file(source_file, backup_dir):
    # Path traversal with os.path.join (still vulnerable)
    backup_path = os.path.join(backup_dir, source_file)
    with open(backup_path, 'w') as f:
        f.write("backup content")
''',
                expected_issues=["B108", "B109"],
                description="Path traversal vulnerabilities",
                severity_levels=["high", "medium"],
                cwe_ids=["22"]
            ),
            
            VulnerableCodeSample(
                name="xss_vulnerabilities",
                language="python",
                code='''
from flask import Flask, request, render_template_string, Markup

app = Flask(__name__)

@app.route('/hello')
def hello():
    # XSS via render_template_string
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

@app.route('/comment')
def show_comment():
    # XSS via Markup without escaping
    comment = request.args.get('comment', '')
    return Markup(f"<div class='comment'>{comment}</div>")

def generate_html_response(user_input):
    # XSS in HTML generation
    html = f"""
    <html>
        <body>
            <h1>Welcome {user_input}</h1>
            <script>
                var userInput = '{user_input}';
                console.log(userInput);
            </script>
        </body>
    </html>
    """
    return html

def create_javascript_code(callback_name):
    # XSS in JavaScript generation
    js_code = f"function handleCallback() {{ {callback_name}(); }}"
    return js_code
''',
                expected_issues=["B201", "B202"],
                description="Cross-site scripting vulnerabilities",
                severity_levels=["high", "medium"],
                cwe_ids=["79"]
            ),
            
            VulnerableCodeSample(
                name="insecure_random",
                language="python",
                code='''
import random
import time

def generate_session_token():
    # Weak random for security-sensitive operation
    return str(random.randint(100000, 999999))

def create_password_reset_token():
    # Predictable random based on time
    random.seed(int(time.time()))
    return ''.join([str(random.randint(0, 9)) for _ in range(8)])

def generate_csrf_token():
    # Weak random for CSRF protection
    return hex(random.getrandbits(128))[2:]

def create_api_key():
    # Insecure random for API key generation
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(random.choice(chars) for _ in range(32))

class TokenGenerator:
    def __init__(self):
        # Predictable seed
        random.seed(12345)
    
    def generate_token(self):
        return random.randint(1000000, 9999999)
''',
                expected_issues=["B311"],
                description="Insecure random number generation",
                severity_levels=["medium", "low"],
                cwe_ids=["330"]
            )
        ]
    
    @staticmethod
    def get_javascript_samples() -> List[VulnerableCodeSample]:
        """Get JavaScript vulnerable code samples."""
        return [
            VulnerableCodeSample(
                name="js_injection",
                language="javascript",
                code='''
// XSS and injection vulnerabilities in JavaScript

function displayUserName(name) {
    // XSS via innerHTML
    document.getElementById('username').innerHTML = 'Hello ' + name;
}

function executeUserCode(code) {
    // Code injection via eval
    eval(code);
}

function createScript(userInput) {
    // XSS via script creation
    var script = document.createElement('script');
    script.innerHTML = 'var userInput = "' + userInput + '";';
    document.head.appendChild(script);
}

function updatePage(html) {
    // XSS via document.write
    document.write('<div>' + html + '</div>');
}

function processTemplate(template, data) {
    // Template injection
    return template.replace('{{data}}', data);
}

// Insecure API calls
function makeApiCall(endpoint) {
    // Potential SSRF
    fetch('https://api.example.com/' + endpoint)
        .then(response => response.json())
        .then(data => console.log(data));
}
''',
                expected_issues=["JS001", "JS002", "JS003"],
                description="JavaScript injection and XSS vulnerabilities",
                severity_levels=["high", "medium"],
                cwe_ids=["79", "94"]
            ),
            
            VulnerableCodeSample(
                name="js_hardcoded_secrets",
                language="javascript",
                code='''
// Hardcoded secrets in JavaScript

const API_KEY = "sk-1234567890abcdef";
const DATABASE_PASSWORD = "admin123";
const JWT_SECRET = "my-jwt-secret-key";

const config = {
    apiKey: "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI",
    authDomain: "myapp.firebaseapp.com",
    databaseURL: "https://myapp.firebaseio.com",
    projectId: "myapp",
    storageBucket: "myapp.appspot.com",
    messagingSenderId: "123456789"
};

function connectToDatabase() {
    const connectionString = `mongodb://admin:${DATABASE_PASSWORD}@localhost:27017/myapp`;
    return connectionString;
}

// AWS credentials in code
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
''',
                expected_issues=["JS101", "JS102"],
                description="Hardcoded secrets in JavaScript",
                severity_levels=["critical", "high"],
                cwe_ids=["798"]
            )
        ]
    
    @staticmethod
    def get_java_samples() -> List[VulnerableCodeSample]:
        """Get Java vulnerable code samples."""
        return [
            VulnerableCodeSample(
                name="java_sql_injection",
                language="java",
                code='''
import java.sql.*;

public class UserService {
    private Connection connection;
    
    public User getUserByName(String username) throws SQLException {
        // SQL injection vulnerability
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return mapResultSetToUser(rs);
    }
    
    public List<User> searchUsers(String searchTerm) throws SQLException {
        // SQL injection via String.format
        String query = String.format("SELECT * FROM users WHERE name LIKE '%%%s%%'", searchTerm);
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return mapResultSetToUsers(rs);
    }
    
    public void updateUserEmail(int userId, String email) throws SQLException {
        // SQL injection in UPDATE statement
        String query = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;
        Statement stmt = connection.createStatement();
        stmt.executeUpdate(query);
    }
}
''',
                expected_issues=["JAVA001", "JAVA002"],
                description="SQL injection in Java",
                severity_levels=["critical", "high"],
                cwe_ids=["89"]
            ),
            
            VulnerableCodeSample(
                name="java_hardcoded_secrets",
                language="java",
                code='''
public class DatabaseConfig {
    // Hardcoded database credentials
    private static final String DB_PASSWORD = "admin123";
    private static final String DB_USERNAME = "root";
    private static final String CONNECTION_STRING = "jdbc:mysql://localhost:3306/myapp?user=root&password=admin123";
    
    // Hardcoded API keys
    private static final String API_KEY = "sk-1234567890abcdef";
    private static final String SECRET_KEY = "my-secret-key-12345";
    
    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(CONNECTION_STRING);
    }
    
    public String getApiKey() {
        return API_KEY;
    }
}

public class CryptoUtils {
    // Hardcoded encryption key
    private static final byte[] ENCRYPTION_KEY = "1234567890123456".getBytes();
    
    public byte[] encrypt(String data) {
        // Encryption implementation
        return data.getBytes();
    }
}
''',
                expected_issues=["JAVA101", "JAVA102"],
                description="Hardcoded secrets in Java",
                severity_levels=["critical", "high"],
                cwe_ids=["798"]
            )
        ]
    
    @staticmethod
    def get_all_samples() -> Dict[str, List[VulnerableCodeSample]]:
        """Get all vulnerable code samples organized by language."""
        return {
            "python": VulnerableCodeSamples.get_python_samples(),
            "javascript": VulnerableCodeSamples.get_javascript_samples(),
            "java": VulnerableCodeSamples.get_java_samples()
        }
    
    @staticmethod
    def get_samples_by_cwe(cwe_id: str) -> List[VulnerableCodeSample]:
        """Get samples that contain a specific CWE."""
        all_samples = []
        for language_samples in VulnerableCodeSamples.get_all_samples().values():
            all_samples.extend(language_samples)
        
        return [
            sample for sample in all_samples 
            if sample.cwe_ids and cwe_id in sample.cwe_ids
        ]
    
    @staticmethod
    def get_samples_by_severity(severity: str) -> List[VulnerableCodeSample]:
        """Get samples that contain issues of specific severity."""
        all_samples = []
        for language_samples in VulnerableCodeSamples.get_all_samples().values():
            all_samples.extend(language_samples)
        
        return [
            sample for sample in all_samples 
            if severity in sample.severity_levels
        ]