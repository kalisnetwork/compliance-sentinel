#!/usr/bin/env python3
"""
Python code with various security vulnerabilities for comprehensive testing.
"""

import os
import subprocess
import hashlib
import pickle
import sqlite3
import requests
import xml.etree.ElementTree as ET
from flask import Flask, request
import random
import tempfile

# 1. Hardcoded credentials (multiple types)
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef1234567890abcdef"
JWT_SECRET = "my-super-secret-jwt-key"
ENCRYPTION_KEY = "AES256-key-here"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# 2. SQL Injection vulnerabilities
def get_user_by_id(user_id):
    # Direct f-string injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

def search_users(name, email):
    # String concatenation injection
    query = "SELECT * FROM users WHERE name = '" + name + "' AND email = '" + email + "'"
    return query

def get_user_orders(user_id, status):
    # Format string injection
    query = "SELECT * FROM orders WHERE user_id = {} AND status = '{}'".format(user_id, status)
    return query

# 3. Command injection vulnerabilities
def process_file(filename):
    # os.system injection
    os.system(f"cat {filename}")
    
def backup_database(db_name):
    # subprocess with shell=True
    subprocess.run(f"mysqldump {db_name} > backup.sql", shell=True)
    
def convert_image(input_file, output_file):
    # Another command injection
    os.system(f"convert {input_file} {output_file}")

# 4. Weak cryptography
def hash_password(password):
    # MD5 - weak hash
    return hashlib.md5(password.encode()).hexdigest()

def hash_data(data):
    # SHA1 - weak hash
    return hashlib.sha1(data.encode()).hexdigest()

def generate_token():
    # Insecure random for security purposes
    return str(random.randint(100000, 999999))

# 5. Path traversal vulnerabilities
def read_user_file(filename):
    # Direct path traversal
    with open(f"/var/www/uploads/{filename}", 'r') as f:
        return f.read()

def load_template(template_name):
    # Another path traversal
    with open(f"templates/{template_name}.html", 'r') as f:
        return f.read()

# 6. Insecure deserialization
def load_user_session(session_data):
    # Pickle deserialization
    return pickle.loads(session_data)

def deserialize_config(config_bytes):
    # Another pickle vulnerability
    return pickle.load(config_bytes)

# 7. XML vulnerabilities (XXE)
def parse_xml_config(xml_string):
    # XML parsing without XXE protection
    root = ET.parse(xml_string)
    return root

def process_xml_data(xml_content):
    # Another XML vulnerability
    return ET.fromstring(xml_content)

# 8. Flask web vulnerabilities
app = Flask(__name__)

@app.route('/user/<user_id>')
def get_user(user_id):
    # SQL injection in web endpoint
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # Also missing input validation
    return query

@app.route('/search')
def search():
    # XSS vulnerability - no output escaping
    search_term = request.args.get('q', '')
    return f"<h1>Search results for: {search_term}</h1>"

@app.route('/upload', methods=['POST'])
def upload_file():
    # Path traversal in file upload
    filename = request.form.get('filename')
    content = request.form.get('content')
    with open(f"uploads/{filename}", 'w') as f:
        f.write(content)
    return "File uploaded"

# 9. Information disclosure
def handle_database_error(e):
    # Exposing internal error details
    print(f"Database connection failed: {str(e)}")
    print(f"Connection string: postgresql://user:password@localhost/db")
    return str(e)

def debug_user_login(username, password):
    # Logging sensitive information
    print(f"Login attempt: {username}:{password}")
    return authenticate(username, password)

# 10. Insecure HTTP requests
def fetch_user_data(user_id):
    # HTTP instead of HTTPS
    url = f"http://api.example.com/users/{user_id}"
    response = requests.get(url, verify=False)  # Also SSL verification disabled
    return response.json()

# 11. Code injection vulnerabilities
def execute_user_formula(formula):
    # eval() usage
    result = eval(formula)
    return result

def run_user_script(script_code):
    # exec() usage
    exec(script_code)

# 12. Insecure file operations
def save_user_avatar(user_id, filename, content):
    # No file type validation
    file_path = f"/var/www/avatars/{filename}"
    with open(file_path, 'wb') as f:
        f.write(content)

# 13. Race condition vulnerabilities
def transfer_money(from_account, to_account, amount):
    # Race condition in financial transaction
    balance = get_balance(from_account)
    if balance >= amount:
        # Race condition here - balance could change between check and update
        update_balance(from_account, balance - amount)
        update_balance(to_account, get_balance(to_account) + amount)

# 14. Insecure temporary file usage
def process_uploaded_data(data):
    # Insecure temporary file
    temp_file = "/tmp/upload_" + str(random.randint(1000, 9999))
    with open(temp_file, 'w') as f:
        f.write(data)
    return temp_file

# 15. LDAP injection
def authenticate_user(username, password):
    # LDAP injection vulnerability
    ldap_query = f"(&(uid={username})(password={password}))"
    return ldap_query

# Helper functions (would normally be implemented)
def authenticate(username, password):
    return username == "admin" and password == "admin123"

def get_balance(account):
    return 1000.0

def update_balance(account, new_balance):
    pass

if __name__ == "__main__":
    print("This file contains intentional security vulnerabilities for testing.")
    print("NEVER use this code in production!")