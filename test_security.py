#!/usr/bin/env python3
"""Test file with intentional security issues for demonstration."""

import os
import subprocess
import hashlib

# Security issue 1: Hardcoded password
PASSWORD = "admin123"  # This should be flagged

# Security issue 2: SQL injection vulnerability
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection risk
    return query

# Security issue 3: Command injection
def run_command(user_input):
    cmd = f"ls {user_input}"  # Command injection risk
    return subprocess.run(cmd, shell=True, capture_output=True)

# Security issue 4: Weak cryptography
def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()  # MD5 is weak

# Security issue 5: Path traversal
def read_file(filename):
    with open(f"/var/log/{filename}", 'r') as f:  # Path traversal risk
        return f.read()

# Good practice example
def secure_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

if __name__ == "__main__":
    print("This is a test file with security issues")