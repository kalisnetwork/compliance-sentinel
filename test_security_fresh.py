#!/usr/bin/env python3
"""
Fresh test file with various security issues for Compliance Sentinel to detect.
"""

import subprocess
import hashlib
import os

# 1. Hardcoded password (should be detected)
PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

# 2. SQL injection vulnerability (should be detected)
def get_user_data(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# 3. Command injection (should be detected)
def run_command(user_input):
    subprocess.run(f"ls {user_input}", shell=True)

# 4. Weak cryptography (should be detected)
def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

print("This file contains intentional security vulnerabilities for testing.")