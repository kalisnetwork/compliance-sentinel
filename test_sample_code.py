#!/usr/bin/env python3
"""
Sample code with some security issues for testing.
"""

import os
import subprocess
import hashlib

# Hardcoded password (security issue)
PASSWORD = "admin123"

# SQL injection vulnerability
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# Command injection vulnerability
def process_file(filename):
    os.system(f"cat {filename}")

# Weak cryptography
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Subprocess with shell=True (security issue)
def run_command(cmd):
    subprocess.run(cmd, shell=True)

if __name__ == "__main__":
    print("Sample code with security issues")