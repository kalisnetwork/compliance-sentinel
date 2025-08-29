#!/usr/bin/env python3
"""
Quick syntax error checker and fixer for the compliance_sentinel project.
"""

import ast
import os
import sys
from pathlib import Path


def check_syntax(file_path):
    """Check if a Python file has syntax errors."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Try to parse the file
        ast.parse(content)
        return True, None
    except SyntaxError as e:
        return False, e
    except Exception as e:
        return False, e


def find_python_files(directory):
    """Find all Python files in the directory."""
    python_files = []
    for root, dirs, files in os.walk(directory):
        # Skip __pycache__ directories
        dirs[:] = [d for d in dirs if d != '__pycache__']
        
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    
    return python_files


def main():
    """Main function to check syntax errors."""
    print("🔍 Checking Python files for syntax errors...")
    
    # Find all Python files in compliance_sentinel directory
    python_files = find_python_files('compliance_sentinel')
    
    errors_found = []
    
    for file_path in python_files:
        is_valid, error = check_syntax(file_path)
        
        if not is_valid:
            errors_found.append((file_path, error))
            print(f"❌ {file_path}: {error}")
        else:
            print(f"✅ {file_path}")
    
    if errors_found:
        print(f"\n💥 Found {len(errors_found)} files with syntax errors:")
        for file_path, error in errors_found:
            print(f"  - {file_path}: Line {error.lineno if hasattr(error, 'lineno') else 'unknown'}")
        return 1
    else:
        print(f"\n🎉 All {len(python_files)} Python files have valid syntax!")
        return 0


if __name__ == "__main__":
    sys.exit(main())