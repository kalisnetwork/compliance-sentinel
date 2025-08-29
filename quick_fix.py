#!/usr/bin/env python3
"""
Quick fix script for common syntax errors.
"""

import re
import os


def fix_file(file_path):
    """Fix common syntax errors in a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Fix common issues
        # 1. Fix escaped quotes in f-strings
        content = re.sub(r'f"([^"]*)"\\"\)', r'f"\1")', content)
        
        # 2. Fix malformed string continuations
        content = re.sub(r'\\"\)\n\s*\n', ')\n\n', content)
        
        # 3. Fix invalid escape sequences
        content = re.sub(r'\\\.', r'\\.', content)
        
        # 4. Fix quote issues
        content = content.replace('")\\n', '")\n')
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✅ Fixed {file_path}")
            return True
        else:
            print(f"⚪ No changes needed for {file_path}")
            return False
            
    except Exception as e:
        print(f"❌ Error fixing {file_path}: {e}")
        return False


def main():
    """Fix syntax errors in problematic files."""
    
    # Files with known syntax errors
    problematic_files = [
        "compliance_sentinel/monitoring/monitoring_system.py",
        "compliance_sentinel/monitoring/alert_manager.py",
        "compliance_sentinel/analyzers/ml_threat_detector.py",
        "compliance_sentinel/security/data_retention.py",
        "compliance_sentinel/security/gdpr_compliance.py",
        "compliance_sentinel/ide_integration/lsp_server.py",
        "compliance_sentinel/testing/vulnerability_test_suite.py",
        "compliance_sentinel/threat_intelligence/threat_enrichment.py",
        "compliance_sentinel/threat_intelligence/threat_hunting.py",
        "compliance_sentinel/threat_intelligence/automated_response.py"
    ]
    
    fixed_count = 0
    
    for file_path in problematic_files:
        if os.path.exists(file_path):
            if fix_file(file_path):
                fixed_count += 1
        else:
            print(f"⚠️  File not found: {file_path}")
    
    print(f"\n🔧 Fixed {fixed_count} files")


if __name__ == "__main__":
    main()