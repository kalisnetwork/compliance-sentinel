# Compliance Sentinel Test Suite

This directory contains the comprehensive test suite for Compliance Sentinel, covering unit tests, integration tests, performance tests, and ML model tests.

## Test Structure

```
tests/
├── __init__.py                 # Test package initialization
├── conftest.py                # Pytest configuration and fixtures
├── test_core_analyzer.py      # Core analyzer functionality tests
├── test_ml_threat_detector.py # ML threat detection tests
├── test_integration.py        # End-to-end integration tests
├── test_performance.py        # Performance and scalability tests
├── test_config_manager.py     # Configuration management tests
├── test_hook_manager.py       # Git hooks and CI/CD tests
├── test_suite_runner.py       # Test suite runner tests
└── README.md                  # This file
```

## Test Categories

### Unit Tests
- **Core Analyzer Tests** (`test_core_analyzer.py`)
  - Language detection
  - Security issue creation and validation
  - Pattern matching for various vulnerability types
  - Issue filtering and grouping
  - Confidence scoring
  - Error handling

- **Configuration Tests** (`test_config_manager.py`)
  - Configuration loading and validation
  - Custom rules management
  - Environment-specific settings

- **Hook Manager Tests** (`test_hook_manager.py`)
  - Git hook installation and management
  - CI/CD pipeline integration
  - Automated scanning triggers

### Integration Tests
- **End-to-End Workflow Tests** (`test_integration.py`)
  - Complete project scanning
  - Git integration workflow
  - CI/CD pipeline integration
  - Real-time monitoring
  - Configuration management integration

### Performance Tests
- **Performance Benchmarks** (`test_performance.py`)
  - Single file analysis performance
  - Concurrent file analysis
  - Memory usage optimization
  - Batch processing performance
  - Scalability stress testing

### ML Tests
- **ML Threat Detection Tests** (`test_ml_threat_detector.py`)
  - Code feature extraction
  - Anomaly detection model training
  - Threat classification
  - Model persistence and loading

## Running Tests

### Using the Test Runner Script

```bash
# Run all tests
python run_tests.py

# Run specific test categories
python run_tests.py unit
python run_tests.py integration
python run_tests.py performance
python run_tests.py ml

# Run fast tests only (excludes slow performance tests)
python run_tests.py fast

# Run with verbose output
python run_tests.py -v

# Run with coverage reporting
python run_tests.py -c
```

### Using Pytest Directly

```bash
# Run all tests
pytest tests/

# Run specific test files
pytest tests/test_core_analyzer.py
pytest tests/test_integration.py

# Run tests with markers
pytest -m "not slow"           # Exclude slow tests
pytest -m "integration"        # Only integration tests
pytest -m "performance"        # Only performance tests

# Run with coverage
pytest --cov=compliance_sentinel --cov-report=html tests/
```

## Test Fixtures and Utilities

### Common Fixtures (`conftest.py`)
- `temp_project_dir`: Temporary directory for test projects
- `sample_security_issues`: Pre-defined security issues for testing
- `mock_analyzer`: Mock analyzer for unit tests
- `test_code_samples`: Code samples with various security issues

### Test Markers
- `@pytest.mark.slow`: Marks tests that take longer to run
- `@pytest.mark.integration`: Marks integration tests
- `@pytest.mark.performance`: Marks performance tests

## Test Data and Samples

### Code Samples
The test suite includes various code samples to test different scenarios:

- **Python samples**: Hardcoded secrets, SQL injection, weak crypto
- **JavaScript samples**: XSS vulnerabilities, insecure transport
- **Java samples**: Command injection, insecure configurations
- **Configuration files**: Database configs, environment files

### Security Issues
Tests cover detection of:
- Hardcoded secrets (API keys, passwords, tokens)
- Injection vulnerabilities (SQL, command, code)
- Cross-site scripting (XSS)
- Insecure cryptography
- Insecure transport protocols
- Input validation issues

## Performance Benchmarks

### Expected Performance Metrics
- **Single file analysis**: >1000 lines/second
- **Concurrent analysis**: 2-4x speedup with multiple threads
- **Memory usage**: <100MB increase for large files
- **Batch processing**: >10 files/second
- **Stress test**: >95% success rate under load

### Scalability Tests
- Large file processing (1000+ functions)
- Concurrent analysis (8+ threads)
- Batch processing (100+ files)
- Memory efficiency with streaming analysis

## Continuous Integration

### GitHub Actions Integration
```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.9
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov
      - name: Run tests
        run: python run_tests.py -c
```

### Jenkins Integration
```groovy
pipeline {
    agent any
    stages {
        stage('Test') {
            steps {
                sh 'python run_tests.py -c'
            }
            post {
                always {
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'htmlcov',
                        reportFiles: 'index.html',
                        reportName: 'Coverage Report'
                    ])
                }
            }
        }
    }
}
```

## Test Coverage Goals

- **Unit Tests**: >90% code coverage
- **Integration Tests**: Cover all major workflows
- **Performance Tests**: Validate scalability requirements
- **ML Tests**: Cover model training and inference

## Adding New Tests

### Guidelines for New Tests
1. Follow the existing test structure and naming conventions
2. Use appropriate fixtures and markers
3. Include both positive and negative test cases
4. Add performance considerations for new features
5. Update this README when adding new test categories

### Test Naming Convention
- Test files: `test_<module_name>.py`
- Test classes: `Test<FeatureName>`
- Test methods: `test_<specific_functionality>`

### Example Test Structure
```python
class TestNewFeature:
    def setup_method(self):
        """Set up test fixtures."""
        pass
    
    def test_basic_functionality(self):
        """Test basic feature functionality."""
        pass
    
    def test_error_handling(self):
        """Test error handling scenarios."""
        pass
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        pass
```

## Troubleshooting

### Common Issues
1. **Import errors**: Ensure PYTHONPATH includes project root
2. **Fixture not found**: Check conftest.py is in the right location
3. **Slow tests**: Use `-m "not slow"` to skip performance tests
4. **Coverage issues**: Ensure all source files are included in coverage

### Debug Mode
```bash
# Run with debug output
pytest -v -s tests/test_specific.py::test_method

# Run with pdb on failure
pytest --pdb tests/

# Run with detailed output
pytest -vv --tb=long tests/
```