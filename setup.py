"""Setup script for Compliance Sentinel package."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = requirements_file.read_text().strip().split('\n')
    requirements = [req.strip() for req in requirements if req.strip() and not req.startswith('#')]

# Read version
version_file = Path(__file__).parent / "compliance_sentinel" / "__init__.py"
version = "0.1.0"
if version_file.exists():
    for line in version_file.read_text().split('\n'):
        if line.startswith('__version__'):
            version = line.split('=')[1].strip().strip('"').strip("'")
            break

setup(
    name="compliance-sentinel",
    version=version,
    author="Compliance Sentinel Team",
    author_email="team@compliance-sentinel.dev",
    description="Proactive Security and Compliance Enforcement System for Development Workflows",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/compliance-sentinel/compliance-sentinel",
    project_urls={
        "Bug Reports": "https://github.com/compliance-sentinel/compliance-sentinel/issues",
        "Source": "https://github.com/compliance-sentinel/compliance-sentinel",
        "Documentation": "https://compliance-sentinel.readthedocs.io/",
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Web Environment",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "myst-parser>=1.0.0",
        ],
        "performance": [
            "psutil>=5.9.0",
            "memory-profiler>=0.60.0",
        ],
        "all": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "myst-parser>=1.0.0",
            "psutil>=5.9.0",
            "memory-profiler>=0.60.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "compliance-sentinel=compliance_sentinel.cli:cli",
            "cs=compliance_sentinel.cli:cli",  # Short alias
        ],
        "compliance_sentinel.analyzers": [
            "bandit=compliance_sentinel.analyzers.bandit_analyzer:BanditAnalyzer",
            "semgrep=compliance_sentinel.analyzers.semgrep_analyzer:SemgrepAnalyzer",
        ],
        "compliance_sentinel.scanners": [
            "safety=compliance_sentinel.scanners.dependency_scanner:DependencyScanner",
        ],
    },
    include_package_data=True,
    package_data={
        "compliance_sentinel": [
            "config/templates/*.yaml",
            "config/templates/*.json",
            "hooks/templates/*.json",
            "hooks/templates/*.py",
            "mcp_server/openapi.yaml",
            "data/*.json",
            "data/*.yaml",
        ],
    },
    zip_safe=False,
    keywords=[
        "security", "compliance", "static-analysis", "vulnerability-scanning",
        "code-quality", "devsecops", "sast", "dependency-scanning",
        "policy-enforcement", "kiro", "ide-integration"
    ],
    platforms=["any"],
    license="MIT",
)