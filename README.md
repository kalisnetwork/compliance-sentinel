# Compliance Sentinel

A proactive security and compliance enforcement system that integrates with Kiro's agentic capabilities to provide real-time security analysis, policy enforcement, and intelligent feedback during development.

## Overview

The Compliance Sentinel transforms security from a reactive process to a proactive, automated one. Instead of relying on manual code reviews or post-development checks, it integrates compliance directly into your development workflow using:

- **Agent Steering**: Centralized policy definition via `.kiro/steering/security.md`
- **Agent Hooks**: Automated security scanning triggered by file saves
- **Model Context Protocol (MCP)**: External vulnerability intelligence integration

## Features

- 🔍 **Real-time Security Analysis** - Automatic scanning on file save
- 📋 **Policy-Driven Compliance** - Centralized security policy management
- 🌐 **External Intelligence** - Integration with vulnerability databases
- 🛠️ **Multiple Analysis Tools** - Bandit, Semgrep, OWASP Dependency-Check
- 💡 **Intelligent Feedback** - Actionable remediation suggestions
- ⚡ **Performance Optimized** - Asynchronous processing with caching
- 🔧 **Highly Configurable** - Customizable rules and thresholds
- 🔌 **MCP Integration** - Model Context Protocol server for IDE integration

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/compliance-sentinel/compliance-sentinel.git
cd compliance-sentinel

# Create virtual environment (Python 3.11+ required)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .
```

### Basic Setup

1. **Initialize Configuration**:
```bash
compliance-sentinel init
```

2. **Create Security Policy** (`.kiro/steering/security.md`):
```markdown
# Security Policy

## Rules

### Rule 1: API Security
All API endpoints must implement authentication and rate-limiting policies.

### Rule 2: Credential Management  
Never hardcode sensitive credentials. All secrets must be loaded from environment variables.

### Rule 3: Dependency Validation
Use of external libraries must be validated against known vulnerabilities.
```

3. **Deploy MCP Server (100% FREE)**:

**🔺 Vercel (Recommended - Always Free):**
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/kalisnetwork/compliance-sentinel)

**🚀 Other Free Options:**
[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/kalisnetwork/compliance-sentinel)

**Or run locally:**
```bash
python run_mcp_server.py
# Or for web version:
python web_mcp_server.py
```

See [VERCEL_DEPLOY.md](VERCEL_DEPLOY.md) for detailed Vercel deployment guide!

4. **Configure Kiro Agent Hook** (automatically done during init)

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   IDE/Editor    │    │   Kiro Agent     │    │  Analysis       │
│                 │    │   System         │    │  Engine         │
│  File Save ────►│    │                  │    │                 │
│                 │    │  Agent Steering  │    │  Bandit         │
└─────────────────┘    │  Agent Hooks ───┼───►│  Semgrep        │
                       │  MCP Client      │    │  Dependency     │
                       └──────────────────┘    │  Scanner        │
                                               └─────────────────┘
                                                        │
                       ┌─────────────────┐             │
                       │   MCP Server    │◄────────────┘
                       │                 │
                       │  FastAPI +      │    ┌─────────────────┐
                       │  fastapi-mcp    │    │  External       │
                       │                 │    │  Intelligence   │
                       └─────────────────┘    │                 │
                                              │  NVD Database   │
                                              │  CVE Feeds      │
                                              │  Regulatory APIs│
                                              └─────────────────┘
```

## Configuration

The system uses YAML configuration files in `.kiro/compliance-sentinel/`:

- `system.yaml` - Main system settings
- `hooks.yaml` - Agent Hook configuration  
- `mcp.yaml` - MCP server settings
- `analysis.yaml` - Analysis tool configuration
- `feedback.yaml` - Feedback formatting options

### Example System Configuration

```yaml
python_version: "3.11"
analysis_tools:
  - "bandit"
  - "semgrep"
mcp_server_url: "http://localhost:8000"
cache_ttl: 3600
max_concurrent_analyses: 5
severity_threshold: "medium"
enable_external_intelligence: true
analysis_timeout: 300
```

## MCP Server Integration

The Compliance Sentinel includes a Model Context Protocol (MCP) server that integrates with IDEs like Kiro to provide real-time security analysis tools.

### MCP Configuration

Add this configuration to your IDE's MCP settings (e.g., `.kiro/settings/mcp.json`):

```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "command": "python",
      "args": ["run_mcp_server.py"],
      "env": {
        "PYTHONPATH": ".",
        "LOG_LEVEL": "INFO"
      },
      "disabled": false,
      "autoApprove": [
        "analyze_code",
        "analyze_file",
        "analyze_directory",
        "check_dependencies",
        "get_security_recommendations",
        "validate_compliance"
      ]
    }
  }
}
```

### Available MCP Tools

- **analyze_code**: Analyze code snippets for security issues
- **analyze_file**: Analyze specific files
- **analyze_directory**: Analyze entire directories recursively
- **check_dependencies**: Scan project dependencies for vulnerabilities
- **get_security_recommendations**: Get actionable remediation advice
- **validate_compliance**: Check against compliance frameworks (OWASP, CWE, NIST, etc.)

See [MCP_README.md](MCP_README.md) for detailed MCP server documentation.

## Usage

### Command Line Interface

```bash
# Start MCP server (recommended)
python run_mcp_server.py

# Or start MCP server directly
python mcp_server.py

# The MCP server provides tools for:
# - analyze_code: Analyze code snippets
# - analyze_file: Analyze specific files  
# - analyze_directory: Analyze entire directories
# - check_dependencies: Scan for vulnerable dependencies
# - get_security_recommendations: Get remediation advice
# - validate_compliance: Check against compliance frameworks
```

### Programmatic Usage

```python
from compliance_sentinel import ComplianceAgent
from compliance_sentinel.models.config import SystemConfiguration

# Initialize with custom config
config = SystemConfiguration(
    analysis_tools=["bandit", "semgrep"],
    severity_threshold="high"
)

agent = ComplianceAgent(config)

# Analyze a file
result = await agent.analyze_file("src/app.py")

# Process results
for issue in result.issues:
    print(f"{issue.severity}: {issue.description}")
    for suggestion in issue.remediation_suggestions:
        print(f"  → {suggestion}")
```

## Development

### Setup Development Environment

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run type checking
mypy compliance_sentinel

# Format code
black compliance_sentinel
isort compliance_sentinel

# Lint code
flake8 compliance_sentinel
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=compliance_sentinel

# Run specific test categories
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m "not slow"    # Skip slow tests
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Run the test suite (`pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](https://compliance-sentinel.readthedocs.io)
- 🐛 [Issue Tracker](https://github.com/compliance-sentinel/compliance-sentinel/issues)
- 💬 [Discussions](https://github.com/compliance-sentinel/compliance-sentinel/discussions)

## Roadmap

- [ ] Support for additional programming languages (JavaScript, TypeScript, Go)
- [ ] Integration with more SAST tools (CodeQL, SonarQube)
- [ ] Advanced ML-based vulnerability detection
- [ ] Custom rule creation UI
- [ ] Integration with CI/CD pipelines
- [ ] Compliance reporting and dashboards# compliance-sentinel
