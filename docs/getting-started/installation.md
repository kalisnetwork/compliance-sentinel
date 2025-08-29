# Installation Guide

This guide covers all installation methods for Compliance Sentinel across different platforms and environments.

## 📋 System Requirements

### Minimum Requirements
- **Operating System**: Linux, macOS, or Windows 10+
- **Python**: 3.8 or higher
- **Memory**: 4GB RAM
- **Storage**: 10GB available space
- **CPU**: 2 cores
- **Network**: Internet connection (for threat intelligence feeds)

### Recommended Requirements
- **Memory**: 16GB RAM or more
- **Storage**: 50GB available space (for caching and databases)
- **CPU**: 8 cores or more
- **SSD**: For better performance
- **Network**: High-speed internet connection

## 🐍 Python Installation Methods

### Method 1: pip install (Recommended)

```bash
# Install from PyPI
pip install compliance-sentinel

# Install with all optional dependencies
pip install compliance-sentinel[all]

# Install specific extras
pip install compliance-sentinel[ml,monitoring,integrations]
```

### Method 2: pipx (Isolated Installation)

```bash
# Install pipx if not already installed
pip install pipx

# Install Compliance Sentinel in isolated environment
pipx install compliance-sentinel

# Install with extras
pipx install compliance-sentinel[all]
```

### Method 3: From Source

```bash
# Clone repository
git clone https://github.com/your-org/compliance-sentinel.git
cd compliance-sentinel

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## 🔌 IDE and Editor Integrations

### Visual Studio Code

```bash
# Install VS Code extension
code --install-extension compliance-sentinel.vscode-extension

# Or install from marketplace
# 1. Open VS Code
# 2. Go to Extensions (Ctrl+Shift+X)
# 3. Search for "Compliance Sentinel"
# 4. Click Install
```

### IntelliJ IDEA / PyCharm

```bash
# Install from JetBrains Marketplace
# 1. Go to File → Settings → Plugins
# 2. Click "Marketplace" tab
# 3. Search for "Compliance Sentinel"
# 4. Click Install and restart IDE
```

## 🚀 Post-Installation Setup

### 1. Verify Installation

```bash
# Check version
compliance-sentinel --version

# Run system check
compliance-sentinel doctor

# Test basic functionality
compliance-sentinel scan --help
```

### 2. Initialize Configuration

```bash
# Create default configuration
compliance-sentinel init

# Create configuration with specific frameworks
compliance-sentinel init --frameworks soc2,pci_dss,hipaa

# Create enterprise configuration
compliance-sentinel init --template enterprise
```

### 3. Download Threat Intelligence Feeds

```bash
# Download initial threat intelligence data
compliance-sentinel threat-intel update

# Configure API keys for premium feeds
compliance-sentinel config set threat_intel.virustotal_api_key "your-api-key"
compliance-sentinel config set threat_intel.alienvault_api_key "your-api-key"
```

## 🔍 Troubleshooting Installation

### Common Issues

#### Permission Denied Errors

```bash
# Fix ownership
sudo chown -R $USER ~/.compliance-sentinel

# Fix permissions
chmod 755 ~/.compliance-sentinel
chmod 644 ~/.compliance-sentinel/config.yaml
```

#### Python Version Issues

```bash
# Check Python version
python --version

# Install specific Python version (Ubuntu)
sudo apt install python3.9 python3.9-venv python3.9-dev

# Use specific Python version
python3.9 -m pip install compliance-sentinel
```

### Getting Help

```bash
# Run diagnostic tool
compliance-sentinel doctor

# Enable debug logging
compliance-sentinel --log-level DEBUG scan .

# Check system requirements
compliance-sentinel system-info

# Validate configuration
compliance-sentinel config validate
```

---

**Next Steps**: After installation, proceed to the [Configuration Guide](configuration.md) to set up Compliance Sentinel for your specific needs.