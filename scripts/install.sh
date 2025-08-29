#!/bin/bash
# Compliance Sentinel Installation Script
# This script installs Compliance Sentinel and sets up the development environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PYTHON_MIN_VERSION="3.9"
INSTALL_DIR="${HOME}/.compliance-sentinel"
VENV_DIR="${INSTALL_DIR}/venv"
CONFIG_DIR="${HOME}/.compliance-sentinel/config"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_python_version() {
    log_info "Checking Python version..."
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed. Please install Python 3.9 or later."
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    
    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)"; then
        log_error "Python ${PYTHON_VERSION} is installed, but Python ${PYTHON_MIN_VERSION} or later is required."
        exit 1
    fi
    
    log_success "Python ${PYTHON_VERSION} is compatible"
}

check_dependencies() {
    log_info "Checking system dependencies..."
    
    # Check for git
    if ! command -v git &> /dev/null; then
        log_error "Git is not installed. Please install Git."
        exit 1
    fi
    
    # Check for curl
    if ! command -v curl &> /dev/null; then
        log_error "curl is not installed. Please install curl."
        exit 1
    fi
    
    log_success "System dependencies are available"
}

create_directories() {
    log_info "Creating installation directories..."
    
    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${INSTALL_DIR}/logs"
    mkdir -p "${INSTALL_DIR}/data"
    
    log_success "Directories created"
}

setup_virtual_environment() {
    log_info "Setting up Python virtual environment..."
    
    if [ -d "${VENV_DIR}" ]; then
        log_warning "Virtual environment already exists. Removing..."
        rm -rf "${VENV_DIR}"
    fi
    
    python3 -m venv "${VENV_DIR}"
    source "${VENV_DIR}/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel
    
    log_success "Virtual environment created"
}

install_compliance_sentinel() {
    log_info "Installing Compliance Sentinel..."
    
    source "${VENV_DIR}/bin/activate"
    
    # Install from PyPI (or local development)
    if [ -f "setup.py" ] || [ -f "pyproject.toml" ]; then
        log_info "Installing from local source..."
        pip install -e .
    else
        log_info "Installing from PyPI..."
        pip install compliance-sentinel
    fi
    
    log_success "Compliance Sentinel installed"
}

install_external_tools() {
    log_info "Installing external security tools..."
    
    source "${VENV_DIR}/bin/activate"
    
    # Install security analysis tools
    pip install bandit semgrep safety
    
    # Check if tools are available
    if command -v bandit &> /dev/null; then
        log_success "Bandit installed"
    else
        log_warning "Bandit installation may have failed"
    fi
    
    if command -v semgrep &> /dev/null; then
        log_success "Semgrep installed"
    else
        log_warning "Semgrep installation may have failed"
    fi
    
    if command -v safety &> /dev/null; then
        log_success "Safety installed"
    else
        log_warning "Safety installation may have failed"
    fi
}

create_default_config() {
    log_info "Creating default configuration..."
    
    source "${VENV_DIR}/bin/activate"
    
    # Initialize default configuration
    "${VENV_DIR}/bin/compliance-sentinel" config init --project-name "default" --scope user
    
    log_success "Default configuration created"
}

setup_shell_integration() {
    log_info "Setting up shell integration..."
    
    # Add to PATH
    SHELL_RC=""
    if [ -n "$BASH_VERSION" ]; then
        SHELL_RC="$HOME/.bashrc"
    elif [ -n "$ZSH_VERSION" ]; then
        SHELL_RC="$HOME/.zshrc"
    else
        SHELL_RC="$HOME/.profile"
    fi
    
    if [ -f "$SHELL_RC" ]; then
        # Check if already added
        if ! grep -q "compliance-sentinel" "$SHELL_RC"; then
            echo "" >> "$SHELL_RC"
            echo "# Compliance Sentinel" >> "$SHELL_RC"
            echo "export PATH=\"${VENV_DIR}/bin:\$PATH\"" >> "$SHELL_RC"
            echo "alias cs='compliance-sentinel'" >> "$SHELL_RC"
            
            log_success "Shell integration added to $SHELL_RC"
            log_info "Please run 'source $SHELL_RC' or restart your shell"
        else
            log_info "Shell integration already exists"
        fi
    fi
}

setup_kiro_hooks() {
    log_info "Setting up Kiro Agent Hooks..."
    
    KIRO_HOOKS_DIR="${HOME}/.kiro/hooks"
    
    if [ -d "$KIRO_HOOKS_DIR" ]; then
        # Copy hook configurations
        if [ -d "kiro_hooks" ]; then
            cp kiro_hooks/*.json "$KIRO_HOOKS_DIR/"
            log_success "Kiro hooks installed"
        else
            log_warning "Kiro hook configurations not found"
        fi
    else
        log_info "Kiro not detected. Hooks will be available when Kiro is installed."
    fi
}

run_health_check() {
    log_info "Running health check..."
    
    source "${VENV_DIR}/bin/activate"
    
    # Test basic functionality
    if "${VENV_DIR}/bin/compliance-sentinel" --version &> /dev/null; then
        log_success "Compliance Sentinel is working"
    else
        log_error "Compliance Sentinel installation verification failed"
        exit 1
    fi
    
    # Test configuration
    if "${VENV_DIR}/bin/compliance-sentinel" config validate &> /dev/null; then
        log_success "Configuration is valid"
    else
        log_warning "Configuration validation failed"
    fi
}

print_success_message() {
    echo ""
    echo -e "${GREEN}🎉 Compliance Sentinel Installation Complete!${NC}"
    echo ""
    echo "Installation Details:"
    echo "  • Installation Directory: ${INSTALL_DIR}"
    echo "  • Configuration Directory: ${CONFIG_DIR}"
    echo "  • Virtual Environment: ${VENV_DIR}"
    echo ""
    echo "Getting Started:"
    echo "  1. Activate the environment: source ${VENV_DIR}/bin/activate"
    echo "  2. Run: compliance-sentinel --help"
    echo "  3. Initialize project: compliance-sentinel config init --project-name 'my-project'"
    echo "  4. Analyze files: compliance-sentinel analyze file.py"
    echo ""
    echo "Documentation: https://compliance-sentinel.readthedocs.io/"
    echo "Support: https://github.com/compliance-sentinel/compliance-sentinel/issues"
    echo ""
}

# Main installation process
main() {
    echo -e "${BLUE}Compliance Sentinel Installation Script${NC}"
    echo "========================================"
    echo ""
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        log_error "Please do not run this script as root"
        exit 1
    fi
    
    # Run installation steps
    check_python_version
    check_dependencies
    create_directories
    setup_virtual_environment
    install_compliance_sentinel
    install_external_tools
    create_default_config
    setup_shell_integration
    setup_kiro_hooks
    run_health_check
    print_success_message
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Compliance Sentinel Installation Script"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --uninstall    Uninstall Compliance Sentinel"
        echo "  --update       Update existing installation"
        echo ""
        exit 0
        ;;
    --uninstall)
        log_info "Uninstalling Compliance Sentinel..."
        if [ -d "${INSTALL_DIR}" ]; then
            rm -rf "${INSTALL_DIR}"
            log_success "Compliance Sentinel uninstalled"
        else
            log_info "Compliance Sentinel is not installed"
        fi
        exit 0
        ;;
    --update)
        log_info "Updating Compliance Sentinel..."
        if [ -d "${VENV_DIR}" ]; then
            source "${VENV_DIR}/bin/activate"
            pip install --upgrade compliance-sentinel
            log_success "Compliance Sentinel updated"
        else
            log_error "Compliance Sentinel is not installed. Run without --update to install."
            exit 1
        fi
        exit 0
        ;;
    "")
        main
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac