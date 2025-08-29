# Compliance Sentinel Installation Script for Windows PowerShell
# This script installs Compliance Sentinel and sets up the development environment

param(
    [switch]$Help,
    [switch]$Uninstall,
    [switch]$Update
)

# Configuration
$PythonMinVersion = [Version]"3.9.0"
$InstallDir = "$env:USERPROFILE\.compliance-sentinel"
$VenvDir = "$InstallDir\venv"
$ConfigDir = "$env:USERPROFILE\.compliance-sentinel\config"

# Colors for output
$Colors = @{
    Red = "Red"
    Green = "Green"
    Yellow = "Yellow"
    Blue = "Blue"
    White = "White"
}

# Functions
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Colors.Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Colors.Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Colors.Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Colors.Red
}

function Test-PythonVersion {
    Write-Info "Checking Python version..."
    
    try {
        $pythonVersion = & python --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Python not found"
        }
        
        $versionString = $pythonVersion -replace "Python ", ""
        $version = [Version]$versionString
        
        if ($version -lt $PythonMinVersion) {
            Write-Error "Python $version is installed, but Python $PythonMinVersion or later is required."
            exit 1
        }
        
        Write-Success "Python $version is compatible"
    }
    catch {
        Write-Error "Python 3 is not installed or not in PATH. Please install Python 3.9 or later."
        exit 1
    }
}

function Test-Dependencies {
    Write-Info "Checking system dependencies..."
    
    # Check for git
    try {
        & git --version | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Git not found"
        }
    }
    catch {
        Write-Error "Git is not installed. Please install Git."
        exit 1
    }
    
    Write-Success "System dependencies are available"
}

function New-Directories {
    Write-Info "Creating installation directories..."
    
    $directories = @($InstallDir, $ConfigDir, "$InstallDir\logs", "$InstallDir\data")
    
    foreach ($dir in $directories) {
        if (!(Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    Write-Success "Directories created"
}

function New-VirtualEnvironment {
    Write-Info "Setting up Python virtual environment..."
    
    if (Test-Path $VenvDir) {
        Write-Warning "Virtual environment already exists. Removing..."
        Remove-Item -Recurse -Force $VenvDir
    }
    
    & python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create virtual environment"
        exit 1
    }
    
    # Activate virtual environment
    & "$VenvDir\Scripts\Activate.ps1"
    
    # Upgrade pip
    & "$VenvDir\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel
    
    Write-Success "Virtual environment created"
}

function Install-ComplianceSentinel {
    Write-Info "Installing Compliance Sentinel..."
    
    # Activate virtual environment
    & "$VenvDir\Scripts\Activate.ps1"
    
    # Install from PyPI (or local development)
    if ((Test-Path "setup.py") -or (Test-Path "pyproject.toml")) {
        Write-Info "Installing from local source..."
        & "$VenvDir\Scripts\pip.exe" install -e .
    }
    else {
        Write-Info "Installing from PyPI..."
        & "$VenvDir\Scripts\pip.exe" install compliance-sentinel
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install Compliance Sentinel"
        exit 1
    }
    
    Write-Success "Compliance Sentinel installed"
}

function Install-ExternalTools {
    Write-Info "Installing external security tools..."
    
    # Activate virtual environment
    & "$VenvDir\Scripts\Activate.ps1"
    
    # Install security analysis tools
    & "$VenvDir\Scripts\pip.exe" install bandit semgrep safety
    
    # Check if tools are available
    $tools = @("bandit", "semgrep", "safety")
    foreach ($tool in $tools) {
        try {
            & "$VenvDir\Scripts\$tool.exe" --version | Out-Null
            Write-Success "$tool installed"
        }
        catch {
            Write-Warning "$tool installation may have failed"
        }
    }
}

function New-DefaultConfig {
    Write-Info "Creating default configuration..."
    
    # Activate virtual environment and create config
    & "$VenvDir\Scripts\compliance-sentinel.exe" config init --project-name "default" --scope user
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Default configuration created"
    }
    else {
        Write-Warning "Failed to create default configuration"
    }
}

function Set-ShellIntegration {
    Write-Info "Setting up PowerShell integration..."
    
    # Add to PowerShell profile
    $profilePath = $PROFILE
    
    if (!(Test-Path $profilePath)) {
        New-Item -ItemType File -Path $profilePath -Force | Out-Null
    }
    
    $profileContent = Get-Content $profilePath -ErrorAction SilentlyContinue
    
    if ($profileContent -notcontains "# Compliance Sentinel") {
        Add-Content $profilePath ""
        Add-Content $profilePath "# Compliance Sentinel"
        Add-Content $profilePath "`$env:PATH = `"$VenvDir\Scripts;`$env:PATH`""
        Add-Content $profilePath "Set-Alias cs compliance-sentinel"
        
        Write-Success "PowerShell integration added to $profilePath"
        Write-Info "Please restart PowerShell or run '. `$PROFILE' to reload"
    }
    else {
        Write-Info "PowerShell integration already exists"
    }
}

function Set-KiroHooks {
    Write-Info "Setting up Kiro Agent Hooks..."
    
    $kiroHooksDir = "$env:USERPROFILE\.kiro\hooks"
    
    if (Test-Path $kiroHooksDir) {
        # Copy hook configurations
        if (Test-Path "kiro_hooks") {
            Copy-Item "kiro_hooks\*.json" $kiroHooksDir -Force
            Write-Success "Kiro hooks installed"
        }
        else {
            Write-Warning "Kiro hook configurations not found"
        }
    }
    else {
        Write-Info "Kiro not detected. Hooks will be available when Kiro is installed."
    }
}

function Test-Installation {
    Write-Info "Running health check..."
    
    # Test basic functionality
    try {
        & "$VenvDir\Scripts\compliance-sentinel.exe" --version | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Compliance Sentinel is working"
        }
        else {
            throw "Version check failed"
        }
    }
    catch {
        Write-Error "Compliance Sentinel installation verification failed"
        exit 1
    }
    
    # Test configuration
    try {
        & "$VenvDir\Scripts\compliance-sentinel.exe" config validate | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Configuration is valid"
        }
        else {
            Write-Warning "Configuration validation failed"
        }
    }
    catch {
        Write-Warning "Configuration validation failed"
    }
}

function Show-SuccessMessage {
    Write-Host ""
    Write-Success "🎉 Compliance Sentinel Installation Complete!"
    Write-Host ""
    Write-Host "Installation Details:" -ForegroundColor $Colors.White
    Write-Host "  • Installation Directory: $InstallDir" -ForegroundColor $Colors.White
    Write-Host "  • Configuration Directory: $ConfigDir" -ForegroundColor $Colors.White
    Write-Host "  • Virtual Environment: $VenvDir" -ForegroundColor $Colors.White
    Write-Host ""
    Write-Host "Getting Started:" -ForegroundColor $Colors.White
    Write-Host "  1. Restart PowerShell or run: . `$PROFILE" -ForegroundColor $Colors.White
    Write-Host "  2. Run: compliance-sentinel --help" -ForegroundColor $Colors.White
    Write-Host "  3. Initialize project: compliance-sentinel config init --project-name 'my-project'" -ForegroundColor $Colors.White
    Write-Host "  4. Analyze files: compliance-sentinel analyze file.py" -ForegroundColor $Colors.White
    Write-Host ""
    Write-Host "Documentation: https://compliance-sentinel.readthedocs.io/" -ForegroundColor $Colors.Blue
    Write-Host "Support: https://github.com/compliance-sentinel/compliance-sentinel/issues" -ForegroundColor $Colors.Blue
    Write-Host ""
}

# Main installation process
function Start-Installation {
    Write-Host "Compliance Sentinel Installation Script" -ForegroundColor $Colors.Blue
    Write-Host "========================================" -ForegroundColor $Colors.Blue
    Write-Host ""
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "Running as Administrator. This is not recommended for user installation."
    }
    
    # Run installation steps
    Test-PythonVersion
    Test-Dependencies
    New-Directories
    New-VirtualEnvironment
    Install-ComplianceSentinel
    Install-ExternalTools
    New-DefaultConfig
    Set-ShellIntegration
    Set-KiroHooks
    Test-Installation
    Show-SuccessMessage
}

function Remove-Installation {
    Write-Info "Uninstalling Compliance Sentinel..."
    
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
        Write-Success "Compliance Sentinel uninstalled"
    }
    else {
        Write-Info "Compliance Sentinel is not installed"
    }
}

function Update-Installation {
    Write-Info "Updating Compliance Sentinel..."
    
    if (Test-Path $VenvDir) {
        & "$VenvDir\Scripts\pip.exe" install --upgrade compliance-sentinel
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Compliance Sentinel updated"
        }
        else {
            Write-Error "Failed to update Compliance Sentinel"
            exit 1
        }
    }
    else {
        Write-Error "Compliance Sentinel is not installed. Run without -Update to install."
        exit 1
    }
}

# Handle script parameters
if ($Help) {
    Write-Host "Compliance Sentinel Installation Script for Windows"
    Write-Host ""
    Write-Host "Usage: .\install.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Help        Show this help message"
    Write-Host "  -Uninstall   Uninstall Compliance Sentinel"
    Write-Host "  -Update      Update existing installation"
    Write-Host ""
    exit 0
}
elseif ($Uninstall) {
    Remove-Installation
    exit 0
}
elseif ($Update) {
    Update-Installation
    exit 0
}
else {
    Start-Installation
}