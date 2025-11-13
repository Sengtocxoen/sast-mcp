#!/bin/bash
################################################################################
# SAST-MCP Security Tools Installation Script
#
# This script installs all security tools required for the SAST-MCP server
# Run on Kali Linux or Debian-based systems
#
# Usage: sudo bash install_tools.sh
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root or with sudo${NC}"
    exit 1
fi

echo -e "${BLUE}=================================${NC}"
echo -e "${BLUE}SAST-MCP Tools Installation${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""

# Function to print status
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

################################################################################
# SYSTEM UPDATE
################################################################################

print_status "Updating system packages..."
apt update -qq
print_success "System packages updated"

################################################################################
# INSTALL PYTHON AND PIP
################################################################################

print_status "Installing Python and pip..."
apt install -y python3 python3-pip python3-venv >/dev/null 2>&1
print_success "Python and pip installed"

################################################################################
# INSTALL NODE.JS AND NPM
################################################################################

print_status "Installing Node.js and npm..."
if ! command_exists node; then
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs >/dev/null 2>&1
fi
print_success "Node.js and npm installed"

################################################################################
# INSTALL RUBY AND GEM
################################################################################

print_status "Installing Ruby and gem..."
apt install -y ruby ruby-dev >/dev/null 2>&1
print_success "Ruby and gem installed"

################################################################################
# INSTALL GO (for some tools)
################################################################################

print_status "Installing Go..."
if ! command_exists go; then
    apt install -y golang-go >/dev/null 2>&1
fi
print_success "Go installed"

################################################################################
# SAST TOOLS INSTALLATION
################################################################################

echo ""
echo -e "${BLUE}Installing SAST Tools...${NC}"
echo ""

# Semgrep
print_status "Installing Semgrep..."
if ! command_exists semgrep; then
    pip3 install semgrep >/dev/null 2>&1
    print_success "Semgrep installed"
else
    print_warning "Semgrep already installed"
fi

# Bandit
print_status "Installing Bandit..."
if ! command_exists bandit; then
    pip3 install bandit >/dev/null 2>&1
    print_success "Bandit installed"
else
    print_warning "Bandit already installed"
fi

# Bearer
print_status "Installing Bearer..."
if ! command_exists bearer; then
    curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b /usr/local/bin >/dev/null 2>&1
    print_success "Bearer installed"
else
    print_warning "Bearer already installed"
fi

# Graudit
print_status "Installing Graudit..."
if ! command_exists graudit; then
    apt install -y graudit >/dev/null 2>&1 || {
        cd /opt
        git clone https://github.com/wireghoul/graudit.git >/dev/null 2>&1
        ln -sf /opt/graudit/graudit /usr/local/bin/graudit
    }
    print_success "Graudit installed"
else
    print_warning "Graudit already installed"
fi

# Gosec
print_status "Installing Gosec..."
if ! command_exists gosec; then
    go install github.com/securego/gosec/v2/cmd/gosec@latest >/dev/null 2>&1
    ln -sf /root/go/bin/gosec /usr/local/bin/gosec 2>/dev/null || true
    print_success "Gosec installed"
else
    print_warning "Gosec already installed"
fi

# Brakeman
print_status "Installing Brakeman..."
if ! command_exists brakeman; then
    gem install brakeman >/dev/null 2>&1
    print_success "Brakeman installed"
else
    print_warning "Brakeman already installed"
fi

# ESLint (with security plugins)
print_status "Installing ESLint with security plugins..."
if ! command_exists eslint; then
    npm install -g eslint eslint-plugin-security >/dev/null 2>&1
    print_success "ESLint installed"
else
    print_warning "ESLint already installed"
fi

################################################################################
# SECRET SCANNING TOOLS
################################################################################

echo ""
echo -e "${BLUE}Installing Secret Scanning Tools...${NC}"
echo ""

# TruffleHog
print_status "Installing TruffleHog..."
if ! command_exists trufflehog; then
    pip3 install truffleHog >/dev/null 2>&1
    print_success "TruffleHog installed"
else
    print_warning "TruffleHog already installed"
fi

# Gitleaks
print_status "Installing Gitleaks..."
if ! command_exists gitleaks; then
    GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d '"' -f 4)
    wget -q https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION:1}_linux_x64.tar.gz
    tar -xzf gitleaks_${GITLEAKS_VERSION:1}_linux_x64.tar.gz
    mv gitleaks /usr/local/bin/
    rm gitleaks_${GITLEAKS_VERSION:1}_linux_x64.tar.gz
    print_success "Gitleaks installed"
else
    print_warning "Gitleaks already installed"
fi

################################################################################
# DEPENDENCY SCANNING TOOLS
################################################################################

echo ""
echo -e "${BLUE}Installing Dependency Scanning Tools...${NC}"
echo ""

# Safety
print_status "Installing Safety..."
if ! command_exists safety; then
    pip3 install safety >/dev/null 2>&1
    print_success "Safety installed"
else
    print_warning "Safety already installed"
fi

# npm audit (comes with npm)
print_success "npm audit available (comes with npm)"

# OWASP Dependency-Check
print_status "Installing OWASP Dependency-Check..."
if ! command_exists dependency-check; then
    cd /opt
    DEPCHECK_VERSION=$(curl -s https://jeremylong.github.io/DependencyCheck/current.txt)
    wget -q https://github.com/jeremylong/DependencyCheck/releases/download/v${DEPCHECK_VERSION}/dependency-check-${DEPCHECK_VERSION}-release.zip
    unzip -q dependency-check-${DEPCHECK_VERSION}-release.zip
    rm dependency-check-${DEPCHECK_VERSION}-release.zip
    ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh
    print_success "OWASP Dependency-Check installed"
else
    print_warning "OWASP Dependency-Check already installed"
fi

# Snyk
print_status "Installing Snyk..."
if ! command_exists snyk; then
    npm install -g snyk >/dev/null 2>&1
    print_success "Snyk installed"
else
    print_warning "Snyk already installed"
fi

################################################################################
# INFRASTRUCTURE AS CODE TOOLS
################################################################################

echo ""
echo -e "${BLUE}Installing IaC Security Tools...${NC}"
echo ""

# Checkov
print_status "Installing Checkov..."
if ! command_exists checkov; then
    pip3 install checkov >/dev/null 2>&1
    print_success "Checkov installed"
else
    print_warning "Checkov already installed"
fi

# tfsec
print_status "Installing tfsec..."
if ! command_exists tfsec; then
    curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash >/dev/null 2>&1
    print_success "tfsec installed"
else
    print_warning "tfsec already installed"
fi

# Trivy
print_status "Installing Trivy..."
if ! command_exists trivy; then
    apt install -y wget apt-transport-https gnupg lsb-release >/dev/null 2>&1
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/trivy.list
    apt update -qq
    apt install -y trivy >/dev/null 2>&1
    print_success "Trivy installed"
else
    print_warning "Trivy already installed"
fi

################################################################################
# KALI LINUX SECURITY TOOLS
################################################################################

echo ""
echo -e "${BLUE}Installing Kali Security Tools...${NC}"
echo ""

# Nikto
print_status "Installing Nikto..."
if ! command_exists nikto; then
    apt install -y nikto >/dev/null 2>&1
    print_success "Nikto installed"
else
    print_warning "Nikto already installed"
fi

# Nmap
print_status "Installing Nmap..."
if ! command_exists nmap; then
    apt install -y nmap >/dev/null 2>&1
    print_success "Nmap installed"
else
    print_warning "Nmap already installed"
fi

# SQLMap
print_status "Installing SQLMap..."
if ! command_exists sqlmap; then
    apt install -y sqlmap >/dev/null 2>&1
    print_success "SQLMap installed"
else
    print_warning "SQLMap already installed"
fi

# WPScan
print_status "Installing WPScan..."
if ! command_exists wpscan; then
    gem install wpscan >/dev/null 2>&1
    print_success "WPScan installed"
else
    print_warning "WPScan already installed"
fi

# DIRB
print_status "Installing DIRB..."
if ! command_exists dirb; then
    apt install -y dirb >/dev/null 2>&1
    print_success "DIRB installed"
else
    print_warning "DIRB already installed"
fi

# Lynis
print_status "Installing Lynis..."
if ! command_exists lynis; then
    apt install -y lynis >/dev/null 2>&1
    print_success "Lynis installed"
else
    print_warning "Lynis already installed"
fi

# ClamAV
print_status "Installing ClamAV..."
if ! command_exists clamscan; then
    apt install -y clamav clamav-daemon >/dev/null 2>&1
    print_status "Updating ClamAV virus definitions (this may take a while)..."
    systemctl stop clamav-freshclam 2>/dev/null || true
    freshclam >/dev/null 2>&1 || print_warning "ClamAV update failed, will retry later"
    systemctl start clamav-freshclam 2>/dev/null || true
    print_success "ClamAV installed"
else
    print_warning "ClamAV already installed"
fi

################################################################################
# PYTHON DEPENDENCIES FOR MCP SERVER
################################################################################

echo ""
echo -e "${BLUE}Installing Python dependencies for MCP server...${NC}"
echo ""

print_status "Installing Flask and dependencies..."
pip3 install flask python-dotenv requests >/dev/null 2>&1
print_success "Flask and dependencies installed"

print_status "Installing MCP SDK..."
pip3 install mcp >/dev/null 2>&1
print_success "MCP SDK installed"

################################################################################
# VERIFICATION
################################################################################

echo ""
echo -e "${BLUE}=================================${NC}"
echo -e "${BLUE}Verifying Installation${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""

TOOLS=(
    "semgrep"
    "bandit"
    "bearer"
    "graudit"
    "gosec"
    "brakeman"
    "eslint"
    "trufflehog"
    "gitleaks"
    "safety"
    "checkov"
    "tfsec"
    "trivy"
    "nikto"
    "nmap"
    "sqlmap"
    "wpscan"
    "dirb"
    "lynis"
    "clamscan"
    "snyk"
)

INSTALLED=0
FAILED=0

for tool in "${TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}✓${NC} $tool"
        ((INSTALLED++))
    else
        echo -e "${RED}✗${NC} $tool"
        ((FAILED++))
    fi
done

echo ""
echo -e "${BLUE}=================================${NC}"
echo -e "${GREEN}Installed: $INSTALLED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED${NC}"
fi
echo -e "${BLUE}=================================${NC}"

################################################################################
# FINAL NOTES
################################################################################

echo ""
echo -e "${GREEN}Installation Complete!${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Copy .env.example to .env and configure your settings"
echo "   cp .env.example .env"
echo "   nano .env"
echo ""
echo "2. Start the SAST server:"
echo "   python3 sast_server.py --port 6000"
echo ""
echo "3. Test the server:"
echo "   curl http://localhost:6000/health"
echo ""
echo -e "${YELLOW}Notes:${NC}"
echo "- Some tools may require additional configuration"
echo "- Snyk requires authentication: snyk auth"
echo "- WPScan API token recommended: https://wpscan.com/api"
echo "- ClamAV virus definitions update automatically"
echo ""
echo -e "${BLUE}Happy Scanning! 🔒${NC}"
