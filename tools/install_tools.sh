#!/bin/bash
################################################################################
# SAST-MCP Security Tools Installation Script
#
# This script installs all security tools required for the SAST-MCP server
# Run on Kali Linux or Debian-based systems
#
# Usage: sudo bash install_tools.sh
################################################################################

# Don't exit on error - we want to continue even if some tools fail
# set -e

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
# EFFECTIVE PATH FOR TOOL CHECKS
#
# Installers write to places sudo's secure_path does not always list: gem and
# npm use a prefix of their own, go uses $GOPATH/bin, and pipx uses the
# invoking user's ~/.local/bin. When a tool lands in one of those it is
# installed and runnable, yet `command -v <tool>` here says no - so the run
# ends with a "Failed tools" list that names working tools. On 2026-11-15 both
# tfsec and bearer printed their own "installed at /usr/local/bin" line and
# were still reported as failures.
#
# Build the PATH once, covering every directory the steps below install into,
# and export it so the installers and the final verification agree.
################################################################################

INSTALL_USER="${SUDO_USER:-${USER:-root}}"
INSTALL_USER_HOME="$(getent passwd "$INSTALL_USER" 2>/dev/null | cut -d: -f6)"
[ -n "$INSTALL_USER_HOME" ] || INSTALL_USER_HOME="${HOME:-/root}"

add_to_path() {
    case ":$PATH:" in
        *":$1:"*) return 0 ;;
    esac
    if [ -n "$1" ] && [ -d "$1" ]; then
        PATH="$1:$PATH"
    fi
    return 0
}

GEM_BIN="$(gem environment gemdir 2>/dev/null)/bin"
NPM_BIN="$(npm prefix -g 2>/dev/null)/bin"
PIPX_BIN="$INSTALL_USER_HOME/.local/bin"
for _dir in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin \
            /snap/bin /root/.local/bin /root/go/bin /usr/local/go/bin \
            "$PIPX_BIN" "$INSTALL_USER_HOME/go/bin" "$GEM_BIN" "$NPM_BIN"; do
    add_to_path "$_dir"
done
export PATH

# Where the installers that used to be silenced leave their output.
LOG_DIR="${LOG_DIR:-/tmp/sast-install-logs}"
mkdir -p "$LOG_DIR" 2>/dev/null || LOG_DIR=/tmp

run_logged() {
    # run_logged <name> <cmd...>: run quietly, keep the output, show the tail
    # on failure. Replaces `cmd >/dev/null 2>&1` followed by an unconditional
    # success message - the pattern that had brakeman and snyk reporting
    # installed while their install had actually failed.
    local name="$1"; shift
    local log="$LOG_DIR/${name}.log"
    local rc=0
    "$@" >"$log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        print_warning "$name failed (exit $rc). Last lines of $log:"
        tail -5 "$log" 2>/dev/null | sed 's/^/      /'
    fi
    return "$rc"
}

github_latest_tag() {
    # grep -o rather than a line match: this endpoint can return the whole
    # release object on a single line (0 newlines), in which case a
    # line-based `cut -d'"' -f4` yields the fourth quoted string in the
    # entire document - the release URL - instead of the tag.
    curl -fsSL --max-time 30 "https://api.github.com/repos/$1/releases/latest" 2>/dev/null \
        | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | head -1 | cut -d'"' -f4
}

case "$(uname -m)" in
    x86_64|amd64)  REL_ARCH="amd64" ;;
    aarch64|arm64) REL_ARCH="arm64" ;;
    *)             REL_ARCH="" ;;
esac

drop_root_symlink() {
    # A /usr/local/bin/<tool> symlink pointing into /root is readable only by
    # root. The server runs as a normal user (uid 1000 on the Kali box), so for
    # that process the name resolves to nothing, or to an older copy elsewhere.
    #
    # This is not hypothetical. `go install` with GOPATH=/root/go put gosec in
    # /root/go/bin and symlinked it here, and the server kept using a stale
    # gosec under /home/<user>/go/bin instead.
    #
    # Clear the link so the install step below can put the real binary in
    # /usr/local/bin, where every user can execute it. Done before any check,
    # because `command -v` as root is happy with the link and would otherwise
    # skip the install entirely.
    # USR_LOCAL_BIN is overridable so this is testable; it is /usr/local/bin in use.
    local link="${USR_LOCAL_BIN:-/usr/local/bin}/$1"
    local target
    [ -L "$link" ] || return 0
    target="$(readlink "$link" 2>/dev/null)"
    case "$target" in
        /root/*)
            print_warning "removing $link -> $target (the server user cannot read it)"
            rm -f "$link"
            ;;
    esac
    return 0
}

resolves_into_root() {
    # True when the only copy of this tool that we can see lives under /root.
    #
    # This exists because dropping the symlink is not enough. Root's own PATH
    # includes /root/go/bin, so after the symlink goes `command -v gosec` still
    # succeeds, the install step below is skipped as "already installed", and
    # no world-readable copy is ever created. The server user still cannot
    # reach it. Treat that state as "needs installing", not as installed.
    local path
    path="$(command -v "$1" 2>/dev/null)"
    [ -n "$path" ] || return 1
    case "$(readlink -f "$path" 2>/dev/null)" in
        /root/*) return 0 ;;
    esac
    return 1
}

needs_shared_install() {
    # True when the tool is missing, or present only somewhere unreadable by
    # the non-root user the server runs as.
    if ! command_exists "$1"; then
        return 0
    fi
    resolves_into_root "$1"
}

# Go-installed tools are the ones that used to be symlinked out of /root.
for _tool in gosec gitleaks tfsec; do
    drop_root_symlink "$_tool"
done

# GOBIN puts the binary itself in /usr/local/bin. GOPATH keeps the module
# cache in root's home, so a sudo run cannot leave root-owned files in the
# invoking user's ~/go.
GO_INSTALL_ENV="GOPATH=/root/go GOBIN=/usr/local/bin"

tool_satisfied() {
    # True when the tool, or an accepted stand-in, is runnable. The only
    # stand-in is the one the server itself already accepts:
    # server/routes/health.py maps "opengrep" to ("semgrep",), because the two
    # share one CLI and opengrep_scan runs whichever is installed.
    if command_exists "$1"; then
        return 0
    fi
    case "$1" in
        opengrep) command_exists semgrep ;;
        *) return 1 ;;
    esac
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
# pipx is required for the Python-based scanners: it gives each one its own
# venv, so they survive a rebuild of the server's virtualenv.
apt install -y python3 python3-pip python3-venv pipx >/dev/null 2>&1
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

# Opengrep
#
# Deliberately NOT installed here. Two separate reasons:
#
# 1. What this step used to run, `pip install opengrep`, cannot work at all:
#    opengrep is not published on PyPI (pypi.org/pypi/opengrep/json returns
#    404), and PEP 668 blocks system-wide pip installs on Kali regardless. It
#    installed nothing and printed success.
# 2. Installing the real binary is not a neutral act. core.resolve_grep_engine()
#    prefers `opengrep` over `semgrep`, so dropping the binary onto PATH
#    switches the engine behind every /api/sast/semgrep and /api/repo-scan run,
#    including the weekly sweep - whose rule packs (p/python, p/security-audit)
#    and finding baselines all come from semgrep 1.185.0. Swapping engines is
#    its own change, with its own verification. It is not a side effect an
#    install script should have.
#
# server/routes/health.py already treats the two as interchangeable
# ("opengrep": ("semgrep",)) and opengrep_scan runs whichever binary is
# present, so semgrep satisfies this slot. The verification at the end of this
# script reports it that way instead of counting a phantom failure.
print_status "Opengrep: skipped on purpose; semgrep covers this engine slot"

# Bandit
print_status "Installing Bandit..."
if command_exists bandit; then
    print_warning "Bandit already installed ($(command -v bandit))"
else
    # `pip3 install bandit` is blocked by PEP 668 on Kali. apt carries a
    # package; pipx is the fallback, installed as the invoking user like the
    # other Python scanners.
    run_logged bandit-apt apt install -y bandit \
        || run_logged bandit-pipx sudo -u "$INSTALL_USER" pipx install bandit \
        || true
    if command_exists bandit; then
        print_success "Bandit installed ($(command -v bandit))"
    else
        print_warning "Bandit installation failed - see $LOG_DIR/bandit-*.log"
    fi
fi

# Bearer
print_status "Installing Bearer..."
if command_exists bearer; then
    print_warning "Bearer already installed ($(command -v bearer))"
else
    curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh 2>/dev/null \
        | sh -s -- -b /usr/local/bin >"$LOG_DIR/bearer.log" 2>&1 || true
    if command_exists bearer; then
        print_success "Bearer installed ($(command -v bearer))"
    elif [ -x /usr/local/bin/bearer ]; then
        print_warning "Bearer is at /usr/local/bin/bearer but not on PATH: $PATH"
    else
        print_warning "Bearer installation failed - see $LOG_DIR/bearer.log"
    fi
fi

# Graudit
print_status "Installing Graudit..."
if ! command_exists graudit; then
    apt install -y graudit 2>&1 | grep -v "WARNING" || {
        print_status "Installing from source..."
        cd /opt
        git clone https://github.com/wireghoul/graudit.git 2>&1 | tail -1
        ln -sf /opt/graudit/graudit /usr/local/bin/graudit
        cd - >/dev/null
    }
    if command_exists graudit; then
        print_success "Graudit installed"
    else
        print_warning "Graudit installation failed"
    fi
else
    print_warning "Graudit already installed"
fi

# Gosec
print_status "Installing Gosec..."
if ! needs_shared_install gosec; then
    print_warning "Gosec already installed ($(command -v gosec))"
else
    if command_exists gosec; then
        print_status "Gosec resolves to $(command -v gosec), under /root; \
reinstalling into /usr/local/bin so the server user can run it"
    fi
    run_logged gosec env $GO_INSTALL_ENV \
        go install github.com/securego/gosec/v2/cmd/gosec@latest || true
    if command_exists gosec; then
        print_success "Gosec installed ($(command -v gosec))"
    else
        print_warning "Gosec installation failed (Go required) - see $LOG_DIR/gosec.log"
    fi
fi

# Brakeman
print_status "Installing Brakeman..."
if command_exists brakeman; then
    print_warning "Brakeman already installed ($(command -v brakeman))"
else
    run_logged brakeman gem install --no-document brakeman || true
    if command_exists brakeman; then
        print_success "Brakeman installed ($(command -v brakeman))"
    else
        print_warning "Brakeman installation failed - see $LOG_DIR/brakeman.log"
    fi
fi

# ESLint (with security plugins)
print_status "Installing ESLint with security plugins..."
if command_exists eslint; then
    print_warning "ESLint already installed ($(command -v eslint))"
else
    run_logged eslint npm install -g eslint eslint-plugin-security || true
    if command_exists eslint; then
        print_success "ESLint installed ($(command -v eslint))"
    else
        print_warning "ESLint installation failed - see $LOG_DIR/eslint.log"
    fi
fi

################################################################################
# SECRET SCANNING TOOLS
################################################################################

echo ""
echo -e "${BLUE}Installing Secret Scanning Tools...${NC}"
echo ""

# TruffleHog
print_status "Installing TruffleHog..."
if command_exists trufflehog; then
    print_warning "TruffleHog already installed ($(command -v trufflehog))"
elif [ -z "$REL_ARCH" ]; then
    print_warning "TruffleHog: no release binary for $(uname -m), skipping"
else
    # Release assets carry the version in the filename, e.g.
    # trufflehog_3.99.9_linux_amd64.tar.gz. The old
    # releases/latest/download/trufflehog_linux_amd64.tar.gz does not exist and
    # 404s, which sent every run into a `pip3 install truffleHog` fallback that
    # PEP 668 blocks - and that package is the abandoned v2 anyway.
    TH_TAG="$(github_latest_tag trufflesecurity/trufflehog)"
    TH_VER="${TH_TAG#v}"
    TH_TMP="$(mktemp -d)"
    if [ -n "$TH_VER" ] && curl -fsSL --max-time 300 -o "$TH_TMP/trufflehog.tar.gz" \
        "https://github.com/trufflesecurity/trufflehog/releases/download/${TH_TAG}/trufflehog_${TH_VER}_linux_${REL_ARCH}.tar.gz"; then
        tar -xzf "$TH_TMP/trufflehog.tar.gz" -C "$TH_TMP" trufflehog 2>/dev/null \
            && install -m 755 "$TH_TMP/trufflehog" /usr/local/bin/trufflehog
    else
        print_warning "TruffleHog download failed (tag=${TH_TAG:-unknown} arch=${REL_ARCH})"
    fi
    rm -rf "$TH_TMP"
    if command_exists trufflehog; then
        print_success "TruffleHog ${TH_TAG} installed ($(command -v trufflehog))"
    else
        print_warning "TruffleHog installation failed"
    fi
fi

# Gitleaks
print_status "Installing Gitleaks..."
if needs_shared_install gitleaks; then
    # Try to get latest version, fallback to direct install
    GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest 2>/dev/null | grep -o '"tag_name": "v[^"]*"' | cut -d'"' -f4)

    if [ -z "$GITLEAKS_VERSION" ]; then
        print_warning "Could not fetch latest version, using fallback method..."
        # Fallback: use apt if available or install from alternative source
        apt install -y gitleaks 2>&1 | grep -v "WARNING" || {
            # Alternative: install using go, into /usr/local/bin (see
            # drop_root_symlink above for why not /root/go/bin).
            run_logged gitleaks-go env $GO_INSTALL_ENV \
                go install github.com/gitleaks/gitleaks/v8@latest || true
        }
    else
        wget -q https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION:1}_linux_x64.tar.gz 2>/dev/null || {
            print_warning "Download failed, trying alternative method..."
            apt install -y gitleaks 2>&1 | grep -v "WARNING" || true
        }
        if [ -f "gitleaks_${GITLEAKS_VERSION:1}_linux_x64.tar.gz" ]; then
            tar -xzf gitleaks_${GITLEAKS_VERSION:1}_linux_x64.tar.gz
            mv gitleaks /usr/local/bin/ 2>/dev/null || true
            rm gitleaks_${GITLEAKS_VERSION:1}_linux_x64.tar.gz 2>/dev/null || true
        fi
    fi

    if command_exists gitleaks; then
        print_success "Gitleaks installed"
    else
        print_warning "Gitleaks installation failed"
    fi
else
    print_warning "Gitleaks already installed"
fi

################################################################################
# DEPENDENCY SCANNING TOOLS
################################################################################

echo ""
echo -e "${BLUE}Installing Dependency Scanning Tools...${NC}"
echo ""

# Python-based scanners: semgrep, checkov, safety.
#
# These used to be installed here with a bare `pip3 install`, which puts them
# wherever the active interpreter points. When that was the server's own venv,
# recreating it for Python 3.14 deleted all three at once: /health reported them
# missing and scans kept returning success with those engines simply absent.
#
# scripts/install-python-scanners.sh is the single definition of how they are
# installed (pipx, one venv each). Run it as the invoking user, not root, so the
# binaries land in that user's ~/.local/bin where the server can execute them.
print_status "Installing Python scanners (semgrep, checkov, safety) via pipx..."
_SCANNERS_SH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/install-python-scanners.sh"
_SCANNER_USER="${SUDO_USER:-$USER}"
if [ ! -f "$_SCANNERS_SH" ]; then
    print_warning "Missing $_SCANNERS_SH - skipping Python scanners"
elif sudo -u "$_SCANNER_USER" bash "$_SCANNERS_SH"; then
    print_success "Python scanners installed for $_SCANNER_USER"
else
    print_warning "Python scanner install reported a problem - see output above"
fi

# npm audit (comes with npm)
print_success "npm audit available (comes with npm)"

# OWASP Dependency-Check
#
# Two bugs lived here. First, current.txt now has a second line:
#   12.1.0
#   The OWASP DependencyCheck project has moved to https://github.com/...
# Unquoted, that whole sentence went into the download URL, so wget tried to
# fetch 'old' and 'repository.-release.zip'. Take the first line only, and read
# it from the project's new home. Second, the download-failure branch called
# `return` outside a function, which bash refuses - and the `cd /opt` before it
# then leaked into the following steps.
print_status "Installing OWASP Dependency-Check..."
if command_exists dependency-check.sh; then
    print_warning "OWASP Dependency-Check already installed"
else
    DEPCHECK_VERSION="$(curl -fsSL --max-time 30 \
        https://dependency-check.github.io/DependencyCheck/current.txt 2>/dev/null \
        | head -1 | tr -d '[:space:]')"
    if ! printf '%s' "$DEPCHECK_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        DEPCHECK_VERSION="$(github_latest_tag dependency-check/DependencyCheck | sed 's/^v//')"
    fi
    if ! printf '%s' "$DEPCHECK_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        print_warning "Could not determine version, using 12.1.0 as fallback..."
        DEPCHECK_VERSION="12.1.0"
    fi

    print_status "Downloading Dependency-Check v${DEPCHECK_VERSION}..."
    DC_ZIP="$LOG_DIR/dependency-check-${DEPCHECK_VERSION}-release.zip"
    if curl -fsSL --max-time 900 -o "$DC_ZIP" \
        "https://github.com/dependency-check/DependencyCheck/releases/download/v${DEPCHECK_VERSION}/dependency-check-${DEPCHECK_VERSION}-release.zip"; then
        rm -rf /opt/dependency-check
        if unzip -q "$DC_ZIP" -d /opt; then
            chmod +x /opt/dependency-check/bin/dependency-check.sh
            ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh
        fi
        rm -f "$DC_ZIP"
    else
        print_warning "Dependency-Check download failed (v${DEPCHECK_VERSION})"
    fi

    if command_exists dependency-check.sh; then
        print_success "OWASP Dependency-Check v${DEPCHECK_VERSION} installed"
        command_exists java || print_warning "dependency-check needs a JRE: apt install -y default-jre"
    else
        print_warning "OWASP Dependency-Check installation failed"
    fi
fi

# Snyk
print_status "Installing Snyk..."
if command_exists snyk; then
    print_warning "Snyk already installed ($(command -v snyk))"
else
    run_logged snyk npm install -g snyk || true
    if command_exists snyk; then
        print_success "Snyk installed ($(command -v snyk))"
    else
        print_warning "Snyk installation failed - see $LOG_DIR/snyk.log"
    fi
fi

################################################################################
# INFRASTRUCTURE AS CODE TOOLS
################################################################################

echo ""
echo -e "${BLUE}Installing IaC Security Tools...${NC}"
echo ""

# Checkov is installed with semgrep and safety by
# scripts/install-python-scanners.sh, in the "Dependency Scanning Tools" section
# above. Do not add a `pip3 install checkov` back here: that is what tied it to
# the server venv and lost it on the Python 3.14 rebuild.

# tfsec
print_status "Installing tfsec..."
if ! needs_shared_install tfsec; then
    print_warning "tfsec already installed ($(command -v tfsec))"
else
    # The upstream installer ends by printing "Current tfsec version: v1.28.14".
    # Piping it through `tail -1` surfaced that line as if it were an error,
    # while the real problem was that the installed binary in /usr/local/bin
    # was not on this script's PATH. Keep the output in a log instead.
    curl -fsSL --max-time 60 \
        https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh 2>/dev/null \
        | bash >"$LOG_DIR/tfsec.log" 2>&1 || true
    if ! command_exists tfsec; then
        run_logged tfsec-apt apt install -y tfsec \
            || run_logged tfsec-go env $GO_INSTALL_ENV \
                go install github.com/aquasecurity/tfsec/cmd/tfsec@latest \
            || true
    fi
    if command_exists tfsec; then
        print_success "tfsec installed ($(command -v tfsec))"
    else
        print_warning "tfsec installation failed - see $LOG_DIR/tfsec.log"
    fi
fi

# Trivy
print_status "Installing Trivy..."
if ! command_exists trivy; then
    # Install dependencies
    apt install -y wget apt-transport-https gnupg lsb-release 2>&1 | grep -v "WARNING" || true

    # Try new method (without deprecated apt-key)
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key 2>/dev/null | gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/dev/null || {
        # Fallback to old method
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key 2>/dev/null | apt-key add - 2>&1 | tail -1 || true
    }

    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/trivy.list >/dev/null 2>&1 || {
        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/trivy.list >/dev/null 2>&1
    }

    apt update -qq 2>&1 | tail -1
    apt install -y trivy 2>&1 | grep -v "WARNING" || print_warning "Trivy installation failed"

    if command_exists trivy; then
        print_success "Trivy installed"
    else
        print_warning "Trivy installation failed"
    fi
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

# PEP 668: Kali refuses system-wide pip installs ("externally-managed-
# environment"), so the three `python3 -m pip install` calls that used to live
# here failed on every run while still printing success - the hint text in the
# 2026-11-15 log ("note: If you believe this is a mistake...") is all that was
# left of them. Install into the repo's own venv instead: that is the
# interpreter the server runs on, and core.get_enhanced_env() already puts
# <repo>/venv/bin on the executor PATH.
#
# The scanners (semgrep, checkov, safety) deliberately do NOT go in the venv -
# see scripts/install-python-scanners.sh for why.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${SAST_VENV:-$REPO_ROOT/venv}"

print_status "Installing server dependencies into $VENV_DIR..."
if [ ! -x "$VENV_DIR/bin/python" ]; then
    run_logged venv-create sudo -u "$INSTALL_USER" python3 -m venv "$VENV_DIR" || true
fi

if [ ! -x "$VENV_DIR/bin/python" ]; then
    print_warning "No venv at $VENV_DIR - see $LOG_DIR/venv-create.log"
    print_warning "Server deps not installed. Create it by hand, then:"
    print_warning "  $VENV_DIR/bin/python -m pip install -r $REPO_ROOT/requirements.txt"
else
    run_logged server-deps sudo -u "$INSTALL_USER" "$VENV_DIR/bin/python" -m pip install \
        --upgrade pip -r "$REPO_ROOT/requirements.txt" || true
    # python-toon is used by the TOON output path; keep it explicit so a
    # requirements.txt edit cannot drop it silently.
    run_logged python-toon sudo -u "$INSTALL_USER" "$VENV_DIR/bin/python" -m pip install \
        --upgrade python-toon || true

    while IFS='|' read -r label code; do
        [ -n "$label" ] || continue
        if "$VENV_DIR/bin/python" -c "$code" 2>/dev/null; then
            print_success "$label verified in $VENV_DIR"
        else
            print_warning "$label NOT importable in $VENV_DIR - see $LOG_DIR/server-deps.log"
        fi
    done <<'PY_CHECKS'
flask|import flask
flask-cors|import flask_cors
requests|import requests
MCP SDK|import mcp
python-toon|from toon import encode, decode
PY_CHECKS
fi

################################################################################
# VERIFICATION
################################################################################

echo ""
echo -e "${BLUE}=================================${NC}"
echo -e "${BLUE}Verifying Installation${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""

TOOLS=(
    "opengrep"
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

# Print the resolved path, not just a tick: a tool found in an unexpected
# directory is the difference between "installed" and "installed where the
# server cannot see it".
for tool in "${TOOLS[@]}"; do
    tool_path="$(command -v "$tool" 2>/dev/null)"
    if [ -n "$tool_path" ]; then
        printf '%b %-12s %s\n' "${GREEN}✓${NC}" "$tool" "$tool_path"
        ((INSTALLED++))
    elif tool_satisfied "$tool"; then
        printf '%b %-12s %s\n' "${GREEN}✓${NC}" "$tool" \
            "satisfied by semgrep ($(command -v semgrep))"
        ((INSTALLED++))
    else
        printf '%b %-12s %s\n' "${RED}✗${NC}" "$tool" ""
        ((FAILED++))
    fi
done

echo ""
echo -e "${BLUE}=================================${NC}"
echo -e "${GREEN}Installed: $INSTALLED / $(( ${#TOOLS[@]} ))${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED${NC}"
    echo ""
    echo -e "${YELLOW}Failed tools:${NC}"
    for tool in "${TOOLS[@]}"; do
        if tool_satisfied "$tool"; then
            continue
        fi
        stray=""
        for _dir in /usr/local/bin /usr/bin /snap/bin /root/.local/bin "$PIPX_BIN" \
                    /root/go/bin "$GEM_BIN" "$NPM_BIN"; do
            if [ -n "$_dir" ] && [ -x "$_dir/$tool" ]; then
                stray="$_dir/$tool"
                break
            fi
        done
        if [ -n "$stray" ]; then
            echo "  - $tool (installed at $stray but not on PATH - fix PATH, not the install)"
        else
            echo "  - $tool (see $LOG_DIR for its install log)"
        fi
    done
fi
echo -e "${BLUE}=================================${NC}"

################################################################################
# FINAL NOTES
################################################################################

echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ Installation Complete! All tools installed successfully.${NC}"
else
    echo -e "${YELLOW}⚠ Installation Complete with warnings.${NC}"
    echo -e "${YELLOW}Some tools failed to install but the server can still function.${NC}"
fi
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Copy .env.example to .env and configure your settings"
echo -e "   ${BLUE}cp .env.example .env${NC}"
echo -e "   ${BLUE}nano .env${NC}"
echo ""
echo "2. Start the SAST server:"
echo -e "   ${BLUE}${VENV_DIR:-venv}/bin/python server/sast_server.py --port 6000${NC}"
echo ""
echo "3. Test the server:"
echo -e "   ${BLUE}curl http://localhost:6000/health${NC}"
echo ""
echo -e "${YELLOW}Important Notes:${NC}"
echo "- Install logs for this run: $LOG_DIR"
echo "- /health lists fragile_tools: tools only reachable from the server venv"
echo "- Where each scanner resolved from: scripts/check-tools.sh --versions"
echo "- Some tools may require additional configuration"
echo -e "- Snyk requires authentication: ${BLUE}snyk auth${NC}"
echo -e "- WPScan API token recommended: ${BLUE}https://wpscan.com/api${NC}"
echo "- ClamAV virus definitions update automatically"
echo ""
if [ $FAILED -gt 0 ]; then
    echo -e "${YELLOW}Troubleshooting Failed Tools:${NC}"
    echo "- Check internet connection and firewall settings"
    echo "- Some tools may need manual installation from official docs"
    echo "- Run the script again - some failures may be temporary"
    echo "- Check the error messages above for specific issues"
    echo ""
fi
echo -e "${BLUE}Happy Scanning! 🔒${NC}"
