# MCP-SAST-Server

A comprehensive **Model Context Protocol (MCP)** server that integrates multiple SAST (Static Application Security Testing) tools with Claude Code AI, enabling automated security analysis and vulnerability scanning directly from your AI assistant.

## Overview

This project provides a bridge between Claude Code and industry-standard security scanning tools, allowing developers to perform comprehensive security analysis through natural language commands.

### Key Features

- **23+ Security Tools Integration**:
  - SAST: Semgrep, Bandit, ESLint Security, Gosec, Brakeman, Graudit, Bearer
  - Secrets: TruffleHog, Gitleaks
  - Dependencies: Safety, npm audit, OWASP Dependency-Check, Snyk
  - IaC: Checkov, tfsec, Trivy
  - Kali Tools: Nikto, Nmap, SQLMap, WPScan, DIRB, Lynis, ClamAV
- **MCP Protocol**: Seamless integration with Claude Code AI
- **Remote Execution**: Run security tools on a dedicated security VM (Kali Linux) while working on Windows
- **Path Resolution**: Automatic Windows ↔ Linux path mapping for cross-platform operation
- **File Output Support**: All tools support saving results to files for further analysis
- **Flexible Architecture**: Choose between full-featured or lightweight server
- **Comprehensive Coverage**: Code analysis, secret scanning, dependency checking, IaC security, web security, network scanning, malware detection

## Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│  Claude Code    │  MCP    │  MCP Client      │  HTTP   │  SAST Server    │
│  (Windows)      │◄───────►│  sast_mcp_client │◄───────►│  (Kali Linux)   │
│                 │         │  .py             │         │                 │
└─────────────────┘         └──────────────────┘         └─────────────────┘
                                                                  │
                                                                  ▼
                                                          ┌─────────────────┐
                                                          │  Security Tools │
                                                          │  - Semgrep      │
                                                          │  - Bandit       │
                                                          │  - TruffleHog   │
                                                          │  - Checkov      │
                                                          │  - And more...  │
                                                          └─────────────────┘
```

## Supported Tools

### Code Analysis
- **Semgrep** - Multi-language static analysis (30+ languages)
- **Bandit** - Python security scanner
- **ESLint Security** - JavaScript/TypeScript security linting
- **Gosec** - Go security checker
- **Brakeman** - Ruby on Rails security scanner
- **Graudit** - Grep-based source code auditing
- **Bearer** - Security and privacy risk scanner

### Secret Detection
- **TruffleHog** - Secret scanner for git repos and filesystems
- **Gitleaks** - Fast secret detection for git repositories

### Dependency Scanning
- **Safety** - Python dependency vulnerability checker
- **npm audit** - Node.js dependency security audit
- **OWASP Dependency-Check** - Multi-language dependency scanner
- **Snyk** - Modern dependency and container scanner

### Infrastructure as Code
- **Checkov** - Terraform, CloudFormation, Kubernetes, Dockerfile scanner
- **tfsec** - Terraform security scanner
- **Trivy** - Container and IaC vulnerability scanner

### Kali Linux Security Tools
- **Nikto** - Web server vulnerability scanner
- **Nmap** - Network and port scanner
- **SQLMap** - SQL injection detection and exploitation
- **WPScan** - WordPress security scanner
- **DIRB** - Web content discovery scanner
- **Lynis** - System auditing and hardening tool
- **ClamAV** - Antivirus and malware scanner

## Installation

### Prerequisites

**Windows Machine (Client):**
- Python 3.8+
- Claude Code installed

**Linux Machine (Server - Kali Linux recommended):**
- Python 3.8+
- Security tools installed (see [Tool Installation](#tool-installation))

### Quick Start

#### 1. Clone the Repository

```bash
git clone https://github.com/your-username/MCP-SAST-Server.git
cd MCP-SAST-Server
```

#### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

#### 3. Configure Server (Optional)

Copy the example environment file and customize:

```bash
cp .env.example .env
# Edit .env with your settings (port, paths, timeouts)
```

#### 4. Start SAST Server (on Kali Linux)

**Option A: Full-Featured Server** (recommended for complete functionality)

```bash
python3 sast_server.py --port 6000
```

**Option B: Simple Server** (no external dependencies, basic functionality)

```bash
python3 simple_sast_server.py --port 6000
```

#### 5. Configure Claude Code (on Windows)

**Option A: Use the example configuration**

1. Open `config.example.json` in the repository
2. Copy the configuration that matches your setup
3. Add it to your `.claude.json` file
4. Update the paths and server URL

**Option B: Manual configuration**

Add the MCP server configuration to your `.claude.json`:

```json
{
  "mcpServers": {
    "sast_tools": {
      "type": "stdio",
      "command": "python",
      "args": [
        "/path/to/MCP-SAST-Server/sast_mcp_client.py",
        "--server",
        "http://YOUR_KALI_IP:6000"
      ]
    }
  }
}
```

**Important: Update these values:**
- `/path/to/MCP-SAST-Server/sast_mcp_client.py` - Full path to the MCP client script
- `YOUR_KALI_IP` - Your Kali Linux machine's IP address (e.g., `192.168.1.100`)
- Port `6000` - Change if you configured a different port

**Windows Path Examples:**
- `C:/Projects/MCP-SAST-Server/sast_mcp_client.py`
- `F:/work/MCP-SAST-Server/sast_mcp_client.py`

**Linux/Mac Path Examples:**
- `/home/user/MCP-SAST-Server/sast_mcp_client.py`
- `~/projects/MCP-SAST-Server/sast_mcp_client.py`

#### 6. Verify Installation

**On Kali Linux:**
```bash
curl http://localhost:6000/health
```

**In Claude Code:**
```
@sast_tools

Check the SAST server health and show me available tools
```

## Usage Examples

### Security Scanning

**Scan Python code for vulnerabilities:**
```
@sast_tools

Run a Bandit scan on F:/work/MyProject/backend with high severity filter
```

**Multi-language security audit:**
```
@sast_tools

Use Semgrep with OWASP Top 10 rules to scan F:/work/MyProject
```

**Find secrets in repository:**
```
@sast_tools

Scan F:/work/MyProject for leaked secrets using TruffleHog
```

### Dependency Checking

**Check Python dependencies:**
```
@sast_tools

Run Safety check on F:/work/MyProject/requirements.txt
```

**Audit Node.js packages:**
```
@sast_tools

Run npm audit on F:/work/MyProject/frontend with critical severity
```

### Infrastructure Security

**Scan Terraform files:**
```
@sast_tools

Use Checkov to scan Terraform configurations in F:/work/MyProject/terraform
```

**Check Docker security:**
```
@sast_tools

Scan F:/work/MyProject/Dockerfile with Trivy
```

### Kali Security Tools

**Scan web server with Nikto:**
```
@sast_tools

Run Nikto scan on https://example.com with SSL and save results to /tmp/nikto-scan.txt
```

**Network scanning with Nmap:**
```
@sast_tools

Use Nmap to scan 192.168.1.1 for open ports 1-1000 and save results
```

**SQL injection testing:**
```
@sast_tools

Test https://example.com/login.php for SQL injection using SQLMap
```

**WordPress security scan:**
```
@sast_tools

Scan https://wordpress-site.com with WPScan to enumerate vulnerable plugins
```

**Web content discovery:**
```
@sast_tools

Run DIRB on https://example.com to discover hidden directories and files
```

**System audit:**
```
@sast_tools

Run Lynis system audit to check security hardening
```

**Malware scanning:**
```
@sast_tools

Scan F:/work/MyProject with ClamAV antivirus to detect malware
```

## Tool Installation

### Installing Security Tools on Kali Linux

Many tools come pre-installed on Kali Linux. For missing tools:

**Semgrep:**
```bash
pip3 install semgrep
```

**Bandit:**
```bash
pip3 install bandit
```

**TruffleHog:**
```bash
pip3 install trufflehog
```

**Gitleaks:**
```bash
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

**Checkov:**
```bash
pip3 install checkov
```

**Safety:**
```bash
pip3 install safety
```

**Trivy:**
```bash
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt update
sudo apt install trivy
```

### Installing Kali Linux Tools

Most Kali tools come pre-installed on Kali Linux. For missing tools:

**Nikto:**
```bash
sudo apt install nikto
```

**Nmap:**
```bash
sudo apt install nmap
```

**SQLMap:**
```bash
sudo apt install sqlmap
```

**WPScan:**
```bash
sudo gem install wpscan
# Or
sudo apt install wpscan
```

**DIRB:**
```bash
sudo apt install dirb
```

**Lynis:**
```bash
sudo apt install lynis
```

**Snyk:**
```bash
npm install -g snyk
# Or download from https://github.com/snyk/cli
```

**ClamAV:**
```bash
sudo apt install clamav clamav-daemon
sudo freshclam  # Update virus definitions
```

For a complete installation guide, refer to each tool's official documentation.

## Configuration

### Server Configuration (.env file)

The server can be configured using environment variables or a `.env` file:

**Using .env file (recommended):**

```bash
# Copy the example file
cp .env.example .env

# Edit .env with your settings
nano .env
```

**Available Configuration Options:**

```bash
# Server Port (default: 6000)
API_PORT=6000

# Debug Mode (default: 0)
DEBUG_MODE=0

# Command Timeout in seconds (default: 3600 / 1 hour)
COMMAND_TIMEOUT=3600

# Max timeout limit (default: 86400 / 24 hours)
# For scans that take days, increase this value
# Examples: 259200 (3 days), 604800 (1 week)
MAX_TIMEOUT=86400

# Tool-Specific Timeouts (in seconds)
# Customize timeout for each security tool based on your needs
NIKTO_TIMEOUT=3600        # Web server scanning
NMAP_TIMEOUT=7200         # Network/port scanning
SQLMAP_TIMEOUT=7200       # SQL injection testing
WPSCAN_TIMEOUT=3600       # WordPress scanning
DIRB_TIMEOUT=7200         # Web content discovery
LYNIS_TIMEOUT=1800        # System auditing
SNYK_TIMEOUT=3600         # Dependency scanning
CLAMAV_TIMEOUT=14400      # Malware scanning (4 hours)
SEMGREP_TIMEOUT=7200      # Code analysis
BANDIT_TIMEOUT=1800       # Python security
TRUFFLEHOG_TIMEOUT=3600   # Secret detection

# Path Mapping (for Windows/Linux cross-platform)
MOUNT_POINT=/mnt/work
WINDOWS_BASE=F:/work
```

**Timeout Configuration Tips:**

For large-scale or comprehensive security scans, you may need to increase timeouts:

- **Large codebases (>100K LOC)**: Increase `SEMGREP_TIMEOUT` to 14400 (4 hours)
- **Full network scans**: Set `NMAP_TIMEOUT` to 28800 (8 hours) or higher
- **Thorough SQL injection testing**: Use `SQLMAP_TIMEOUT` of 21600 (6 hours)
- **Complete malware scans**: Set `CLAMAV_TIMEOUT` to 43200 (12 hours)
- **Multi-day scans**: Increase `MAX_TIMEOUT` to 259200 (3 days) or more

The server saves partial results if a scan times out, so you won't lose all data.

**Using environment variables directly:**

```bash
export API_PORT=6000
export DEBUG_MODE=1
export MOUNT_POINT=/mnt/work
export WINDOWS_BASE=F:/work
```

### Client Configuration (config.example.json)

For Claude Code configuration, see `config.example.json` which includes:
- Windows with local Kali VM example
- Windows with remote Kali server example
- Linux/Mac configuration example

Simply copy the appropriate configuration to your `.claude.json` and update the paths and IP address.

### Path Resolution

The server automatically resolves Windows paths to Linux mount paths:

- `F:/work/Project` → `/mnt/work/Project`
- `F:\work\Project` → `/mnt/work/Project`

Configure your mount point using environment variables if different.

## API Endpoints

### Health Check
```http
GET /health
```

### SAST Tools
```http
POST /api/sast/semgrep
POST /api/sast/bandit
POST /api/sast/bearer
POST /api/sast/graudit
POST /api/sast/gosec
POST /api/sast/brakeman
POST /api/sast/eslint-security
```

### Secret Scanning
```http
POST /api/secrets/trufflehog
POST /api/secrets/gitleaks
```

### Dependency Scanning
```http
POST /api/dependencies/safety
POST /api/dependencies/npm-audit
POST /api/dependencies/dependency-check
```

### Infrastructure as Code
```http
POST /api/iac/checkov
POST /api/iac/tfsec
```

### Container Security
```http
POST /api/container/trivy
```

### Custom Commands
```http
POST /api/command
```

## Project Structure

```
MCP-SAST-Server/
├── sast_server.py              # Full-featured SAST server (recommended)
├── simple_sast_server.py       # Lightweight alternative (minimal dependencies)
├── sast_mcp_client.py          # MCP client for Claude Code integration
├── requirements.txt            # Python dependencies
├── .env.example                # Server configuration template
├── config.example.json         # Claude Code configuration examples
├── .gitignore                  # Git ignore rules
├── LICENSE                     # MIT License
├── CONTRIBUTING.md             # Contribution guidelines
└── README.md                   # This file (main documentation)
```

### File Descriptions

**Core Files:**
- `sast_server.py` - Main SAST server with .env support and path resolution
- `sast_mcp_client.py` - MCP client that connects Claude Code to the server
- `simple_sast_server.py` - Alternative server with no external dependencies

**Configuration:**
- `.env.example` - Environment variables template for server configuration
- `config.example.json` - Claude Code integration examples for different setups

**Documentation:**
- `README.md` - Complete project documentation (you're reading it!)
- `CONTRIBUTING.md` - Guidelines for contributing to the project
- `LICENSE` - MIT License terms

## Troubleshooting

### Connection Issues

**Problem:** Cannot connect to SAST server

**Solution:**
1. Verify server is running: `curl http://KALI_IP:6000/health`
2. Check firewall settings on Kali Linux
3. Ensure IP address in `.claude.json` is correct
4. Check network connectivity between Windows and Kali

### Path Resolution Issues

**Problem:** Scans fail with "path not found"

**Solution:**
1. Verify Windows share is mounted on Linux: `ls /mnt/work`
2. Check mount point configuration matches `MOUNT_POINT` environment variable
3. Ensure paths use forward slashes in `.claude.json`

### Tool Not Available

**Problem:** Health check shows tool as unavailable

**Solution:**
1. Install missing tools (see [Tool Installation](#tool-installation))
2. Verify tool is in PATH: `which semgrep`
3. Test tool manually: `semgrep --version`

## Security Considerations

- **Network Security**: Use firewall rules to restrict access to SAST server port
- **Authentication**: Consider adding API authentication for production use
- **Secrets**: Never commit API keys or credentials to the repository
- **Isolation**: Run SAST server in isolated VM or container
- **Updates**: Regularly update security tools to get latest vulnerability signatures

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [Anthropic](https://www.anthropic.com/) - Claude AI and Claude Code
- All the amazing open-source security tool maintainers

## Support

For issues, questions, or contributions:

- **Issues**: [GitHub Issues](https://github.com/your-username/MCP-SAST-Server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/MCP-SAST-Server/discussions)

## Roadmap

- [ ] Add authentication/authorization
- [ ] Implement scan result caching
- [ ] Add webhook notifications
- [ ] Create web dashboard for scan results
- [ ] Support for additional SAST tools
- [ ] Docker containerization
- [ ] CI/CD integration examples

---

**Built with ❤️ for secure code development**
