# MCP-SAST-Server

A comprehensive **Model Context Protocol (MCP)** server that integrates multiple SAST (Static Application Security Testing) tools with Claude Code AI, enabling automated security analysis and vulnerability scanning directly from your AI assistant.

## Overview

This project provides a bridge between Claude Code and industry-standard security scanning tools, allowing developers to perform comprehensive security analysis through natural language commands.

### Key Features

- **15+ SAST Tools Integration**: Semgrep, Bandit, ESLint Security, TruffleHog, Gitleaks, and more
- **MCP Protocol**: Seamless integration with Claude Code AI
- **Remote Execution**: Run security tools on a dedicated security VM (Kali Linux) while working on Windows
- **Path Resolution**: Automatic Windows ↔ Linux path mapping for cross-platform operation
- **Flexible Architecture**: Choose between full-featured or lightweight server
- **Comprehensive Coverage**: Code analysis, secret scanning, dependency checking, IaC security

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

### Infrastructure as Code
- **Checkov** - Terraform, CloudFormation, Kubernetes, Dockerfile scanner
- **tfsec** - Terraform security scanner
- **Trivy** - Container and IaC vulnerability scanner

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

#### 3. Start SAST Server (on Kali Linux)

**Option A: Full-Featured Server** (recommended for complete functionality)

```bash
python3 sast_server.py --port 6000
```

**Option B: Simple Server** (no external dependencies, basic functionality)

```bash
python3 simple_sast_server.py --port 6000
```

#### 4. Configure Claude Code (on Windows)

Add the MCP server configuration to your `.claude.json`:

```json
{
  "projects": {
    "F:\\work\\YourProject": {
      "mcpServers": {
        "sast_tools": {
          "type": "stdio",
          "command": "python",
          "args": [
            "F:/work/Resola/Pentesting/MCP-SAST-Server/sast_mcp_client.py",
            "--server",
            "http://YOUR_KALI_IP:6000"
          ]
        }
      }
    }
  }
}
```

Replace:
- `F:\\work\\YourProject` with your actual project path
- `F:/work/Resola/Pentesting/MCP-SAST-Server/sast_mcp_client.py` with the actual path to the client script
- `YOUR_KALI_IP` with your Kali Linux machine's IP address

#### 5. Verify Installation

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

For a complete installation guide, refer to each tool's official documentation.

## Configuration

### Environment Variables

**Server Configuration:**

```bash
# Server Port (default: 6000)
export API_PORT=6000

# Debug Mode (default: false)
export DEBUG_MODE=1

# Command Timeout in seconds (default: 3600)
export COMMAND_TIMEOUT=3600

# Path Mapping
export MOUNT_POINT=/mnt/work
export WINDOWS_BASE=F:/work
```

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
├── sast_server.py              # Full-featured SAST server
├── simple_sast_server.py       # Lightweight server (no dependencies)
├── sast_mcp_client.py          # MCP client for Claude Code integration
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git ignore rules
├── README.md                   # This file
├── PATH_RESOLUTION_GUIDE.md    # Path resolution documentation
└── TOOL_COMMANDS_VERIFICATION.md # Tool command verification guide
```

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
