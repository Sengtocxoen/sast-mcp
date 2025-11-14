# Proper MCP Tool Usage Guide

## Problem: Running Tools Directly vs. Through MCP

❌ **WRONG** - Running tools directly via bash (tools not installed on Windows):
```bash
cd /f/work/Resola/Deca/deca-tables-api
semgrep --config auto --json --output results.json .
```

✅ **CORRECT** - Call tools through MCP server (runs on Kali):
```python
# The MCP tool calls the Kali server which has all tools installed
semgrep_scan(
    target="/f/work/Resola/Deca/deca-tables-api",
    config="auto",
    output_format="json",
    output_file="F:/work/Resola/Security-Reports/Deca/deca-tables-api/semgrep-results.json"
)
```

## How MCP Tools Work

1. **You call** the MCP tool from Claude Code (Windows)
2. **MCP client** (`sast_mcp_client.py`) sends request to Flask server (Kali)
3. **Flask server** runs the security tool on Kali (where tools are installed)
4. **Results saved** to shared folder accessible from both Windows and Kali
5. **Summary returned** to Claude Code (small response, avoids token limits)

## Complete Scan Workflow for deca-tables-api

### Step 1: Create Output Directory (Windows)

```bash
# On Windows, create the output directory
mkdir F:\work\Resola\Security-Reports\Deca\deca-tables-api
```

Or from Claude Code:
```bash
mkdir -p "/f/work/Resola/Security-Reports/Deca/deca-tables-api"
```

### Step 2: Call MCP Tools with output_file Parameter

**Important:** When calling from Claude Code, use these exact tool calls:

#### 1. Semgrep (SAST - Code Analysis)
```
Use the semgrep_scan MCP tool with:
- target: "/f/work/Resola/Deca/deca-tables-api"
- config: "auto"
- output_format: "json"
- output_file: "F:/work/Resola/Security-Reports/Deca/deca-tables-api/semgrep-results.json"
```

#### 2. TruffleHog (Secret Detection)
```
Use the trufflehog_scan MCP tool with:
- target_path: "/f/work/Resola/Deca/deca-tables-api"
- scan_type: "filesystem"
- output_file: "F:/work/Resola/Security-Reports/Deca/deca-tables-api/trufflehog-results.json"
```

#### 3. Gitleaks (Git Secret Scanning)
```
Use the gitleaks_scan MCP tool with:
- target_path: "/f/work/Resola/Deca/deca-tables-api"
- scan_type: "detect"
- output_file: "F:/work/Resola/Security-Reports/Deca/deca-tables-api/gitleaks-results.json"
```

#### 4. Bandit (Python Security)
```
Use the bandit_scan MCP tool with:
- target_path: "/f/work/Resola/Deca/deca-tables-api"
- severity: "medium"
- output_file: "F:/work/Resola/Security-Reports/Deca/deca-tables-api/bandit-results.json"
```

#### 5. ESLint (JavaScript/TypeScript)
```
Use the eslint_scan MCP tool with:
- target_path: "/f/work/Resola/Deca/deca-tables-api"
- output_format: "json"
- output_file: "F:/work/Resola/Security-Reports/Deca/deca-tables-api/eslint-results.json"
```

#### 6. Safety (Python Dependencies)
```
Use the safety_check MCP tool with:
- requirements_file: "/f/work/Resola/Deca/deca-tables-api/requirements.txt"
- output_file: "F:/work/Resola/Security-Reports/Deca/deca-tables-api/safety-results.json"
```

#### 7. npm audit (Node.js Dependencies)
```
Use the npm_audit MCP tool with:
- project_path: "/f/work/Resola/Deca/deca-tables-api"
- audit_level: "moderate"
- output_file: "F:/work/Resola/Security-Reports/Deca/deca-tables-api/npm-audit-results.json"
```

#### 8. Trivy (Container/Filesystem Scanning)
```
Use the trivy_scan MCP tool with:
- target_path: "/f/work/Resola/Deca/deca-tables-api"
- scan_type: "fs"
- severity: "CRITICAL,HIGH,MEDIUM"
- output_file: "F:/work/Resola/Security-Reports/Deca/deca-tables-api/trivy-results.json"
```

#### 9. Bearer (Data Security)
```
Use the bearer_scan MCP tool with:
- target_path: "/f/work/Resola/Deca/deca-tables-api"
- scanner_type: "sast"
- output_file: "F:/work/Resola/Security-Reports/Deca/deca-tables-api/bearer-results.json"
```

#### 10. Graudit (Source Code Audit)
```
Use the graudit_scan MCP tool with:
- target_path: "/f/work/Resola/Deca/deca-tables-api"
- database: "all"
- output_file: "F:/work/Resola/Security-Reports/Deca/deca-tables-api/graudit-results.txt"
```

### Step 3: Read Results

After scans complete, read the results from Windows:

```bash
# View Semgrep results
cat F:/work/Resola/Security-Reports/Deca/deca-tables-api/semgrep-results.json

# View TruffleHog results
cat F:/work/Resola/Security-Reports/Deca/deca-tables-api/trufflehog-results.json

# List all result files
ls -la F:/work/Resola/Security-Reports/Deca/deca-tables-api/
```

From Kali:
```bash
# View results from Kali side
ls -la /mnt/work/work/Resola/Security-Reports/Deca/deca-tables-api/
```

## Expected MCP Tool Response

When you use `output_file`, you'll get a small response like:

```json
{
  "status": "success",
  "tool": "semgrep",
  "scan_completed": true,
  "findings": {
    "total": 14,
    "by_severity": {
      "ERROR": 2,
      "WARNING": 12
    }
  },
  "output_file": {
    "linux_path": "/mnt/work/work/Resola/Security-Reports/Deca/deca-tables-api/semgrep-results.json",
    "windows_path": "F:/work/Resola/Security-Reports/Deca/deca-tables-api/semgrep-results.json",
    "size_bytes": 45632
  },
  "execution_time": "12.34s"
}
```

This is only ~200-300 tokens instead of 40,000+ tokens!

## Troubleshooting

### Issue: "command not found" errors
**Cause:** Claude Code is trying to run bash commands directly instead of using MCP tools
**Solution:** Always use MCP tool calls, never direct bash commands for security tools

### Issue: "Token limit exceeded"
**Cause:** MCP tool called without `output_file` parameter
**Solution:** Always include `output_file` parameter in tool calls

### Issue: "Path not found"
**Cause:** Incorrect path format
**Solution:** Use `/f/work/...` format for target paths, `F:/work/...` for output files

### Issue: Tools not available
**Cause:** MCP server not running on Kali
**Solution:** Start the server on Kali: `python3 /mnt/work/sast-mcp/sast_server.py`

## Claude Code Prompt Template

When asking Claude Code to run scans, use this prompt:

```
Please run comprehensive security scans on /f/work/Resola/Deca/deca-tables-api
and save all results to F:/work/Resola/Security-Reports/Deca/deca-tables-api/

Use these MCP tools with output_file parameter:
1. semgrep_scan - with config "auto", output_format "json"
2. trufflehog_scan - filesystem scan
3. gitleaks_scan - detect mode
4. bandit_scan - medium severity
5. eslint_scan - json output
6. npm_audit - moderate level
7. trivy_scan - filesystem mode, CRITICAL,HIGH,MEDIUM severity
8. bearer_scan - sast mode
9. graudit_scan - all databases

After scans complete, provide a summary of findings from each tool.
```

## Path Mapping Reference

| Windows Path | Linux Path (Kali) |
|--------------|-------------------|
| F:/ | /mnt/work/ |
| F:/work/Resola | /mnt/work/work/Resola |
| F:/work/Resola/Security-Reports | /mnt/work/work/Resola/Security-Reports |
| /f/work/Resola (Git bash) | /mnt/work/work/Resola |

## All Available MCP Tools

### SAST Tools
- `semgrep_scan` - Multi-language SAST
- `bandit_scan` - Python security
- `eslint_scan` - JavaScript/TypeScript
- `gosec_scan` - Go security
- `brakeman_scan` - Ruby on Rails
- `bearer_scan` - Data security
- `graudit_scan` - Source code audit

### Secret Scanning
- `trufflehog_scan` - Secret detection
- `gitleaks_scan` - Git secret scanning

### Dependency Scanning
- `safety_check` - Python dependencies
- `npm_audit` - Node.js dependencies
- `owasp_dependency_check` - Multi-language dependencies
- `snyk_test` - Snyk vulnerability scanning

### Infrastructure as Code
- `checkov_scan` - IaC security
- `tfsec_scan` - Terraform security
- `trivy_scan` - Container/IaC/filesystem scanning

### Web Application Testing
- `nikto_scan` - Web server vulnerabilities
- `sqlmap_scan` - SQL injection testing
- `wpscan_scan` - WordPress security
- `dirb_scan` - Web content discovery

### Network Scanning
- `nmap_scan` - Port and service scanning

### System Security
- `lynis_scan` - System auditing
- `clamav_scan` - Malware detection
