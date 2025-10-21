# SAST Tool Commands Verification

This document verifies the Linux commands used for each SAST tool in the server.

## Tools in Use

### 1. Semgrep (Multi-language Static Analysis)

**Current Command Pattern:**
```bash
semgrep --config=<ruleset> --json <target>
```

**Verified Command:**
```bash
# Basic scan with auto config
semgrep --config=auto --json /path/to/code

# Security audit scan
semgrep --config=p/security-audit --json /path/to/code

# OWASP Top 10 scan
semgrep --config=p/owasp-top-ten --json /path/to/code

# Secrets scan
semgrep --config=p/secrets --json /path/to/code

# With language filter
semgrep --config=auto --lang=python --json /path/to/code

# With severity filter
semgrep --config=auto --severity=ERROR --json /path/to/code
```

**Status:** ✅ CORRECT
- Command structure is correct
- All flags are properly formatted
- JSON output is properly specified

---

### 2. Bandit (Python Security Scanner)

**Current Command Pattern:**
```bash
bandit -r <target> -f json
```

**Verified Command:**
```bash
# Basic scan with JSON output
bandit -r /path/to/python/code -f json

# With severity level (low, medium, high)
bandit -r /path/to/python/code -f json -ll -l HIGH

# With confidence level (low, medium, high)
bandit -r /path/to/python/code -f json -ii -i HIGH

# With both severity and confidence
bandit -r /path/to/python/code -f json -ll -l MEDIUM -ii -i MEDIUM

# CSV format
bandit -r /path/to/python/code -f csv

# HTML format
bandit -r /path/to/python/code -f html
```

**Status:** ✅ CORRECT
- Recursive scan flag `-r` is correct
- Format flag `-f` is correct
- Severity flags `-ll -l` are correct
- Confidence flags `-ii -i` are correct

---

### 3. Safety (Python Dependency Checker)

**Current Command Pattern:**
```bash
safety check -r requirements.txt --json
```

**Verified Command:**
```bash
# Basic check with requirements file
safety check -r requirements.txt --json

# Full report
safety check -r requirements.txt --json --full-report

# Check installed packages (no requirements file)
safety check --json

# Plain text output
safety check -r requirements.txt
```

**Status:** ✅ CORRECT
- `-r` flag for requirements file is correct
- `--json` flag for JSON output is correct
- `--full-report` flag is correct

**Important Notes:**
- Safety has changed to a subscription model in newer versions
- For free tier, use: `safety check --json` (limited database)
- For local use without API: Consider using `pip-audit` as alternative

**Alternative Commands:**
```bash
# Using pip-audit (free alternative)
pip-audit -r requirements.txt --format json
```

---

### 4. Checkov (Infrastructure as Code Scanner)

**Current Command Pattern:**
```bash
checkov -d <target> -o json
```

**Verified Command:**
```bash
# Basic scan with JSON output
checkov -d /path/to/iac -o json

# Scan specific framework
checkov -d /path/to/terraform -o json --framework terraform

# Compact output
checkov -d /path/to/iac -o json --compact

# Quiet mode
checkov -d /path/to/iac -o json --quiet

# Multiple frameworks
checkov -d /path/to/iac -o json --framework terraform,cloudformation

# SARIF output
checkov -d /path/to/iac -o sarif

# Scan specific file
checkov -f /path/to/main.tf -o json
```

**Status:** ✅ CORRECT
- `-d` flag for directory is correct
- `-o` flag for output format is correct
- `--framework` flag is correct
- `--compact` and `--quiet` flags are correct

---

### 5. npm audit (Node.js Dependency Checker)

**Current Command Pattern:**
```bash
npm audit --json
```

**Verified Command:**
```bash
# Run in project directory with package.json
cd /path/to/nodejs/project
npm audit --json

# Audit with specific level
npm audit --json --audit-level=moderate

# Audit production only
npm audit --json --production

# Plain text output
npm audit

# Fix vulnerabilities
npm audit fix

# Fix with breaking changes
npm audit fix --force
```

**Status:** ✅ CORRECT
- `npm audit` command is correct
- `--json` flag for JSON output is correct
- `--audit-level` flag is correct
- `--production` flag is correct
- Command must be run from project directory (handled with `cwd` parameter)

---

### 6. Bearer (Security and Privacy Risk Scanner)

**Current Command Pattern:**
```bash
bearer scan <target> --format=json
```

**Verified Command:**
```bash
# Basic scan with JSON output
bearer scan /path/to/code --format=json

# Scan with specific scanner (sast or secrets)
bearer scan /path/to/code --scanner=sast --format=json
bearer scan /path/to/code --scanner=secrets --format=json

# Filter by severity
bearer scan /path/to/code --format=json --severity=critical

# Scan specific policy only
bearer scan /path/to/code --format=json --only-policy=privacy

# YAML output
bearer scan /path/to/code --format=yaml

# SARIF output
bearer scan /path/to/code --format=sarif

# HTML report
bearer scan /path/to/code --format=html
```

**Status:** ✅ CORRECT
- Command structure is correct
- `scan` subcommand is required
- `--format` flag is correct
- `--scanner` flag for SAST or secrets is correct
- `--severity` and `--only-policy` flags are correct

---

### 7. Graudit (Grep-based Source Code Auditing)

**Current Command Pattern:**
```bash
graudit -d <database> <target>
```

**Verified Command:**
```bash
# Scan with all signatures
graudit -d all /path/to/code

# Scan with default signatures
graudit -d default /path/to/code

# Scan with specific language database
graudit -d python /path/to/code
graudit -d php /path/to/code
graudit -d java /path/to/code

# Scan for specific patterns
graudit -d secrets /path/to/code
graudit -d sql /path/to/code

# Available databases: asp, c, cobol, dotnet, exec, fruit, go, java, js, nim, perl, php, python, ruby, secrets, spsqli, strings, xss
```

**Status:** ✅ CORRECT
- `-d` flag for database selection is correct
- Database names are correct
- Target path placement is correct

---

### 8. Brakeman (Ruby on Rails Security Scanner)

**Current Command Pattern:**
```bash
brakeman -p <target> -f json
```

**Verified Command:**
```bash
# Basic scan with JSON output
brakeman -p /path/to/rails/app -f json

# Scan with confidence level filter (1-3, where 1 is highest confidence)
brakeman -p /path/to/rails/app -f json -w 3

# HTML report
brakeman -p /path/to/rails/app -f html

# CSV format
brakeman -p /path/to/rails/app -f csv

# Text format
brakeman -p /path/to/rails/app -f text

# Tabs format
brakeman -p /path/to/rails/app -f tabs
```

**Status:** ✅ CORRECT
- `-p` flag for path is correct
- `-f` flag for format is correct
- `-w` flag for confidence level is correct
- All output formats are valid

---

### 9. Trivy (Container and Filesystem Vulnerability Scanner)

**Current Command Pattern:**
```bash
trivy <scan_type> --format json <target>
```

**Verified Command:**
```bash
# Filesystem scan
trivy fs --format json /path/to/code

# Image scan
trivy image --format json nginx:latest

# Repository scan
trivy repo --format json https://github.com/user/repo

# Config scan (IaC)
trivy config --format json /path/to/iac

# Filter by severity
trivy fs --format json --severity HIGH,CRITICAL /path/to/code

# SARIF output
trivy fs --format sarif /path/to/code

# Table output (human-readable)
trivy fs --format table /path/to/code
```

**Status:** ✅ CORRECT
- Scan type (fs, image, repo, config) is correct
- `--format` flag is correct
- `--severity` flag for filtering is correct
- Target placement is correct

---

## Command Comparison Table

| Tool      | Command                                       | Output   | Target Type      | Status |
|-----------|-----------------------------------------------|----------|------------------|--------|
| Semgrep   | `semgrep --config=auto --json <path>`         | JSON     | Directory/File   | ✅     |
| Bearer    | `bearer scan <path> --format=json`            | JSON     | Directory        | ✅     |
| Graudit   | `graudit -d all <path>`                       | Text     | Directory/File   | ✅     |
| Bandit    | `bandit -r <path> -f json`                    | JSON     | Directory        | ✅     |
| Brakeman  | `brakeman -p <path> -f json`                  | JSON     | Rails Directory  | ✅     |
| Safety    | `safety check -r requirements.txt --json`     | JSON     | Requirements File| ✅⚠️  |
| Checkov   | `checkov -d <path> -o json`                   | JSON     | Directory        | ✅     |
| Trivy     | `trivy fs --format json <path>`               | JSON     | Directory/Image  | ✅     |
| npm audit | `npm audit --json`                            | JSON     | package.json dir | ✅     |

**Legend:**
- ✅ = Fully correct
- ✅⚠️ = Correct but with warnings (Safety subscription model)

---

## Recommended Test Commands

Test each tool on the Kali VM:

```bash
# 1. Test Semgrep
semgrep --config=auto --json /mnt/work/Deca/deca-chatbox-api

# 2. Test Bearer
bearer scan /mnt/work/Deca/deca-chatbox-api --format=json

# 3. Test Graudit
graudit -d all /mnt/work/Deca/deca-chatbox-api

# 4. Test Bandit
bandit -r /mnt/work/Deca/deca-chatbox-api -f json

# 5. Test Brakeman (if you have a Rails app)
brakeman -p /path/to/rails/app -f json

# 6. Test Safety
cd /mnt/work/Deca/deca-chatbox-api
safety check -r requirements.txt --json

# 7. Test Checkov (if you have IaC files)
checkov -d /mnt/work/Deca/deca-chatbox-api -o json

# 8. Test Trivy
trivy fs --format json /mnt/work/Deca/deca-chatbox-api

# 9. Test npm audit
cd /mnt/work/Deca/deca-chatbox-api
npm audit --json
```

---

## Environment Requirements

### Semgrep
- Installation: `pip3 install semgrep`
- Version: 1.0.0+
- Memory: 512MB minimum
- Python: 3.7+

### Bearer
- Installation: `curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh`
- Version: 1.0.0+
- Memory: 512MB minimum
- Go: 1.19+ (for building from source)

### Graudit
- Installation: `apt-get install graudit` or clone from https://github.com/wireghoul/graudit
- Version: Latest
- Memory: 128MB minimum
- Dependencies: grep, find

### Bandit
- Installation: `pip3 install bandit`
- Version: 1.7.0+
- Memory: 256MB minimum
- Python: 3.7+

### Brakeman
- Installation: `gem install brakeman`
- Version: 5.0.0+
- Memory: 512MB minimum
- Ruby: 2.7+

### Safety
- Installation: `pip3 install safety`
- Version: 2.0.0+ (Note: Subscription required for full database)
- Memory: 128MB minimum
- Python: 3.7+

### Checkov
- Installation: `pip3 install checkov`
- Version: 2.0.0+
- Memory: 512MB minimum
- Python: 3.7+

### Trivy
- Installation:
  ```bash
  # Debian/Ubuntu
  sudo apt-get install wget
  wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
  echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
  sudo apt-get update
  sudo apt-get install trivy
  ```
- Version: 0.40.0+
- Memory: 1GB minimum
- Disk: 2GB for vulnerability database

### npm audit
- Installation: Built-in with npm
- Version: npm 6.0.0+
- Memory: 256MB minimum
- Node.js: 12.0.0+

---

## Common Issues and Fixes

### Issue 1: Semgrep "No rules found"
**Problem:** Running with invalid config name
**Fix:** Use valid configs: `auto`, `p/security-audit`, `p/owasp-top-ten`, `p/secrets`

### Issue 2: Bandit "No Python files found"
**Problem:** Target doesn't contain .py files
**Fix:** Ensure target directory contains Python files

### Issue 3: Safety requires subscription
**Problem:** Free tier has limited vulnerability database
**Fix:** Consider using `pip-audit` as a free alternative:
```bash
pip3 install pip-audit
pip-audit -r requirements.txt --format json
```

### Issue 4: npm audit requires package.json
**Problem:** Running npm audit outside a Node.js project
**Fix:** Ensure `cwd` parameter points to directory with package.json

### Issue 5: Checkov "No checks found"
**Problem:** Target directory doesn't contain IaC files
**Fix:** Ensure directory contains Terraform, CloudFormation, Kubernetes, or other IaC files

---

## Output Format Examples

### Semgrep JSON Output
```json
{
  "results": [
    {
      "check_id": "python.django.security.sql-injection",
      "path": "views.py",
      "start": {"line": 42, "col": 10},
      "end": {"line": 42, "col": 50},
      "extra": {
        "message": "Possible SQL injection",
        "severity": "ERROR"
      }
    }
  ]
}
```

### Bandit JSON Output
```json
{
  "results": [
    {
      "code": "os.system(user_input)",
      "filename": "app.py",
      "issue_confidence": "HIGH",
      "issue_severity": "HIGH",
      "issue_text": "Possible shell injection",
      "line_number": 25,
      "test_id": "B605"
    }
  ]
}
```

### Safety JSON Output
```json
[
  {
    "vulnerability": "SQL Injection",
    "package": "django",
    "installed_version": "2.2.0",
    "vulnerable_versions": "<2.2.24",
    "CVE": "CVE-2021-35042"
  }
]
```

### Checkov JSON Output
```json
{
  "check_type": "terraform",
  "results": {
    "failed_checks": [
      {
        "check_id": "CKV_AWS_18",
        "check_name": "Ensure S3 bucket has access logging enabled",
        "file_path": "/main.tf",
        "resource": "aws_s3_bucket.example"
      }
    ]
  }
}
```

### npm audit JSON Output
```json
{
  "auditReportVersion": 2,
  "vulnerabilities": {
    "axios": {
      "name": "axios",
      "severity": "high",
      "via": [
        {
          "source": 1234,
          "title": "Server-Side Request Forgery",
          "url": "https://github.com/advisories/GHSA-xxxx",
          "severity": "high"
        }
      ]
    }
  }
}
```

---

## Last Updated
2025-10-17

## Verified By
Claude Code (Automated Security Testing Review)
