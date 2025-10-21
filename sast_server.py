#!/usr/bin/env python3
"""
================================================================================
MCP-SAST-Server - Security Analysis Server for Claude Code
================================================================================

A comprehensive SAST (Static Application Security Testing) server that provides
security code analysis tools through HTTP API endpoints. Designed to work with
the MCP (Model Context Protocol) client for Claude Code integration.

FEATURES:
    - 15+ security scanning tools integration
    - Cross-platform path resolution (Windows ↔ Linux)
    - Timeout handling for long-running scans
    - JSON output for easy parsing
    - Health check endpoint for monitoring

SUPPORTED TOOLS:
    Code Analysis:
        - Semgrep: Multi-language static analysis (30+ languages)
        - Bandit: Python security scanner
        - ESLint Security: JavaScript/TypeScript security
        - Gosec: Go security checker
        - Brakeman: Ruby on Rails security scanner
        - Graudit: Grep-based code auditing
        - Bearer: Security and privacy risk scanner

    Secret Detection:
        - TruffleHog: Secrets scanner for repos and filesystems
        - Gitleaks: Git secrets detector

    Dependency Scanning:
        - Safety: Python dependency checker
        - npm audit: Node.js dependency checker
        - OWASP Dependency-Check: Multi-language scanner

    Infrastructure as Code:
        - Checkov: Terraform, CloudFormation, Kubernetes scanner
        - tfsec: Terraform security scanner
        - Trivy: Container and IaC vulnerability scanner

CONFIGURATION:
    Set via environment variables or .env file:
        - API_PORT: Server port (default: 6000)
        - DEBUG_MODE: Enable debug logging (default: 0)
        - COMMAND_TIMEOUT: Scan timeout in seconds (default: 3600)
        - MOUNT_POINT: Linux mount path (default: /mnt/work)
        - WINDOWS_BASE: Windows base path (default: F:/work)

USAGE:
    python3 sast_server.py --port 6000
    python3 sast_server.py --port 6000 --debug

AUTHOR: MCP-SAST-Server Contributors
LICENSE: MIT
================================================================================
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
import re
from typing import Dict, Any, List, Optional
from flask import Flask, request, jsonify
from datetime import datetime
import tempfile
import shutil

# ============================================================================
# ENVIRONMENT & CONFIGURATION
# ============================================================================

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed, will use system environment variables
    pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Server Configuration
API_PORT = int(os.environ.get("API_PORT", 6000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 3600))  # 1 hour default
MAX_TIMEOUT = 7200  # 2 hours maximum

# Path Resolution Configuration
# These settings enable cross-platform operation (Windows client -> Linux server)
MOUNT_POINT = os.environ.get("MOUNT_POINT", "/mnt/work")  # Linux mount point
WINDOWS_BASE = os.environ.get("WINDOWS_BASE", "F:/work")  # Windows base path

# Initialize Flask application
app = Flask(__name__)

# ============================================================================
# PATH RESOLUTION
# ============================================================================

def resolve_windows_path(windows_path: str) -> str:
    """
    Convert Windows path to Linux mount path

    Mount mapping: F:/work <-> /mnt/work

    Examples:
        F:/work/Resola/Deca/deca-chatbox-api -> /mnt/work/Resola/Deca/deca-chatbox-api
        F:\\work\\Resola\\Deca\\deca-chatbox-api -> /mnt/work/Resola/Deca/deca-chatbox-api
    """
    # Normalize path separators
    normalized_path = windows_path.replace('\\', '/')

    logger.info(f"Resolving path: {windows_path} -> normalized: {normalized_path}")

    # Try different Windows path patterns
    # F:/work -> /mnt/work
    patterns = [
        (r'^F:/work/', '/mnt/work/'),       # F:/work/... -> /mnt/work/...
        (r'^F:/work$', '/mnt/work'),        # F:/work -> /mnt/work
        (r'^/f/work/', '/mnt/work/'),       # Git bash: /f/work/... -> /mnt/work/...
        (r'^/f/work$', '/mnt/work'),        # Git bash: /f/work -> /mnt/work
        (r'^f:/work/', '/mnt/work/'),       # Lowercase: f:/work/... -> /mnt/work/...
        (r'^f:/work$', '/mnt/work'),        # Lowercase: f:/work -> /mnt/work
    ]

    for pattern, replacement in patterns:
        if re.match(pattern, normalized_path, re.IGNORECASE):
            # Replace the Windows base with Linux mount point
            linux_path = re.sub(pattern, replacement, normalized_path, flags=re.IGNORECASE)

            logger.info(f"✓ Pattern matched: {pattern}")
            logger.info(f"✓ Path resolved: {windows_path} -> {linux_path}")

            # Verify path exists
            if os.path.exists(linux_path):
                logger.info(f"✓ Path exists: {linux_path}")
                return linux_path
            else:
                logger.warning(f"⚠ Resolved path does not exist: {linux_path}")
                # Return it anyway, let the tool fail with proper error
                return linux_path

    # If path is already a valid Linux path starting with /mnt/work, return as-is
    if normalized_path.startswith('/mnt/work'):
        logger.info(f"✓ Path already valid Linux path: {normalized_path}")
        return normalized_path

    # If path starts with / and exists, it's already a Linux path
    if normalized_path.startswith('/') and os.path.exists(normalized_path):
        logger.info(f"✓ Path is valid Linux path: {normalized_path}")
        return normalized_path

    # If no pattern matched, return original
    logger.warning(f"⚠ Could not resolve path: {windows_path}")
    logger.warning(f"⚠ Returning original path as-is")
    return windows_path


def verify_mount() -> Dict[str, Any]:
    """
    Verify that the Windows share is mounted and accessible

    Returns dict with status information
    """
    issues = []

    # Check if mount point exists
    if not os.path.exists(MOUNT_POINT):
        issues.append(f"Mount point does not exist: {MOUNT_POINT}")

    # Check if mount point is actually mounted
    elif not os.path.ismount(MOUNT_POINT):
        # Try to check if it's a directory with files (might not show as mount on all systems)
        try:
            files = os.listdir(MOUNT_POINT)
            if not files:
                issues.append(f"Mount point exists but appears empty: {MOUNT_POINT}")
        except PermissionError:
            issues.append(f"No read permission on mount point: {MOUNT_POINT}")
        except Exception as e:
            issues.append(f"Error accessing mount point: {str(e)}")

    # Try to test read access
    else:
        try:
            os.listdir(MOUNT_POINT)
        except PermissionError:
            issues.append(f"No read permission on mount point: {MOUNT_POINT}")
        except Exception as e:
            issues.append(f"Error reading mount point: {str(e)}")

    is_healthy = len(issues) == 0

    return {
        "is_mounted": is_healthy,
        "mount_point": MOUNT_POINT,
        "windows_base": WINDOWS_BASE,
        "issues": issues
    }

class CommandExecutor:
    """
    Enhanced command executor with proper timeout and output handling.

    This class handles running shell commands with:
        - Configurable timeouts (prevents hanging on long scans)
        - Real-time output capture (stdout and stderr)
        - Graceful termination (SIGTERM then SIGKILL if needed)
        - Partial result support (returns output even if timed out)

    Attributes:
        command: Shell command to execute
        timeout: Maximum execution time in seconds
        cwd: Working directory for command execution
        stdout_data: Captured standard output
        stderr_data: Captured standard error
        return_code: Command exit code
        timed_out: Whether the command exceeded timeout
    """

    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT, cwd: Optional[str] = None):
        """
        Initialize the command executor.

        Args:
            command: Shell command to execute
            timeout: Maximum execution time (capped at MAX_TIMEOUT)
            cwd: Working directory for execution (optional)
        """
        self.command = command
        self.timeout = min(timeout, MAX_TIMEOUT)  # Enforce maximum timeout
        self.cwd = cwd
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False

    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        try:
            for line in iter(self.process.stdout.readline, ''):
                self.stdout_data += line
        except Exception as e:
            logger.error(f"Error reading stdout: {e}")

    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        try:
            for line in iter(self.process.stderr.readline, ''):
                self.stderr_data += line
        except Exception as e:
            logger.error(f"Error reading stderr: {e}")

    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command[:200]}...")
        if self.cwd:
            logger.info(f"Working directory: {self.cwd}")

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=self.cwd
            )

            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.stdout_thread.join(timeout=5)
                self.stderr_thread.join(timeout=5)
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds")

                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning("Killing unresponsive process")
                    self.process.kill()

                self.return_code = -1

            # Consider success if we have output even with timeout
            success = (
                (self.timed_out and (self.stdout_data or self.stderr_data)) or
                (self.return_code == 0)
            )

            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and bool(self.stdout_data or self.stderr_data),
                "command": self.command[:200]  # First 200 chars for logging
            }

        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
                "error": str(e)
            }


def execute_command(command: str, cwd: Optional[str] = None, timeout: int = COMMAND_TIMEOUT) -> Dict[str, Any]:
    """Execute a shell command and return the result"""
    executor = CommandExecutor(command, timeout=timeout, cwd=cwd)
    return executor.execute()


# ============================================================================
# SAST TOOL ENDPOINTS
# ============================================================================

@app.route("/api/sast/semgrep", methods=["POST"])
def semgrep():
    """
    Execute Semgrep static analysis

    Parameters:
    - target: Path to code directory or file
    - config: Semgrep config (auto, p/security-audit, p/owasp-top-ten, etc.)
    - lang: Language filter (python, javascript, go, java, etc.)
    - severity: Filter by severity (ERROR, WARNING, INFO)
    - output_format: json, sarif, text, gitlab-sast
    - additional_args: Additional Semgrep arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        config = params.get("config", "auto")
        lang = params.get("lang", "")
        severity = params.get("severity", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        command = f"semgrep --config={config}"

        if lang:
            command += f" --lang={lang}"

        if severity:
            command += f" --severity={severity}"

        command += f" --{output_format}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {resolved_target}"

        result = execute_command(command, timeout=3600)

        # Add path resolution info to result
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        # Try to parse JSON output
        if output_format == "json" and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in semgrep endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/sast/bearer", methods=["POST"])
def bearer():
    """
    Execute Bearer security scanner

    Parameters:
    - target: Path to code directory
    - scanner: Type of scan (sast, secrets)
    - format: Output format (json, yaml, sarif, html)
    - only_policy: Only check specific policy
    - severity: Filter by severity (critical, high, medium, low, warning)
    - additional_args: Additional Bearer arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        scanner = params.get("scanner", "")
        output_format = params.get("format", "json")
        only_policy = params.get("only_policy", "")
        severity = params.get("severity", "")
        additional_args = params.get("additional_args", "")

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        command = f"bearer scan {resolved_target}"

        if scanner:
            command += f" --scanner={scanner}"
    
        # Suppress verbose output - results will be in the output file
        command += " --quiet"

        if output_format:
            command += f" --format={output_format}"

        if only_policy:
            command += f" --only-policy={only_policy}"

        if severity:
            command += f" --severity={severity}"

        if additional_args:
            command += f" {additional_args}"

        # Redirect all output to suppress verbose logging
        command += " 2>&1"

        result = execute_command(command, timeout=3600)

        # Add path resolution info to result
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        if output_format == "json" and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in bearer endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/sast/graudit", methods=["POST"])
def graudit():
    """
    Execute Graudit source code auditing

    Parameters:
    - target: Path to code directory or file
    - database: Signature database to use (default, all, or specific like asp, c, perl, php, python, etc.)
    - additional_args: Additional graudit arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        database = params.get("database", "all")
        additional_args = params.get("additional_args", "")

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        command = f"graudit -d {database}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {resolved_target}"

        result = execute_command(command, timeout=300)

        # Add path resolution info to result
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in graudit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/sast/bandit", methods=["POST"])
def bandit():
    """
    Execute Bandit Python security scanner

    Parameters:
    - target: Path to Python code directory or file
    - severity_level: Report only issues of a given severity (low, medium, high)
    - confidence_level: Report only issues of given confidence (low, medium, high)
    - format: Output format (json, csv, txt, html, xml)
    - additional_args: Additional Bandit arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        severity_level = params.get("severity_level", "")
        confidence_level = params.get("confidence_level", "")
        output_format = params.get("format", "json")
        additional_args = params.get("additional_args", "")

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        command = f"bandit -r {resolved_target} -f {output_format}"

        if severity_level:
            command += f" -ll -l {severity_level.upper()}"

        if confidence_level:
            command += f" -ii -i {confidence_level.upper()}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=300)

        # Add path resolution info to result
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        if output_format == "json" and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in bandit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/sast/gosec", methods=["POST"])
def gosec():
    """
    Execute Gosec Go security checker

    Parameters:
    - target: Path to Go code directory
    - format: Output format (json, yaml, csv, junit-xml, html, sonarqube, golint, sarif, text)
    - severity: Filter by severity (low, medium, high)
    - confidence: Filter by confidence (low, medium, high)
    - additional_args: Additional gosec arguments
    """
    try:
        params = request.json
        target = params.get("target", "./...")
        output_format = params.get("format", "json")
        severity = params.get("severity", "")
        confidence = params.get("confidence", "")
        additional_args = params.get("additional_args", "")

        command = f"gosec -fmt={output_format}"

        if severity:
            command += f" -severity={severity}"

        if confidence:
            command += f" -confidence={confidence}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target}"

        result = execute_command(command, timeout=300)

        if output_format == "json" and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gosec endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/sast/brakeman", methods=["POST"])
def brakeman():
    """
    Execute Brakeman Rails security scanner

    Parameters:
    - target: Path to Rails application directory
    - format: Output format (json, html, csv, tabs, text)
    - confidence_level: Minimum confidence level (1-3, 1 is highest)
    - additional_args: Additional Brakeman arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        output_format = params.get("format", "json")
        confidence_level = params.get("confidence_level", "")
        additional_args = params.get("additional_args", "")

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        command = f"brakeman -p {resolved_target} -f {output_format}"

        if confidence_level:
            command += f" -w {confidence_level}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=300)

        # Add path resolution info to result
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        if output_format == "json" and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in brakeman endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/sast/nodejsscan", methods=["POST"])
def nodejsscan():
    """
    Execute NodeJSScan Node.js security scanner

    Parameters:
    - target: Path to Node.js code directory
    - output_file: Output file path (optional)
    """
    try:
        params = request.json
        target = params.get("target", ".")
        output_file = params.get("output_file", "")

        command = f"nodejsscan -d {target}"

        if output_file:
            command += f" -o {output_file}"

        result = execute_command(command, timeout=3600)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nodejsscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/sast/eslint-security", methods=["POST"])
def eslint_security():
    """
    Execute ESLint with security plugins

    Parameters:
    - target: Path to JavaScript/TypeScript code
    - config: ESLint config file path
    - format: Output format (stylish, json, html, etc.)
    - fix: Automatically fix problems (boolean)
    - additional_args: Additional ESLint arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        config = params.get("config", "")
        output_format = params.get("format", "json")
        fix = params.get("fix", False)
        additional_args = params.get("additional_args", "")

        command = f"eslint {target} -f {output_format}"

        if config:
            command += f" -c {config}"

        if fix:
            command += " --fix"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=3600)

        if output_format == "json" and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in eslint-security endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# SECRET SCANNING ENDPOINTS
# ============================================================================

@app.route("/api/secrets/trufflehog", methods=["POST"])
def trufflehog():
    """
    Execute TruffleHog secrets scanner

    Parameters:
    - target: Git repository URL or filesystem path
    - scan_type: Type of scan (git, filesystem, github, gitlab, s3, etc.)
    - json_output: Return JSON format (boolean)
    - only_verified: Only show verified secrets (boolean)
    - additional_args: Additional TruffleHog arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        scan_type = params.get("scan_type", "filesystem")
        json_output = params.get("json_output", True)
        only_verified = params.get("only_verified", False)
        additional_args = params.get("additional_args", "")

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        command = f"trufflehog {scan_type} {resolved_target}"

        if json_output:
            command += " --json"

        if only_verified:
            command += " --only-verified"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=600)

        # Add path resolution info to result
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        # Parse JSON lines output
        if json_output and result["stdout"]:
            try:
                secrets = []
                for line in result["stdout"].strip().split('\n'):
                    if line.strip():
                        secrets.append(json.loads(line))
                result["parsed_secrets"] = secrets
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in trufflehog endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/secrets/gitleaks", methods=["POST"])
def gitleaks():
    """
    Execute Gitleaks secret scanner

    Parameters:
    - target: Path to git repository or directory
    - config: Path to gitleaks config file
    - report_format: Output format (json, csv, sarif)
    - report_path: Path to save report
    - verbose: Enable verbose output (boolean)
    - additional_args: Additional gitleaks arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        config = params.get("config", "")
        report_format = params.get("report_format", "json")
        report_path = params.get("report_path", "")
        verbose = params.get("verbose", False)
        additional_args = params.get("additional_args", "")

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        command = f"gitleaks detect --source={resolved_target} --report-format={report_format}"

        if config:
            command += f" --config={config}"

        if report_path:
            command += f" --report-path={report_path}"

        if verbose:
            command += " -v"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=300)

        # Add path resolution info to result
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        # Read report file if specified
        if report_path and os.path.exists(report_path):
            try:
                with open(report_path, 'r') as f:
                    if report_format == "json":
                        result["parsed_report"] = json.load(f)
                    else:
                        result["report_content"] = f.read()
            except Exception as e:
                logger.warning(f"Error reading report file: {e}")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gitleaks endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# DEPENDENCY SCANNING ENDPOINTS
# ============================================================================

@app.route("/api/dependencies/safety", methods=["POST"])
def safety():
    """
    Execute Safety Python dependency checker

    Parameters:
    - requirements_file: Path to requirements.txt
    - json_output: Return JSON format (boolean)
    - full_report: Include full report (boolean)
    - additional_args: Additional Safety arguments
    """
    try:
        params = request.json
        requirements_file = params.get("requirements_file", "requirements.txt")
        json_output = params.get("json_output", True)
        full_report = params.get("full_report", False)
        additional_args = params.get("additional_args", "")

        command = f"safety check -r {requirements_file}"

        if json_output:
            command += " --json"

        if full_report:
            command += " --full-report"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=1800)

        if json_output and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in safety endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/dependencies/npm-audit", methods=["POST"])
def npm_audit():
    """
    Execute npm audit for Node.js dependencies

    Parameters:
    - target: Path to Node.js project directory
    - json_output: Return JSON format (boolean)
    - audit_level: Minimum level to report (info, low, moderate, high, critical)
    - production: Only audit production dependencies (boolean)
    - additional_args: Additional npm audit arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        json_output = params.get("json_output", True)
        audit_level = params.get("audit_level", "")
        production = params.get("production", False)
        additional_args = params.get("additional_args", "")

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        command = "npm audit"

        if json_output:
            command += " --json"

        if audit_level:
            command += f" --audit-level={audit_level}"

        if production:
            command += " --production"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, cwd=resolved_target, timeout=180)

        # Add path resolution info to result
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        if json_output and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in npm-audit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/dependencies/dependency-check", methods=["POST"])
def dependency_check():
    """
    Execute OWASP Dependency-Check

    Parameters:
    - target: Path to project directory
    - project_name: Name of the project
    - format: Output format (HTML, XML, CSV, JSON, JUNIT, SARIF, ALL)
    - scan: Comma-separated list of paths to scan
    - additional_args: Additional dependency-check arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        project_name = params.get("project_name", "project")
        output_format = params.get("format", "JSON")
        scan = params.get("scan", target)
        additional_args = params.get("additional_args", "")

        # Create temporary output directory
        output_dir = tempfile.mkdtemp()

        command = f"dependency-check --project {project_name} --scan {scan} --format {output_format} --out {output_dir}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=900)  # 15 minutes for large projects

        # Read generated report
        try:
            report_files = os.listdir(output_dir)
            for report_file in report_files:
                report_path = os.path.join(output_dir, report_file)
                with open(report_path, 'r') as f:
                    if report_file.endswith('.json'):
                        result["parsed_report"] = json.load(f)
                    else:
                        result["report_content"] = f.read()
        except Exception as e:
            logger.warning(f"Error reading report: {e}")
        finally:
            # Cleanup
            try:
                shutil.rmtree(output_dir)
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dependency-check endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# INFRASTRUCTURE AS CODE SCANNING
# ============================================================================

@app.route("/api/iac/checkov", methods=["POST"])
def checkov():
    """
    Execute Checkov IaC security scanner

    Parameters:
    - target: Path to IaC directory
    - framework: Framework to scan (terraform, cloudformation, kubernetes, helm, etc.)
    - output_format: Output format (cli, json, junitxml, sarif, github_failed_only)
    - compact: Compact output (boolean)
    - quiet: Quiet mode (boolean)
    - additional_args: Additional Checkov arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        framework = params.get("framework", "")
        output_format = params.get("output_format", "json")
        compact = params.get("compact", False)
        quiet = params.get("quiet", False)
        additional_args = params.get("additional_args", "")

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        command = f"checkov -d {resolved_target} -o {output_format}"

        if framework:
            command += f" --framework {framework}"

        if compact:
            command += " --compact"

        if quiet:
            command += " --quiet"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=3600)

        # Add path resolution info to result
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        if output_format == "json" and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in checkov endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/iac/tfsec", methods=["POST"])
def tfsec():
    """
    Execute tfsec Terraform security scanner

    Parameters:
    - target: Path to Terraform directory
    - format: Output format (default, json, csv, checkstyle, junit, sarif)
    - minimum_severity: Minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL)
    - additional_args: Additional tfsec arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        output_format = params.get("format", "json")
        minimum_severity = params.get("minimum_severity", "")
        additional_args = params.get("additional_args", "")

        command = f"tfsec {target} --format {output_format}"

        if minimum_severity:
            command += f" --minimum-severity {minimum_severity}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=3600)

        if output_format == "json" and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in tfsec endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# CONTAINER SECURITY
# ============================================================================

@app.route("/api/container/trivy", methods=["POST"])
def trivy():
    """
    Execute Trivy container/IaC security scanner

    Parameters:
    - target: Image name, directory, or repository
    - scan_type: Type of scan (image, fs, repo, config)
    - format: Output format (table, json, sarif, template)
    - severity: Severities to include (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)
    - additional_args: Additional Trivy arguments
    """
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "fs")
        output_format = params.get("format", "json")
        severity = params.get("severity", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        command = f"trivy {scan_type} --format {output_format}"

        if severity:
            command += f" --severity {severity}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {resolved_target}"

        result = execute_command(command, timeout=3600)

        # Add path resolution info to result
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        if output_format == "json" and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in trivy endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# UTILITY ENDPOINTS
# ============================================================================

@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request"""
    try:
        params = request.json
        command = params.get("command", "")
        cwd = params.get("cwd", None)
        timeout = params.get("timeout", COMMAND_TIMEOUT)

        if not command:
            return jsonify({"error": "Command parameter is required"}), 400

        result = execute_command(command, cwd=cwd, timeout=timeout)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint with tool availability"""

    # Essential SAST tools to check
    essential_tools = {
        "semgrep": "semgrep --version",
        "bandit": "bandit --version",
        "eslint": "eslint --version",
        "npm": "npm --version",
        "safety": "safety --version",
        "trufflehog": "trufflehog --version",
        "gitleaks": "gitleaks version"
    }

    # Additional tools
    additional_tools = {
        "bearer": "bearer version",
        "graudit": "which graudit",
        "gosec": "gosec -version",
        "brakeman": "brakeman --version",
        "checkov": "checkov --version",
        "tfsec": "tfsec --version",
        "trivy": "trivy --version",
        "dependency-check": "dependency-check.sh --version"
    }

    tools_status = {}

    # Check essential tools
    for tool, check_cmd in essential_tools.items():
        try:
            result = execute_command(check_cmd, timeout=10)
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False

    # Check additional tools
    for tool, check_cmd in additional_tools.items():
        try:
            result = execute_command(check_cmd, timeout=10)
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False

    all_essential_available = all([tools_status.get(tool, False) for tool in essential_tools.keys()])
    available_count = sum(1 for available in tools_status.values() if available)
    total_count = len(tools_status)

    return jsonify({
        "status": "healthy",
        "message": "SAST Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_available,
        "total_tools_available": available_count,
        "total_tools_count": total_count,
        "version": "1.0.0"
    })


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Run the SAST Tools API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        API_PORT = args.port

    logger.info(f"Starting SAST Tools API Server on port {API_PORT}")
    logger.info("Supported tools: Semgrep, Bearer, Graudit, Bandit, Gosec, Brakeman, ESLint, TruffleHog, Gitleaks, Safety, npm audit, Checkov, tfsec, Trivy, OWASP Dependency-Check")

    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)
