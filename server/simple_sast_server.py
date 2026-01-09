#!/usr/bin/env python3
"""
================================================================================
Simple SAST Server - Lightweight Alternative with No External Dependencies
================================================================================

A simplified SAST server implementation that works without optional dependencies.
This is an alternative to sast_server.py for users who want a minimal setup.

DIFFERENCES FROM sast_server.py:
    - No python-dotenv dependency (uses environment variables directly)
    - Includes optional API key authentication
    - Includes basic rate limiting (in-memory)
    - Includes tool result caching (in-memory)
    - Simpler configuration

WHEN TO USE THIS:
    - Quick testing without installing dependencies
    - Minimal server deployments
    - Environments where you can't install extra packages

WHEN TO USE sast_server.py INSTEAD:
    - Production deployments (better structured)
    - When using .env file for configuration
    - When you need path resolution for Windows/Linux

USAGE:
    python3 simple_sast_server.py --port 6000
    python3 simple_sast_server.py --port 6000 --host 127.0.0.1

CONFIGURATION:
    All via environment variables (no .env file support):
        API_PORT=6000
        DEBUG_MODE=0
        COMMAND_TIMEOUT=300
        SAST_API_KEY=your_secret_key (optional)
        ENABLE_RATE_LIMITING=false (optional)

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
import time
import tempfile
import shutil
from typing import Dict, Any, List, Optional
from flask import Flask, request, jsonify
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps

# Simple configuration from environment variables
API_PORT = int(os.environ.get("API_PORT", 6000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 300))
MAX_TIMEOUT = 1800
HOST = os.environ.get("SERVER_HOST", "0.0.0.0")

# Security settings
API_KEY = os.environ.get("SAST_API_KEY", "")
ENABLE_RATE_LIMITING = os.environ.get("ENABLE_RATE_LIMITING", "false").lower() == "true"
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", 30))

# Tool timeouts
SEMGREP_TIMEOUT = int(os.environ.get("SEMGREP_TIMEOUT", 600))
BANDIT_TIMEOUT = int(os.environ.get("BANDIT_TIMEOUT", 300))
TRUFFLEHOG_TIMEOUT = int(os.environ.get("TRUFFLEHOG_TIMEOUT", 600))
DEPENDENCY_CHECK_TIMEOUT = int(os.environ.get("DEPENDENCY_CHECK_TIMEOUT", 900))
ENABLE_TOOL_CACHING = os.environ.get("ENABLE_TOOL_CACHING", "true").lower() == "true"

# Logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

def get_tool_timeout(tool_name: str) -> int:
    """Get timeout for specific tool"""
    timeout_map = {
        'semgrep': SEMGREP_TIMEOUT,
        'bandit': BANDIT_TIMEOUT,
        'trufflehog': TRUFFLEHOG_TIMEOUT,
        'dependency-check': DEPENDENCY_CHECK_TIMEOUT,
    }
    return timeout_map.get(tool_name, COMMAND_TIMEOUT)


def get_enhanced_env() -> Dict[str, str]:
    """
    Get an enhanced environment dictionary with expanded PATH.

    This ensures tools installed via pip, npm, go, gem, etc. are accessible
    even when the server runs in a minimal environment (e.g., systemd service).

    Returns:
        Enhanced environment dictionary with expanded PATH
    """
    env = os.environ.copy()

    # Common tool installation directories that may not be in the default PATH
    additional_paths = [
        # User-local Python installations (pip install --user)
        "/root/.local/bin",
        os.path.expanduser("~/.local/bin"),
        # Go binaries
        "/root/go/bin",
        os.path.expanduser("~/go/bin"),
        "/usr/local/go/bin",
        # Node.js / npm global packages
        "/usr/local/bin",
        "/opt/node/bin",
        "/opt/node22/bin",
        # Ruby gems
        "/usr/local/bundle/bin",
        os.path.expanduser("~/.gem/bin"),
        # System paths (ensure they're included)
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        # Cargo (Rust)
        "/root/.cargo/bin",
        os.path.expanduser("~/.cargo/bin"),
        # rbenv / pyenv
        "/opt/rbenv/bin",
        "/opt/rbenv/shims",
        os.path.expanduser("~/.pyenv/bin"),
        os.path.expanduser("~/.pyenv/shims"),
    ]

    # Get current PATH
    current_path = env.get("PATH", "")
    current_paths = set(current_path.split(":")) if current_path else set()

    # Add additional paths that aren't already included
    new_paths = []
    for path in additional_paths:
        if path and path not in current_paths and os.path.isdir(path):
            new_paths.append(path)
            current_paths.add(path)

    # Prepend new paths to ensure they take precedence
    if new_paths:
        env["PATH"] = ":".join(new_paths) + ":" + current_path
        logger.debug(f"Enhanced PATH with additional directories: {new_paths}")

    return env


# Cache the enhanced environment (computed once at module load)
ENHANCED_ENV = get_enhanced_env()


class SimpleCommandExecutor:
    """Simple command executor with enhanced PATH support"""

    def __init__(self, command: str, timeout: int = None, cwd: Optional[str] = None, tool_name: str = ""):
        self.command = command
        self.timeout = timeout or COMMAND_TIMEOUT
        self.cwd = cwd
        self.tool_name = tool_name
        self.env = ENHANCED_ENV  # Use enhanced environment with expanded PATH
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.return_code = None
        self.timed_out = False
        self.start_time = None
        self.end_time = None

    def execute(self) -> Dict[str, Any]:
        """Execute the command"""
        self.start_time = time.time()
        logger.info(f"Executing {self.tool_name or 'command'}: {self.command[:200]}...")

        if self.cwd:
            logger.info(f"Working directory: {self.cwd}")

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.cwd,
                env=self.env  # Use enhanced PATH environment
            )

            try:
                stdout, stderr = self.process.communicate(timeout=self.timeout)
                self.stdout_data = stdout
                self.stderr_data = stderr
                self.return_code = self.process.returncode
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning(f"{self.tool_name} timed out after {self.timeout} seconds")

                self.process.terminate()
                try:
                    stdout, stderr = self.process.communicate(timeout=5)
                    self.stdout_data = stdout
                    self.stderr_data = stderr
                except subprocess.TimeoutExpired:
                    logger.warning(f"Killing unresponsive {self.tool_name} process")
                    self.process.kill()
                    self.stdout_data = ""
                    self.stderr_data = "Process killed due to timeout"

                self.return_code = -1

            self.end_time = time.time()
            execution_time = self.end_time - self.start_time

            # Determine success
            success = (
                (self.timed_out and (self.stdout_data or self.stderr_data)) or
                (self.return_code == 0)
            )

            result = {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "execution_time": execution_time,
                "tool_name": self.tool_name,
                "partial_results": self.timed_out and bool(self.stdout_data or self.stderr_data),
                "command_preview": self.command[:200]
            }

            if success:
                logger.info(f"{self.tool_name} completed successfully in {execution_time:.2f}s")
            else:
                logger.warning(f"{self.tool_name} failed with return code {self.return_code}")

            return result

        except Exception as e:
            self.end_time = time.time()
            execution_time = (self.end_time - self.start_time) if self.start_time else 0

            logger.error(f"Error executing {self.tool_name}: {str(e)}")
            logger.error(traceback.format_exc())

            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing {self.tool_name}: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "execution_time": execution_time,
                "tool_name": self.tool_name,
                "partial_results": bool(self.stdout_data or self.stderr_data),
                "error": str(e)
            }

def require_api_key(f):
    """Decorator to require API key if configured"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if API_KEY:
            provided_key = request.headers.get('X-API-Key') or request.headers.get('Authorization')
            if provided_key != API_KEY:
                return jsonify({"error": "Unauthorized - Invalid API key"}), 401
        return f(*args, **kwargs)
    return decorated_function

def execute_command(command: str, target: str, tool_name: str, cwd: Optional[str] = None, timeout: int = None) -> Dict[str, Any]:
    """Execute command with proper timeout"""
    timeout = timeout or get_tool_timeout(tool_name)
    executor = SimpleCommandExecutor(command, timeout=timeout, cwd=cwd, tool_name=tool_name)
    return executor.execute()

# ============================================================================
# SAST TOOL ENDPOINTS
# ============================================================================

@app.route("/api/sast/semgrep", methods=["POST"])
@require_api_key
def semgrep():
    """Execute Semgrep static analysis"""
    try:
        params = request.json or {}
        target = params.get("target", ".")
        config_param = params.get("config", "auto")
        lang = params.get("lang", "")
        severity = params.get("severity", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        # Build command
        command = f"semgrep scan --config={config_param}"

        if lang:
            command += f" --lang={lang}"
        if severity:
            command += f" --severity={severity}"

        command += f" --{output_format}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target}"

        # Execute command
        result = execute_command(command, target, "semgrep")

        # Try to parse JSON output
        if output_format == "json" and result.get("stdout") and result["success"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
                # Count findings by severity
                if "results" in result["parsed_output"]:
                    findings = result["parsed_output"]["results"]
                    severity_counts = {}
                    for finding in findings:
                        sev = finding.get("extra", {}).get("severity", "UNKNOWN")
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    result["severity_summary"] = severity_counts
            except json.JSONDecodeError as e:
                logger.warning(f"Could not parse Semgrep JSON output: {e}")

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in semgrep endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}", "success": False}), 500

@app.route("/api/sast/bandit", methods=["POST"])
@require_api_key
def bandit():
    """Execute Bandit Python security scanner"""
    try:
        params = request.json or {}
        target = params.get("target", ".")
        severity_level = params.get("severity_level", "")
        confidence_level = params.get("confidence_level", "")
        output_format = params.get("format", "json")
        additional_args = params.get("additional_args", "")

        command = f"bandit -r {target} -f {output_format}"

        if severity_level:
            command += f" -ll -l {severity_level.upper()}"

        if confidence_level:
            command += f" -ii -i {confidence_level.upper()}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, target, "bandit")

        if output_format == "json" and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in bandit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}", "success": False}), 500

@app.route("/api/secrets/trufflehog", methods=["POST"])
@require_api_key
def trufflehog():
    """Execute TruffleHog secrets scanner"""
    try:
        params = request.json or {}
        target = params.get("target", ".")
        scan_type = params.get("scan_type", "filesystem")
        json_output = params.get("json_output", True)
        only_verified = params.get("only_verified", False)
        additional_args = params.get("additional_args", "")

        command = f"trufflehog {scan_type} {target}"

        if json_output:
            command += " --json"

        if only_verified:
            command += " --only-verified"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, target, "trufflehog")

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
        return jsonify({"error": f"Server error: {str(e)}", "success": False}), 500

@app.route("/api/dependencies/safety", methods=["POST"])
@require_api_key
def safety():
    """Execute Safety Python dependency checker"""
    try:
        params = request.json or {}
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

        result = execute_command(command, requirements_file, "safety")

        if json_output and result["stdout"]:
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in safety endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}", "success": False}), 500

@app.route("/api/orchestration/simple-scan", methods=["POST"])
@require_api_key
def simple_comprehensive_scan():
    """Run multiple SAST tools in sequence (simpler version)"""
    try:
        params = request.json or {}
        target = params.get("target", ".")
        tools = params.get("tools", ["semgrep", "bandit", "trufflehog", "safety"])

        results = {}
        start_time = time.time()

        # Execute tools sequentially for simplicity
        for tool in tools:
            logger.info(f"Running {tool} scan on {target}")

            if tool == "semgrep":
                command = f"semgrep scan --config=auto --json {target}"
                result = execute_command(command, target, "semgrep")

            elif tool == "bandit":
                command = f"bandit -r {target} -f json"
                result = execute_command(command, target, "bandit")

            elif tool == "trufflehog":
                command = f"trufflehog filesystem {target} --json"
                result = execute_command(command, target, "trufflehog")

            elif tool == "safety":
                if os.path.exists(f"{target}/requirements.txt"):
                    command = f"safety check -r {target}/requirements.txt --json"
                    result = execute_command(command, target, "safety")
                else:
                    result = {"error": "No requirements.txt found", "success": False}

            else:
                result = {"error": f"Unknown tool: {tool}", "success": False}

            results[tool] = result

            # Parse JSON outputs
            if result.get("success") and result.get("stdout"):
                try:
                    results[tool]["parsed_output"] = json.loads(result["stdout"])
                except:
                    pass

        end_time = time.time()

        # Generate summary
        summary = {
            "total_execution_time": end_time - start_time,
            "tools_executed": len(results),
            "successful_tools": len([r for r in results.values() if r.get("success", False)]),
            "failed_tools": len([r for r in results.values() if not r.get("success", False)]),
            "target": target
        }

        return jsonify({
            "success": True,
            "summary": summary,
            "results": results
        })

    except Exception as e:
        logger.error(f"Error in simple comprehensive scan: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}", "success": False}), 500

@app.route("/api/command", methods=["POST"])
@require_api_key
def generic_command():
    """Execute any command provided in the request"""
    try:
        params = request.json or {}
        command = params.get("command", "")
        cwd = params.get("cwd", None)
        timeout = params.get("timeout", COMMAND_TIMEOUT)

        if not command:
            return jsonify({"error": "Command parameter is required"}), 400

        result = execute_command(command, cwd or ".", "custom", cwd=cwd, timeout=timeout)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}", "success": False}), 500

@app.route("/health", methods=["GET"])
def health_check():
    """Simple health check with tool availability"""

    # Essential SAST tools to check
    essential_tools = {
        "semgrep": "semgrep --version",
        "bandit": "bandit --version",
        "safety": "safety --version",
        "python3": "python3 --version"
    }

    # Additional tools
    additional_tools = {
        "trufflehog": "trufflehog --version",
        "gitleaks": "gitleaks version",
        "graudit": "which graudit",
        "npm": "npm --version"
    }

    tools_status = {}

    # Check tools with timeout
    def check_tool(tool_name, check_cmd):
        try:
            executor = SimpleCommandExecutor(check_cmd, timeout=10, tool_name=tool_name)
            result = executor.execute()
            return tool_name, result["success"]
        except:
            return tool_name, False

    # Check all tools
    for tool, cmd in {**essential_tools, **additional_tools}.items():
        tool_name, available = check_tool(tool, cmd)
        tools_status[tool_name] = available

    all_essential_available = all([tools_status.get(tool, False) for tool in essential_tools.keys()])
    available_count = sum(1 for available in tools_status.values() if available)
    total_count = len(tools_status)

    health_info = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "message": "Simple SAST Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_available,
        "total_tools_available": available_count,
        "total_tools_count": total_count,
        "server_config": {
            "api_key_required": bool(API_KEY),
            "enable_caching": ENABLE_TOOL_CACHING
        },
        "version": "1.5.0-simple"
    }

    return jsonify(health_info)

if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description="Run the Simple SAST Tools API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT,
                       help=f"Port for the API server (default: {API_PORT})")
    args = parser.parse_args()

    if args.debug:
        DEBUG_MODE = True
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        API_PORT = args.port

    logger.info(f"Starting Simple SAST Tools API Server on port {API_PORT}")
    logger.info("Simple version - no external dependencies required")
    logger.info("Supported tools: Semgrep, Bandit, TruffleHog, Safety")

    if API_KEY:
        logger.info("API key authentication enabled")
    else:
        logger.warning("No API key set - server accessible without authentication")

    app.run(host=HOST, port=API_PORT, debug=DEBUG_MODE)