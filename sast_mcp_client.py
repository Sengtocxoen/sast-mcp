#!/usr/bin/env python3
"""
SAST MCP Client - Connects Claude Code AI to SAST Tools Server

This MCP client provides Claude Code with access to comprehensive
Static Application Security Testing (SAST) tools for code security analysis.
"""

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_SAST_SERVER = "http://192.168.204.160:6000"
DEFAULT_REQUEST_TIMEOUT = 600  # 10 minutes default timeout


class SASTToolsClient:
    """Client for communicating with the SAST Tools API Server"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the SAST Tools Client

        Args:
            server_url: URL of the SAST Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized SAST Tools Client connecting to {server_url}")

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data

        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send

        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_get(self, endpoint: str) -> Dict[str, Any]:
        """Perform a GET request"""
        url = f"{self.server_url}/{endpoint}"

        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}

    def check_health(self) -> Dict[str, Any]:
        """Check the health of the SAST Tools API Server"""
        return self.safe_get("health")


def setup_mcp_server(sast_client: SASTToolsClient) -> FastMCP:
    """
    Set up the MCP server with all SAST tool functions

    Args:
        sast_client: Initialized SASTToolsClient

    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("sast-tools")

    # ========================================================================
    # SAST TOOLS
    # ========================================================================

    @mcp.tool()
    def semgrep_scan(
        target: str = ".",
        config: str = "auto",
        lang: str = "",
        severity: str = "",
        output_format: str = "json",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Semgrep static analysis for finding security vulnerabilities and code issues.
        Semgrep supports 30+ languages including Python, JavaScript, Java, Go, Ruby, PHP, etc.

        Args:
            target: Path to code directory or file to scan (default: current directory)
            config: Semgrep ruleset to use:
                   - "auto" (default): Automatically detect and use appropriate rules
                   - "p/security-audit": General security audit
                   - "p/owasp-top-ten": OWASP Top 10 vulnerabilities
                   - "p/cwe-top-25": CWE Top 25 most dangerous software weaknesses
                   - "p/javascript": JavaScript-specific rules
                   - "p/python": Python-specific rules
                   - "p/ci": CI/CD security rules
                   - Or path to custom config file
            lang: Filter by language (python, javascript, typescript, go, java, ruby, php, etc.)
            severity: Filter by severity level (ERROR, WARNING, INFO)
            output_format: Output format (json, sarif, text, gitlab-sast)
            additional_args: Additional Semgrep command-line arguments

        Returns:
            Scan results with identified security issues and code quality problems
        """
        data = {
            "target": target,
            "config": config,
            "lang": lang,
            "severity": severity,
            "output_format": output_format,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/sast/semgrep", data)

    @mcp.tool()
    def bearer_scan(
        target: str = ".",
        scanner: str = "",
        format: str = "json",
        only_policy: str = "",
        severity: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Bearer security and privacy scanner for detecting security risks and data leaks.
        Bearer analyzes code for sensitive data flows and security vulnerabilities.

        Args:
            target: Path to code directory to scan (default: current directory)
            scanner: Type of scan to perform:
                    - "" (empty): All scanners (default)
                    - "sast": Static application security testing
                    - "secrets": Scan for hardcoded secrets
            format: Output format (json, yaml, sarif, html)
            only_policy: Only check specific security policy
            severity: Filter by severity (critical, high, medium, low, warning)
            additional_args: Additional Bearer arguments

        Returns:
            Security findings including data leaks, vulnerabilities, and privacy issues
        """
        data = {
            "target": target,
            "scanner": scanner,
            "format": format,
            "only_policy": only_policy,
            "severity": severity,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/sast/bearer", data)

    @mcp.tool()
    def graudit_scan(
        target: str = ".",
        database: str = "all",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Graudit grep-based source code auditing for finding security issues.
        Fast pattern-matching security scanner using signature databases.

        Args:
            target: Path to code directory or file to audit (default: current directory)
            database: Signature database to use:
                     - "all": All available signatures (default)
                     - "default": Default signatures
                     - Language-specific: "asp", "c", "cobol", "dotnet", "exec", "fruit",
                       "go", "java", "js", "nim", "perl", "php", "python", "ruby", "secrets",
                       "spsqli", "strings", "xss"
            additional_args: Additional graudit arguments

        Returns:
            List of potential security issues found by pattern matching
        """
        data = {
            "target": target,
            "database": database,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/sast/graudit", data)

    @mcp.tool()
    def bandit_scan(
        target: str = ".",
        severity_level: str = "",
        confidence_level: str = "",
        format: str = "json",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Bandit security scanner for Python code.
        Identifies common security issues in Python applications.

        Args:
            target: Path to Python code directory or file (default: current directory)
            severity_level: Minimum severity to report (low, medium, high)
            confidence_level: Minimum confidence to report (low, medium, high)
            format: Output format (json, csv, txt, html, xml)
            additional_args: Additional Bandit arguments

        Returns:
            Python security issues including SQL injection, hardcoded passwords,
            insecure random usage, etc.
        """
        data = {
            "target": target,
            "severity_level": severity_level,
            "confidence_level": confidence_level,
            "format": format,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/sast/bandit", data)

    @mcp.tool()
    def gosec_scan(
        target: str = "./...",
        format: str = "json",
        severity: str = "",
        confidence: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Gosec security scanner for Go (Golang) code.
        Inspects Go source code for security problems.

        Args:
            target: Path to Go code directory (default: ./... for all packages)
            format: Output format (json, yaml, csv, junit-xml, html, sonarqube, golint, sarif, text)
            severity: Filter by severity (low, medium, high)
            confidence: Filter by confidence (low, medium, high)
            additional_args: Additional gosec arguments

        Returns:
            Go-specific security issues and vulnerabilities
        """
        data = {
            "target": target,
            "format": format,
            "severity": severity,
            "confidence": confidence,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/sast/gosec", data)

    @mcp.tool()
    def brakeman_scan(
        target: str = ".",
        format: str = "json",
        confidence_level: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Brakeman security scanner for Ruby on Rails applications.
        Static analysis tool designed specifically for Rails security.

        Args:
            target: Path to Rails application directory (default: current directory)
            format: Output format (json, html, csv, tabs, text)
            confidence_level: Minimum confidence level (1-3, where 1 is highest confidence)
            additional_args: Additional Brakeman arguments

        Returns:
            Rails-specific security vulnerabilities like SQL injection, XSS,
            mass assignment, etc.
        """
        data = {
            "target": target,
            "format": format,
            "confidence_level": confidence_level,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/sast/brakeman", data)

    @mcp.tool()
    def eslint_security_scan(
        target: str = ".",
        config: str = "",
        format: str = "json",
        fix: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute ESLint with security plugins for JavaScript/TypeScript code analysis.
        Detects security issues and code quality problems in JavaScript projects.

        Args:
            target: Path to JavaScript/TypeScript code (default: current directory)
            config: Path to ESLint config file (uses project config if empty)
            format: Output format (json, stylish, html, compact, unix, etc.)
            fix: Automatically fix problems where possible (boolean)
            additional_args: Additional ESLint arguments

        Returns:
            JavaScript/TypeScript security and quality issues
        """
        data = {
            "target": target,
            "config": config,
            "format": format,
            "fix": fix,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/sast/eslint-security", data)

    # ========================================================================
    # SECRET SCANNING
    # ========================================================================

    @mcp.tool()
    def trufflehog_scan(
        target: str = ".",
        scan_type: str = "filesystem",
        json_output: bool = True,
        only_verified: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute TruffleHog for finding leaked secrets, credentials, and API keys.
        Scans git history, filesystems, and cloud storage for exposed secrets.

        Args:
            target: Git repository URL or filesystem path to scan
            scan_type: Type of scan (filesystem, git, github, gitlab, s3, docker, etc.)
            json_output: Return results in JSON format (boolean)
            only_verified: Only show verified secrets that were validated (boolean)
            additional_args: Additional TruffleHog arguments

        Returns:
            Discovered secrets with details about location and verification status
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "json_output": json_output,
            "only_verified": only_verified,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/secrets/trufflehog", data)

    @mcp.tool()
    def gitleaks_scan(
        target: str = ".",
        config: str = "",
        report_format: str = "json",
        report_path: str = "",
        verbose: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Gitleaks for detecting secrets and sensitive information in git repositories.
        Fast and accurate secret scanner for git repos, files, and directories.

        Args:
            target: Path to git repository or directory to scan
            config: Path to gitleaks config file for custom rules
            report_format: Output format (json, csv, sarif)
            report_path: Path to save the report file
            verbose: Enable verbose output for debugging (boolean)
            additional_args: Additional gitleaks arguments

        Returns:
            Secrets found in code with details about type, location, and commit
        """
        data = {
            "target": target,
            "config": config,
            "report_format": report_format,
            "report_path": report_path,
            "verbose": verbose,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/secrets/gitleaks", data)

    # ========================================================================
    # DEPENDENCY SCANNING
    # ========================================================================

    @mcp.tool()
    def safety_check(
        requirements_file: str = "requirements.txt",
        json_output: bool = True,
        full_report: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Safety to check Python dependencies for known security vulnerabilities.
        Checks Python packages against a database of known security advisories.

        Args:
            requirements_file: Path to requirements.txt file (default: requirements.txt)
            json_output: Return JSON format (boolean)
            full_report: Include full vulnerability details (boolean)
            additional_args: Additional Safety arguments

        Returns:
            List of vulnerable Python packages with CVE details and remediation advice
        """
        data = {
            "requirements_file": requirements_file,
            "json_output": json_output,
            "full_report": full_report,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/dependencies/safety", data)

    @mcp.tool()
    def npm_audit(
        target: str = ".",
        json_output: bool = True,
        audit_level: str = "",
        production: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute npm audit to check Node.js dependencies for security vulnerabilities.
        Analyzes package.json and package-lock.json for known vulnerabilities.

        Args:
            target: Path to Node.js project directory (default: current directory)
            json_output: Return JSON format (boolean)
            audit_level: Minimum severity level (info, low, moderate, high, critical)
            production: Only audit production dependencies, skip devDependencies (boolean)
            additional_args: Additional npm audit arguments

        Returns:
            Vulnerable npm packages with severity, CVE, and fix recommendations
        """
        data = {
            "target": target,
            "json_output": json_output,
            "audit_level": audit_level,
            "production": production,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/dependencies/npm-audit", data)

    @mcp.tool()
    def dependency_check(
        target: str = ".",
        project_name: str = "project",
        format: str = "JSON",
        scan: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute OWASP Dependency-Check for multi-language dependency vulnerability scanning.
        Identifies known vulnerabilities in project dependencies using CVE database.

        Args:
            target: Path to project directory (default: current directory)
            project_name: Name of the project for the report
            format: Output format (HTML, XML, CSV, JSON, JUNIT, SARIF, ALL)
            scan: Comma-separated paths to scan (uses target if empty)
            additional_args: Additional dependency-check arguments

        Returns:
            Comprehensive dependency vulnerability report with CPE, CVE, and CVSS scores
        """
        data = {
            "target": target,
            "project_name": project_name,
            "format": format,
            "scan": scan or target,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/dependencies/dependency-check", data)

    # ========================================================================
    # INFRASTRUCTURE AS CODE (IaC)
    # ========================================================================

    @mcp.tool()
    def checkov_scan(
        target: str = ".",
        framework: str = "",
        output_format: str = "json",
        compact: bool = False,
        quiet: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Checkov for Infrastructure as Code security and compliance scanning.
        Scans Terraform, CloudFormation, Kubernetes, Dockerfile, and more.

        Args:
            target: Path to IaC directory (default: current directory)
            framework: Specific framework to scan (terraform, cloudformation, kubernetes,
                      helm, arm, dockerfile, secrets, github_configuration, etc.)
            output_format: Output format (cli, json, junitxml, sarif, github_failed_only)
            compact: Use compact output format (boolean)
            quiet: Suppress verbose output (boolean)
            additional_args: Additional Checkov arguments

        Returns:
            IaC security misconfigurations and compliance violations
        """
        data = {
            "target": target,
            "framework": framework,
            "output_format": output_format,
            "compact": compact,
            "quiet": quiet,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/iac/checkov", data)

    @mcp.tool()
    def tfsec_scan(
        target: str = ".",
        format: str = "json",
        minimum_severity: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute tfsec for Terraform security scanning.
        Static analysis security scanner designed specifically for Terraform code.

        Args:
            target: Path to Terraform directory (default: current directory)
            format: Output format (default, json, csv, checkstyle, junit, sarif)
            minimum_severity: Minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL)
            additional_args: Additional tfsec arguments

        Returns:
            Terraform-specific security issues and best practice violations
        """
        data = {
            "target": target,
            "format": format,
            "minimum_severity": minimum_severity,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/iac/tfsec", data)

    # ========================================================================
    # CONTAINER SECURITY
    # ========================================================================

    @mcp.tool()
    def trivy_scan(
        target: str,
        scan_type: str = "fs",
        format: str = "json",
        severity: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Trivy for comprehensive vulnerability scanning of containers and code.
        Scans container images, filesystems, git repositories, and IaC for vulnerabilities.

        Args:
            target: Target to scan (image name, directory path, or repository)
            scan_type: Type of scan:
                      - "image": Scan container image
                      - "fs": Scan filesystem (default)
                      - "repo": Scan git repository
                      - "config": Scan IaC configurations
            format: Output format (table, json, sarif, template)
            severity: Severities to include (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)
            additional_args: Additional Trivy arguments

        Returns:
            Vulnerabilities in dependencies, OS packages, and configurations
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "format": format,
            "severity": severity,
            "additional_args": additional_args
        }
        return sast_client.safe_post("api/container/trivy", data)

    # ========================================================================
    # UTILITY TOOLS
    # ========================================================================

    @mcp.tool()
    def sast_server_health() -> Dict[str, Any]:
        """
        Check the health status of the SAST Tools server.
        Returns server status and availability of all SAST tools.

        Returns:
            Server health information and tool availability status
        """
        return sast_client.check_health()

    @mcp.tool()
    def execute_custom_sast_command(command: str, cwd: str = "", timeout: int = 300) -> Dict[str, Any]:
        """
        Execute a custom SAST command on the server.
        Use this for SAST tools not directly supported by other functions.

        Args:
            command: The command to execute
            cwd: Working directory for command execution (optional)
            timeout: Command timeout in seconds (default: 300)

        Returns:
            Command execution results
        """
        data = {
            "command": command,
            "cwd": cwd if cwd else None,
            "timeout": timeout
        }
        return sast_client.safe_post("api/command", data)

    return mcp


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Run the SAST MCP Client")
    parser.add_argument(
        "--server",
        type=str,
        default=DEFAULT_SAST_SERVER,
        help=f"SAST API server URL (default: {DEFAULT_SAST_SERVER})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_REQUEST_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    """Main entry point for the MCP server"""
    args = parse_args()

    # Configure logging
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Initialize the SAST Tools client
    sast_client = SASTToolsClient(args.server, args.timeout)

    # Check server health and log the result
    health = sast_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to SAST API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to SAST API server at {args.server}")
        logger.info(f"Server health status: {health.get('status')}")
        logger.info(f"Tools available: {health.get('total_tools_available', 0)}/{health.get('total_tools_count', 0)}")

        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential SAST tools are available on the server")
            tools_status = health.get("tools_status", {})
            missing_tools = [tool for tool, available in tools_status.items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")

    # Set up and run the MCP server
    mcp = setup_mcp_server(sast_client)
    logger.info("Starting SAST MCP server for Claude Code integration")
    mcp.run()


if __name__ == "__main__":
    main()
