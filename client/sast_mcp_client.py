#!/usr/bin/env python3
"""
================================================================================
MCP-SAST-Client - Claude Code Integration for Security Analysis
================================================================================

This MCP (Model Context Protocol) client connects Claude Code to the SAST
Tools Server, enabling AI-powered security analysis through natural language.

FEATURES:
    - 15+ SAST tool integrations via MCP protocol
    - Simple function calls from Claude Code
    - Automatic server communication
    - JSON result parsing
    - Health monitoring

ARCHITECTURE:
    Claude Code ← → MCP Client (this file) ← → SAST Server ← → Security Tools

CONFIGURATION:
    Command-line arguments:
        --server: SAST server URL (default: http://localhost:6000)
        --timeout: Request timeout in seconds (default: 600)
        --debug: Enable debug logging

USAGE:
    python3 sast_mcp_client.py --server http://192.168.1.100:6000
    python3 sast_mcp_client.py --server http://localhost:6000 --debug

INTEGRATION:
    Add to .claude.json:
    {
      "mcpServers": {
        "sast_tools": {
          "type": "stdio",
          "command": "python",
          "args": [
            "/path/to/sast_mcp_client.py",
            "--server",
            "http://YOUR_SERVER_IP:6000"
          ]
        }
      }
    }

AUTHOR: MCP-SAST-Server Contributors
LICENSE: MIT
================================================================================
"""

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import asyncio
import aiohttp

from mcp.server.fastmcp import FastMCP

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)

# ============================================================================
# DEFAULT CONFIGURATION
# ============================================================================

# SAST Server URL Configuration
# IMPORTANT: Update this to your SAST server's IP address
# Examples:
#   - Localhost (server on same machine): "http://localhost:6000"
#   - Remote server (Kali VM): "http://192.168.1.100:6000"
#   - Custom port: "http://192.168.1.100:8080"
DEFAULT_SAST_SERVER = "http://localhost:6000"

# Request Timeout (in seconds)
# Increase for large codebases or slow networks
DEFAULT_REQUEST_TIMEOUT = 600  # 10 minutes

# ============================================================================
# HTTP CLIENT
# ============================================================================

class SASTToolsClient:
    """
    Async HTTP client for communicating with the SAST Tools API Server.

    This class handles all HTTP communication between the MCP client and
    the SAST server, including request formatting and error handling.

    Attributes:
        server_url: Base URL of the SAST server
        timeout: Request timeout in seconds
    """

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the SAST Tools Client

        Args:
            server_url: URL of the SAST Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = None
        logger.info(f"Initialized SAST Tools Client connecting to {server_url}")

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session

    async def close(self):
        """Close the aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()

    async def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform an async POST request with JSON data

        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send

        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"POST {url} with data: {json_data}")
            session = await self._get_session()
            async with session.post(url, json=json_data) as response:
                response.raise_for_status()
                return await response.json()
        except aiohttp.ClientError as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    async def safe_get(self, endpoint: str) -> Dict[str, Any]:
        """Perform an async GET request"""
        url = f"{self.server_url}/{endpoint}"

        try:
            session = await self._get_session()
            async with session.get(url) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}

    async def check_health(self) -> Dict[str, Any]:
        """Check the health of the SAST Tools API Server"""
        return await self.safe_get("health")


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
    async def semgrep_scan(
        target: str = ".",
        config: str = "auto",
        lang: str = "",
        severity: str = "",
        output_format: str = "json",
        output_file: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Semgrep static analysis for finding security vulnerabilities and code issues.
        Semgrep supports 30+ languages including Python, JavaScript, Java, Go, Ruby, PHP, etc.

        This tool now runs with async/await for better performance and uses maximum accuracy by default.

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
            output_file: Path to save scan results (Windows format: F:/path/to/file.json).
                        If provided, full results are saved to file and only summary is returned
                        to avoid token limits.
            max_accuracy: Enable maximum accuracy mode - slower but more thorough (default: True)
            additional_args: Additional Semgrep command-line arguments

        Returns:
            Scan results with identified security issues and code quality problems.
            If output_file is provided, returns summary with file location instead of full results.
        """
        # Add comprehensive scanning flags for maximum accuracy
        accuracy_flags = ""
        if max_accuracy:
            accuracy_flags = " --max-memory 0 --timeout 0 --max-target-bytes 0"

        combined_args = f"{accuracy_flags} {additional_args}".strip()

        data = {
            "target": target,
            "config": config,
            "lang": lang,
            "severity": severity,
            "output_format": output_format,
            "output_file": output_file,
            "additional_args": combined_args
        }
        return await sast_client.safe_post("api/sast/semgrep", data)

    @mcp.tool()
    async def bearer_scan(
        target: str = ".",
        scanner: str = "",
        format: str = "json",
        only_policy: str = "",
        severity: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Bearer security and privacy scanner for detecting security risks and data leaks.
        Bearer analyzes code for sensitive data flows and security vulnerabilities.

        This tool now runs with async/await for better performance and uses maximum accuracy by default.

        Args:
            target: Path to code directory to scan (default: current directory)
            scanner: Type of scan to perform:
                    - "" (empty): All scanners (default)
                    - "sast": Static application security testing
                    - "secrets": Scan for hardcoded secrets
            format: Output format (json, yaml, sarif, html)
            only_policy: Only check specific security policy
            severity: Filter by severity (critical, high, medium, low, warning)
            max_accuracy: Enable maximum accuracy mode - slower but more thorough (default: True)
            additional_args: Additional Bearer arguments

        Returns:
            Security findings including data leaks, vulnerabilities, and privacy issues
        """
        # Add comprehensive scanning flags for maximum accuracy
        accuracy_flags = ""
        if max_accuracy:
            # Disable quiet mode for full output, enable all checks
            accuracy_flags = " --skip-path= --disable-default-rules=false"

        combined_args = f"{accuracy_flags} {additional_args}".strip()

        data = {
            "target": target,
            "scanner": scanner,
            "format": format,
            "only_policy": only_policy,
            "severity": severity,
            "additional_args": combined_args
        }
        return await sast_client.safe_post("api/sast/bearer", data)

    @mcp.tool()
    async def graudit_scan(
        target: str = ".",
        database: str = "all",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Graudit grep-based source code auditing for finding security issues.
        Fast pattern-matching security scanner using signature databases.

        This tool now runs with async/await for better performance and uses maximum accuracy by default.

        Args:
            target: Path to code directory or file to audit (default: current directory)
            database: Signature database to use:
                     - "all": All available signatures (default)
                     - "default": Default signatures
                     - Language-specific: "asp", "c", "cobol", "dotnet", "exec", "fruit",
                       "go", "java", "js", "nim", "perl", "php", "python", "ruby", "secrets",
                       "spsqli", "strings", "xss"
            max_accuracy: Enable maximum accuracy mode - slower but more thorough (default: True)
            additional_args: Additional graudit arguments

        Returns:
            List of potential security issues found by pattern matching
        """
        data = {
            "target": target,
            "database": database,
            "additional_args": additional_args
        }
        return await sast_client.safe_post("api/sast/graudit", data)

    @mcp.tool()
    async def bandit_scan(
        target: str = ".",
        severity_level: str = "",
        confidence_level: str = "",
        format: str = "json",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Bandit security scanner for Python code.
        Identifies common security issues in Python applications.

        This tool now runs with async/await for better performance and uses maximum accuracy by default.

        Args:
            target: Path to Python code directory or file (default: current directory)
            severity_level: Minimum severity to report (low, medium, high)
            confidence_level: Minimum confidence to report (low, medium, high)
            format: Output format (json, csv, txt, html, xml)
            max_accuracy: Enable maximum accuracy mode - slower but more thorough (default: True)
            additional_args: Additional Bandit arguments

        Returns:
            Python security issues including SQL injection, hardcoded passwords,
            insecure random usage, etc.
        """
        # Add comprehensive scanning flags for maximum accuracy
        accuracy_flags = ""
        if max_accuracy:
            # Include all checks, no skips
            accuracy_flags = " --verbose"

        combined_args = f"{accuracy_flags} {additional_args}".strip()

        data = {
            "target": target,
            "severity_level": severity_level,
            "confidence_level": confidence_level,
            "format": format,
            "additional_args": combined_args
        }
        return await sast_client.safe_post("api/sast/bandit", data)

    @mcp.tool()
    async def gosec_scan(
        target: str = "./...",
        format: str = "json",
        severity: str = "",
        confidence: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Gosec security scanner for Go (Golang) code.
        Inspects Go source code for security problems.

        This tool now runs with async/await for better performance and uses maximum accuracy by default.

        Args:
            target: Path to Go code directory (default: ./... for all packages)
            format: Output format (json, yaml, csv, junit-xml, html, sonarqube, golint, sarif, text)
            severity: Filter by severity (low, medium, high)
            confidence: Filter by confidence (low, medium, high)
            max_accuracy: Enable maximum accuracy mode - slower but more thorough (default: True)
            additional_args: Additional gosec arguments

        Returns:
            Go-specific security issues and vulnerabilities
        """
        # Add comprehensive scanning flags for maximum accuracy
        accuracy_flags = ""
        if max_accuracy:
            # Verbose output and check all packages
            accuracy_flags = " -verbose=text"

        combined_args = f"{accuracy_flags} {additional_args}".strip()

        data = {
            "target": target,
            "format": format,
            "severity": severity,
            "confidence": confidence,
            "additional_args": combined_args
        }
        return await sast_client.safe_post("api/sast/gosec", data)

    @mcp.tool()
    async def brakeman_scan(
        target: str = ".",
        format: str = "json",
        confidence_level: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Brakeman security scanner for Ruby on Rails applications.
        Static analysis tool designed specifically for Rails security.

        This tool now runs with async/await for better performance and uses maximum accuracy by default.

        Args:
            target: Path to Rails application directory (default: current directory)
            format: Output format (json, html, csv, tabs, text)
            confidence_level: Minimum confidence level (1-3, where 1 is highest confidence)
            max_accuracy: Enable maximum accuracy mode - slower but more thorough (default: True)
            additional_args: Additional Brakeman arguments

        Returns:
            Rails-specific security vulnerabilities like SQL injection, XSS,
            mass assignment, etc.
        """
        # Add comprehensive scanning flags for maximum accuracy
        accuracy_flags = ""
        if max_accuracy:
            # Enable all checks and interprocedural analysis
            accuracy_flags = " --interprocedural"

        combined_args = f"{accuracy_flags} {additional_args}".strip()

        data = {
            "target": target,
            "format": format,
            "confidence_level": confidence_level,
            "additional_args": combined_args
        }
        return await sast_client.safe_post("api/sast/brakeman", data)

    @mcp.tool()
    async def eslint_security_scan(
        target: str = ".",
        config: str = "",
        format: str = "json",
        fix: bool = False,
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute ESLint with security plugins for JavaScript/TypeScript code analysis.
        Detects security issues and code quality problems in JavaScript projects.

        This tool now runs with async/await for better performance and uses maximum accuracy by default.

        Args:
            target: Path to JavaScript/TypeScript code (default: current directory)
            config: Path to ESLint config file (uses project config if empty)
            format: Output format (json, stylish, html, compact, unix, etc.)
            fix: Automatically fix problems where possible (boolean)
            max_accuracy: Enable maximum accuracy mode - slower but more thorough (default: True)
            additional_args: Additional ESLint arguments

        Returns:
            JavaScript/TypeScript security and quality issues
        """
        # Add comprehensive scanning flags for maximum accuracy
        accuracy_flags = ""
        if max_accuracy:
            # Report unused disable directives and show all warnings
            accuracy_flags = " --report-unused-disable-directives --max-warnings 0"

        combined_args = f"{accuracy_flags} {additional_args}".strip()

        data = {
            "target": target,
            "config": config,
            "format": format,
            "fix": fix,
            "additional_args": combined_args
        }
        return await sast_client.safe_post("api/sast/eslint-security", data)

    # ========================================================================
    # SECRET SCANNING
    # ========================================================================

    @mcp.tool()
    async def trufflehog_scan(
        target: str = ".",
        scan_type: str = "filesystem",
        json_output: bool = True,
        only_verified: bool = False,
        max_accuracy: bool = True,
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
        return await sast_client.safe_post("api/secrets/trufflehog", data)

    @mcp.tool()
    async def gitleaks_scan(
        target: str = ".",
        config: str = "",
        report_format: str = "json",
        report_path: str = "",
        verbose: bool = False,
        max_accuracy: bool = True,
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
        return await sast_client.safe_post("api/secrets/gitleaks", data)

    # ========================================================================
    # DEPENDENCY SCANNING
    # ========================================================================

    @mcp.tool()
    async def safety_check(
        requirements_file: str = "requirements.txt",
        json_output: bool = True,
        full_report: bool = False,
        max_accuracy: bool = True,
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
        return await sast_client.safe_post("api/dependencies/safety", data)

    @mcp.tool()
    async def npm_audit(
        target: str = ".",
        json_output: bool = True,
        audit_level: str = "",
        production: bool = False,
        max_accuracy: bool = True,
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
        return await sast_client.safe_post("api/dependencies/npm-audit", data)

    @mcp.tool()
    async def dependency_check(
        target: str = ".",
        project_name: str = "project",
        format: str = "JSON",
        scan: str = "",
        max_accuracy: bool = True,
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
        return await sast_client.safe_post("api/dependencies/dependency-check", data)

    # ========================================================================
    # INFRASTRUCTURE AS CODE (IaC)
    # ========================================================================

    @mcp.tool()
    async def checkov_scan(
        target: str = ".",
        framework: str = "",
        output_format: str = "json",
        compact: bool = False,
        quiet: bool = False,
        max_accuracy: bool = True,
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
        return await sast_client.safe_post("api/iac/checkov", data)

    @mcp.tool()
    async def tfsec_scan(
        target: str = ".",
        format: str = "json",
        minimum_severity: str = "",
        max_accuracy: bool = True,
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
        return await sast_client.safe_post("api/iac/tfsec", data)

    # ========================================================================
    # CONTAINER SECURITY
    # ========================================================================

    @mcp.tool()
    async def trivy_scan(
        target: str,
        scan_type: str = "fs",
        format: str = "json",
        severity: str = "",
        max_accuracy: bool = True,
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
        return await sast_client.safe_post("api/container/trivy", data)

    # ========================================================================
    # KALI LINUX SECURITY TOOLS
    # ========================================================================

    @mcp.tool()
    async def nikto_scan(
        target: str,
        port: str = "80",
        ssl: bool = False,
        output_format: str = "txt",
        output_file: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Nikto web server scanner to identify security issues and misconfigurations.
        Comprehensive web server security scanner that tests for thousands of vulnerabilities.

        Args:
            target: Target host (IP address or domain name)
            port: Port to scan (default: 80)
            ssl: Use SSL/HTTPS connection (boolean)
            output_format: Output format (txt, html, csv, xml)
            output_file: Path to save the scan results
            additional_args: Additional Nikto command-line arguments

        Returns:
            Web server vulnerabilities, misconfigurations, and security issues
        """
        data = {
            "target": target,
            "port": port,
            "ssl": ssl,
            "output_format": output_format,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return await sast_client.safe_post("api/web/nikto", data)

    @mcp.tool()
    async def nmap_scan(
        target: str,
        scan_type: str = "-sV",
        ports: str = "",
        output_format: str = "normal",
        output_file: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Nmap network and port scanner for host discovery and service detection.
        Industry-standard tool for network exploration and security auditing.

        Args:
            target: Target host(s) to scan (IP, domain, or CIDR notation like 192.168.1.0/24)
            scan_type: Type of scan to perform (default: -sV for version detection):
                      - "-sS": SYN stealth scan
                      - "-sT": TCP connect scan
                      - "-sU": UDP scan
                      - "-sV": Service version detection
                      - "-sC": Script scan with default scripts
                      - "-A": Aggressive scan (OS detection, version detection, scripts, traceroute)
                      - "-sn": Ping scan (host discovery only)
            ports: Port specification (e.g., "80,443,8080" or "1-1000" or "1-65535")
            output_format: Output format (normal, xml, grepable)
            output_file: Path to save scan results
            additional_args: Additional Nmap arguments

        Returns:
            Open ports, running services, versions, and OS detection results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "output_format": output_format,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return await sast_client.safe_post("api/network/nmap", data)

    @mcp.tool()
    async def sqlmap_scan(
        target: str,
        data: str = "",
        cookie: str = "",
        level: str = "1",
        risk: str = "1",
        batch: bool = True,
        output_dir: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute SQLMap for automated SQL injection detection and exploitation.
        Powerful tool for finding and exploiting SQL injection vulnerabilities.

        Args:
            target: Target URL to test for SQL injection
            data: POST data string for testing POST parameters
            cookie: HTTP Cookie header value for authenticated testing
            level: Level of tests to perform (1-5, default: 1):
                  - 1: Basic tests
                  - 5: Most comprehensive tests
            risk: Risk level of tests (1-3, default: 1):
                 - 1: Safe tests only
                 - 3: Heavy query tests that may cause database issues
            batch: Never ask for user input, use defaults (boolean, default: True)
            output_dir: Directory to save detailed output and session files
            additional_args: Additional SQLMap arguments

        Returns:
            SQL injection vulnerabilities found with details on exploitation
        """
        data_dict = {
            "target": target,
            "data": data,
            "cookie": cookie,
            "level": level,
            "risk": risk,
            "batch": batch,
            "output_dir": output_dir,
            "additional_args": additional_args
        }
        return await sast_client.safe_post("api/web/sqlmap", data_dict)

    @mcp.tool()
    async def wpscan_scan(
        target: str,
        enumerate: str = "vp",
        api_token: str = "",
        output_file: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute WPScan WordPress security scanner for WordPress-specific vulnerabilities.
        Specialized scanner for WordPress sites, plugins, and themes.

        Args:
            target: Target WordPress URL (e.g., https://example.com)
            enumerate: What to enumerate:
                      - "vp": Vulnerable plugins (default)
                      - "ap": All plugins
                      - "vt": Vulnerable themes
                      - "at": All themes
                      - "u": Users
                      - "m": Media IDs
                      - Multiple options: "vp,vt,u"
            api_token: WPScan API token for vulnerability data (get free token from wpscan.com)
            output_file: Path to save scan results (JSON format)
            additional_args: Additional WPScan arguments

        Returns:
            WordPress vulnerabilities in core, plugins, themes, and user enumeration results
        """
        data = {
            "target": target,
            "enumerate": enumerate,
            "api_token": api_token,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return await sast_client.safe_post("api/web/wpscan", data)

    @mcp.tool()
    async def dirb_scan(
        target: str,
        wordlist: str = "/usr/share/dirb/wordlists/common.txt",
        extensions: str = "",
        output_file: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute DIRB web content scanner for finding hidden directories and files.
        Dictionary-based web content discovery tool.

        Args:
            target: Target URL to scan (e.g., http://example.com)
            wordlist: Path to wordlist file (default: /usr/share/dirb/wordlists/common.txt)
                     Other options: big.txt, small.txt, catala.txt, spanish.txt, etc.
            extensions: File extensions to check (e.g., "php,html,js,txt")
            output_file: Path to save scan results
            additional_args: Additional DIRB arguments

        Returns:
            Discovered directories, files, and hidden web content
        """
        data = {
            "target": target,
            "wordlist": wordlist,
            "extensions": extensions,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return await sast_client.safe_post("api/web/dirb", data)

    @mcp.tool()
    async def lynis_audit(
        target: str = "",
        audit_mode: str = "system",
        quick: bool = False,
        log_file: str = "",
        report_file: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Lynis security auditing tool for Unix/Linux system hardening assessment.
        Comprehensive security audit tool for system hardening and compliance.

        Args:
            target: Target directory or file (for dockerfile mode)
            audit_mode: Type of audit to perform:
                       - "system": Full system audit (default)
                       - "dockerfile": Audit a Dockerfile
            quick: Quick scan mode (boolean, less comprehensive but faster)
            log_file: Path to save detailed log file
            report_file: Path to save audit report
            additional_args: Additional Lynis arguments

        Returns:
            System security assessment with hardening recommendations and compliance findings
        """
        data = {
            "target": target,
            "audit_mode": audit_mode,
            "quick": quick,
            "log_file": log_file,
            "report_file": report_file,
            "additional_args": additional_args
        }
        return await sast_client.safe_post("api/system/lynis", data)

    @mcp.tool()
    async def snyk_scan(
        target: str = ".",
        test_type: str = "test",
        severity_threshold: str = "",
        json_output: bool = True,
        output_file: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Snyk security scanner for modern dependency and container vulnerability scanning.
        Developer-first security tool for finding and fixing vulnerabilities.

        Args:
            target: Path to project directory (default: current directory)
            test_type: Type of test to perform:
                      - "test": Test for open source vulnerabilities (default)
                      - "container": Test container images
                      - "iac": Test Infrastructure as Code files
                      - "code": Test source code (SAST)
            severity_threshold: Only report issues of this severity or higher (low, medium, high, critical)
            json_output: Output in JSON format (boolean, default: True)
            output_file: Path to save scan results
            additional_args: Additional Snyk arguments

        Returns:
            Vulnerabilities in dependencies, containers, IaC, or code with fix recommendations
        """
        data = {
            "target": target,
            "test_type": test_type,
            "severity_threshold": severity_threshold,
            "json_output": json_output,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return await sast_client.safe_post("api/dependencies/snyk", data)

    @mcp.tool()
    async def clamav_scan(
        target: str,
        recursive: bool = True,
        infected_only: bool = False,
        output_file: str = "",
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute ClamAV antivirus scanner for malware and virus detection.
        Open-source antivirus engine for detecting trojans, viruses, malware, and other malicious threats.

        Args:
            target: Path to file or directory to scan
            recursive: Scan directories recursively (boolean, default: True)
            infected_only: Only display infected files in output (boolean)
            output_file: Path to save scan log
            additional_args: Additional ClamAV arguments

        Returns:
            Malware detection results with infected file locations and threat names
        """
        data = {
            "target": target,
            "recursive": recursive,
            "infected_only": infected_only,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return await sast_client.safe_post("api/malware/clamav", data)

    # ========================================================================
    # UTILITY TOOLS
    # ========================================================================

    @mcp.tool()
    async def scan_project_structure(
        project_path: str = ".",
        deep_scan: bool = True,
        include_hidden: bool = False
    ) -> Dict[str, Any]:
        """
        Deeply scan project structure to find dependency files and project metadata.
        This helps improve scan accuracy by identifying all relevant files for security analysis.

        Args:
            project_path: Path to the project directory to scan (default: current directory)
            deep_scan: Recursively scan subdirectories (boolean, default: True)
            include_hidden: Include hidden files and directories (boolean, default: False)

        Returns:
            Comprehensive project structure information including:
            - Detected project type(s) (Python, Node.js, Go, Ruby, Java, etc.)
            - Dependency files (requirements.txt, package.json, go.mod, Gemfile, pom.xml, etc.)
            - Configuration files (.env, config files, etc.)
            - Source code directories
            - Recommended scan targets for each tool
        """
        data = {
            "project_path": project_path,
            "deep_scan": deep_scan,
            "include_hidden": include_hidden
        }
        return await sast_client.safe_post("api/util/scan-project-structure", data)

    @mcp.tool()
    async def get_scan_statistics() -> Dict[str, Any]:
        """
        Get current parallel scan statistics from the server.
        Shows how many scans are active, queued, completed, and failed.
        Also displays available scan slots.

        Returns:
            Parallel scan statistics including:
            - Maximum parallel scans allowed (default: 3)
            - Active scans currently running
            - Queued scans waiting for slots
            - Completed and failed scan counts
            - Available scan slots
            - Wait timeout configuration (default: 30 minutes)
        """
        return await sast_client.safe_get("api/util/scan-stats")

    @mcp.tool()
    async def sast_server_health() -> Dict[str, Any]:
        """
        Check the health status of the SAST Tools server.
        Returns server status and availability of all SAST tools.

        Returns:
            Server health information and tool availability status
        """
        return await sast_client.check_health()

    @mcp.tool()
    async def execute_custom_sast_command(command: str, cwd: str = "", timeout: int = 300) -> Dict[str, Any]:
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
        return await sast_client.safe_post("api/command", data)

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


async def check_server_health_async(sast_client, server_url):
    """Async helper to check server health on startup"""
    health = await sast_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to SAST API server at {server_url}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to SAST API server at {server_url}")
        logger.info(f"Server health status: {health.get('status')}")
        logger.info(f"Tools available: {health.get('total_tools_available', 0)}/{health.get('total_tools_count', 0)}")

        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential SAST tools are available on the server")
            tools_status = health.get("tools_status", {})
            missing_tools = [tool for tool, available in tools_status.items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")


def main():
    """Main entry point for the MCP server"""
    args = parse_args()

    # Configure logging
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Initialize the SAST Tools client
    sast_client = SASTToolsClient(args.server, args.timeout)

    # Skip initial health check to avoid closing the event loop
    # The health check will happen on first tool use instead
    logger.info(f"SAST Tools Client initialized for server: {args.server}")
    logger.info("Health check will be performed on first tool use")

    # Set up and run the MCP server
    mcp = setup_mcp_server(sast_client)
    logger.info("Starting SAST MCP server for Claude Code integration with async/await support")
    logger.info("All scan tools now run asynchronously for better performance")
    logger.info("Maximum accuracy mode enabled by default for thorough scanning")
    mcp.run()


if __name__ == "__main__":
    main()
