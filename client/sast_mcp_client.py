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
from typing import Dict, Any, List, Optional
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

        # Default to background mode for scan endpoints when the caller hasn't set a preference.
        # We do NOT force it unconditionally: when the server runs FORCE_SYNC_SCANS=1 it
        # returns compact toon-analysis, so the caller can pass force_sync=True to get
        # inline results without an extra poll round-trip.
        SCAN_PREFIXES = ('api/sast/', 'api/secrets/', 'api/dependencies/',
                         'api/iac/', 'api/container/', 'api/web/',
                         'api/network/', 'api/system/', 'api/malware/')
        if any(endpoint.startswith(p) for p in SCAN_PREFIXES):
            if "background" not in json_data and "force_sync" not in json_data:
                json_data["background"] = True
                logger.info(f"Background mode defaulted for {endpoint} (pass force_sync=True for inline results)")

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
    async def opengrep_scan(
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
        Execute Opengrep static analysis for finding security vulnerabilities and code issues.
        Opengrep supports 30+ languages including Python, JavaScript, Java, Go, Ruby, PHP, etc.

        This tool now runs with async/await for better performance and uses maximum accuracy by default.

        Args:
            target: Path to code directory or file to scan (default: current directory)
            config: Opengrep ruleset to use:
                   - "auto" (default): resolves server-side to p/default. True registry
                     auto-config cannot run here because the server always passes
                     --metrics=off, which opengrep refuses to build an auto config without
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
            max_accuracy: Thorough but bounded scanning (default: True). Scans files of
                   any size, with a 30s per-rule timeout. It deliberately does NOT remove
                   the memory cap: scans run inside a memory cgroup, so an unbounded scan
                   is OOM-killed on large repos and a killed engine reports zero findings
            additional_args: Additional Opengrep command-line arguments

        Returns:
            Scan results with identified security issues and code quality problems.
            If output_file is provided, returns summary with file location instead of full results.
        """
        # Thorough, but still bounded. This used to send
        # "--max-memory 0 --timeout 0", and unbounded memory is not a more
        # accurate scan: the server runs each scan inside a SCAN_MEMORY_MAX_MB
        # cgroup, so on a large repo the engine was OOM-killed and still wrote
        # well-formed JSON with zero results. "Maximum accuracy" was turning big
        # repositories into clean reports (measured on IPS/rebot, IPS/teijin).
        # --max-target-bytes 0 is kept: large files are slow, not fatal. The
        # server clamps anything unbounded that still arrives, as a backstop.
        accuracy_flags = ""
        if max_accuracy:
            accuracy_flags = " --max-target-bytes 0 --timeout 30 --timeout-threshold 3"

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
        return await sast_client.safe_post("api/sast/opengrep", data)

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

    @mcp.tool()
    async def nodejsscan_scan(
        target: str = ".",
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute NodeJSScan Node.js security scanner for JavaScript/Node.js applications.
        Static analysis tool for Node.js security vulnerabilities.

        Args:
            target: Path to Node.js code directory to scan (default: current directory)
            output_file: Path to save scan results (optional). If provided, full results
                         are saved to file and only summary is returned to avoid token limits.
            additional_args: Additional NodeJSScan command-line arguments

        Returns:
            Node.js security findings and vulnerability report
        """
        data = {
            "target": target,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return await sast_client.safe_post("api/sast/nodejsscan", data)

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

        Scope note: gitleaks reads GIT HISTORY, not the working tree. It finds
        secrets in commits (including ones deleted from HEAD) but never sees an
        untracked or gitignored file. Working-tree scanners (repo_scan,
        opengrep_scan) are the mirror image. See DOCS.md section 11.

        Args:
            target: Path to git repository or directory to scan. Pass
                    additional_args="--no-git" for a plain directory or a tree of
                    repos; the history-depth limit is then omitted automatically.
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
        target: str = ".",
        stage: str = "",
        key: str = "",
        debug: bool = False,
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Run Safety CLI 3 scan on a Python project directory.
        Scans the given directory for dependency vulnerabilities (replaces legacy safety check -r file).

        Args:
            target: Project directory to scan (default: current directory)
            stage: Lifecycle stage: development | cicd | production (default: development)
            key: API key for cicd/production; or set SAFETY_API_KEY env
            debug: Enable debug output
            additional_args: Extra Safety CLI arguments

        Returns:
            Scan result with vulnerability findings
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        if stage:
            data["stage"] = stage
        if key:
            data["key"] = key
        if debug:
            data["debug"] = True
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
        file: str = "",
        output_format: str = "json",
        output_file_path: str = "",
        framework: str = "",
        skip_framework: str = "",
        check: str = "",
        skip_check: str = "",
        soft_fail: bool = False,
        soft_fail_on: str = "",
        hard_fail_on: str = "",
        baseline: str = "",
        create_baseline: bool = False,
        compact: bool = False,
        quiet: bool = False,
        max_accuracy: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Run Checkov for IaC security and compliance scanning.
        Use target (directory) or file (path to file); -d and -f are mutually exclusive.

        Args:
            target: IaC root directory (default: .). Ignored if file is set.
            file: File(s) to scan (-f). Use instead of target for single/file scan.
            output_format: cli, csv, cyclonedx, cyclonedx_json, json, junitxml,
                          github_failed_only, gitlab_sast, sarif, spdx
            output_file_path: Output file/folder for report
            framework: Comma-separated or single framework (terraform, dockerfile, kubernetes, etc.)
            skip_framework: Framework(s) to skip
            check: Run only these checks (CKV_*, BC_*, or severity)
            skip_check: Skip these checks
            soft_fail: Always exit 0
            soft_fail_on: Exit 0 if only these fail (severity or check IDs)
            hard_fail_on: Non-zero exit for these
            baseline: Path to .checkov.baseline file
            create_baseline: Save results to .checkov.baseline
            compact: Compact CLI output
            quiet: Only failed checks
            additional_args: Extra Checkov CLI arguments

        Returns:
            IaC scan result and parsed findings when output_format is json
        """
        data = {
            "target": target,
            "output_format": output_format,
            "compact": compact,
            "quiet": quiet,
            "additional_args": additional_args
        }
        if file:
            data["file"] = file
        if output_file_path:
            data["output_file_path"] = output_file_path
        if framework:
            data["framework"] = framework
        if skip_framework:
            data["skip_framework"] = skip_framework
        if check:
            data["check"] = check
        if skip_check:
            data["skip_check"] = skip_check
        if soft_fail:
            data["soft_fail"] = True
        if soft_fail_on:
            data["soft_fail_on"] = soft_fail_on
        if hard_fail_on:
            data["hard_fail_on"] = hard_fail_on
        if baseline:
            data["baseline"] = baseline
        if create_baseline:
            data["create_baseline"] = True
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
    async def batch_scan_dirs(
        target: str = ".",
        max_depth: int = 1,
        min_files: int = 1,
        max_targets: int = 20
    ) -> Dict[str, Any]:
        """
        Split a large directory into smaller scan targets to avoid token overload.

        Use this BEFORE scanning large codebases. It lists subdirectories as
        individual scan targets so you can scan each one separately and retrieve
        paginated results without hitting token limits.

        Workflow:
        1. Call batch_scan_dirs(target="F:/work/Resola/Deca") to get list of sub-targets
        2. For each target in result["targets"], call the appropriate scan tool
        3. Use get_scan_result_toon(job_id, page=1) to fetch findings page by page

        Args:
            target: Root directory to split into scan targets
            max_depth: Depth of directory splitting (1=immediate subdirs, default: 1)
            min_files: Minimum file count for a subdir to be included (default: 1)
            max_targets: Maximum number of targets to return (default: 20)

        Returns:
            List of scan targets with:
            - targets[].path: Windows path to use as scan target
            - targets[].name: Directory name
            - targets[].file_count: Estimated number of files
            - total_scan_targets: Number of targets found
            - recommendation: Suggested scanning strategy
        """
        data = {
            "target": target,
            "max_depth": max_depth,
            "min_files": min_files,
            "max_targets": max_targets
        }
        return await sast_client.safe_post("api/util/batch-scan-dirs", data)

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
    async def find_repos(
        root: str = "",
        max_depth: int = 3,
        limit: int = 500,
        require_git: bool = True,
        include_git_info: bool = False
    ) -> Dict[str, Any]:
        """
        Discover repositories on the mounted shares, ready to scan.

        Use this FIRST when asked to scan "our repos" or "everything under X" —
        it removes the need to know or type each path. Every returned repo's
        'path' can be passed straight to repo_scan.

        Args:
            root: Where to search (client or server path). Empty = every mounted share.
            max_depth: How deep to descend looking for repos (1-6, default: 3)
            limit: Max repos to return (default: 500)
            require_git: Only list dirs with a .git (default: True). False also
                         lists project dirs identified by package.json/go.mod/etc.
            include_git_info: Add branch + last commit per repo. Costs one git
                              call per repo, so leave off for large listings.

        Returns:
            - repos[].path: path to hand to repo_scan
            - repos[].name, .languages, .source_files, .has_git
            - total, roots_searched, truncated
        """
        data = {"max_depth": max_depth, "limit": limit,
                "require_git": require_git, "include_git_info": include_git_info}
        if root:
            data["root"] = root
        return await sast_client.safe_post("api/util/find-repos", data)

    @mcp.tool()
    async def list_mounts() -> Dict[str, Any]:
        """
        Show the server's path-mapping table and allowed scan roots.

        Call this when a scan fails with "outside the allowed mount roots", or
        when a path doesn't resolve: it reports which client->server mappings are
        configured, which targets actually exist on disk, and which shares were
        auto-discovered.

        Returns:
            - mappings[]: {client, server, exists}
            - allowed_roots[]: {path, exists}
            - auto_discovered[]: shares found without explicit config
            - sources: which config mechanisms are active
        """
        return await sast_client.safe_get("api/util/mounts")

    @mcp.tool()
    async def reload_mounts() -> Dict[str, Any]:
        """
        Re-read mount configuration and re-discover shares, without restarting
        the server. Call this after mounting a new shared folder so its repos
        become scannable immediately.
        """
        return await sast_client.safe_post("api/util/mounts/reload", {})

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
    async def get_detailed_scan_statistics() -> Dict[str, Any]:
        """
        Get detailed scan statistics and system health from the server.
        Includes process health, job counts by status, success/failure rates,
        and multi-process backend configuration.

        Returns:
            Detailed statistics including:
            - scan_statistics: Active, completed, failed, retried counts
            - metrics: Success rate, retry rate, failure rate (percent)
            - job_statistics: Total jobs and breakdown by status
            - process_health: Worker process health info
            - system_info: Multiprocessing config, max workers, etc.
        """
        return await sast_client.safe_get("api/scan/statistics")

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
    async def check_scan_result(job_id: str) -> Dict[str, Any]:
        """
        Check if a scan result file exists for a given job ID.
        Returns simple ok/not ok status based on file existence.

        This is useful for background scans to verify completion without
        consuming tokens by fetching full results.

        Args:
            job_id: Job ID returned from a background scan request

        Returns:
            Simple status dictionary with:
            - status: "ok" if result file exists, "not_ok" otherwise
            - exists: Boolean indicating file existence
            - job_status: Current job status (pending, running, completed, failed, cancelled)
            - message: Human-readable status message
        """
        return await sast_client.safe_get(f"api/jobs/{job_id}/check")

    @mcp.tool()
    async def get_job_status(job_id: str) -> Dict[str, Any]:
        """
        Get the status of a background scan job.

        Args:
            job_id: Job ID returned from a background scan request

        Returns:
            Job status information including:
            - job_id: The job identifier
            - tool_name: Name of the scan tool
            - status: Job status (pending, running, completed, failed, cancelled)
            - created_at: Job creation timestamp
            - started_at: Job start timestamp (if started)
            - completed_at: Job completion timestamp (if completed)
            - output_file: Path to result file
            - progress: Job progress percentage
        """
        return await sast_client.safe_get(f"api/jobs/{job_id}")

    @mcp.tool()
    async def list_scan_jobs(
        status_filter: str = "",
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        List background scan jobs with optional filtering.

        Args:
            status_filter: Filter by status (pending, running, completed, failed, cancelled)
            limit: Maximum number of jobs to return (default: 100)

        Returns:
            List of jobs with their status information
        """
        endpoint = f"api/jobs?limit={limit}"
        if status_filter:
            endpoint += f"&status={status_filter}"
        return await sast_client.safe_get(endpoint)

    @mcp.tool()
    async def cancel_scan_job(job_id: str) -> Dict[str, Any]:
        """
        Cancel a running or pending scan job.

        Args:
            job_id: Job ID returned from a background scan request

        Returns:
            Success or failure message. Jobs that are already completed or failed
            cannot be cancelled.
        """
        return await sast_client.safe_post(f"api/jobs/{job_id}/cancel", {})

    @mcp.tool()
    async def cleanup_scan_jobs() -> Dict[str, Any]:
        """
        Clean up old completed/failed/cancelled jobs from the server.
        Frees disk space and keeps the job list manageable.

        Returns:
            Message with the number of jobs cleaned up
        """
        return await sast_client.safe_post("api/jobs/cleanup", {})

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

    # ========================================================================
    # AI ANALYSIS & TOON RESULT TOOLS
    # ========================================================================

    @mcp.tool()
    async def get_scan_result_toon(
        job_id: str,
        include_findings: bool = True,
        page: int = 1,
        page_size: int = 20
    ) -> Dict[str, Any]:
        """
        Get scan results in TOON format with AI-powered analysis.

        This is the recommended way to retrieve scan results. Returns a compact,
        AI-analyzed result in TOON format that includes:
        - Risk assessment with severity-based scoring (0-10 scale)
        - Critical findings extracted and highlighted
        - Remediation priorities with effort estimates
        - False positive detection using heuristics
        - File hotspots showing most affected files
        - Actionable security recommendations

        TOON format is 30-60% more token-efficient than raw JSON, making it
        ideal for AI/LLM consumption while preserving all essential information.

        Args:
            job_id: Job ID returned from a scan request
            include_findings: Include individual findings in the output (default: True)
            page: Page number for paginated findings (default: 1, starts at 1)
            page_size: Number of findings per page (default: 20, max: 100)

        Returns:
            TOON-analyzed result with:
            - toon_result.analysis.risk: Overall risk assessment (CRITICAL/HIGH/MEDIUM/LOW/INFO)
            - toon_result.analysis.severity: Severity breakdown counts
            - toon_result.analysis.critical_findings: Most critical issues found
            - toon_result.analysis.top_priorities: Remediation priorities ranked by impact
            - toon_result.analysis.recommendations: Actionable next steps
            - toon_result.findings: Paginated findings sorted by severity (if included)
            - pagination.total_pages: Total number of pages available
            - pagination.has_next: Whether more pages exist
        """
        page = max(1, page)
        page_size = min(100, max(1, page_size))
        endpoint = f"api/jobs/{job_id}/result-toon?include_findings={str(include_findings).lower()}&page={page}&page_size={page_size}"
        return await sast_client.safe_get(endpoint)

    @mcp.tool()
    async def analyze_scan_results(
        job_id: str,
        analysis_type: str = "full",
        custom_prompt: str = ""
    ) -> Dict[str, Any]:
        """
        Perform AI-powered analysis on completed scan results.

        Analyzes scan findings and provides intelligent insights including:
        - Severity-weighted risk scoring
        - Critical finding extraction
        - Remediation priority ranking with effort estimates
        - False positive detection using pattern-based heuristics
        - File hotspot identification (files with most issues)
        - Contextual security recommendations

        NOTE: When AI service is not configured (no AI_API_KEY), this falls back
        to heuristic analysis identical to get_scan_result_toon(). The response
        will include "analysis_source": "heuristic" in that case.
        Use get_scan_result_toon() directly for the primary TOON-format output.

        Args:
            job_id: Job ID of a completed scan to analyze
            analysis_type: Type of analysis to perform:
                          - "full" (default): Complete analysis with all sections
                          - "quick": Summary and risk score only
                          - "prioritization": Focus on remediation priorities
            custom_prompt: Optional custom analysis instructions (used when AI
                          service is configured)

        Returns:
            Analysis results in toon-analysis format. When AI service is
            configured: AI-generated insights. Otherwise: heuristic analysis
            with toon_result containing risk, severity, critical_findings,
            top_priorities, file_hotspots, and recommendations.
        """
        data = {
            "job_id": job_id,
            "analysis_type": analysis_type,
            "custom_prompt": custom_prompt if custom_prompt else None
        }
        return await sast_client.safe_post("api/analysis/ai-summary", data)

    @mcp.tool()
    async def summarize_scan_results(job_id: str) -> Dict[str, Any]:
        """
        Generate a statistical summary of completed scan results (no AI required).
        Lightweight summary with counts and severity breakdown; use when you do
        not need AI-powered analysis.

        Args:
            job_id: Job ID of a completed scan to summarize

        Returns:
            Statistical summary with finding counts, severity breakdown, and
            basic metrics. Does not require AI service to be configured.
        """
        return await sast_client.safe_post("api/analysis/summarize", {"job_id": job_id})

    @mcp.tool()
    async def get_toon_ai_status() -> Dict[str, Any]:
        """
        Check the status of TOON converter and AI analysis features.

        Returns:
            Status of TOON and AI features including:
            - toon_available: Whether TOON format conversion is available
            - ai_configured: Whether AI service is configured
            - features: Available analysis features
        """
        return await sast_client.safe_get("api/analysis/toon-status")

    # ========================================================================
    # HUNT PIPELINE (first-party: the analysis lives in this repo, not in a
    # third-party binary). See docs/hunt-pipeline/ARCHITECTURE.md.
    # ========================================================================

    @mcp.tool()
    async def hunt_catalog(
        catalog: str = "parsers",
        tags: str = "parsers",
        limit: int = 0,
        refresh: bool = False
    ) -> Dict[str, Any]:
        """
        List candidate libraries to attack, by category. Step 1 of target gating.

        Turns a single-file-library catalog into deduplicated owner/name repo slugs,
        filtered to the categories that actually parse untrusted input (image, audio,
        3d, mesh, pack, parse, file, serial, video). In the campaign this took 297
        repos down to 62 before a single request was spent on gating.

        Args:
            catalog: 'parsers' (the committed 62), 'all' (the committed 297),
                     'readme' (fetch nothings/single_file_libs live), or a raw README URL
            tags: 'parsers' for the default parser categories, 'all' to also include
                  the 2d/json/net tags that were never gated, or a comma-separated list
            limit: Return at most N entries (0 = all)
            refresh: Bypass the cache when fetching a live README

        Returns:
            Repo slugs with their category tags and counts, ready for hunt_target_gate
        """
        data = {"catalog": catalog, "tags": tags, "limit": limit, "refresh": refresh}
        return await sast_client.safe_post("api/hunt/catalog", data)

    @mcp.tool()
    async def hunt_target_gate(
        repos: Optional[List[str]] = None,
        catalog: str = "parsers",
        tags: str = "parsers",
        local_root: str = "",
        max_repos: int = 25,
        workers: int = 6,
        gates: Optional[List[str]] = None,
        max_age_days: int = 400,
        include_issues: bool = True,
        fail_fast: bool = True,
        background: bool = False
    ) -> Dict[str, Any]:
        """
        Stage A target gating: decide WHICH library is worth attacking.

        This is the measured high-precision stage of the hunt pipeline: 297 repos ->
        62 parsers -> 2 survivors, and both survivors yielded findings (~100%
        precision). Pattern-matching code for bug shapes measured under 2% by
        comparison, so this is where static-analysis budget belongs.

        Five independent gates, each of which rejected something real:
          G1 maintained    - last COMMIT date (never pushed_at, which over-reports)
          G2 not saturated - OSS-Fuzz project.yaml must 404 (killed stb, lz4, miniz)
          G3 no harness    - no in-repo *fuzz* files (killed bddisasm, qoi, minimp3)
          G4 uncontested   - distinct open-PR authors (killed nanosvg: 36 authors)
          GHSA             - no advisory ids in-tree (flagged wildmidi as swept)

        G3 and GHSA need a checkout; without local_root they report 'skip' rather
        than inventing a pass. A gate that errors is never counted as a pass, so a
        'survivor' is a repo that provably cleared every gate that ran.

        Costs ~3 metered GitHub requests per repo. The unauthenticated ceiling is 60
        requests/hour, so set GITHUB_TOKEN on the server for 5,000/hour; the run
        stops cleanly at the ceiling and returns a `not_gated` resume list.

        Args:
            repos: Explicit 'owner/name' slugs to gate (takes precedence over catalog)
            catalog: Where to get repos if none given: 'parsers', 'all', 'readme', or a URL
            tags: Category filter when pulling from a catalog
            local_root: Directory holding checkouts, so G3/GHSA can be evaluated
            max_repos: Cap on repos gated in one call (budget protection)
            workers: Concurrent repos (1-16)
            gates: Subset of ['G1','G2','G3','G4','GHSA'] to run
            max_age_days: G1 staleness threshold
            include_issues: Also read open-issue count for G4 (one extra request/repo)
            fail_fast: Stop a repo at its first reject to save budget
            background: Run as a job (use for a whole-catalog sweep)

        Returns:
            Per-repo verdicts with evidence, the survivor list, rejects by gate,
            remaining API budget, and a resume list if the ceiling was hit
        """
        data: Dict[str, Any] = {
            "catalog": catalog, "tags": tags, "max_repos": max_repos,
            "workers": workers, "max_age_days": max_age_days,
            "include_issues": include_issues, "fail_fast": fail_fast,
            "background": background,
        }
        if repos:
            data["repos"] = repos
        if local_root:
            data["local_root"] = local_root
        if gates:
            data["gates"] = gates
        return await sast_client.safe_post("api/hunt/target-gate", data)

    @mcp.tool()
    async def hunt_shape_scan(
        target: str,
        shapes: Optional[List[str]] = None,
        allow_retired: bool = False,
        workers: int = 8,
        max_hits: int = 500
    ) -> Dict[str, Any]:
        """
        Stage B shape scanning: C memory-safety patterns. LOW YIELD BY MEASUREMENT.

        Read this before using it: in the campaign this stage produced 60 hits and
        exactly one real bug, which was already known. Use hunt_target_gate instead
        if you have budget for only one. It is kept because a cheap sweep over a NEW
        codebase occasionally pays, and because the negative result is worth knowing.

        Shapes:
          scan2 - narrowing cast of a parsed size used as a signed bound (assetsys).
                  1 of 7 hits real. The default, and the only field-validated one.
          scan1 - malloc(X) then a copy to an offset destination with length X
                  (paldither). Never produced a finding; unvalidated.
          scan3 - allocation size from a multiplication of int-width operands.
                  RETIRED: 53 hits, 0 real. Requires allow_retired=True.

        Every scanner self-tests against a known-positive first, and a zero-hit
        result is only reported as admissible if that self-test passed - otherwise a
        silently broken pattern looks exactly like clean code. Hits carry
        likely_false_positive when a guard is visible nearby.

        Args:
            target: Path to a checked-out C/C++ tree (must be under an allowed mount)
            shapes: Which to run, e.g. ['scan2'] (default), ['scan1','scan2']
            allow_retired: Required to run scan3 at all
            workers: Concurrent file readers (1-16)
            max_hits: Cap on returned hits

        Returns:
            Hits with the code, the bound/size expression, why it matters, and
            per-scanner measured precision so a hit is not over-trusted
        """
        data: Dict[str, Any] = {
            "target": target, "allow_retired": allow_retired,
            "workers": workers, "max_hits": max_hits,
        }
        if shapes:
            data["shapes"] = shapes
        return await sast_client.safe_post("api/hunt/shape-scan", data)

    @mcp.tool()
    async def hunt_evidence_check(
        log: str = "",
        log_path: str = "",
        claimed_crashes: int = 0,
        object_paths: Optional[List[str]] = None,
        harness_source: str = "",
        harness_path: str = "",
        jobs: int = 1,
        poc_build_command: str = "",
        signal: str = "store",
        assert_source: str = "",
        assert_line: int = 0
    ) -> Dict[str, Any]:
        """
        Prove a fuzzing run actually happened before believing it found nothing.

        A fuzzer that never started reports zero crashes, and so does a fuzzer that
        found none. In the campaign six '0 crashes' verdicts were never tests at all
        (a backgrounded process died when the tool call returned) and two of those
        targets were sitting on real bugs. This is the check that separates the two.

        What it catches:
          - no INITED line / no execution count    -> the run never happened
          - exec/s below ~50                        -> harness is filesystem-bound
            (vgmstream: 14,309 execs in 40 minutes; ~40 lines of memory-backed
            reader took it to 3,934 exec/s AND raised coverage 3,689 -> 4,087)
          - cov: under ~100                         -> target objects uninstrumented
            (fluidsynth reported cov: 20, which was the harness alone; a clean
            rebuild with CMAKE_C_FLAGS_DEBUG gave 12,990 counters and cov: 1480)
          - zero sanitizer_cov symbols in an object -> the fuzzer is blind to it
          - a timeout under -jobs>1                 -> re-run single-threaded first
            (5 campaign 'timeouts' completed in under 250ms alone)
          - a store-signal PoC built above -O0      -> dead-store elimination can
            delete the overflowing write, and the PoC then reports 'survived'
          - assert(false) with a correct path below -> not reportable under NDEBUG
            (OpenFBX: 6 crashes, all clean. dmc_unrar: same shape, no fallback, real)

        Args:
            log: Fuzzing log text (libFuzzer or Go native)
            log_path: Read the log from a file instead (must be under an allowed mount)
            claimed_crashes: How many crashes the run claims to have found
            object_paths: Target .o/.a files to check for coverage instrumentation
            harness_source: Harness source text, to check for per-execution file I/O
            harness_path: Read the harness from a file instead
            jobs: The -jobs value used, so parallel timeouts can be flagged
            poc_build_command: The PoC compile command, to validate its -O level
            signal: 'store' (needs -O0) or 'asan' (optimisation-independent)
            assert_source: Source text or path for assert triage
            assert_line: The assert's line number

        Returns:
            A verdict of proven_clean / unproven / crash, the blocking flags, and
            concrete remediation hints for each one
        """
        data: Dict[str, Any] = {
            "log": log, "claimed_crashes": claimed_crashes, "jobs": jobs,
            "harness_source": harness_source, "signal": signal,
        }
        if log_path:
            data["log_path"] = log_path
        if harness_path:
            data["harness_path"] = harness_path
        if object_paths:
            data["object_paths"] = object_paths
        if poc_build_command:
            data["poc_build_command"] = poc_build_command
        if assert_source and assert_line:
            data["assert_source"] = assert_source
            data["assert_line"] = assert_line
        return await sast_client.safe_post("api/hunt/evidence", data)

    @mcp.tool()
    async def hunt_disclosure_preflight(
        repos: Optional[List[str]] = None,
        repo: str = ""
    ) -> Dict[str, Any]:
        """
        Find out where a vulnerability report can actually be sent, before writing it.

        Run this BEFORE drafting the report. Every report in the campaign originally
        said 'open a private GHSA' - then the endpoint was actually checked and
        private vulnerability reporting was enabled:false on 11 of 12 targets, making
        the instruction impossible to follow.

        It also reads SECURITY.md, which changes what the report must contain:
          - vgmstream's has an explicit LLM clause ('LLM-generated reports or patches
            with no clear human participation may be closed without warning') and
            calls DoS 'not huge'
          - raylib's directs reports to public Issues, so asking for an embargo
            contradicts the maintainer's own policy

        Costs one metered GitHub request per repo; the policy fetch is free. An
        ambiguous answer always lands on 'no_documented_channel' rather than a
        guessed route.

        Args:
            repos: Several 'owner/name' slugs (max 20)
            repo: A single 'owner/name' slug

        Returns:
            The route that provably exists (private_ghsa / email / public_issue /
            no_documented_channel), blocking policy clauses with quotes, required
            actions, and whether the report is ready to send
        """
        data: Dict[str, Any] = {}
        if repos:
            data["repos"] = repos
        elif repo:
            data["repo"] = repo
        return await sast_client.safe_post("api/hunt/disclosure", data)

    @mcp.tool()
    async def hunt_budget(repos: int = 25) -> Dict[str, Any]:
        """
        Check the GitHub API budget left, and what a gating run of N repos will cost.

        The unauthenticated ceiling is 60 requests/hour, which is fewer than one per
        catalog repo - so check this before gating a category, and set GITHUB_TOKEN
        on the server to lift it to 5,000/hour.

        Args:
            repos: How many repos you intend to gate, for the cost estimate

        Returns:
            Remaining requests, reset time, cache hits, and repos-per-hour at the
            current authentication level
        """
        return await sast_client.safe_get(f"api/hunt/budget?repos={repos}")

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
