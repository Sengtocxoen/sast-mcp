#!/usr/bin/env python3
"""
Comprehensive Security Scan Script

This script demonstrates the CORRECT way to use MCP SAST tools.
It shows how to call tools with output_file parameter to avoid token limits.

Usage:
    python run_comprehensive_scan.py

Note: This is a REFERENCE/EXAMPLE script showing the proper MCP tool call format.
      In practice, you would call these tools through Claude Code's MCP interface.
"""

import json
import os
from datetime import datetime


def create_scan_config(project_path: str, output_dir: str) -> dict:
    """
    Create scan configuration for a project.

    Args:
        project_path: Path to project (e.g., "/f/work/Resola/Deca/deca-tables-api")
        output_dir: Path to output directory (e.g., "F:/work/Resola/Security-Reports/Deca/deca-tables-api")

    Returns:
        Dictionary of scan configurations
    """

    # Ensure output directory exists
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    scans = {
        "semgrep": {
            "tool": "semgrep_scan",
            "params": {
                "target": project_path,
                "config": "auto",
                "output_format": "json",
                "output_file": f"{output_dir}/semgrep-results.json"
            },
            "description": "Multi-language SAST scanning"
        },

        "trufflehog": {
            "tool": "trufflehog_scan",
            "params": {
                "target_path": project_path,
                "scan_type": "filesystem",
                "output_file": f"{output_dir}/trufflehog-results.json"
            },
            "description": "Secret detection in code and git history"
        },

        "gitleaks": {
            "tool": "gitleaks_scan",
            "params": {
                "target_path": project_path,
                "scan_type": "detect",
                "output_file": f"{output_dir}/gitleaks-results.json"
            },
            "description": "Git-focused secret scanning"
        },

        "bandit": {
            "tool": "bandit_scan",
            "params": {
                "target_path": project_path,
                "severity": "medium",
                "output_file": f"{output_dir}/bandit-results.json"
            },
            "description": "Python security analysis"
        },

        "eslint": {
            "tool": "eslint_scan",
            "params": {
                "target_path": project_path,
                "output_format": "json",
                "output_file": f"{output_dir}/eslint-results.json"
            },
            "description": "JavaScript/TypeScript security"
        },

        "npm_audit": {
            "tool": "npm_audit",
            "params": {
                "project_path": project_path,
                "audit_level": "moderate",
                "output_file": f"{output_dir}/npm-audit-results.json"
            },
            "description": "Node.js dependency vulnerabilities"
        },

        "safety": {
            "tool": "safety_check",
            "params": {
                "requirements_file": f"{project_path}/requirements.txt",
                "output_file": f"{output_dir}/safety-results.json"
            },
            "description": "Python dependency vulnerabilities"
        },

        "trivy": {
            "tool": "trivy_scan",
            "params": {
                "target_path": project_path,
                "scan_type": "fs",
                "severity": "CRITICAL,HIGH,MEDIUM",
                "output_file": f"{output_dir}/trivy-results.json"
            },
            "description": "Container and filesystem security"
        },

        "bearer": {
            "tool": "bearer_scan",
            "params": {
                "target_path": project_path,
                "scanner_type": "sast",
                "output_file": f"{output_dir}/bearer-results.json"
            },
            "description": "Data security and privacy scanning"
        },

        "graudit": {
            "tool": "graudit_scan",
            "params": {
                "target_path": project_path,
                "database": "all",
                "output_file": f"{output_dir}/graudit-results.txt"
            },
            "description": "Source code auditing"
        },

        "checkov": {
            "tool": "checkov_scan",
            "params": {
                "target_path": project_path,
                "framework": "all",
                "output_format": "json",
                "output_file": f"{output_dir}/checkov-results.json"
            },
            "description": "Infrastructure as Code security"
        },

        "nikto": {
            "tool": "nikto_scan",
            "params": {
                "target": "localhost:3000",  # Adjust as needed
                "port": "3000",
                "output_format": "json",
                "output_file": f"{output_dir}/nikto-results.json"
            },
            "description": "Web server vulnerability scanning"
        }
    }

    return scans


def print_claude_code_instructions(project_path: str, output_dir: str):
    """Print instructions for using with Claude Code"""

    print("=" * 80)
    print("COMPREHENSIVE SECURITY SCAN INSTRUCTIONS FOR CLAUDE CODE")
    print("=" * 80)
    print()
    print(f"Project: {project_path}")
    print(f"Output:  {output_dir}")
    print()
    print("STEP 1: Create output directory")
    print("-" * 80)
    print(f'mkdir -p "{output_dir}"')
    print()

    print("STEP 2: Run MCP tools with output_file parameter")
    print("-" * 80)
    print()

    scans = create_scan_config(project_path, output_dir)

    for scan_name, scan_config in scans.items():
        print(f"### {scan_name.upper()} - {scan_config['description']}")
        print(f"MCP Tool: {scan_config['tool']}")
        print("Parameters:")
        for param, value in scan_config['params'].items():
            print(f"  - {param}: {value}")
        print()

    print("=" * 80)
    print("STEP 3: After scans complete, analyze results")
    print("-" * 80)
    print(f'ls -la "{output_dir}"')
    print()
    print("Read each result file:")
    for scan_name, scan_config in scans.items():
        output_file = scan_config['params'].get('output_file', '')
        if output_file:
            print(f'# {scan_name}: cat "{output_file}"')
    print()
    print("=" * 80)


def generate_scan_manifest(project_path: str, output_dir: str, output_file: str):
    """Generate a JSON manifest of all scans to run"""

    scans = create_scan_config(project_path, output_dir)

    manifest = {
        "project": project_path,
        "output_directory": output_dir,
        "generated_at": datetime.now().isoformat(),
        "scans": scans,
        "usage": {
            "description": "This manifest shows all available security scans",
            "how_to_use": "Call each MCP tool with the specified parameters",
            "important": "Always include output_file parameter to avoid token limits",
            "note": "Scans can be run in parallel or sequentially as needed"
        }
    }

    with open(output_file, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"Scan manifest saved to: {output_file}")


def main():
    """Main function"""

    # Example configuration
    PROJECT_PATH = "/f/work/Resola/Deca/deca-tables-api"
    OUTPUT_DIR = "F:/work/Resola/Security-Reports/Deca/deca-tables-api"

    print()
    print("=" * 80)
    print("MCP SAST TOOLS - COMPREHENSIVE SCAN CONFIGURATION")
    print("=" * 80)
    print()
    print("This script generates the proper configuration for running")
    print("comprehensive security scans using MCP tools.")
    print()
    print("⚠️  IMPORTANT:")
    print("   - Always use MCP tool calls (not direct bash commands)")
    print("   - Always include output_file parameter (avoid token limits)")
    print("   - Tools run on Kali server (not Windows)")
    print()

    # Generate manifest
    manifest_file = "/home/user/sast-mcp/scan_manifest.json"
    generate_scan_manifest(PROJECT_PATH, OUTPUT_DIR, manifest_file)
    print()

    # Print Claude Code instructions
    print_claude_code_instructions(PROJECT_PATH, OUTPUT_DIR)

    print()
    print("TIP: Copy the scan configurations above and paste them into Claude Code")
    print("     as MCP tool calls with the output_file parameter.")
    print()


if __name__ == "__main__":
    main()
