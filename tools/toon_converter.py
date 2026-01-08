#!/usr/bin/env python3
"""
================================================================================
TOON Format Converter for SAST MCP Server
================================================================================

This module provides utilities to convert SAST scan results from JSON to TOON
format (Token-Oriented Object Notation). TOON is a compact, human-readable
format optimized for LLMs, reducing token usage by 30-60% compared to JSON.

FEATURES:
    - JSON to TOON conversion for scan results
    - Optimized for LLM consumption
    - Maintains data structure and readability
    - Prepares data for AI-powered analysis

USAGE:
    from toon_converter import convert_scan_result_to_toon

    toon_output = convert_scan_result_to_toon(scan_result_dict)

AUTHOR: MCP-SAST-Server Contributors
LICENSE: MIT
================================================================================
"""

import json
import logging
from typing import Dict, Any, Optional

# Setup logger
logger = logging.getLogger(__name__)

# Try to import python-toon, but provide fallback if not available
try:
    from python_toon import encode as toon_encode, decode as toon_decode
    TOON_AVAILABLE = True
    logger.info("TOON converter loaded successfully")
except ImportError:
    TOON_AVAILABLE = False
    logger.warning("python-toon package not installed. TOON conversion will be disabled.")
    logger.warning("Install with: pip install python-toon")


def is_toon_available() -> bool:
    """Check if TOON converter is available"""
    return TOON_AVAILABLE


def convert_to_toon(data: Dict[str, Any]) -> Optional[str]:
    """
    Convert a Python dictionary to TOON format string.

    Args:
        data: Dictionary to convert

    Returns:
        TOON format string, or None if conversion fails
    """
    if not TOON_AVAILABLE:
        logger.warning("TOON converter not available. Skipping conversion.")
        return None

    try:
        toon_string = toon_encode(data)
        logger.info(f"Successfully converted data to TOON format ({len(toon_string)} chars)")
        return toon_string
    except Exception as e:
        logger.error(f"Error converting to TOON format: {str(e)}")
        return None


def convert_from_toon(toon_string: str) -> Optional[Dict[str, Any]]:
    """
    Convert a TOON format string back to Python dictionary.

    Args:
        toon_string: TOON format string

    Returns:
        Python dictionary, or None if conversion fails
    """
    if not TOON_AVAILABLE:
        logger.warning("TOON converter not available. Skipping conversion.")
        return None

    try:
        data = toon_decode(toon_string)
        logger.info("Successfully converted TOON format back to dictionary")
        return data
    except Exception as e:
        logger.error(f"Error converting from TOON format: {str(e)}")
        return None


def convert_scan_result_to_toon(scan_result: Dict[str, Any]) -> Optional[str]:
    """
    Convert SAST scan result to TOON format.

    This function takes a complete scan result dictionary (including metadata,
    scan parameters, and findings) and converts it to the compact TOON format
    optimized for LLM consumption.

    Args:
        scan_result: Complete scan result dictionary with metadata and findings

    Returns:
        TOON format string ready for LLM processing, or None if conversion fails

    Example:
        scan_result = {
            "job_id": "abc-123",
            "tool_name": "semgrep",
            "scan_result": {
                "results": [...],
                "errors": [...]
            }
        }

        toon_output = convert_scan_result_to_toon(scan_result)
    """
    if not TOON_AVAILABLE:
        logger.warning("TOON converter not available. Cannot convert scan result.")
        return None

    try:
        # Convert the entire scan result to TOON format
        toon_string = convert_to_toon(scan_result)

        if toon_string:
            # Calculate token savings estimate
            json_size = len(json.dumps(scan_result))
            toon_size = len(toon_string)
            savings_percent = ((json_size - toon_size) / json_size) * 100 if json_size > 0 else 0

            logger.info(f"Scan result conversion: JSON={json_size} chars, TOON={toon_size} chars")
            logger.info(f"Token savings: ~{savings_percent:.1f}%")

        return toon_string

    except Exception as e:
        logger.error(f"Error converting scan result to TOON: {str(e)}")
        return None


def prepare_toon_for_ai_analysis(
    toon_data: str,
    scan_metadata: Dict[str, Any],
    json_data: Optional[Dict[str, Any]] = None,
    output_format: str = "toon"
) -> Dict[str, Any]:
    """
    Prepare scan results for AI analysis in either TOON or JSON format.

    This function creates a structured payload that combines the scan results
    with metadata, ready to be sent to an AI service for analysis. The data
    can be in TOON format (compact, token-optimized) or JSON format (standard,
    jq-compatible).

    Args:
        toon_data: TOON formatted scan result string
        scan_metadata: Metadata about the scan (tool, target, timestamp, etc.)
        json_data: Optional JSON data (required if output_format is "json")
        output_format: Format for the data field - "toon" or "json" (default: "toon")

    Returns:
        Dictionary ready for AI service consumption

    Example:
        # TOON format (compact)
        payload = prepare_toon_for_ai_analysis(
            toon_data=toon_string,
            scan_metadata={...},
            output_format="toon"
        )

        # JSON format (jq-compatible)
        payload = prepare_toon_for_ai_analysis(
            toon_data=toon_string,
            scan_metadata={...},
            json_data=original_json,
            output_format="json"
        )
    """
    # Determine the data to include based on output format
    if output_format == "json" and json_data:
        data_content = json_data
        data_format = "json"
    else:
        data_content = toon_data
        data_format = "toon"

    return {
        "format": data_format,
        "data": data_content,
        "metadata": scan_metadata,
        "ai_ready": True,
        "instructions": {
            "task": "analyze_security_findings",
            "output_format": "structured_summary",
            "include": [
                "critical_findings",
                "risk_assessment",
                "remediation_priorities",
                "false_positive_analysis"
            ]
        }
    }


def calculate_token_savings(json_data: Dict[str, Any], toon_string: str) -> Dict[str, Any]:
    """
    Calculate estimated token savings from using TOON format.

    Args:
        json_data: Original JSON data dictionary
        toon_string: TOON formatted string

    Returns:
        Dictionary with savings statistics
    """
    json_size = len(json.dumps(json_data))
    toon_size = len(toon_string)

    # Rough estimation: 1 token ≈ 4 characters
    json_tokens = json_size // 4
    toon_tokens = toon_size // 4

    savings_chars = json_size - toon_size
    savings_tokens = json_tokens - toon_tokens
    savings_percent = ((json_size - toon_size) / json_size) * 100 if json_size > 0 else 0

    return {
        "json_chars": json_size,
        "toon_chars": toon_size,
        "savings_chars": savings_chars,
        "json_tokens_estimate": json_tokens,
        "toon_tokens_estimate": toon_tokens,
        "savings_tokens_estimate": savings_tokens,
        "savings_percent": round(savings_percent, 2)
    }


# Maximum size for AI-compact format (200KB to stay safely under 256KB limit)
AI_COMPACT_MAX_SIZE = 200 * 1024


def create_ai_compact_format(
    scan_result: Dict[str, Any],
    max_size: int = AI_COMPACT_MAX_SIZE
) -> Dict[str, Any]:
    """
    Create a compact AI-friendly format of scan results.

    This format is optimized for AI tools that have file size limits (e.g., 256KB).
    It extracts only essential information: findings with severity, location, and message.
    Large fields like raw stdout/stderr are excluded.

    Args:
        scan_result: Complete scan result dictionary
        max_size: Maximum size in bytes (default: 200KB)

    Returns:
        Compact dictionary suitable for AI consumption
    """
    job_id = scan_result.get("job_id", "unknown")
    tool_name = scan_result.get("tool_name", "unknown")
    scan_params = scan_result.get("scan_params", {})
    scan_data = scan_result.get("scan_result", {})

    # Extract target information
    target = scan_params.get("target", scan_params.get("path", "unknown"))

    # Build compact output
    compact = {
        "format": "ai-compact",
        "version": "1.0",
        "job_id": job_id,
        "tool": tool_name,
        "target": target,
        "scan_time": scan_result.get("completed_at", scan_result.get("started_at", "")),
        "success": scan_data.get("success", False),
        "return_code": scan_data.get("return_code", -1),
    }

    # Extract findings based on tool type
    findings = []
    parsed_output = scan_data.get("parsed_output", {})

    if tool_name == "semgrep":
        findings = _extract_semgrep_findings(parsed_output)
        compact["errors_count"] = len(parsed_output.get("errors", []))

    elif tool_name == "bandit":
        findings = _extract_bandit_findings(parsed_output)

    elif tool_name == "trufflehog":
        secrets = scan_data.get("parsed_secrets", [])
        findings = _extract_trufflehog_findings(secrets)

    elif tool_name == "gitleaks":
        findings = _extract_gitleaks_findings(parsed_output)

    elif tool_name == "bearer":
        findings = _extract_bearer_findings(parsed_output)

    elif tool_name == "gosec":
        findings = _extract_gosec_findings(parsed_output)

    elif tool_name == "checkov":
        findings = _extract_checkov_findings(parsed_output)

    elif tool_name == "nikto":
        findings = _extract_nikto_findings(parsed_output)

    elif tool_name == "nmap":
        findings = _extract_nmap_findings(parsed_output)

    else:
        # Generic extraction for unknown tools
        findings = _extract_generic_findings(parsed_output)

    # Generate summary statistics
    summary = _generate_summary(findings, tool_name)
    compact["summary"] = summary

    # Truncate findings if needed to stay under size limit
    compact["findings"] = _truncate_findings_to_fit(findings, compact, max_size)
    compact["total_findings"] = len(findings)
    compact["included_findings"] = len(compact["findings"])
    compact["truncated"] = len(compact["findings"]) < len(findings)

    return compact


def _extract_semgrep_findings(parsed_output: Dict[str, Any]) -> list:
    """Extract compact findings from Semgrep output."""
    findings = []
    results = parsed_output.get("results", [])

    for r in results:
        finding = {
            "id": r.get("check_id", "unknown"),
            "severity": r.get("extra", {}).get("severity", "UNKNOWN"),
            "message": r.get("extra", {}).get("message", "")[:500],  # Limit message length
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "end_line": r.get("end", {}).get("line", 0),
        }
        # Add CWE if available
        metadata = r.get("extra", {}).get("metadata", {})
        if metadata.get("cwe"):
            finding["cwe"] = metadata.get("cwe")[:3] if isinstance(metadata.get("cwe"), list) else metadata.get("cwe")
        findings.append(finding)

    return findings


def _extract_bandit_findings(parsed_output: Dict[str, Any]) -> list:
    """Extract compact findings from Bandit output."""
    findings = []
    results = parsed_output.get("results", [])

    for r in results:
        findings.append({
            "id": r.get("test_id", "unknown"),
            "severity": r.get("issue_severity", "UNKNOWN"),
            "confidence": r.get("issue_confidence", "UNKNOWN"),
            "message": r.get("issue_text", "")[:500],
            "file": r.get("filename", ""),
            "line": r.get("line_number", 0),
            "cwe": r.get("issue_cwe", {}).get("id") if r.get("issue_cwe") else None,
        })

    return findings


def _extract_trufflehog_findings(secrets: list) -> list:
    """Extract compact findings from TruffleHog output."""
    findings = []

    for s in secrets:
        findings.append({
            "type": s.get("DetectorType", "unknown"),
            "verified": s.get("Verified", False),
            "file": s.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
            "line": s.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
            "severity": "HIGH" if s.get("Verified") else "MEDIUM",
        })

    return findings


def _extract_gitleaks_findings(parsed_output: Dict[str, Any]) -> list:
    """Extract compact findings from Gitleaks output."""
    findings = []
    results = parsed_output if isinstance(parsed_output, list) else parsed_output.get("results", [])

    for r in results:
        findings.append({
            "rule": r.get("RuleID", r.get("rule", "unknown")),
            "file": r.get("File", r.get("file", "")),
            "line": r.get("StartLine", r.get("line", 0)),
            "commit": r.get("Commit", r.get("commit", ""))[:12],  # Short commit hash
            "severity": "HIGH",
        })

    return findings


def _extract_bearer_findings(parsed_output: Dict[str, Any]) -> list:
    """Extract compact findings from Bearer output."""
    findings = []
    results = parsed_output.get("findings", parsed_output.get("results", []))

    for r in results:
        findings.append({
            "id": r.get("rule_id", r.get("id", "unknown")),
            "severity": r.get("severity", "UNKNOWN"),
            "message": r.get("title", r.get("message", ""))[:500],
            "file": r.get("filename", r.get("file", "")),
            "line": r.get("line_number", r.get("line", 0)),
            "category": r.get("category", ""),
        })

    return findings


def _extract_gosec_findings(parsed_output: Dict[str, Any]) -> list:
    """Extract compact findings from Gosec output."""
    findings = []
    issues = parsed_output.get("Issues", [])

    for r in issues:
        findings.append({
            "id": r.get("rule_id", "unknown"),
            "severity": r.get("severity", "UNKNOWN"),
            "confidence": r.get("confidence", "UNKNOWN"),
            "message": r.get("details", "")[:500],
            "file": r.get("file", ""),
            "line": r.get("line", 0),
            "cwe": r.get("cwe", {}).get("id") if r.get("cwe") else None,
        })

    return findings


def _extract_checkov_findings(parsed_output: Dict[str, Any]) -> list:
    """Extract compact findings from Checkov output."""
    findings = []

    # Checkov can have results in different formats
    checks = parsed_output.get("results", {})
    failed_checks = checks.get("failed_checks", [])

    for r in failed_checks:
        findings.append({
            "id": r.get("check_id", "unknown"),
            "severity": r.get("severity", "MEDIUM"),
            "message": r.get("check_name", "")[:500],
            "file": r.get("file_path", ""),
            "resource": r.get("resource", ""),
            "guideline": r.get("guideline", "")[:200],
        })

    return findings


def _extract_nikto_findings(parsed_output: Dict[str, Any]) -> list:
    """Extract compact findings from Nikto output."""
    findings = []
    vulnerabilities = parsed_output.get("vulnerabilities", [])

    for r in vulnerabilities:
        findings.append({
            "id": r.get("id", "unknown"),
            "method": r.get("method", "GET"),
            "url": r.get("url", ""),
            "message": r.get("msg", "")[:500],
            "severity": "MEDIUM",  # Nikto doesn't have severity
        })

    return findings


def _extract_nmap_findings(parsed_output: Dict[str, Any]) -> list:
    """Extract compact findings from Nmap output."""
    findings = []
    hosts = parsed_output.get("hosts", [])

    for host in hosts:
        host_addr = host.get("address", "unknown")
        for port in host.get("ports", []):
            findings.append({
                "host": host_addr,
                "port": port.get("port", 0),
                "protocol": port.get("protocol", "tcp"),
                "state": port.get("state", "unknown"),
                "service": port.get("service", {}).get("name", "unknown"),
                "version": port.get("service", {}).get("version", ""),
            })

    return findings


def _extract_generic_findings(parsed_output: Dict[str, Any]) -> list:
    """Extract findings from unknown tool output with generic approach."""
    findings = []

    # Try common field names
    results = (parsed_output.get("results", []) or
               parsed_output.get("findings", []) or
               parsed_output.get("issues", []) or
               parsed_output.get("vulnerabilities", []))

    if isinstance(results, list):
        for r in results[:500]:  # Limit to 500 findings
            if isinstance(r, dict):
                findings.append({
                    "id": r.get("id", r.get("rule_id", r.get("check_id", "unknown"))),
                    "severity": r.get("severity", r.get("level", "UNKNOWN")),
                    "message": str(r.get("message", r.get("description", "")))[:500],
                    "file": r.get("file", r.get("path", r.get("filename", ""))),
                    "line": r.get("line", r.get("line_number", 0)),
                })

    return findings


def _generate_summary(findings: list, tool_name: str) -> Dict[str, Any]:
    """Generate summary statistics from findings."""
    summary = {
        "total": len(findings),
        "by_severity": {},
    }

    for f in findings:
        severity = f.get("severity", "UNKNOWN")
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

    # Add tool-specific summaries
    if tool_name == "trufflehog":
        verified = sum(1 for f in findings if f.get("verified"))
        summary["verified_secrets"] = verified
        summary["unverified_secrets"] = len(findings) - verified

    return summary


def _truncate_findings_to_fit(
    findings: list,
    compact: Dict[str, Any],
    max_size: int
) -> list:
    """Truncate findings list to fit within max_size."""
    # Calculate base size without findings
    base = compact.copy()
    base["findings"] = []
    base_size = len(json.dumps(base, ensure_ascii=False))

    # Available space for findings
    available = max_size - base_size - 1000  # Leave 1KB buffer

    if available <= 0:
        return []

    # Sort by severity importance
    severity_order = {"CRITICAL": 0, "HIGH": 1, "ERROR": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "UNKNOWN"), 5))

    # Add findings until we exceed size limit
    result = []
    current_size = 0

    for f in sorted_findings:
        finding_size = len(json.dumps(f, ensure_ascii=False)) + 2  # +2 for comma and space
        if current_size + finding_size > available:
            break
        result.append(f)
        current_size += finding_size

    return result
