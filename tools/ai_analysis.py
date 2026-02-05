#!/usr/bin/env python3
"""
================================================================================
AI Analysis Module for SAST MCP Server
================================================================================

This module provides AI-powered analysis capabilities for SAST scan results.
It processes scan data and provides intelligent summarization, risk assessment,
and remediation guidance - returning results in TOON-optimized format for
efficient LLM consumption.

FEATURES:
    - Intelligent scan result analysis with severity-based risk scoring
    - Structured summarization of security findings
    - Risk prioritization and assessment
    - Remediation recommendations per finding type
    - False positive detection heuristics
    - TOON-format optimized output for AI consumption

USAGE:
    from ai_analysis import analyze_scan_results, create_toon_analysis_result

    # Analyze scan results and get TOON-ready output
    analysis = analyze_scan_results(scan_result_dict)
    toon_result = create_toon_analysis_result(scan_result_dict, analysis)

AUTHOR: MCP-SAST-Server Contributors
LICENSE: MIT
================================================================================
"""

import json
import logging
import os
from typing import Dict, Any, Optional, List
from datetime import datetime

# Setup logger
logger = logging.getLogger(__name__)

# Configuration for AI services
AI_SERVICE_ENABLED = os.environ.get("AI_SERVICE_ENABLED", "false").lower() == "true"
AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_SERVICE_URL = os.environ.get("AI_SERVICE_URL", "")
AI_MODEL = os.environ.get("AI_MODEL", "claude-3-5-sonnet-20241022")
AI_MAX_TOKENS = int(os.environ.get("AI_MAX_TOKENS", 4096))

# Severity weights for risk scoring
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "ERROR": 7,
    "MEDIUM": 4,
    "WARNING": 4,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 3,
}

# Known false-positive patterns by tool
FALSE_POSITIVE_PATTERNS = {
    "semgrep": [
        {"pattern": "test", "field": "path", "reason": "Test files often contain intentional vulnerable patterns"},
        {"pattern": "example", "field": "path", "reason": "Example files may contain intentional samples"},
        {"pattern": "mock", "field": "path", "reason": "Mock files often simulate vulnerabilities"},
        {"pattern": "vendor", "field": "path", "reason": "Vendor/third-party code outside direct control"},
        {"pattern": "node_modules", "field": "path", "reason": "Third-party dependency code"},
    ],
    "bandit": [
        {"pattern": "test_", "field": "filename", "reason": "Test files may trigger security warnings intentionally"},
        {"pattern": "assert", "field": "issue_text", "reason": "Assert statements in test code are expected"},
    ],
    "trufflehog": [
        {"pattern": "example", "field": "file", "reason": "Example files may contain placeholder secrets"},
        {"pattern": "test", "field": "file", "reason": "Test fixtures may contain fake credentials"},
    ],
}

# Remediation guidance database
REMEDIATION_DB = {
    "sql-injection": {
        "title": "SQL Injection Prevention",
        "guidance": "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
        "effort": "LOW",
        "references": ["CWE-89", "OWASP A03:2021"],
    },
    "xss": {
        "title": "Cross-Site Scripting Prevention",
        "guidance": "Sanitize and encode all user-supplied output. Use Content-Security-Policy headers.",
        "effort": "MEDIUM",
        "references": ["CWE-79", "OWASP A03:2021"],
    },
    "hardcoded-secret": {
        "title": "Hardcoded Secret Removal",
        "guidance": "Move secrets to environment variables or a secrets manager. Rotate any exposed credentials immediately.",
        "effort": "LOW",
        "references": ["CWE-798", "OWASP A07:2021"],
    },
    "insecure-deserialization": {
        "title": "Insecure Deserialization Fix",
        "guidance": "Avoid deserializing untrusted data. Use safe serialization formats like JSON instead of pickle/yaml.load.",
        "effort": "MEDIUM",
        "references": ["CWE-502", "OWASP A08:2021"],
    },
    "path-traversal": {
        "title": "Path Traversal Prevention",
        "guidance": "Validate and sanitize file paths. Use allowlists for accessible directories.",
        "effort": "LOW",
        "references": ["CWE-22", "OWASP A01:2021"],
    },
    "command-injection": {
        "title": "Command Injection Prevention",
        "guidance": "Avoid shell=True in subprocess calls. Use parameterized commands and input validation.",
        "effort": "MEDIUM",
        "references": ["CWE-78", "OWASP A03:2021"],
    },
    "weak-crypto": {
        "title": "Weak Cryptography Fix",
        "guidance": "Replace MD5/SHA1 with SHA-256+. Use established crypto libraries instead of custom implementations.",
        "effort": "LOW",
        "references": ["CWE-327", "OWASP A02:2021"],
    },
    "insecure-config": {
        "title": "Insecure Configuration Fix",
        "guidance": "Enable security headers, use TLS, disable debug mode in production.",
        "effort": "LOW",
        "references": ["CWE-16", "OWASP A05:2021"],
    },
    "default": {
        "title": "Security Finding Remediation",
        "guidance": "Review the finding in context. Apply security best practices for the identified issue type.",
        "effort": "MEDIUM",
        "references": ["OWASP Top 10"],
    },
}


def is_ai_configured() -> bool:
    """Check if AI analysis is configured and available."""
    return AI_SERVICE_ENABLED and bool(AI_API_KEY)


def analyze_scan_results(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform comprehensive analysis of scan results.

    This function analyzes the scan findings and produces a structured
    analysis including risk assessment, severity breakdown, remediation
    priorities, and false positive detection.

    Args:
        scan_result: Complete scan result dictionary with metadata and findings

    Returns:
        Structured analysis dictionary
    """
    tool_name = scan_result.get("tool_name", "unknown")
    scan_data = scan_result.get("scan_result", {})
    job_id = scan_result.get("job_id", "unknown")

    logger.info(f"Analyzing scan results for job {job_id}, tool: {tool_name}")

    # Extract findings based on tool type
    findings = _extract_findings(scan_data, tool_name)

    # Perform analysis
    severity_breakdown = _analyze_severity(findings, tool_name)
    risk_assessment = _calculate_risk_score(findings, severity_breakdown)
    remediation_priorities = _generate_remediation_priorities(findings, tool_name)
    false_positive_candidates = _detect_false_positives(findings, tool_name)
    critical_findings = _extract_critical_findings(findings, tool_name)
    file_hotspots = _identify_file_hotspots(findings, tool_name)

    analysis = {
        "job_id": job_id,
        "tool": tool_name,
        "analyzed_at": datetime.now().isoformat(),
        "total_findings": len(findings),
        "severity_breakdown": severity_breakdown,
        "risk_assessment": risk_assessment,
        "critical_findings": critical_findings[:10],  # Top 10 critical
        "remediation_priorities": remediation_priorities[:10],  # Top 10 priorities
        "false_positive_candidates": false_positive_candidates,
        "file_hotspots": file_hotspots[:10],  # Top 10 files with most issues
        "recommendations": _generate_recommendations(
            severity_breakdown, risk_assessment, len(findings), tool_name
        ),
    }

    logger.info(
        f"Analysis complete: {len(findings)} findings, "
        f"risk_score={risk_assessment.get('risk_score', 0)}, "
        f"risk_level={risk_assessment.get('overall_risk', 'UNKNOWN')}"
    )

    return analysis


def create_toon_analysis_result(
    scan_result: Dict[str, Any],
    analysis: Dict[str, Any],
    include_raw_findings: bool = False,
    max_findings: int = 50,
) -> Dict[str, Any]:
    """
    Create a TOON-optimized analysis result combining scan data and AI analysis.

    This produces a compact, structured result optimized for LLM consumption
    with token-efficient formatting.

    Args:
        scan_result: Original scan result dictionary
        analysis: Analysis from analyze_scan_results()
        include_raw_findings: Whether to include raw findings (increases size)
        max_findings: Maximum number of findings to include if raw included

    Returns:
        TOON-optimized result dictionary
    """
    tool_name = scan_result.get("tool_name", "unknown")
    scan_data = scan_result.get("scan_result", {})

    toon_result = {
        "format": "toon-analysis",
        "version": "1.0",
        "job_id": scan_result.get("job_id", "unknown"),
        "tool": tool_name,
        "target": scan_result.get("scan_params", {}).get(
            "target", scan_result.get("scan_params", {}).get("path", "unknown")
        ),
        "scan_time": scan_result.get("completed_at", scan_result.get("started_at", "")),
        "duration_seconds": scan_result.get("duration_seconds", 0),
        "success": scan_data.get("success", False),
        "analysis": {
            "total_findings": analysis.get("total_findings", 0),
            "risk": analysis.get("risk_assessment", {}),
            "severity": analysis.get("severity_breakdown", {}),
            "critical_findings": analysis.get("critical_findings", []),
            "top_priorities": analysis.get("remediation_priorities", []),
            "false_positive_suspects": len(
                analysis.get("false_positive_candidates", {}).get("candidates", [])
            ),
            "file_hotspots": analysis.get("file_hotspots", []),
            "recommendations": analysis.get("recommendations", []),
        },
    }

    # Optionally include compact findings
    if include_raw_findings:
        findings = _extract_findings(scan_data, tool_name)
        # Sort by severity and limit
        severity_order = {
            "CRITICAL": 0, "HIGH": 1, "ERROR": 1, "MEDIUM": 2,
            "WARNING": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5,
        }
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "UNKNOWN"), 5),
        )
        toon_result["findings"] = sorted_findings[:max_findings]
        toon_result["findings_truncated"] = len(findings) > max_findings

    return toon_result


def summarize_findings(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a comprehensive summary of scan findings.

    Args:
        scan_results: Complete scan results dictionary

    Returns:
        Dictionary with summary statistics and analysis
    """
    try:
        tool_name = scan_results.get("tool_name", "unknown")
        scan_result = scan_results.get("scan_result", {})

        # Extract findings using the unified extractor
        findings = _extract_findings(scan_result, tool_name)

        # Build severity breakdown
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Calculate risk score
        risk = _calculate_risk_score(findings, severity_counts)

        summary = {
            "tool": tool_name,
            "summary_type": "ai-enhanced",
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "risk_assessment": risk,
        }

        # Tool-specific enrichments
        if tool_name == "semgrep":
            parsed = scan_result.get("parsed_output", {})
            summary["errors"] = len(parsed.get("errors", []))
            # Unique rule IDs
            rule_ids = set()
            for r in parsed.get("results", []):
                rule_ids.add(r.get("check_id", "unknown"))
            summary["unique_rules_triggered"] = len(rule_ids)

        elif tool_name == "trufflehog":
            secrets = scan_result.get("parsed_secrets", [])
            verified = sum(1 for s in secrets if s.get("Verified", False))
            summary["total_secrets"] = len(secrets)
            summary["verified_secrets"] = verified
            summary["unverified_secrets"] = len(secrets) - verified

        elif tool_name == "bandit":
            parsed = scan_result.get("parsed_output", {})
            summary["metrics"] = parsed.get("metrics", {})

        return summary

    except Exception as e:
        logger.error(f"Error generating summary: {str(e)}")
        return {"error": str(e)}


def prioritize_findings(
    findings: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Prioritize security findings based on severity, impact, and context.

    Args:
        findings: List of security findings
        context: Optional context about the application/environment

    Returns:
        Prioritized list of findings with rank and remediation info
    """
    severity_order = {
        "CRITICAL": 0, "HIGH": 1, "ERROR": 1, "MEDIUM": 2,
        "WARNING": 2, "LOW": 3, "INFO": 4,
    }

    def get_priority(finding: Dict[str, Any]) -> int:
        severity = finding.get("severity", finding.get("extra", {}).get("severity", "LOW"))
        return severity_order.get(severity.upper(), 5)

    sorted_findings = sorted(findings, key=get_priority)

    result = []
    for idx, finding in enumerate(sorted_findings):
        severity = finding.get("severity", finding.get("extra", {}).get("severity", "UNKNOWN"))
        remediation_key = _classify_finding_type(finding)
        remediation = REMEDIATION_DB.get(remediation_key, REMEDIATION_DB["default"])

        result.append({
            "priority_rank": idx + 1,
            "severity": severity,
            "finding": finding,
            "remediation": remediation,
        })

    return result


def generate_remediation_guidance(
    finding: Dict[str, Any],
    tool_name: str,
) -> Dict[str, Any]:
    """
    Generate remediation guidance for a specific finding.

    Args:
        finding: Individual security finding
        tool_name: Name of the scanning tool

    Returns:
        Dictionary with remediation guidance
    """
    finding_type = _classify_finding_type(finding)
    remediation = REMEDIATION_DB.get(finding_type, REMEDIATION_DB["default"])

    return {
        "finding_type": finding_type,
        "remediation": remediation,
        "tool": tool_name,
    }


def analyze_scan_with_ai(
    ai_payload: Dict[str, Any],
    api_key: Optional[str] = None,
    custom_prompt: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyze scan results using AI/LLM service.

    When AI service is not configured, falls back to rule-based analysis.

    Args:
        ai_payload: AI-ready payload with scan data
        api_key: Optional API key
        custom_prompt: Optional custom analysis prompt

    Returns:
        Dictionary containing analysis results
    """
    metadata = ai_payload.get("metadata", {})
    tool_name = metadata.get("tool_name", "unknown")
    job_id = metadata.get("job_id", "unknown")

    # Extract scan data from payload
    data_content = ai_payload.get("data", {})

    # If data is a full scan result dict, analyze it directly
    if isinstance(data_content, dict) and "scan_result" in data_content:
        analysis = analyze_scan_results(data_content)
    else:
        # Create a minimal scan result structure for analysis
        analysis = {
            "job_id": job_id,
            "tool": tool_name,
            "analyzed_at": datetime.now().isoformat(),
            "message": "Analysis performed on payload data",
            "ai_configured": is_ai_configured(),
        }

    analysis["analysis_method"] = "ai-service" if is_ai_configured() else "rule-based"
    return analysis


# ============================================================================
# INTERNAL ANALYSIS FUNCTIONS
# ============================================================================


def _extract_findings(scan_data: Dict[str, Any], tool_name: str) -> List[Dict[str, Any]]:
    """Extract normalized findings from scan data based on tool type."""
    findings = []
    parsed_output = scan_data.get("parsed_output", {})

    if tool_name == "semgrep":
        for r in parsed_output.get("results", []):
            findings.append({
                "id": r.get("check_id", "unknown"),
                "severity": r.get("extra", {}).get("severity", "UNKNOWN"),
                "message": r.get("extra", {}).get("message", "")[:500],
                "file": r.get("path", ""),
                "line": r.get("start", {}).get("line", 0),
                "end_line": r.get("end", {}).get("line", 0),
                "cwe": r.get("extra", {}).get("metadata", {}).get("cwe"),
            })

    elif tool_name == "bandit":
        for r in parsed_output.get("results", []):
            findings.append({
                "id": r.get("test_id", "unknown"),
                "severity": r.get("issue_severity", "UNKNOWN"),
                "confidence": r.get("issue_confidence", "UNKNOWN"),
                "message": r.get("issue_text", "")[:500],
                "file": r.get("filename", ""),
                "line": r.get("line_number", 0),
                "cwe": r.get("issue_cwe", {}).get("id") if r.get("issue_cwe") else None,
            })

    elif tool_name == "trufflehog":
        secrets = scan_data.get("parsed_secrets", [])
        for s in secrets:
            findings.append({
                "type": s.get("DetectorType", "unknown"),
                "verified": s.get("Verified", False),
                "file": s.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                "line": s.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                "severity": "HIGH" if s.get("Verified") else "MEDIUM",
            })

    elif tool_name == "gitleaks":
        results = parsed_output if isinstance(parsed_output, list) else parsed_output.get("results", [])
        for r in results:
            findings.append({
                "rule": r.get("RuleID", r.get("rule", "unknown")),
                "file": r.get("File", r.get("file", "")),
                "line": r.get("StartLine", r.get("line", 0)),
                "commit": r.get("Commit", r.get("commit", ""))[:12],
                "severity": "HIGH",
            })

    elif tool_name == "bearer":
        results = parsed_output.get("findings", parsed_output.get("results", []))
        for r in results:
            findings.append({
                "id": r.get("rule_id", r.get("id", "unknown")),
                "severity": r.get("severity", "UNKNOWN"),
                "message": r.get("title", r.get("message", ""))[:500],
                "file": r.get("filename", r.get("file", "")),
                "line": r.get("line_number", r.get("line", 0)),
            })

    elif tool_name == "gosec":
        for r in parsed_output.get("Issues", []):
            findings.append({
                "id": r.get("rule_id", "unknown"),
                "severity": r.get("severity", "UNKNOWN"),
                "confidence": r.get("confidence", "UNKNOWN"),
                "message": r.get("details", "")[:500],
                "file": r.get("file", ""),
                "line": r.get("line", 0),
            })

    elif tool_name == "checkov":
        failed_checks = parsed_output.get("results", {}).get("failed_checks", [])
        for r in failed_checks:
            findings.append({
                "id": r.get("check_id", "unknown"),
                "severity": r.get("severity", "MEDIUM"),
                "message": r.get("check_name", "")[:500],
                "file": r.get("file_path", ""),
                "resource": r.get("resource", ""),
            })

    elif tool_name == "nikto":
        for r in parsed_output.get("vulnerabilities", []):
            findings.append({
                "id": r.get("id", "unknown"),
                "method": r.get("method", "GET"),
                "url": r.get("url", ""),
                "message": r.get("msg", "")[:500],
                "severity": "MEDIUM",
            })

    elif tool_name == "nmap":
        for host in parsed_output.get("hosts", []):
            host_addr = host.get("address", "unknown")
            for port in host.get("ports", []):
                findings.append({
                    "host": host_addr,
                    "port": port.get("port", 0),
                    "protocol": port.get("protocol", "tcp"),
                    "state": port.get("state", "unknown"),
                    "service": port.get("service", {}).get("name", "unknown"),
                    "severity": "INFO",
                })

    else:
        # Generic extraction
        results = (
            parsed_output.get("results", [])
            or parsed_output.get("findings", [])
            or parsed_output.get("issues", [])
            or parsed_output.get("vulnerabilities", [])
        )
        if isinstance(results, list):
            for r in results[:500]:
                if isinstance(r, dict):
                    findings.append({
                        "id": r.get("id", r.get("rule_id", r.get("check_id", "unknown"))),
                        "severity": r.get("severity", r.get("level", "UNKNOWN")),
                        "message": str(r.get("message", r.get("description", "")))[:500],
                        "file": r.get("file", r.get("path", r.get("filename", ""))),
                        "line": r.get("line", r.get("line_number", 0)),
                    })

    return findings


def _analyze_severity(findings: List[Dict[str, Any]], tool_name: str) -> Dict[str, int]:
    """Analyze severity distribution of findings."""
    severity_counts = {}
    for f in findings:
        severity = f.get("severity", "UNKNOWN")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return severity_counts


def _calculate_risk_score(
    findings: List[Dict[str, Any]],
    severity_breakdown: Dict[str, int],
) -> Dict[str, Any]:
    """Calculate overall risk score based on findings."""
    if not findings:
        return {
            "overall_risk": "NONE",
            "risk_score": 0.0,
            "risk_factors": [],
            "max_severity": "NONE",
        }

    # Calculate weighted score
    total_weight = 0
    for severity, count in severity_breakdown.items():
        weight = SEVERITY_WEIGHTS.get(severity, 3)
        total_weight += weight * count

    # Normalize score to 0-10
    max_possible = len(findings) * 10  # All CRITICAL
    risk_score = round((total_weight / max_possible) * 10, 1) if max_possible > 0 else 0

    # Determine risk level
    if risk_score >= 8:
        overall_risk = "CRITICAL"
    elif risk_score >= 6:
        overall_risk = "HIGH"
    elif risk_score >= 4:
        overall_risk = "MEDIUM"
    elif risk_score >= 2:
        overall_risk = "LOW"
    else:
        overall_risk = "INFO"

    # Identify risk factors
    risk_factors = []
    critical_count = severity_breakdown.get("CRITICAL", 0)
    high_count = severity_breakdown.get("HIGH", 0) + severity_breakdown.get("ERROR", 0)

    if critical_count > 0:
        risk_factors.append(f"{critical_count} critical findings require immediate attention")
    if high_count > 0:
        risk_factors.append(f"{high_count} high-severity findings detected")
    if len(findings) > 50:
        risk_factors.append(f"Large number of findings ({len(findings)}) suggests systemic issues")

    # Find max severity
    severity_order = ["CRITICAL", "HIGH", "ERROR", "MEDIUM", "WARNING", "LOW", "INFO", "UNKNOWN"]
    max_severity = "UNKNOWN"
    for sev in severity_order:
        if severity_breakdown.get(sev, 0) > 0:
            max_severity = sev
            break

    return {
        "overall_risk": overall_risk,
        "risk_score": risk_score,
        "risk_factors": risk_factors,
        "max_severity": max_severity,
        "weighted_score": total_weight,
    }


def _extract_critical_findings(
    findings: List[Dict[str, Any]],
    tool_name: str,
) -> List[Dict[str, Any]]:
    """Extract the most critical findings."""
    critical = []
    for f in findings:
        severity = f.get("severity", "UNKNOWN")
        if severity in ("CRITICAL", "HIGH", "ERROR"):
            critical.append(f)

    # Sort by severity (CRITICAL first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "ERROR": 1}
    critical.sort(key=lambda x: severity_order.get(x.get("severity", ""), 2))
    return critical


def _generate_remediation_priorities(
    findings: List[Dict[str, Any]],
    tool_name: str,
) -> List[Dict[str, Any]]:
    """Generate prioritized remediation items."""
    # Group findings by type/id
    groups = {}
    for f in findings:
        finding_id = f.get("id", f.get("rule", f.get("type", "unknown")))
        if finding_id not in groups:
            groups[finding_id] = {
                "id": finding_id,
                "severity": f.get("severity", "UNKNOWN"),
                "count": 0,
                "sample_message": f.get("message", ""),
                "files": set(),
            }
        groups[finding_id]["count"] += 1
        file_path = f.get("file", "")
        if file_path:
            groups[finding_id]["files"].add(file_path)

    # Build priority list
    priorities = []
    for group_id, group in groups.items():
        finding_type = _classify_finding_type({"id": group_id, "message": group.get("sample_message", "")})
        remediation = REMEDIATION_DB.get(finding_type, REMEDIATION_DB["default"])

        priorities.append({
            "priority": 0,  # Will be set after sorting
            "finding_id": group_id,
            "severity": group["severity"],
            "occurrences": group["count"],
            "affected_files": len(group["files"]),
            "description": group["sample_message"][:200],
            "remediation": remediation["guidance"],
            "effort": remediation["effort"],
        })

    # Sort by severity weight * count
    def priority_score(item):
        weight = SEVERITY_WEIGHTS.get(item["severity"], 3)
        return -(weight * item["occurrences"])  # Negative for descending

    priorities.sort(key=priority_score)

    # Assign priority numbers
    for idx, p in enumerate(priorities):
        p["priority"] = idx + 1

    return priorities


def _detect_false_positives(
    findings: List[Dict[str, Any]],
    tool_name: str,
) -> Dict[str, Any]:
    """Detect potential false positives using heuristics."""
    candidates = []
    patterns = FALSE_POSITIVE_PATTERNS.get(tool_name, [])

    for f in findings:
        for pattern_info in patterns:
            field_value = str(f.get(pattern_info["field"], "")).lower()
            if pattern_info["pattern"] in field_value:
                candidates.append({
                    "finding": {
                        "id": f.get("id", f.get("rule", "unknown")),
                        "file": f.get("file", f.get("filename", "")),
                        "severity": f.get("severity", "UNKNOWN"),
                    },
                    "reason": pattern_info["reason"],
                    "confidence": "MEDIUM",
                })
                break  # One match per finding is enough

    return {
        "total_suspects": len(candidates),
        "candidates": candidates[:20],  # Limit to 20
    }


def _identify_file_hotspots(
    findings: List[Dict[str, Any]],
    tool_name: str,
) -> List[Dict[str, Any]]:
    """Identify files with the most findings."""
    file_counts = {}
    for f in findings:
        file_path = f.get("file", f.get("filename", f.get("path", "")))
        if not file_path:
            continue
        if file_path not in file_counts:
            file_counts[file_path] = {"file": file_path, "count": 0, "severities": {}}
        file_counts[file_path]["count"] += 1
        sev = f.get("severity", "UNKNOWN")
        file_counts[file_path]["severities"][sev] = file_counts[file_path]["severities"].get(sev, 0) + 1

    # Sort by count descending
    hotspots = sorted(file_counts.values(), key=lambda x: -x["count"])
    return hotspots


def _classify_finding_type(finding: Dict[str, Any]) -> str:
    """Classify a finding into a remediation category."""
    finding_id = str(finding.get("id", "")).lower()
    message = str(finding.get("message", "")).lower()
    combined = f"{finding_id} {message}"

    if any(kw in combined for kw in ["sql", "sqli", "injection"]):
        if "command" in combined or "os." in combined or "subprocess" in combined:
            return "command-injection"
        return "sql-injection"
    if any(kw in combined for kw in ["xss", "cross-site", "script"]):
        return "xss"
    if any(kw in combined for kw in ["secret", "password", "credential", "api_key", "apikey", "token"]):
        return "hardcoded-secret"
    if any(kw in combined for kw in ["deserial", "pickle", "yaml.load", "marshal"]):
        return "insecure-deserialization"
    if any(kw in combined for kw in ["path-traversal", "directory-traversal", "lfi", "../"]):
        return "path-traversal"
    if any(kw in combined for kw in ["command", "exec", "shell", "subprocess", "os.system", "os.popen"]):
        return "command-injection"
    if any(kw in combined for kw in ["md5", "sha1", "weak-hash", "weak-cipher", "des", "rc4"]):
        return "weak-crypto"
    if any(kw in combined for kw in ["debug", "verbose", "insecure", "misconfigur"]):
        return "insecure-config"

    return "default"


def _generate_recommendations(
    severity_breakdown: Dict[str, int],
    risk_assessment: Dict[str, Any],
    total_findings: int,
    tool_name: str,
) -> List[str]:
    """Generate actionable recommendations based on analysis."""
    recommendations = []

    risk_level = risk_assessment.get("overall_risk", "UNKNOWN")
    critical_count = severity_breakdown.get("CRITICAL", 0)
    high_count = severity_breakdown.get("HIGH", 0) + severity_breakdown.get("ERROR", 0)

    if critical_count > 0:
        recommendations.append(
            f"URGENT: Address {critical_count} critical findings immediately - "
            "these represent exploitable vulnerabilities."
        )

    if high_count > 0:
        recommendations.append(
            f"Prioritize remediation of {high_count} high-severity findings "
            "in the next development sprint."
        )

    if total_findings > 100:
        recommendations.append(
            "Consider implementing automated security scanning in CI/CD pipeline "
            "to catch issues earlier in development."
        )

    if total_findings > 0 and risk_level in ("CRITICAL", "HIGH"):
        recommendations.append(
            "Conduct a focused security review of the most affected files "
            "(see file hotspots above)."
        )

    if total_findings == 0:
        recommendations.append(
            f"No findings detected by {tool_name}. Consider running additional "
            "tools for comprehensive coverage."
        )

    if risk_level in ("LOW", "INFO", "NONE") and total_findings > 0:
        recommendations.append(
            "Findings are low-severity. Address them as part of regular "
            "code maintenance and cleanup."
        )

    return recommendations


# Configuration check on module load
if __name__ == "__main__":
    if is_ai_configured():
        logger.info("AI analysis is configured and ready")
        logger.info(f"AI Model: {AI_MODEL}")
    else:
        logger.info("AI analysis is not configured (using rule-based analysis)")
        logger.info("Set AI_SERVICE_ENABLED=true and AI_API_KEY to enable LLM-powered analysis")
