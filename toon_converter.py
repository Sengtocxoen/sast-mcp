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


def prepare_toon_for_ai_analysis(toon_data: str, scan_metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare TOON formatted scan results for AI analysis.

    This function creates a structured payload that combines the TOON-formatted
    scan results with metadata, ready to be sent to an AI service for analysis.

    Args:
        toon_data: TOON formatted scan result string
        scan_metadata: Metadata about the scan (tool, target, timestamp, etc.)

    Returns:
        Dictionary ready for AI service consumption

    Example:
        payload = prepare_toon_for_ai_analysis(
            toon_data=toon_string,
            scan_metadata={
                "tool_name": "semgrep",
                "target": "/path/to/code",
                "scan_date": "2025-12-04"
            }
        )
    """
    return {
        "format": "toon",
        "data": toon_data,
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
