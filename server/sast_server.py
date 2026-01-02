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
import multiprocessing
from multiprocessing import Manager, Process, Queue
import re
import uuid
import time
from typing import Dict, Any, List, Optional
from flask import Flask, request, jsonify
from datetime import datetime
import tempfile
import shutil
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from pathlib import Path
import hashlib
import psutil

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import TOON converter utilities
from tools.toon_converter import (
    convert_scan_result_to_toon,
    is_toon_available,
    calculate_token_savings,
    prepare_toon_for_ai_analysis
)

# Import AI analysis utilities
from tools.ai_analysis import (
    analyze_scan_with_ai,
    is_ai_configured,
    summarize_findings,
    prioritize_findings,
    generate_remediation_guidance
)

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
MAX_TIMEOUT = int(os.environ.get("MAX_TIMEOUT", 86400))  # 24 hours default (was 2 hours)

# Tool-specific timeouts (in seconds) - configurable via environment
NIKTO_TIMEOUT = int(os.environ.get("NIKTO_TIMEOUT", 3600))        # 1 hour
NMAP_TIMEOUT = int(os.environ.get("NMAP_TIMEOUT", 7200))          # 2 hours
SQLMAP_TIMEOUT = int(os.environ.get("SQLMAP_TIMEOUT", 7200))      # 2 hours
WPSCAN_TIMEOUT = int(os.environ.get("WPSCAN_TIMEOUT", 3600))      # 1 hour
DIRB_TIMEOUT = int(os.environ.get("DIRB_TIMEOUT", 7200))          # 2 hours
LYNIS_TIMEOUT = int(os.environ.get("LYNIS_TIMEOUT", 1800))        # 30 minutes
SNYK_TIMEOUT = int(os.environ.get("SNYK_TIMEOUT", 3600))          # 1 hour
CLAMAV_TIMEOUT = int(os.environ.get("CLAMAV_TIMEOUT", 14400))     # 4 hours
SEMGREP_TIMEOUT = int(os.environ.get("SEMGREP_TIMEOUT", 7200))    # 2 hours
BANDIT_TIMEOUT = int(os.environ.get("BANDIT_TIMEOUT", 1800))      # 30 minutes
TRUFFLEHOG_TIMEOUT = int(os.environ.get("TRUFFLEHOG_TIMEOUT", 3600))  # 1 hour

# Path Resolution Configuration
# These settings enable cross-platform operation (Windows client -> Linux server)
MOUNT_POINT = os.environ.get("MOUNT_POINT", "/mnt/work")  # Linux mount point
WINDOWS_BASE = os.environ.get("WINDOWS_BASE", "F:/work")  # Windows base path

# Background Job Configuration
DEFAULT_OUTPUT_DIR = os.environ.get("DEFAULT_OUTPUT_DIR", "/var/sast-mcp/scan-results")
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 10))  # Max concurrent scan jobs
JOB_RETENTION_HOURS = int(os.environ.get("JOB_RETENTION_HOURS", 72))  # Keep job data for 72 hours

# Multi-Process Scan Configuration
# Updated to support true parallel execution using multiprocessing
# Each scan runs in its own isolated process for better CPU utilization and stability
MAX_PARALLEL_SCANS = int(os.environ.get("MAX_PARALLEL_SCANS", 4))  # Number of concurrent scans (default: 4)
SCAN_WAIT_TIMEOUT = int(os.environ.get("SCAN_WAIT_TIMEOUT", 1800))  # 30 minutes wait timeout
USE_MULTIPROCESSING = os.environ.get("USE_MULTIPROCESSING", "1").lower() in ("1", "true", "yes", "y")  # Enable multi-process backend

# Process Management Configuration
MAX_PROCESS_WORKERS = int(os.environ.get("MAX_PROCESS_WORKERS", max(4, multiprocessing.cpu_count() - 1)))  # Process pool size
PROCESS_MEMORY_LIMIT_MB = int(os.environ.get("PROCESS_MEMORY_LIMIT_MB", 2048))  # 2GB per process
MAX_RETRY_ATTEMPTS = int(os.environ.get("MAX_RETRY_ATTEMPTS", 2))  # Retry failed scans
RETRY_BACKOFF_BASE = float(os.environ.get("RETRY_BACKOFF_BASE", 2.0))  # Exponential backoff multiplier

# Accuracy and Validation Configuration
ENABLE_RESULT_VALIDATION = os.environ.get("ENABLE_RESULT_VALIDATION", "1").lower() in ("1", "true", "yes", "y")
ENABLE_CHECKSUM_VERIFICATION = os.environ.get("ENABLE_CHECKSUM_VERIFICATION", "1").lower() in ("1", "true", "yes", "y")
MIN_RESULT_SIZE_BYTES = int(os.environ.get("MIN_RESULT_SIZE_BYTES", 10))  # Minimum valid result size

# Initialize Flask application
app = Flask(__name__)

# ============================================================================
# MULTI-PROCESS SCAN CONTROL (PARALLEL EXECUTION)
# ============================================================================

# Initialize multiprocessing manager for shared state
mp_manager = Manager() if USE_MULTIPROCESSING else None

# Semaphore to limit concurrent scans to MAX_PARALLEL_SCANS
# Uses multiprocessing.Semaphore for cross-process synchronization when multiprocessing is enabled
if USE_MULTIPROCESSING:
    scan_semaphore = multiprocessing.Semaphore(MAX_PARALLEL_SCANS)
    scan_stats_lock = multiprocessing.Lock()
    scan_stats = mp_manager.dict({
        "active_scans": 0,
        "total_scans": 0,
        "queued_scans": 0,
        "completed_scans": 0,
        "failed_scans": 0,
        "retried_scans": 0,
        "process_crashes": 0
    })
else:
    # Fallback to threading for compatibility
    scan_semaphore = threading.Semaphore(MAX_PARALLEL_SCANS)
    scan_stats_lock = threading.Lock()
    scan_stats = {
        "active_scans": 0,
        "total_scans": 0,
        "queued_scans": 0,
        "completed_scans": 0,
        "failed_scans": 0,
        "retried_scans": 0,
        "process_crashes": 0
    }

def acquire_scan_slot(timeout: int = SCAN_WAIT_TIMEOUT) -> bool:
    """
    Acquire a slot for parallel scanning with timeout.
    Waits up to 30 minutes (default) if all slots are busy.

    Args:
        timeout: Maximum wait time in seconds (default: 1800 = 30 minutes)

    Returns:
        bool: True if slot acquired, False if timeout
    """
    global scan_stats

    with scan_stats_lock:
        scan_stats["queued_scans"] += 1

    logger.info(f"Attempting to acquire scan slot (timeout: {timeout}s, active: {scan_stats['active_scans']}/{MAX_PARALLEL_SCANS})")

    acquired = scan_semaphore.acquire(timeout=timeout)

    with scan_stats_lock:
        scan_stats["queued_scans"] -= 1
        if acquired:
            scan_stats["active_scans"] += 1
            scan_stats["total_scans"] += 1
            logger.info(f"Scan slot acquired (active: {scan_stats['active_scans']}/{MAX_PARALLEL_SCANS})")
        else:
            logger.warning(f"Failed to acquire scan slot after {timeout}s timeout")

    return acquired

def release_scan_slot():
    """Release a scan slot back to the pool."""
    global scan_stats

    with scan_stats_lock:
        scan_stats["active_scans"] = max(0, scan_stats["active_scans"] - 1)

    scan_semaphore.release()
    logger.info(f"Scan slot released (active: {scan_stats['active_scans']}/{MAX_PARALLEL_SCANS})")

# ============================================================================
# BACKGROUND JOB MANAGEMENT SYSTEM
# ============================================================================

class JobStatus(Enum):
    """Job status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Job:
    """Represents a background scan job"""

    def __init__(self, job_id: str, tool_name: str, params: Dict[str, Any], output_file: str = None):
        self.job_id = job_id
        self.tool_name = tool_name
        self.params = params
        self.status = JobStatus.PENDING
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.output_file = output_file
        self.result = None
        self.error = None
        self.progress = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dictionary for JSON serialization"""
        return {
            "job_id": self.job_id,
            "tool_name": self.tool_name,
            "params": self.params,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "output_file": self.output_file,
            "error": self.error,
            "progress": self.progress,
            "duration_seconds": self._calculate_duration()
        }

    def _calculate_duration(self) -> Optional[float]:
        """Calculate job duration in seconds"""
        if self.started_at:
            end_time = self.completed_at if self.completed_at else datetime.now()
            return (end_time - self.started_at).total_seconds()
        return None


class JobManager:
    """Manages background scan jobs with multi-process support"""

    def __init__(self, max_workers: int = MAX_WORKERS):
        self.jobs: Dict[str, Job] = {}
        self.lock = threading.Lock()

        # Use ProcessPoolExecutor for true parallelism when multiprocessing is enabled
        if USE_MULTIPROCESSING:
            self.executor = ProcessPoolExecutor(max_workers=MAX_PROCESS_WORKERS)
            logger.info(f"JobManager initialized with ProcessPoolExecutor ({MAX_PROCESS_WORKERS} process workers, max {MAX_PARALLEL_SCANS} parallel scans)")
        else:
            self.executor = ThreadPoolExecutor(max_workers=max_workers)
            logger.info(f"JobManager initialized with ThreadPoolExecutor ({max_workers} thread workers)")

        # Ensure default output directory exists
        os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)

    def create_job(self, tool_name: str, params: Dict[str, Any], output_file: str = None) -> Job:
        """Create a new job"""
        job_id = str(uuid.uuid4())

        # Generate default output file if not provided
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{tool_name}_{timestamp}_{job_id[:8]}.json"
            output_file = os.path.join(DEFAULT_OUTPUT_DIR, filename)

        job = Job(job_id, tool_name, params, output_file)

        with self.lock:
            self.jobs[job_id] = job

        logger.info(f"Created job {job_id} for tool {tool_name}")
        return job

    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID"""
        with self.lock:
            return self.jobs.get(job_id)

    def list_jobs(self, status_filter: Optional[str] = None, limit: int = 100) -> List[Job]:
        """List all jobs with optional status filter"""
        with self.lock:
            jobs = list(self.jobs.values())

        if status_filter:
            jobs = [j for j in jobs if j.status.value == status_filter]

        # Sort by created_at descending
        jobs.sort(key=lambda x: x.created_at, reverse=True)

        return jobs[:limit]

    def submit_job(self, job: Job, work_func, *args, **kwargs):
        """Submit a job for background execution"""
        job.status = JobStatus.PENDING
        future = self.executor.submit(self._execute_job, job, work_func, *args, **kwargs)
        logger.info(f"Submitted job {job.job_id} to executor")
        return future

    def _execute_job(self, job: Job, work_func, *args, **kwargs):
        """Execute a job in the background with parallel scan control"""
        global scan_stats

        try:
            # Acquire scan slot with 30-minute timeout
            logger.info(f"Job {job.job_id} waiting for scan slot...")
            slot_acquired = acquire_scan_slot(timeout=SCAN_WAIT_TIMEOUT)

            if not slot_acquired:
                # Timeout waiting for slot
                job.status = JobStatus.FAILED
                job.completed_at = datetime.now()
                job.error = f"Timeout waiting for scan slot after {SCAN_WAIT_TIMEOUT}s (30 minutes). All {MAX_PARALLEL_SCANS} scan slots were busy."
                logger.error(f"Job {job.job_id} failed: {job.error}")

                with scan_stats_lock:
                    scan_stats["failed_scans"] += 1
                return

            try:
                job.status = JobStatus.RUNNING
                job.started_at = datetime.now()
                logger.info(f"Job {job.job_id} started (slot acquired)")

                # Execute the work function
                result = work_func(*args, **kwargs)

                # Save result to file
                self._save_job_result(job, result)

                job.status = JobStatus.COMPLETED
                job.completed_at = datetime.now()
                job.result = {
                    "success": True,
                    "output_file": job.output_file,
                    "summary": result.get("summary", {})
                }

                logger.info(f"Job {job.job_id} completed successfully")

                with scan_stats_lock:
                    scan_stats["completed_scans"] += 1

            finally:
                # Always release the scan slot
                release_scan_slot()

        except Exception as e:
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now()
            job.error = str(e)
            logger.error(f"Job {job.job_id} failed: {str(e)}")
            logger.error(traceback.format_exc())

            with scan_stats_lock:
                scan_stats["failed_scans"] += 1

    def _save_job_result(self, job: Job, result: Dict[str, Any]):
        """Save job result to output file (JSON and TOON formats)"""
        try:
            # Resolve Windows path if needed
            resolved_output_file = resolve_windows_path(job.output_file) if job.output_file.startswith('F:') else job.output_file

            # Ensure directory exists
            os.makedirs(os.path.dirname(resolved_output_file), exist_ok=True)

            # Prepare full result with metadata
            full_result = {
                "job_id": job.job_id,
                "tool_name": job.tool_name,
                "scan_params": job.params,
                "started_at": job.started_at.isoformat(),
                "completed_at": datetime.now().isoformat(),
                "scan_result": result
            }

            # Write JSON to file
            with open(resolved_output_file, 'w', encoding='utf-8') as f:
                json.dump(full_result, f, indent=2, ensure_ascii=False)

            file_size = os.path.getsize(resolved_output_file)
            logger.info(f"Saved job {job.job_id} result to {resolved_output_file} ({file_size} bytes)")

            # Convert to TOON format and save to temp file
            if is_toon_available():
                try:
                    logger.info(f"Converting scan result to TOON format for job {job.job_id}")
                    toon_output = convert_scan_result_to_toon(full_result)

                    if toon_output:
                        # Create TOON output file path (same name but with .toon extension)
                        toon_file_path = resolved_output_file.rsplit('.', 1)[0] + '.toon'

                        # Save TOON format
                        with open(toon_file_path, 'w', encoding='utf-8') as f:
                            f.write(toon_output)

                        toon_file_size = os.path.getsize(toon_file_path)
                        logger.info(f"Saved TOON format to {toon_file_path} ({toon_file_size} bytes)")

                        # Calculate token savings
                        savings = calculate_token_savings(full_result, toon_output)
                        logger.info(f"Token savings: {savings['savings_percent']}% "
                                  f"({savings['savings_tokens_estimate']} tokens)")

                        # Prepare for AI analysis (future feature)
                        # Use JSON format for AI payload to ensure jq compatibility
                        ai_payload = prepare_toon_for_ai_analysis(
                            toon_data=toon_output,
                            scan_metadata={
                                "job_id": job.job_id,
                                "tool_name": job.tool_name,
                                "scan_date": datetime.now().isoformat(),
                                "target": job.params.get("target", "unknown")
                            },
                            json_data=full_result,
                            output_format="json"
                        )

                        # Save AI-ready payload for future processing
                        ai_payload_path = resolved_output_file.rsplit('.', 1)[0] + '.ai-payload.json'
                        with open(ai_payload_path, 'w', encoding='utf-8') as f:
                            json.dump(ai_payload, f, indent=2, ensure_ascii=False)

                        logger.info(f"Saved AI-ready payload to {ai_payload_path} (JSON format, jq-compatible)")
                        logger.info("AI payload ready for future LLM analysis (API key integration pending)")

                    else:
                        logger.warning("TOON conversion returned None, skipping TOON output")

                except Exception as e:
                    logger.error(f"Error during TOON conversion: {str(e)}")
                    logger.error(traceback.format_exc())
                    # Don't raise - TOON conversion failure shouldn't fail the job
            else:
                logger.info("TOON converter not available, skipping TOON format generation")

        except Exception as e:
            logger.error(f"Error saving job result: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job"""
        job = self.get_job(job_id)
        if not job:
            return False

        if job.status in [JobStatus.PENDING, JobStatus.RUNNING]:
            job.status = JobStatus.CANCELLED
            job.completed_at = datetime.now()
            logger.info(f"Job {job_id} cancelled")
            return True

        return False

    def cleanup_old_jobs(self):
        """Remove jobs older than JOB_RETENTION_HOURS"""
        with self.lock:
            current_time = datetime.now()
            jobs_to_remove = []

            for job_id, job in self.jobs.items():
                age_hours = (current_time - job.created_at).total_seconds() / 3600
                if age_hours > JOB_RETENTION_HOURS:
                    jobs_to_remove.append(job_id)

            for job_id in jobs_to_remove:
                del self.jobs[job_id]
                logger.info(f"Cleaned up old job {job_id}")

            return len(jobs_to_remove)


# Global job manager instance
job_manager = JobManager(max_workers=MAX_WORKERS)

# ============================================================================
# PATH RESOLUTION
# ============================================================================

def resolve_windows_path(windows_path: str) -> str:
    """
    Convert Windows path to Linux mount path using configured WINDOWS_BASE and MOUNT_POINT

    Mount mapping: WINDOWS_BASE <-> MOUNT_POINT
    Example (with WINDOWS_BASE=F:/work and MOUNT_POINT=/mnt/work):
        F:/work/MyProject/file.txt -> /mnt/work/MyProject/file.txt
        F:\\work\\project\\scan.json -> /mnt/work/project/scan.json
        F:/work/scan-results.txt -> /mnt/work/scan-results.txt
    """
    # Normalize path separators
    normalized_path = windows_path.replace('\\', '/')

    logger.info(f"Resolving path: {windows_path} -> normalized: {normalized_path}")
    logger.info(f"Using mapping: {WINDOWS_BASE} -> {MOUNT_POINT}")

    # Normalize WINDOWS_BASE for comparison (remove trailing slash for consistency)
    windows_base_normalized = WINDOWS_BASE.replace('\\', '/').rstrip('/')
    mount_point_normalized = MOUNT_POINT.rstrip('/')

    # Build dynamic patterns based on environment variables
    # Support various formats: F:/work, f:/work, /f:/work (Git Bash)
    patterns = [
        (rf'^{re.escape(windows_base_normalized)}/', f'{mount_point_normalized}/'),  # F:/work/... -> /mnt/work/...
        (rf'^{re.escape(windows_base_normalized)}$', mount_point_normalized),        # F:/work -> /mnt/work
        (rf'^/{re.escape(windows_base_normalized.lower())}/', f'{mount_point_normalized}/'),  # Git bash: /f:/work/... -> /mnt/work/...
        (rf'^/{re.escape(windows_base_normalized.lower())}$', mount_point_normalized),        # Git bash: /f:/work -> /mnt/work
        (rf'^{re.escape(windows_base_normalized.lower())}/', f'{mount_point_normalized}/'),   # Lowercase: f:/work/... -> /mnt/work/...
        (rf'^{re.escape(windows_base_normalized.lower())}$', mount_point_normalized),         # Lowercase: f:/work -> /mnt/work
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

    # If path is already a valid Linux path starting with mount point, return as-is
    if normalized_path.startswith(mount_point_normalized):
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


def save_scan_output_to_file(output_file: str, stdout_data: str, format_type: str = "json") -> Dict[str, Any]:
    """
    Save scan output to file and return summary info

    Args:
        output_file: Windows path where to save the file (e.g., F:/work/results.json)
        stdout_data: The scan output data to save
        format_type: Output format (json, text, xml, etc.)

    Returns:
        Dict with file info and summary stats
    """
    try:
        # Resolve Windows path to Linux mount path
        resolved_output_path = resolve_windows_path(output_file)

        # Ensure directory exists
        output_dir = os.path.dirname(resolved_output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Write output to file
        with open(resolved_output_path, 'w', encoding='utf-8') as f:
            f.write(stdout_data)

        file_size = os.path.getsize(resolved_output_path)

        # Generate summary based on format
        summary = {"total_lines": len(stdout_data.splitlines())}

        if format_type == "json" and stdout_data:
            try:
                parsed = json.loads(stdout_data)
                if isinstance(parsed, dict):
                    # Semgrep format
                    if "results" in parsed:
                        summary["total_findings"] = len(parsed["results"])
                        # Count by severity
                        severity_counts = {}
                        for result in parsed["results"]:
                            sev = result.get("extra", {}).get("severity", "UNKNOWN")
                            severity_counts[sev] = severity_counts.get(sev, 0) + 1
                        summary["by_severity"] = severity_counts
                    if "errors" in parsed:
                        summary["total_errors"] = len(parsed["errors"])
                    # npm audit format
                    if "vulnerabilities" in parsed:
                        summary["vulnerabilities"] = parsed["vulnerabilities"]
            except json.JSONDecodeError:
                logger.warning("Could not parse JSON output for summary")

        logger.info(f"✓ Scan output saved to {resolved_output_path} ({file_size} bytes)")

        return {
            "file_saved": True,
            "linux_path": resolved_output_path,
            "windows_path": output_file,
            "file_size_bytes": file_size,
            "summary": summary
        }

    except Exception as e:
        logger.error(f"Error saving output to file: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "file_saved": False,
            "error": str(e)
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
# RESULT VALIDATION AND ACCURACY VERIFICATION
# ============================================================================

def calculate_checksum(data: str) -> str:
    """Calculate SHA256 checksum of result data"""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def validate_scan_result(result: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
    """
    Validate scan results for accuracy and completeness

    Args:
        result: Raw scan result dictionary
        tool_name: Name of the security tool

    Returns:
        Validation report with status and details
    """
    validation = {
        "valid": True,
        "warnings": [],
        "errors": [],
        "checksum": None,
        "size_bytes": 0
    }

    if not ENABLE_RESULT_VALIDATION:
        return validation

    try:
        # Check if result has required fields
        if not result.get("success"):
            validation["warnings"].append("Scan reported non-success status")

        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")

        # Calculate checksum for result verification
        if ENABLE_CHECKSUM_VERIFICATION and stdout:
            validation["checksum"] = calculate_checksum(stdout)

        # Check minimum result size
        validation["size_bytes"] = len(stdout) + len(stderr)
        if validation["size_bytes"] < MIN_RESULT_SIZE_BYTES:
            validation["warnings"].append(f"Result size ({validation['size_bytes']} bytes) below minimum threshold ({MIN_RESULT_SIZE_BYTES} bytes)")

        # Tool-specific validation
        if tool_name in ["semgrep", "bandit", "eslint"]:
            # Check for JSON output
            if stdout and not (stdout.strip().startswith("{") or stdout.strip().startswith("[")):
                validation["warnings"].append("Expected JSON output not detected")

        # Check for common error patterns
        error_patterns = [
            "command not found",
            "permission denied",
            "no such file or directory",
            "fatal error",
            "cannot allocate memory"
        ]

        combined_output = (stdout + stderr).lower()
        for pattern in error_patterns:
            if pattern in combined_output:
                validation["errors"].append(f"Error pattern detected: {pattern}")
                validation["valid"] = False

        # Check for timeout with no partial results
        if result.get("timed_out") and not result.get("partial_results"):
            validation["warnings"].append("Scan timed out with no partial results")

    except Exception as e:
        validation["errors"].append(f"Validation failed: {str(e)}")
        validation["valid"] = False

    return validation


def check_process_health() -> Dict[str, Any]:
    """
    Check process health and resource usage

    Returns:
        Process health metrics
    """
    try:
        process = psutil.Process()

        # Get memory info
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / (1024 * 1024)

        # Get CPU usage
        cpu_percent = process.cpu_percent(interval=0.1)

        # Check if approaching memory limit
        memory_warning = memory_mb > (PROCESS_MEMORY_LIMIT_MB * 0.9)

        return {
            "healthy": not memory_warning,
            "memory_mb": round(memory_mb, 2),
            "memory_limit_mb": PROCESS_MEMORY_LIMIT_MB,
            "memory_percent": round((memory_mb / PROCESS_MEMORY_LIMIT_MB) * 100, 2),
            "cpu_percent": round(cpu_percent, 2),
            "num_threads": process.num_threads(),
            "warnings": ["Memory usage above 90% threshold"] if memory_warning else []
        }
    except Exception as e:
        logger.error(f"Error checking process health: {e}")
        return {
            "healthy": False,
            "error": str(e)
        }


def retry_with_backoff(func, max_attempts: int = MAX_RETRY_ATTEMPTS, *args, **kwargs) -> Dict[str, Any]:
    """
    Retry a function with exponential backoff

    Args:
        func: Function to retry
        max_attempts: Maximum retry attempts
        *args, **kwargs: Arguments to pass to the function

    Returns:
        Function result or error dict
    """
    global scan_stats

    last_error = None

    for attempt in range(max_attempts):
        try:
            result = func(*args, **kwargs)

            # Validate result
            tool_name = kwargs.get("tool_name", "unknown") if kwargs else "unknown"
            validation = validate_scan_result(result, tool_name)

            # If result is valid or this is the last attempt, return it
            if validation["valid"] or attempt == max_attempts - 1:
                result["validation"] = validation
                result["retry_attempt"] = attempt + 1

                if attempt > 0:
                    with scan_stats_lock:
                        scan_stats["retried_scans"] = scan_stats.get("retried_scans", 0) + 1
                    logger.info(f"Scan succeeded on retry attempt {attempt + 1}/{max_attempts}")

                return result

            # Result invalid, retry
            logger.warning(f"Scan result validation failed on attempt {attempt + 1}/{max_attempts}: {validation['errors']}")
            last_error = validation["errors"]

            # Calculate backoff delay
            if attempt < max_attempts - 1:
                delay = RETRY_BACKOFF_BASE ** attempt
                logger.info(f"Retrying after {delay}s backoff...")
                time.sleep(delay)

        except Exception as e:
            last_error = str(e)
            logger.error(f"Scan failed on attempt {attempt + 1}/{max_attempts}: {e}")

            if attempt < max_attempts - 1:
                delay = RETRY_BACKOFF_BASE ** attempt
                logger.info(f"Retrying after {delay}s backoff...")
                time.sleep(delay)

    # All attempts failed
    return {
        "success": False,
        "stdout": "",
        "stderr": f"All {max_attempts} retry attempts failed. Last error: {last_error}",
        "return_code": -1,
        "error": last_error,
        "retry_attempt": max_attempts
    }


# ============================================================================
# ERROR CATEGORIZATION AND ENHANCED REPORTING
# ============================================================================

class ErrorCategory(Enum):
    """Error category classification"""
    TOOL_NOT_FOUND = "tool_not_found"
    PERMISSION_DENIED = "permission_denied"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    RESOURCE_LIMIT = "resource_limit"
    INVALID_INPUT = "invalid_input"
    TOOL_ERROR = "tool_error"
    PROCESS_CRASH = "process_crash"
    UNKNOWN = "unknown"


def categorize_error(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Categorize errors for better debugging and remediation

    Args:
        result: Scan result dictionary

    Returns:
        Error categorization report
    """
    error_info = {
        "category": ErrorCategory.UNKNOWN.value,
        "severity": "medium",
        "remediation_hint": "Check logs for more details",
        "retryable": True
    }

    if result.get("success"):
        error_info["category"] = None
        error_info["severity"] = None
        error_info["remediation_hint"] = None
        error_info["retryable"] = False
        return error_info

    stderr = result.get("stderr", "").lower()
    stdout = result.get("stdout", "").lower()
    combined = stderr + stdout

    # Categorize based on error patterns
    if "command not found" in combined or "not found" in combined:
        error_info.update({
            "category": ErrorCategory.TOOL_NOT_FOUND.value,
            "severity": "high",
            "remediation_hint": "Install the required security tool or check PATH environment variable",
            "retryable": False
        })

    elif "permission denied" in combined or "access denied" in combined:
        error_info.update({
            "category": ErrorCategory.PERMISSION_DENIED.value,
            "severity": "high",
            "remediation_hint": "Check file/directory permissions or run with appropriate privileges",
            "retryable": False
        })

    elif result.get("timed_out") or "timeout" in combined:
        error_info.update({
            "category": ErrorCategory.TIMEOUT.value,
            "severity": "medium",
            "remediation_hint": "Increase timeout value or reduce scan scope",
            "retryable": True
        })

    elif "connection refused" in combined or "network" in combined or "dns" in combined:
        error_info.update({
            "category": ErrorCategory.NETWORK_ERROR.value,
            "severity": "medium",
            "remediation_hint": "Check network connectivity and firewall settings",
            "retryable": True
        })

    elif "memory" in combined or "resource" in combined or "too many" in combined:
        error_info.update({
            "category": ErrorCategory.RESOURCE_LIMIT.value,
            "severity": "high",
            "remediation_hint": "Increase memory/resource limits or reduce scan scope",
            "retryable": True
        })

    elif "invalid" in combined or "syntax error" in combined or "bad argument" in combined:
        error_info.update({
            "category": ErrorCategory.INVALID_INPUT.value,
            "severity": "high",
            "remediation_hint": "Check input parameters and file paths",
            "retryable": False
        })

    elif result.get("return_code") == -1 or "crash" in combined or "segmentation fault" in combined:
        error_info.update({
            "category": ErrorCategory.PROCESS_CRASH.value,
            "severity": "critical",
            "remediation_hint": "Tool crashed - check tool version and report issue",
            "retryable": True
        })

    elif result.get("return_code", 0) != 0:
        error_info.update({
            "category": ErrorCategory.TOOL_ERROR.value,
            "severity": "medium",
            "remediation_hint": "Tool reported error - check tool logs and documentation",
            "retryable": True
        })

    return error_info


def enhance_result_with_metadata(result: Dict[str, Any], tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhance scan result with additional metadata for better analysis

    Args:
        result: Raw scan result
        tool_name: Name of the tool
        params: Scan parameters

    Returns:
        Enhanced result with metadata
    """
    enhanced = result.copy()

    # Add error categorization
    enhanced["error_info"] = categorize_error(result)

    # Add result validation
    if not result.get("validation"):
        enhanced["validation"] = validate_scan_result(result, tool_name)

    # Add process health at time of scan
    enhanced["process_health"] = check_process_health()

    # Add execution metadata
    enhanced["metadata"] = {
        "tool_name": tool_name,
        "scan_params": params,
        "timestamp": datetime.now().isoformat(),
        "multiprocessing_enabled": USE_MULTIPROCESSING,
        "max_parallel_scans": MAX_PARALLEL_SCANS,
        "retry_enabled": MAX_RETRY_ATTEMPTS > 1
    }

    return enhanced


def execute_scan_with_retry(scan_function, params: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
    """
    Execute a scan with retry logic and enhanced error handling

    Args:
        scan_function: The scan function to execute
        params: Scan parameters
        tool_name: Name of the tool

    Returns:
        Enhanced scan result with validation and error categorization
    """
    # Wrap the scan function for retry logic
    def wrapped_scan():
        return scan_function(params)

    # Execute with retry if enabled
    if MAX_RETRY_ATTEMPTS > 1:
        result = retry_with_backoff(wrapped_scan, max_attempts=MAX_RETRY_ATTEMPTS, tool_name=tool_name)
    else:
        result = wrapped_scan()

    # Enhance result with metadata and error categorization
    enhanced_result = enhance_result_with_metadata(result, tool_name, params)

    return enhanced_result


def run_scan_in_background(tool_name: str, params: Dict[str, Any], scan_function) -> Dict[str, Any]:
    """
    Helper function to run any scan in the background with enhanced multi-process support

    Args:
        tool_name: Name of the tool (e.g., 'semgrep', 'bandit')
        params: Scan parameters
        scan_function: Function that performs the actual scan and returns results

    Returns:
        Response dict with job information
    """
    try:
        # Get output_file from params or use default
        output_file = params.get("output_file", None)

        # Create job
        job = job_manager.create_job(tool_name, params, output_file)

        # Submit job for background execution with enhanced error handling
        # The execute_scan_with_retry wrapper will handle retries and error categorization
        job_manager.submit_job(job, execute_scan_with_retry, scan_function, params, tool_name)

        return {
            "success": True,
            "message": f"Scan job submitted successfully (multi-process mode: {USE_MULTIPROCESSING})",
            "job_id": job.job_id,
            "job_status": job.status.value,
            "output_file": job.output_file,
            "check_status_url": f"/api/jobs/{job.job_id}",
            "get_result_url": f"/api/jobs/{job.job_id}/result",
            "multiprocessing_enabled": USE_MULTIPROCESSING,
            "max_retry_attempts": MAX_RETRY_ATTEMPTS
        }

    except Exception as e:
        logger.error(f"Error submitting background job: {str(e)}")
        logger.error(traceback.format_exc())
        raise


# ============================================================================
# SAST TOOL ENDPOINTS
# ============================================================================

def _semgrep_scan(params: Dict[str, Any]) -> Dict[str, Any]:
    """Internal function to execute semgrep scan"""
    target = params.get("target", ".")
    config = params.get("config", "auto")
    lang = params.get("lang", "")
    severity = params.get("severity", "")
    output_format = params.get("output_format", "json")
    additional_args = params.get("additional_args", "")

    # Resolve Windows path to Linux mount path
    resolved_target = resolve_windows_path(target)

    command = f"semgrep scan --config={config}"

    if lang:
        command += f" --lang={lang}"

    if severity:
        command += f" --severity={severity}"

    command += f" --{output_format}"

    if additional_args:
        command += f" {additional_args}"

    command += f" {resolved_target}"

    result = execute_command(command, timeout=SEMGREP_TIMEOUT)

    # Add path resolution info to result
    result["original_path"] = target
    result["resolved_path"] = resolved_target

    # Try to parse JSON output for summary
    summary = {}
    if output_format == "json" and result["stdout"]:
        try:
            parsed = json.loads(result["stdout"])
            result["parsed_output"] = parsed
            if "results" in parsed:
                summary["total_findings"] = len(parsed["results"])
            if "errors" in parsed:
                summary["total_errors"] = len(parsed["errors"])
        except:
            pass

    result["summary"] = summary
    return result


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
    - output_file: Path to save results (Windows format: F:/path/file.json)
    - additional_args: Additional Semgrep arguments
    - background: Run in background (default: True)
    """
    try:
        params = request.json
        background = params.get("background", True)

        # Run in background by default
        if background:
            result = run_scan_in_background("semgrep", params, _semgrep_scan)
            return jsonify(result)

        # Legacy synchronous mode
        else:
            result = _semgrep_scan(params)
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

        result = execute_command(command, timeout=BANDIT_TIMEOUT)

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

        result = execute_command(command, timeout=TRUFFLEHOG_TIMEOUT)

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
# ADDITIONAL KALI LINUX SECURITY TOOLS
# ============================================================================

def _nikto_scan(params: Dict[str, Any]) -> Dict[str, Any]:
    """Internal function to execute nikto scan"""
    target = params.get("target", "")
    port = params.get("port", "80")
    ssl = params.get("ssl", False)
    output_format = params.get("output_format", "txt")
    output_file = params.get("output_file", "")
    additional_args = params.get("additional_args", "")

    if not target:
        return {"error": "Target parameter is required", "success": False}

    # Resolve output file path if specified
    resolved_output_file = ""
    if output_file:
        resolved_output_file = resolve_windows_path(output_file)

    command = f"nikto -h {target} -p {port}"

    if ssl:
        command += " -ssl"

    if resolved_output_file:
        command += f" -Format {output_format} -output {resolved_output_file}"

    if additional_args:
        command += f" {additional_args}"

    result = execute_command(command, timeout=NIKTO_TIMEOUT)

    # Add path info
    if output_file:
        result["output_file_original"] = output_file
        result["output_file_resolved"] = resolved_output_file

    # Read output file if specified
    if resolved_output_file and os.path.exists(resolved_output_file):
        try:
            with open(resolved_output_file, 'r') as f:
                result["file_content"] = f.read()
        except Exception as e:
            logger.warning(f"Error reading output file: {e}")

    result["summary"] = {"target": target, "port": port}
    return result


@app.route("/api/web/nikto", methods=["POST"])
def nikto():
    """
    Execute Nikto web server scanner

    Parameters:
    - target: Target host (IP or domain)
    - port: Port to scan (default: 80)
    - ssl: Use SSL/HTTPS (boolean)
    - output_format: Output format (txt, html, csv, xml)
    - output_file: Path to save output file
    - additional_args: Additional Nikto arguments
    - background: Run in background (default: True)
    """
    try:
        params = request.json
        background = params.get("background", True)

        # Run in background by default
        if background:
            result = run_scan_in_background("nikto", params, _nikto_scan)
            return jsonify(result)

        # Legacy synchronous mode
        else:
            result = _nikto_scan(params)
            return jsonify(result)

    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/network/nmap", methods=["POST"])
def nmap():
    """
    Execute Nmap network/port scanner

    Parameters:
    - target: Target host(s) to scan (IP, domain, or CIDR)
    - scan_type: Scan type (default: -sV for version detection)
                 Options: -sS (SYN), -sT (TCP Connect), -sU (UDP), -sV (Version),
                         -sC (Script scan), -A (Aggressive), -sn (Ping scan)
    - ports: Port specification (e.g., "80,443" or "1-1000")
    - output_format: Output format (normal, xml, grepable)
    - output_file: Path to save output
    - additional_args: Additional Nmap arguments
    """
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sV")
        ports = params.get("ports", "")
        output_format = params.get("output_format", "normal")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        # Resolve output file path if specified
        resolved_output_file = ""
        if output_file:
            resolved_output_file = resolve_windows_path(output_file)

        command = f"nmap {scan_type}"

        if ports:
            command += f" -p {ports}"

        if resolved_output_file:
            if output_format == "xml":
                command += f" -oX {resolved_output_file}"
            elif output_format == "grepable":
                command += f" -oG {resolved_output_file}"
            else:
                command += f" -oN {resolved_output_file}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target}"

        result = execute_command(command, timeout=NMAP_TIMEOUT)

        # Add path info
        if output_file:
            result["output_file_original"] = output_file
            result["output_file_resolved"] = resolved_output_file

        # Read output file if specified
        if resolved_output_file and os.path.exists(resolved_output_file):
            try:
                with open(resolved_output_file, 'r') as f:
                    result["file_content"] = f.read()
            except Exception as e:
                logger.warning(f"Error reading output file: {e}")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/web/sqlmap", methods=["POST"])
def sqlmap():
    """
    Execute SQLMap for SQL injection testing

    Parameters:
    - target: Target URL to test
    - data: POST data string
    - cookie: HTTP Cookie header value
    - level: Level of tests (1-5, default: 1)
    - risk: Risk of tests (1-3, default: 1)
    - batch: Never ask for user input, use default behavior (boolean)
    - output_dir: Directory to save output files
    - additional_args: Additional SQLMap arguments
    """
    try:
        params = request.json
        target = params.get("target", "")
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        level = params.get("level", "1")
        risk = params.get("risk", "1")
        batch = params.get("batch", True)
        output_dir = params.get("output_dir", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        # Resolve output directory path if specified
        resolved_output_dir = ""
        if output_dir:
            resolved_output_dir = resolve_windows_path(output_dir)

        command = f"sqlmap -u '{target}' --level={level} --risk={risk}"

        if batch:
            command += " --batch"

        if data:
            command += f" --data='{data}'"

        if cookie:
            command += f" --cookie='{cookie}'"

        if resolved_output_dir:
            command += f" --output-dir={resolved_output_dir}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=SQLMAP_TIMEOUT)

        # Add path info
        if output_dir:
            result["output_dir_original"] = output_dir
            result["output_dir_resolved"] = resolved_output_dir

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/web/wpscan", methods=["POST"])
def wpscan():
    """
    Execute WPScan WordPress security scanner

    Parameters:
    - target: Target WordPress URL
    - enumerate: What to enumerate (u: users, p: plugins, t: themes, vp: vulnerable plugins)
    - api_token: WPScan API token for vulnerability data
    - output_file: Path to save output (JSON format)
    - additional_args: Additional WPScan arguments
    """
    try:
        params = request.json
        target = params.get("target", "")
        enumerate = params.get("enumerate", "vp")
        api_token = params.get("api_token", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        # Resolve output file path if specified
        resolved_output_file = ""
        if output_file:
            resolved_output_file = resolve_windows_path(output_file)

        command = f"wpscan --url {target}"

        if enumerate:
            command += f" --enumerate {enumerate}"

        if api_token:
            command += f" --api-token {api_token}"

        if resolved_output_file:
            command += f" --output {resolved_output_file} --format json"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=WPSCAN_TIMEOUT)

        # Add path info
        if output_file:
            result["output_file_original"] = output_file
            result["output_file_resolved"] = resolved_output_file

        # Read output file if specified
        if resolved_output_file and os.path.exists(resolved_output_file):
            try:
                with open(resolved_output_file, 'r') as f:
                    result["parsed_output"] = json.load(f)
            except Exception as e:
                logger.warning(f"Error reading output file: {e}")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/web/dirb", methods=["POST"])
def dirb():
    """
    Execute DIRB web content scanner

    Parameters:
    - target: Target URL to scan
    - wordlist: Path to wordlist file (default: /usr/share/dirb/wordlists/common.txt)
    - extensions: File extensions to check (e.g., "php,html,js")
    - output_file: Path to save output
    - additional_args: Additional DIRB arguments
    """
    try:
        params = request.json
        target = params.get("target", "")
        wordlist = params.get("wordlist", "/usr/share/dirb/wordlists/common.txt")
        extensions = params.get("extensions", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        # Resolve output file path if specified
        resolved_output_file = ""
        if output_file:
            resolved_output_file = resolve_windows_path(output_file)

        command = f"dirb {target} {wordlist}"

        if extensions:
            command += f" -X {extensions}"

        if resolved_output_file:
            command += f" -o {resolved_output_file}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=DIRB_TIMEOUT)

        # Add path info
        if output_file:
            result["output_file_original"] = output_file
            result["output_file_resolved"] = resolved_output_file

        # Read output file if specified
        if resolved_output_file and os.path.exists(resolved_output_file):
            try:
                with open(resolved_output_file, 'r') as f:
                    result["file_content"] = f.read()
            except Exception as e:
                logger.warning(f"Error reading output file: {e}")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/system/lynis", methods=["POST"])
def lynis():
    """
    Execute Lynis security auditing tool for Unix/Linux systems

    Parameters:
    - target: Target directory or system to audit (default: system audit)
    - audit_mode: Audit mode (system, dockerfile)
    - quick: Quick scan mode (boolean)
    - log_file: Path to save log file
    - report_file: Path to save report file
    - additional_args: Additional Lynis arguments
    """
    try:
        params = request.json
        target = params.get("target", "")
        audit_mode = params.get("audit_mode", "system")
        quick = params.get("quick", False)
        log_file = params.get("log_file", "")
        report_file = params.get("report_file", "")
        additional_args = params.get("additional_args", "")

        # Resolve path if provided
        resolved_target = ""
        if target:
            resolved_target = resolve_windows_path(target)

        # Resolve log/report file paths if provided
        resolved_log_file = ""
        resolved_report_file = ""
        if log_file:
            resolved_log_file = resolve_windows_path(log_file)
        if report_file:
            resolved_report_file = resolve_windows_path(report_file)

        command = f"lynis audit {audit_mode}"

        if audit_mode == "dockerfile" and resolved_target:
            command += f" {resolved_target}"

        if quick:
            command += " --quick"

        if resolved_log_file:
            command += f" --logfile {resolved_log_file}"

        if resolved_report_file:
            command += f" --report-file {resolved_report_file}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=LYNIS_TIMEOUT)

        # Add path info
        if target:
            result["target_original"] = target
            result["target_resolved"] = resolved_target
        if log_file:
            result["log_file_original"] = log_file
            result["log_file_resolved"] = resolved_log_file
        if report_file:
            result["report_file_original"] = report_file
            result["report_file_resolved"] = resolved_report_file

        # Read log/report files if specified
        if resolved_log_file and os.path.exists(resolved_log_file):
            try:
                with open(resolved_log_file, 'r') as f:
                    result["log_content"] = f.read()
            except Exception as e:
                logger.warning(f"Error reading log file: {e}")

        if resolved_report_file and os.path.exists(resolved_report_file):
            try:
                with open(resolved_report_file, 'r') as f:
                    result["report_content"] = f.read()
            except Exception as e:
                logger.warning(f"Error reading report file: {e}")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in lynis endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/dependencies/snyk", methods=["POST"])
def snyk():
    """
    Execute Snyk security scanner for dependencies and containers

    Parameters:
    - target: Path to project directory (default: current directory)
    - test_type: Type of test (test, container, iac, code)
    - severity_threshold: Minimum severity to report (low, medium, high, critical)
    - json_output: Output in JSON format (boolean)
    - output_file: Path to save output
    - additional_args: Additional Snyk arguments
    """
    try:
        params = request.json
        target = params.get("target", ".")
        test_type = params.get("test_type", "test")
        severity_threshold = params.get("severity_threshold", "")
        json_output = params.get("json_output", True)
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        # Resolve output file path if specified
        resolved_output_file = ""
        if output_file:
            resolved_output_file = resolve_windows_path(output_file)

        command = f"snyk {test_type} {resolved_target}"

        if json_output:
            command += " --json"

        if severity_threshold:
            command += f" --severity-threshold={severity_threshold}"

        if resolved_output_file:
            command += f" > {resolved_output_file}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=SNYK_TIMEOUT)

        # Add path resolution info
        result["original_path"] = target
        result["resolved_path"] = resolved_target
        if output_file:
            result["output_file_original"] = output_file
            result["output_file_resolved"] = resolved_output_file

        # Parse JSON output
        if json_output and result.get("stdout"):
            try:
                result["parsed_output"] = json.loads(result["stdout"])
            except:
                pass

        # Read output file if specified
        if resolved_output_file and os.path.exists(resolved_output_file):
            try:
                with open(resolved_output_file, 'r') as f:
                    content = f.read()
                    result["file_content"] = content
                    if json_output:
                        try:
                            result["parsed_output"] = json.loads(content)
                        except:
                            pass
            except Exception as e:
                logger.warning(f"Error reading output file: {e}")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in snyk endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/malware/clamav", methods=["POST"])
def clamav():
    """
    Execute ClamAV antivirus scanner

    Parameters:
    - target: Path to file or directory to scan
    - recursive: Scan directories recursively (boolean)
    - infected_only: Only show infected files (boolean)
    - output_file: Path to save scan log
    - additional_args: Additional ClamAV arguments
    """
    try:
        params = request.json
        target = params.get("target", "")
        recursive = params.get("recursive", True)
        infected_only = params.get("infected_only", False)
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        # Resolve Windows path to Linux mount path
        resolved_target = resolve_windows_path(target)

        # Resolve output file path if specified
        resolved_output_file = ""
        if output_file:
            resolved_output_file = resolve_windows_path(output_file)

        command = "clamscan"

        if recursive:
            command += " -r"

        if infected_only:
            command += " -i"

        if resolved_output_file:
            command += f" -l {resolved_output_file}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {resolved_target}"

        result = execute_command(command, timeout=CLAMAV_TIMEOUT)

        # Add path resolution info
        result["original_path"] = target
        result["resolved_path"] = resolved_target
        if output_file:
            result["output_file_original"] = output_file
            result["output_file_resolved"] = resolved_output_file

        # Read output file if specified
        if resolved_output_file and os.path.exists(resolved_output_file):
            try:
                with open(resolved_output_file, 'r') as f:
                    result["file_content"] = f.read()
            except Exception as e:
                logger.warning(f"Error reading output file: {e}")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in clamav endpoint: {str(e)}")
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


@app.route("/api/util/scan-project-structure", methods=["POST"])
def scan_project_structure():
    """
    Deeply scan project structure to find dependency files and project metadata.

    Parameters:
    - project_path: Path to project directory
    - deep_scan: Recursively scan subdirectories (boolean)
    - include_hidden: Include hidden files/directories (boolean)
    """
    try:
        params = request.json
        project_path = params.get("project_path", ".")
        deep_scan = params.get("deep_scan", True)
        include_hidden = params.get("include_hidden", False)

        # Resolve Windows path to Linux mount path
        resolved_path = resolve_windows_path(project_path)

        if not os.path.exists(resolved_path):
            return jsonify({
                "error": f"Project path does not exist: {resolved_path}",
                "original_path": project_path
            }), 404

        # Dependency file patterns
        dependency_files = {
            "python": ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock"],
            "nodejs": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
            "go": ["go.mod", "go.sum", "Gopkg.toml", "Gopkg.lock"],
            "ruby": ["Gemfile", "Gemfile.lock", ".ruby-version"],
            "java": ["pom.xml", "build.gradle", "build.gradle.kts", "gradle.properties"],
            "php": ["composer.json", "composer.lock"],
            "rust": ["Cargo.toml", "Cargo.lock"],
            "dotnet": ["*.csproj", "*.fsproj", "*.vbproj", "packages.config", "*.sln"],
            "terraform": ["*.tf", "terraform.tfvars", "terraform.tfstate"],
            "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"],
            "kubernetes": ["*.yaml", "*.yml"],
            "config": [".env", ".env.example", "config.json", "config.yaml", "config.yml"]
        }

        found_files = {}
        detected_types = set()
        scan_recommendations = {}

        # Walk the directory tree
        max_depth = 10 if deep_scan else 1

        for root, dirs, files in os.walk(resolved_path):
            # Calculate depth
            depth = root[len(resolved_path):].count(os.sep)
            if depth >= max_depth:
                dirs[:] = []  # Don't recurse deeper
                continue

            # Filter hidden directories
            if not include_hidden:
                dirs[:] = [d for d in dirs if not d.startswith('.')]

            # Check for dependency files
            for project_type, patterns in dependency_files.items():
                for pattern in patterns:
                    if '*' in pattern:
                        # Handle wildcard patterns
                        import fnmatch
                        matching_files = [f for f in files if fnmatch.fnmatch(f, pattern)]
                        for matched_file in matching_files:
                            file_path = os.path.join(root, matched_file)
                            rel_path = os.path.relpath(file_path, resolved_path)

                            if project_type not in found_files:
                                found_files[project_type] = []
                            found_files[project_type].append(rel_path)
                            detected_types.add(project_type)
                    else:
                        # Exact filename match
                        if pattern in files:
                            file_path = os.path.join(root, pattern)
                            rel_path = os.path.relpath(file_path, resolved_path)

                            if project_type not in found_files:
                                found_files[project_type] = []
                            found_files[project_type].append(rel_path)
                            detected_types.add(project_type)

        # Generate scan recommendations
        if "python" in detected_types:
            scan_recommendations["python"] = {
                "tools": ["bandit", "safety"],
                "targets": found_files.get("python", []),
                "commands": [
                    f"bandit -r {resolved_path}",
                    f"safety check -r {resolved_path}/requirements.txt" if any("requirements.txt" in f for f in found_files.get("python", [])) else None
                ]
            }

        if "nodejs" in detected_types:
            scan_recommendations["nodejs"] = {
                "tools": ["npm-audit", "eslint-security"],
                "targets": found_files.get("nodejs", []),
                "commands": [
                    f"npm audit --json" if any("package.json" in f for f in found_files.get("nodejs", [])) else None,
                    f"eslint {resolved_path}"
                ]
            }

        if "go" in detected_types:
            scan_recommendations["go"] = {
                "tools": ["gosec"],
                "targets": found_files.get("go", []),
                "commands": [f"gosec -fmt=json ./..."]
            }

        if "ruby" in detected_types:
            scan_recommendations["ruby"] = {
                "tools": ["brakeman"],
                "targets": found_files.get("ruby", []),
                "commands": [f"brakeman -p {resolved_path} -f json"]
            }

        if "terraform" in detected_types:
            scan_recommendations["terraform"] = {
                "tools": ["tfsec", "checkov"],
                "targets": found_files.get("terraform", []),
                "commands": [
                    f"tfsec {resolved_path} --format json",
                    f"checkov -d {resolved_path} -o json"
                ]
            }

        if "docker" in detected_types:
            scan_recommendations["docker"] = {
                "tools": ["trivy", "checkov"],
                "targets": found_files.get("docker", []),
                "commands": [
                    f"trivy config {resolved_path} --format json",
                    f"checkov -d {resolved_path} --framework dockerfile -o json"
                ]
            }

        # Universal scan recommendations
        scan_recommendations["universal"] = {
            "tools": ["semgrep", "trufflehog", "gitleaks"],
            "targets": [resolved_path],
            "commands": [
                f"semgrep scan --config=auto --json {resolved_path}",
                f"trufflehog filesystem {resolved_path} --json",
                f"gitleaks detect --source={resolved_path} --report-format=json"
            ]
        }

        return jsonify({
            "success": True,
            "project_path": project_path,
            "resolved_path": resolved_path,
            "detected_types": list(detected_types),
            "found_files": found_files,
            "scan_recommendations": scan_recommendations,
            "scan_statistics": {
                "total_dependency_files": sum(len(files) for files in found_files.values()),
                "project_types_detected": len(detected_types),
                "recommended_tools": list(set(
                    tool for rec in scan_recommendations.values()
                    for tool in rec.get("tools", [])
                ))
            }
        })

    except Exception as e:
        logger.error(f"Error scanning project structure: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/util/scan-stats", methods=["GET"])
def get_scan_stats():
    """Get current parallel scan statistics"""
    try:
        with scan_stats_lock:
            current_stats = scan_stats.copy()

        return jsonify({
            "success": True,
            "max_parallel_scans": MAX_PARALLEL_SCANS,
            "scan_wait_timeout_seconds": SCAN_WAIT_TIMEOUT,
            "statistics": current_stats,
            "slots_available": MAX_PARALLEL_SCANS - current_stats["active_scans"]
        })
    except Exception as e:
        logger.error(f"Error getting scan stats: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# BACKGROUND JOB MANAGEMENT ENDPOINTS
# ============================================================================

@app.route("/api/jobs", methods=["GET"])
def list_jobs():
    """List all background jobs with optional filtering"""
    try:
        status_filter = request.args.get("status", None)
        limit = int(request.args.get("limit", 100))

        jobs = job_manager.list_jobs(status_filter=status_filter, limit=limit)
        jobs_data = [job.to_dict() for job in jobs]

        return jsonify({
            "success": True,
            "total": len(jobs_data),
            "jobs": jobs_data
        })
    except Exception as e:
        logger.error(f"Error listing jobs: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/jobs/<job_id>", methods=["GET"])
def get_job_status(job_id: str):
    """Get the status of a specific job"""
    try:
        job = job_manager.get_job(job_id)

        if not job:
            return jsonify({"error": "Job not found"}), 404

        return jsonify({
            "success": True,
            "job": job.to_dict()
        })
    except Exception as e:
        logger.error(f"Error getting job status: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/jobs/<job_id>/result", methods=["GET"])
def get_job_result(job_id: str):
    """Get the result of a completed job"""
    try:
        job = job_manager.get_job(job_id)

        if not job:
            return jsonify({"error": "Job not found"}), 404

        if job.status == JobStatus.PENDING:
            return jsonify({
                "success": False,
                "status": "pending",
                "message": "Job is still pending"
            })

        if job.status == JobStatus.RUNNING:
            return jsonify({
                "success": False,
                "status": "running",
                "message": "Job is still running",
                "progress": job.progress
            })

        if job.status == JobStatus.FAILED:
            return jsonify({
                "success": False,
                "status": "failed",
                "error": job.error
            })

        if job.status == JobStatus.CANCELLED:
            return jsonify({
                "success": False,
                "status": "cancelled",
                "message": "Job was cancelled"
            })

        # Job completed - read result from file
        try:
            resolved_output_file = resolve_windows_path(job.output_file) if job.output_file.startswith('F:') else job.output_file

            with open(resolved_output_file, 'r', encoding='utf-8') as f:
                result_data = json.load(f)

            return jsonify({
                "success": True,
                "status": "completed",
                "job": job.to_dict(),
                "result": result_data
            })

        except FileNotFoundError:
            return jsonify({
                "success": False,
                "error": "Result file not found"
            }), 404

    except Exception as e:
        logger.error(f"Error getting job result: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
def cancel_job(job_id: str):
    """Cancel a running or pending job"""
    try:
        success = job_manager.cancel_job(job_id)

        if success:
            return jsonify({
                "success": True,
                "message": f"Job {job_id} cancelled"
            })
        else:
            return jsonify({
                "success": False,
                "message": "Job not found or cannot be cancelled"
            }), 400

    except Exception as e:
        logger.error(f"Error cancelling job: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/jobs/cleanup", methods=["POST"])
def cleanup_jobs():
    """Cleanup old jobs (admin endpoint)"""
    try:
        count = job_manager.cleanup_old_jobs()
        return jsonify({
            "success": True,
            "message": f"Cleaned up {count} old jobs"
        })
    except Exception as e:
        logger.error(f"Error cleaning up jobs: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/scan/statistics", methods=["GET"])
def get_scan_statistics():
    """
    Get detailed scan statistics and system health

    Returns comprehensive statistics about scan execution, process health,
    and multi-process backend performance
    """
    try:
        # Get scan statistics
        with scan_stats_lock:
            scan_statistics = dict(scan_stats)

        # Get process health
        process_health = check_process_health()

        # Calculate additional metrics
        total_scans = scan_statistics.get("total_scans", 0)
        completed_scans = scan_statistics.get("completed_scans", 0)
        failed_scans = scan_statistics.get("failed_scans", 0)
        retried_scans = scan_statistics.get("retried_scans", 0)

        success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
        retry_rate = (retried_scans / total_scans * 100) if total_scans > 0 else 0
        failure_rate = (failed_scans / total_scans * 100) if total_scans > 0 else 0

        # Get job statistics from job manager
        all_jobs = job_manager.list_jobs(limit=1000)
        jobs_by_status = {}
        for job in all_jobs:
            status = job.status.value
            jobs_by_status[status] = jobs_by_status.get(status, 0) + 1

        # System resource usage
        try:
            cpu_count = multiprocessing.cpu_count()
            system_memory = psutil.virtual_memory()
        except:
            cpu_count = "N/A"
            system_memory = None

        return jsonify({
            "success": True,
            "scan_statistics": scan_statistics,
            "metrics": {
                "success_rate_percent": round(success_rate, 2),
                "retry_rate_percent": round(retry_rate, 2),
                "failure_rate_percent": round(failure_rate, 2)
            },
            "job_statistics": {
                "total_jobs": len(all_jobs),
                "jobs_by_status": jobs_by_status
            },
            "process_health": process_health,
            "system_info": {
                "multiprocessing_enabled": USE_MULTIPROCESSING,
                "max_parallel_scans": MAX_PARALLEL_SCANS,
                "max_process_workers": MAX_PROCESS_WORKERS if USE_MULTIPROCESSING else "N/A",
                "max_retry_attempts": MAX_RETRY_ATTEMPTS,
                "cpu_count": cpu_count,
                "system_memory_total_gb": round(system_memory.total / (1024**3), 2) if system_memory else "N/A",
                "system_memory_available_gb": round(system_memory.available / (1024**3), 2) if system_memory else "N/A",
                "system_memory_percent": system_memory.percent if system_memory else "N/A"
            },
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting scan statistics: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# AI ANALYSIS ENDPOINTS (Future Feature)
# ============================================================================

@app.route("/api/analysis/ai-summary", methods=["POST"])
def ai_summary():
    """
    Generate AI-powered summary of scan results (Future Feature)

    Parameters:
    - job_id: Job ID to analyze
    - analysis_type: Type of analysis (full, quick, prioritization)
    - custom_prompt: Optional custom analysis prompt
    - include: List of sections to include (summary, remediation, priorities)
    """
    try:
        params = request.json
        job_id = params.get("job_id", "")
        analysis_type = params.get("analysis_type", "full")
        custom_prompt = params.get("custom_prompt", None)
        include_sections = params.get("include", ["summary", "remediation", "priorities"])

        if not job_id:
            return jsonify({"error": "job_id parameter is required"}), 400

        # Get job
        job = job_manager.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404

        if job.status != JobStatus.COMPLETED:
            return jsonify({
                "error": "Job not completed",
                "status": job.status.value
            }), 400

        # Load AI payload
        try:
            resolved_output_file = resolve_windows_path(job.output_file) if job.output_file.startswith('F:') else job.output_file
            ai_payload_path = resolved_output_file.rsplit('.', 1)[0] + '.ai-payload.json'

            with open(ai_payload_path, 'r', encoding='utf-8') as f:
                ai_payload = json.load(f)

            # Perform AI analysis (currently returns stub)
            analysis_result = analyze_scan_with_ai(ai_payload, custom_prompt=custom_prompt)

            return jsonify({
                "success": True,
                "job_id": job_id,
                "analysis_type": analysis_type,
                "analysis": analysis_result,
                "ai_configured": is_ai_configured()
            })

        except FileNotFoundError:
            return jsonify({
                "error": "AI payload file not found. Ensure TOON converter is installed and job completed successfully."
            }), 404

    except Exception as e:
        logger.error(f"Error in AI summary endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/analysis/summarize", methods=["POST"])
def summarize():
    """
    Generate basic statistical summary of scan results (no AI required)

    Parameters:
    - job_id: Job ID to summarize
    """
    try:
        params = request.json
        job_id = params.get("job_id", "")

        if not job_id:
            return jsonify({"error": "job_id parameter is required"}), 400

        # Get job
        job = job_manager.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404

        if job.status != JobStatus.COMPLETED:
            return jsonify({
                "error": "Job not completed",
                "status": job.status.value
            }), 400

        # Load scan results
        try:
            resolved_output_file = resolve_windows_path(job.output_file) if job.output_file.startswith('F:') else job.output_file

            with open(resolved_output_file, 'r', encoding='utf-8') as f:
                scan_results = json.load(f)

            # Generate summary
            summary = summarize_findings(scan_results)

            return jsonify({
                "success": True,
                "job_id": job_id,
                "summary": summary
            })

        except FileNotFoundError:
            return jsonify({"error": "Result file not found"}), 404

    except Exception as e:
        logger.error(f"Error in summarize endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/analysis/toon-status", methods=["GET"])
def toon_status():
    """Check TOON converter and AI analysis status"""
    try:
        return jsonify({
            "toon_available": is_toon_available(),
            "ai_configured": is_ai_configured(),
            "features": {
                "toon_conversion": is_toon_available(),
                "ai_analysis": is_ai_configured(),
                "statistical_summary": True
            },
            "message": "TOON conversion is " + ("enabled" if is_toon_available() else "disabled") +
                      ", AI analysis is " + ("configured" if is_ai_configured() else "not configured")
        })
    except Exception as e:
        logger.error(f"Error in toon-status endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/jobs/<job_id>/check", methods=["GET"])
def check_job_result_file(job_id: str):
    """
    Simple endpoint to check if a job result file exists
    Returns ok/not ok based on file existence
    """
    try:
        job = job_manager.get_job(job_id)

        if not job:
            return jsonify({
                "status": "not_ok",
                "exists": False,
                "message": "Job not found"
            })

        # Check job status
        if job.status == JobStatus.PENDING:
            return jsonify({
                "status": "not_ok",
                "exists": False,
                "job_status": "pending",
                "message": "Job is pending"
            })

        if job.status == JobStatus.RUNNING:
            return jsonify({
                "status": "not_ok",
                "exists": False,
                "job_status": "running",
                "message": "Job is still running"
            })

        if job.status == JobStatus.FAILED:
            return jsonify({
                "status": "not_ok",
                "exists": False,
                "job_status": "failed",
                "message": "Job failed",
                "error": job.error
            })

        if job.status == JobStatus.CANCELLED:
            return jsonify({
                "status": "not_ok",
                "exists": False,
                "job_status": "cancelled",
                "message": "Job was cancelled"
            })

        # Job is completed - check if result file exists
        if job.output_file:
            resolved_output_file = resolve_windows_path(job.output_file) if job.output_file.startswith('F:') else job.output_file
            file_exists = os.path.exists(resolved_output_file)

            if file_exists:
                file_size = os.path.getsize(resolved_output_file)
                return jsonify({
                    "status": "ok",
                    "exists": True,
                    "job_status": "completed",
                    "output_file": job.output_file,
                    "file_size_bytes": file_size,
                    "message": "Result file exists"
                })
            else:
                return jsonify({
                    "status": "not_ok",
                    "exists": False,
                    "job_status": "completed",
                    "message": "Job completed but result file not found"
                })
        else:
            return jsonify({
                "status": "not_ok",
                "exists": False,
                "job_status": "completed",
                "message": "Job completed but no output file specified"
            })

    except Exception as e:
        logger.error(f"Error checking job result file: {str(e)}")
        return jsonify({
            "status": "not_ok",
            "exists": False,
            "error": str(e)
        }), 500


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

    # Additional SAST tools
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

    # Kali Linux security tools
    kali_tools = {
        "nikto": "nikto -Version",
        "nmap": "nmap --version",
        "sqlmap": "sqlmap --version",
        "wpscan": "wpscan --version",
        "dirb": "which dirb",
        "lynis": "lynis --version",
        "snyk": "snyk --version",
        "clamscan": "clamscan --version"
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

    # Check Kali tools
    for tool, check_cmd in kali_tools.items():
        try:
            result = execute_command(check_cmd, timeout=10)
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False

    all_essential_available = all([tools_status.get(tool, False) for tool in essential_tools.keys()])
    available_count = sum(1 for available in tools_status.values() if available)
    total_count = len(tools_status)
    kali_tools_count = sum(1 for tool in kali_tools.keys() if tools_status.get(tool, False))

    # Get process health metrics
    process_health = check_process_health()

    # Get scan statistics
    with scan_stats_lock:
        scan_statistics = dict(scan_stats)

    return jsonify({
        "status": "healthy",
        "message": "SAST Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_available,
        "total_tools_available": available_count,
        "total_tools_count": total_count,
        "kali_tools_available": kali_tools_count,
        "kali_tools_total": len(kali_tools),
        "process_health": process_health,
        "scan_statistics": scan_statistics,
        "multiprocessing_enabled": USE_MULTIPROCESSING,
        "max_parallel_scans": MAX_PARALLEL_SCANS,
        "max_process_workers": MAX_PROCESS_WORKERS if USE_MULTIPROCESSING else "N/A",
        "version": "3.0.0"
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
    logger.info("Supported SAST tools: Semgrep, Bearer, Graudit, Bandit, Gosec, Brakeman, ESLint, TruffleHog, Gitleaks, Safety, npm audit, Checkov, tfsec, Trivy, OWASP Dependency-Check")
    logger.info("Supported Kali tools: Nikto, Nmap, SQLMap, WPScan, DIRB, Lynis, Snyk, ClamAV")

    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)
