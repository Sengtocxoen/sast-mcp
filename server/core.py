"""
Core execution, job management, path resolution, validation, and scan orchestration.
Used by all route modules. No Flask dependencies.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import traceback
import uuid
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime
from enum import Enum
from multiprocessing import Manager
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

from config import (
    COMMAND_TIMEOUT,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_PAGE_SIZE,
    ENABLE_CHECKSUM_VERIFICATION,
    ENABLE_RESULT_VALIDATION,
    FORCE_SYNC_SCANS,
    MAX_PARALLEL_SCANS,
    MAX_PROCESS_WORKERS,
    MAX_RETRY_ATTEMPTS,
    MAX_TIMEOUT,
    MAX_WORKERS,
    MIN_RESULT_SIZE_BYTES,
    MOUNT_POINT,
    PROCESS_MEMORY_LIMIT_MB,
    RETRY_BACKOFF_BASE,
    SCAN_WAIT_TIMEOUT,
    SYNC_RESPONSE_INCLUDE_FINDINGS,
    SYNC_RESPONSE_MAX_FINDINGS,
    USE_MULTIPROCESSING,
    WINDOWS_BASE,
)

from tools.toon_converter import (
    convert_scan_result_to_toon,
    create_ai_compact_format,
    is_toon_available,
    calculate_token_savings,
    prepare_toon_for_ai_analysis,
)
from tools.ai_analysis import (
    analyze_scan_results,
    create_toon_analysis_result,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Multiprocess / threading state
# ---------------------------------------------------------------------------
mp_manager = Manager() if USE_MULTIPROCESSING else None
if USE_MULTIPROCESSING:
    import multiprocessing
    scan_semaphore = multiprocessing.Semaphore(MAX_PARALLEL_SCANS)
    scan_stats_lock = multiprocessing.Lock()
    scan_stats = mp_manager.dict({
        "active_scans": 0, "total_scans": 0, "queued_scans": 0,
        "completed_scans": 0, "failed_scans": 0, "retried_scans": 0, "process_crashes": 0,
    })
else:
    scan_semaphore = threading.Semaphore(MAX_PARALLEL_SCANS)
    scan_stats_lock = threading.Lock()
    scan_stats = {
        "active_scans": 0, "total_scans": 0, "queued_scans": 0,
        "completed_scans": 0, "failed_scans": 0, "retried_scans": 0, "process_crashes": 0,
    }


def acquire_scan_slot(timeout: int = SCAN_WAIT_TIMEOUT) -> bool:
    with scan_stats_lock:
        scan_stats["queued_scans"] += 1
    logger.info(f"Attempting to acquire scan slot (timeout={timeout}s, active: {scan_stats['active_scans']}/{MAX_PARALLEL_SCANS})")
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


def release_scan_slot() -> None:
    with scan_stats_lock:
        scan_stats["active_scans"] = max(0, scan_stats["active_scans"] - 1)
    scan_semaphore.release()
    logger.info(f"Scan slot released (active: {scan_stats['active_scans']}/{MAX_PARALLEL_SCANS})")


# ---------------------------------------------------------------------------
# Job management
# ---------------------------------------------------------------------------
class JobStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Job:
    def __init__(self, job_id: str, tool_name: str, params: Dict[str, Any], output_file: Optional[str] = None):
        self.job_id = job_id
        self.tool_name = tool_name
        self.params = params
        self.status = JobStatus.PENDING
        self.created_at = datetime.now()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.output_file = output_file
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self.progress = 0

    def to_dict(self) -> Dict[str, Any]:
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
            "duration_seconds": self._duration(),
        }

    def _duration(self) -> Optional[float]:
        if self.started_at:
            end = self.completed_at if self.completed_at else datetime.now()
            return (end - self.started_at).total_seconds()
        return None


def _resolve_path(p: str) -> str:
    return resolve_windows_path(p) if p and p.startswith("F:") else p


def _save_job_result(job: Job, result: Dict[str, Any]) -> None:
    try:
        resolved = resolve_windows_path(job.output_file) if job.output_file.startswith("F:") else job.output_file
        os.makedirs(os.path.dirname(resolved), exist_ok=True)
        full_result = {
            "job_id": job.job_id,
            "tool_name": job.tool_name,
            "scan_params": job.params,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": datetime.now().isoformat(),
            "scan_result": result,
        }
        with open(resolved, "w", encoding="utf-8") as f:
            json.dump(full_result, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved job {job.job_id} result to {resolved}")
        if is_toon_available():
            try:
                toon_output = convert_scan_result_to_toon(full_result)
                if toon_output:
                    toon_path = resolved.rsplit(".", 1)[0] + ".toon"
                    with open(toon_path, "w", encoding="utf-8") as f:
                        f.write(toon_output)
                    ai_compact = create_ai_compact_format(full_result)
                    if ai_compact:
                        compact_path = resolved.rsplit(".", 1)[0] + ".ai-compact.json"
                        with open(compact_path, "w", encoding="utf-8") as f:
                            json.dump(ai_compact, f, ensure_ascii=False)
            except Exception as e:
                logger.warning(f"TOON/compact save failed: {e}")
        try:
            ai_analysis = analyze_scan_results(full_result)
            toon_analysis = create_toon_analysis_result(full_result, ai_analysis, include_raw_findings=True, max_findings=50)
            analysis_path = resolved.rsplit(".", 1)[0] + ".toon-analysis.json"
            with open(analysis_path, "w", encoding="utf-8") as f:
                json.dump(toon_analysis, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"TOON analysis save failed: {e}")
    except Exception as e:
        logger.error(f"Error saving job result: {e}")
        traceback.print_exc()
        raise


class JobManager:
    def __init__(self, max_workers: int = MAX_WORKERS):
        self.jobs: Dict[str, Job] = {}
        self.lock = threading.Lock()
        self.executor = (
            ProcessPoolExecutor(max_workers=MAX_PROCESS_WORKERS)
            if USE_MULTIPROCESSING
            else ThreadPoolExecutor(max_workers=max_workers)
        )
        os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
        logger.info(f"JobManager initialized (multiprocess={USE_MULTIPROCESSING})")

    def create_job(self, tool_name: str, params: Dict[str, Any], output_file: Optional[str] = None) -> Job:
        job_id = str(uuid.uuid4())
        if not output_file:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(DEFAULT_OUTPUT_DIR, f"{tool_name}_{ts}_{job_id[:8]}.json")
        job = Job(job_id, tool_name, params, output_file)
        with self.lock:
            self.jobs[job_id] = job
        logger.info(f"Created job {job_id} for {tool_name}")
        return job

    def get_job(self, job_id: str) -> Optional[Job]:
        with self.lock:
            return self.jobs.get(job_id)

    def list_jobs(self, status_filter: Optional[str] = None, limit: int = 100) -> List[Job]:
        with self.lock:
            jobs = list(self.jobs.values())
        if status_filter:
            jobs = [j for j in jobs if j.status.value == status_filter]
        jobs.sort(key=lambda x: x.created_at, reverse=True)
        return jobs[:limit]

    def submit_job(self, job: Job, work_func: Any, *args: Any, **kwargs: Any) -> None:
        job.status = JobStatus.PENDING
        self.executor.submit(self._run_job, job, work_func, *args, **kwargs)

    def _run_job(self, job: Job, work_func: Any, *args: Any, **kwargs: Any) -> None:
        try:
            if not acquire_scan_slot(timeout=SCAN_WAIT_TIMEOUT):
                job.status = JobStatus.FAILED
                job.completed_at = datetime.now()
                job.error = f"Timeout waiting for scan slot after {SCAN_WAIT_TIMEOUT}s"
                with scan_stats_lock:
                    scan_stats["failed_scans"] = scan_stats.get("failed_scans", 0) + 1
                return
            try:
                job.status = JobStatus.RUNNING
                job.started_at = datetime.now()
                result = work_func(*args, **kwargs)
                _save_job_result(job, result)
                job.status = JobStatus.COMPLETED
                job.completed_at = datetime.now()
                job.result = {"success": True, "output_file": job.output_file, "summary": result.get("summary", {})}
                with scan_stats_lock:
                    scan_stats["completed_scans"] = scan_stats.get("completed_scans", 0) + 1
            finally:
                release_scan_slot()
        except Exception as e:
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now()
            job.error = str(e)
            logger.error(f"Job {job.job_id} failed: {e}")
            traceback.print_exc()
            with scan_stats_lock:
                scan_stats["failed_scans"] = scan_stats.get("failed_scans", 0) + 1

    def cancel_job(self, job_id: str) -> bool:
        job = self.get_job(job_id)
        if not job or job.status not in (JobStatus.PENDING, JobStatus.RUNNING):
            return False
        job.status = JobStatus.CANCELLED
        job.completed_at = datetime.now()
        logger.info(f"Job {job_id} cancelled")
        return True

    def cleanup_old_jobs(self) -> int:
        from config import JOB_RETENTION_HOURS
        with self.lock:
            now = datetime.now()
            to_remove = [jid for jid, j in self.jobs.items() if (now - j.created_at).total_seconds() / 3600 > JOB_RETENTION_HOURS]
            for jid in to_remove:
                del self.jobs[jid]
                logger.info(f"Cleaned up job {jid}")
        return len(to_remove)


job_manager = JobManager(max_workers=MAX_WORKERS)


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
def resolve_windows_path(windows_path: str) -> str:
    normalized = windows_path.replace("\\", "/")
    base = WINDOWS_BASE.replace("\\", "/").rstrip("/")
    mount = MOUNT_POINT.rstrip("/")
    patterns = [
        (rf"^{re.escape(base)}/", f"{mount}/"),
        (rf"^{re.escape(base)}$", mount),
        (rf"^/{re.escape(base.lower())}/", f"{mount}/"),
        (rf"^/{re.escape(base.lower())}$", mount),
        (rf"^{re.escape(base.lower())}/", f"{mount}/"),
        (rf"^{re.escape(base.lower())}$", mount),
    ]
    for pattern, repl in patterns:
        if re.match(pattern, normalized, re.IGNORECASE):
            linux_path = re.sub(pattern, repl, normalized, flags=re.IGNORECASE)
            return linux_path
    if normalized.startswith(mount):
        return normalized
    if normalized.startswith("/") and os.path.exists(normalized):
        return normalized
    return windows_path


def verify_mount() -> Dict[str, Any]:
    issues = []
    if not os.path.exists(MOUNT_POINT):
        issues.append(f"Mount point does not exist: {MOUNT_POINT}")
    else:
        try:
            if not os.path.ismount(MOUNT_POINT) and not os.listdir(MOUNT_POINT):
                issues.append(f"Mount point appears empty: {MOUNT_POINT}")
        except Exception as e:
            issues.append(str(e))
    return {"is_mounted": len(issues) == 0, "mount_point": MOUNT_POINT, "windows_base": WINDOWS_BASE, "issues": issues}


def save_scan_output_to_file(output_file: str, stdout_data: str, format_type: str = "json") -> Dict[str, Any]:
    try:
        path = resolve_windows_path(output_file)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(stdout_data)
        summary = {"total_lines": len(stdout_data.splitlines())}
        if format_type == "json" and stdout_data:
            try:
                data = json.loads(stdout_data)
                if isinstance(data, dict):
                    if "results" in data:
                        summary["total_findings"] = len(data["results"])
                    if "errors" in data:
                        summary["total_errors"] = len(data["errors"])
            except json.JSONDecodeError:
                pass
        return {"file_saved": True, "linux_path": path, "file_size_bytes": os.path.getsize(path), "summary": summary}
    except Exception as e:
        return {"file_saved": False, "error": str(e)}


def get_enhanced_env() -> Dict[str, str]:
    env = os.environ.copy()
    extra = [
        "/root/.local/bin", os.path.expanduser("~/.local/bin"),
        "/root/go/bin", os.path.expanduser("~/go/bin"), "/usr/local/go/bin",
        "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    ]
    current = set((env.get("PATH") or "").split(":"))
    new = [p for p in extra if p and os.path.isdir(p) and p not in current]
    if new:
        env["PATH"] = ":".join(new) + ":" + env.get("PATH", "")
    return env


ENHANCED_ENV = get_enhanced_env()


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------
class CommandExecutor:
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT, cwd: Optional[str] = None):
        self.command = command
        self.timeout = min(timeout, MAX_TIMEOUT)
        self.cwd = cwd
        self.env = ENHANCED_ENV
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.return_code = None
        self.timed_out = False

    def _read_stdout(self) -> None:
        try:
            for line in iter(self.process.stdout.readline, ""):
                self.stdout_data += line
        except Exception as e:
            logger.error(f"stdout read: {e}")

    def _read_stderr(self) -> None:
        try:
            for line in iter(self.process.stderr.readline, ""):
                self.stderr_data += line
        except Exception as e:
            logger.error(f"stderr read: {e}")

    def execute(self) -> Dict[str, Any]:
        try:
            self.process = subprocess.Popen(
                self.command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, cwd=self.cwd, env=self.env,
            )
            t1 = threading.Thread(target=self._read_stdout, daemon=True)
            t2 = threading.Thread(target=self._read_stderr, daemon=True)
            t1.start()
            t2.start()
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self.timed_out = True
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                self.return_code = -1
            t1.join(timeout=5)
            t2.join(timeout=5)
            success = (self.return_code == 0) or (self.timed_out and (self.stdout_data or self.stderr_data))
            return {
                "stdout": self.stdout_data, "stderr": self.stderr_data,
                "return_code": self.return_code, "success": success, "timed_out": self.timed_out,
                "partial_results": self.timed_out and bool(self.stdout_data or self.stderr_data),
                "command": self.command[:200],
            }
        except Exception as e:
            logger.error(f"Execute error: {e}")
            return {
                "stdout": self.stdout_data, "stderr": str(e), "return_code": -1,
                "success": False, "timed_out": False, "partial_results": bool(self.stdout_data or self.stderr_data), "error": str(e),
            }


def execute_command(command: str, cwd: Optional[str] = None, timeout: int = COMMAND_TIMEOUT) -> Dict[str, Any]:
    return CommandExecutor(command, timeout=timeout, cwd=cwd).execute()


# ---------------------------------------------------------------------------
# Validation and retry
# ---------------------------------------------------------------------------
import hashlib

def calculate_checksum(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def validate_scan_result(result: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
    out = {"valid": True, "warnings": [], "errors": [], "checksum": None, "size_bytes": 0}
    if not ENABLE_RESULT_VALIDATION:
        return out
    if not result.get("success"):
        out["warnings"].append("Scan reported non-success")
    stdout, stderr = result.get("stdout", ""), result.get("stderr", "")
    out["size_bytes"] = len(stdout) + len(stderr)
    if ENABLE_CHECKSUM_VERIFICATION and stdout:
        out["checksum"] = calculate_checksum(stdout)
    if out["size_bytes"] < MIN_RESULT_SIZE_BYTES:
        out["warnings"].append(f"Result size below {MIN_RESULT_SIZE_BYTES} bytes")
    for pat in ("command not found", "permission denied", "no such file or directory", "fatal error"):
        if pat in (stdout + stderr).lower():
            out["errors"].append(pat)
            out["valid"] = False
    return out


def check_process_health() -> Dict[str, Any]:
    try:
        p = psutil.Process()
        mem_mb = p.memory_info().rss / (1024 * 1024)
        warn = mem_mb > (PROCESS_MEMORY_LIMIT_MB * 0.9)
        return {
            "healthy": not warn,
            "memory_mb": round(mem_mb, 2),
            "memory_limit_mb": PROCESS_MEMORY_LIMIT_MB,
            "cpu_percent": round(p.cpu_percent(interval=0.1), 2),
            "num_threads": p.num_threads(),
            "warnings": ["Memory above 90%"] if warn else [],
        }
    except Exception as e:
        return {"healthy": False, "error": str(e)}


class ErrorCategory(Enum):
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
    info = {"category": ErrorCategory.UNKNOWN.value, "severity": "medium", "remediation_hint": "Check logs", "retryable": True}
    if result.get("success"):
        info["category"] = info["severity"] = info["remediation_hint"] = None
        info["retryable"] = False
        return info
    combined = (result.get("stderr", "") + result.get("stdout", "")).lower()
    if "command not found" in combined or "not found" in combined:
        info.update({"category": ErrorCategory.TOOL_NOT_FOUND.value, "severity": "high", "retryable": False})
    elif "permission denied" in combined:
        info.update({"category": ErrorCategory.PERMISSION_DENIED.value, "severity": "high", "retryable": False})
    elif result.get("timed_out") or "timeout" in combined:
        info.update({"category": ErrorCategory.TIMEOUT.value})
    elif "connection refused" in combined or "network" in combined:
        info.update({"category": ErrorCategory.NETWORK_ERROR.value})
    elif result.get("return_code") == -1 or "crash" in combined:
        info.update({"category": ErrorCategory.PROCESS_CRASH.value, "severity": "critical"})
    elif result.get("return_code", 0) != 0:
        info.update({"category": ErrorCategory.TOOL_ERROR.value})
    return info


def enhance_result_with_metadata(result: Dict[str, Any], tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    out = result.copy()
    out["error_info"] = categorize_error(result)
    if not result.get("validation"):
        out["validation"] = validate_scan_result(result, tool_name)
    out["process_health"] = check_process_health()
    out["metadata"] = {
        "tool_name": tool_name, "scan_params": params, "timestamp": datetime.now().isoformat(),
        "multiprocessing_enabled": USE_MULTIPROCESSING, "max_parallel_scans": MAX_PARALLEL_SCANS,
        "retry_enabled": MAX_RETRY_ATTEMPTS > 1,
    }
    return out


def execute_scan_with_retry(scan_function: Any, params: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
    def wrapped() -> Dict[str, Any]:
        return scan_function(params)

    last_error: Any = None
    for attempt in range(MAX_RETRY_ATTEMPTS):
        try:
            result = wrapped()
            val = validate_scan_result(result, tool_name)
            if val["valid"] or attempt == MAX_RETRY_ATTEMPTS - 1:
                result["validation"] = val
                return enhance_result_with_metadata(result, tool_name, params)
            last_error = val["errors"]
        except Exception as e:
            last_error = e
        if attempt < MAX_RETRY_ATTEMPTS - 1:
            time.sleep(RETRY_BACKOFF_BASE ** attempt)
    return enhance_result_with_metadata({
        "success": False, "stdout": "", "stderr": str(last_error), "return_code": -1,
    }, tool_name, params)


def run_scan_in_background(tool_name: str, params: Dict[str, Any], scan_function: Any) -> Dict[str, Any]:
    output_file = params.get("output_file")
    job = job_manager.create_job(tool_name, params, output_file)
    job_manager.submit_job(job, execute_scan_with_retry, scan_function, params, tool_name)
    return {
        "success": True,
        "message": "Scan job submitted successfully",
        "job_id": job.job_id,
        "job_status": job.status.value,
        "output_file": job.output_file,
        "check_status_url": f"/api/jobs/{job.job_id}",
        "get_result_url": f"/api/jobs/{job.job_id}/result",
        "multiprocessing_enabled": USE_MULTIPROCESSING,
        "max_retry_attempts": MAX_RETRY_ATTEMPTS,
    }


def run_scan_synchronously(tool_name: str, params: Dict[str, Any], scan_function: Any) -> Dict[str, Any]:
    job_id = str(uuid.uuid4())
    started = datetime.now()
    output_file = params.get("output_file") or os.path.join(DEFAULT_OUTPUT_DIR, f"{tool_name}_{started.strftime('%Y%m%d_%H%M%S')}_{job_id[:8]}.json")
    logger.info(f"Starting sync scan {job_id} for {tool_name}")
    try:
        result = scan_function(params)
        completed = datetime.now()
        if not result.get("success", True) or result.get("error"):
            return {
                "success": False,
                "message": result.get("error", "Scan failed"),
                "job_id": job_id,
                "job_status": "failed",
                "error": result.get("error", "Tool reported failure"),
                "sync_mode": True,
                "duration_seconds": (completed - started).total_seconds(),
                "output_file": output_file,
                "scan_result": result,
            }
        full_result = {
            "job_id": job_id, "tool_name": tool_name, "scan_params": params,
            "started_at": started.isoformat(), "completed_at": completed.isoformat(),
            "duration_seconds": (completed - started).total_seconds(),
            "scan_result": result, "sync_mode": True,
        }
        resolved = resolve_windows_path(output_file) if output_file.startswith("F:") else output_file
        os.makedirs(os.path.dirname(resolved), exist_ok=True)
        with open(resolved, "w", encoding="utf-8") as f:
            json.dump(full_result, f, indent=2, ensure_ascii=False)
        if is_toon_available():
            try:
                toon_output = convert_scan_result_to_toon(full_result)
                if toon_output:
                    with open(resolved.rsplit(".", 1)[0] + ".toon", "w", encoding="utf-8") as f:
                        f.write(toon_output)
                    ac = create_ai_compact_format(full_result)
                    if ac:
                        with open(resolved.rsplit(".", 1)[0] + ".ai-compact.json", "w", encoding="utf-8") as f:
                            json.dump(ac, f, ensure_ascii=False)
            except Exception as e:
                logger.warning(f"TOON save: {e}")
        try:
            ai_analysis = analyze_scan_results(full_result)
            total_findings = ai_analysis.get("total_findings", 0)
            toon_analysis = create_toon_analysis_result(
                full_result, ai_analysis,
                include_raw_findings=SYNC_RESPONSE_INCLUDE_FINDINGS,
                max_findings=SYNC_RESPONSE_MAX_FINDINGS,
            )
            total_pages = max(1, (total_findings + DEFAULT_PAGE_SIZE - 1) // DEFAULT_PAGE_SIZE)
            return {
                "success": True, "message": f"Scan completed. {total_findings} findings saved.",
                "job_id": job_id, "job_status": "completed", "output_file": output_file,
                "duration_seconds": (completed - started).total_seconds(),
                "sync_mode": True, "result_format": "toon-analysis", "toon_result": toon_analysis,
                "pagination": {"total_findings": total_findings, "total_pages": total_pages, "page_size": DEFAULT_PAGE_SIZE, "current_page": 0, "has_more": total_findings > 0, "hint": f"Call get_scan_result_toon(job_id='{job_id}', page=1) for findings"},
            }
        except Exception as e:
            logger.warning(f"AI analysis: {e}")
            return {"success": True, "message": "Scan completed (sync)", "job_id": job_id, "job_status": "completed", "output_file": output_file, "duration_seconds": (completed - started).total_seconds(), "summary": result.get("summary", {}), "sync_mode": True, "scan_result": result}
    except Exception as e:
        logger.error(f"Sync scan {job_id} failed: {e}")
        traceback.print_exc()
        return {"success": False, "message": str(e), "job_id": job_id, "job_status": "failed", "error": str(e), "sync_mode": True}


def response_as_toon(
    tool_name: str,
    params: Dict[str, Any],
    result: Dict[str, Any],
    include_raw_findings: bool = True,
    max_findings: int = 100,
) -> Dict[str, Any]:
    """
    Wrap a raw scan result as TOON format for AI-friendly response.
    Use this so every tool returns a consistent toon_result the AI can save and analyze.
    """
    job_id = f"immediate-{tool_name}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    full = {
        "job_id": job_id,
        "tool_name": tool_name,
        "scan_params": params,
        "started_at": datetime.now().isoformat(),
        "completed_at": datetime.now().isoformat(),
        "scan_result": result,
    }
    try:
        analysis = analyze_scan_results(full)
        toon = create_toon_analysis_result(
            full, analysis, include_raw_findings=include_raw_findings, max_findings=max_findings
        )
        return {
            "success": result.get("success", True),
            "result_format": "toon-analysis",
            "toon_result": toon,
            "job_id": job_id,
            "tool": tool_name,
        }
    except Exception as e:
        logger.warning(f"TOON wrap failed for {tool_name}: {e}")
        return {
            "success": result.get("success", False),
            "result_format": "toon-analysis",
            "toon_result": {
                "format": "toon-analysis",
                "tool": tool_name,
                "job_id": job_id,
                "analysis": {"error": str(e), "total_findings": 0, "risk": {"overall_risk": "UNKNOWN"}},
                "findings": [],
            },
            "raw_result": result,
        }
