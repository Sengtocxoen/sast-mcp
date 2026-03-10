"""
Job management routes: list, get, result, result-toon, cancel, cleanup, statistics, check.
"""
import json
import logging
import multiprocessing
import os
from datetime import datetime

import psutil
from flask import Flask, request, jsonify

from core import (
    job_manager,
    JobStatus,
    resolve_windows_path,
    check_process_health,
    scan_stats_lock,
    scan_stats,
)
from config import (
    MAX_PAGE_SIZE,
    DEFAULT_PAGE_SIZE,
    USE_MULTIPROCESSING,
    MAX_PARALLEL_SCANS,
    MAX_PROCESS_WORKERS,
    MAX_RETRY_ATTEMPTS,
)
from tools.ai_analysis import (
    analyze_scan_results,
    create_toon_analysis_result,
    _extract_findings,
)

logger = logging.getLogger(__name__)


def register(app: Flask) -> None:
    """Register job management routes on the Flask app."""

    @app.route("/api/jobs", methods=["GET"])
    def list_jobs():
        try:
            status_filter = request.args.get("status", None)
            limit = int(request.args.get("limit", 100))

            jobs = job_manager.list_jobs(status_filter=status_filter, limit=limit)
            jobs_data = [job.to_dict() for job in jobs]

            return jsonify({
                "success": True,
                "total": len(jobs_data),
                "jobs": jobs_data,
            })
        except Exception as e:
            logger.error(f"Error listing jobs: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/jobs/<job_id>", methods=["GET"])
    def get_job_status(job_id: str):
        try:
            job = job_manager.get_job(job_id)
            if not job:
                return jsonify({"error": "Job not found"}), 404
            return jsonify({"success": True, "job": job.to_dict()})
        except Exception as e:
            logger.error(f"Error getting job status: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/jobs/<job_id>/result", methods=["GET"])
    def get_job_result(job_id: str):
        try:
            job = job_manager.get_job(job_id)
            if not job:
                return jsonify({"error": "Job not found"}), 404

            if job.status == JobStatus.PENDING:
                return jsonify({
                    "success": False,
                    "status": "pending",
                    "message": "Job is still pending",
                })
            if job.status == JobStatus.RUNNING:
                return jsonify({
                    "success": False,
                    "status": "running",
                    "message": "Job is still running",
                    "progress": job.progress,
                })
            if job.status == JobStatus.FAILED:
                return jsonify({
                    "success": False,
                    "status": "failed",
                    "error": job.error,
                })
            if job.status == JobStatus.CANCELLED:
                return jsonify({
                    "success": False,
                    "status": "cancelled",
                    "message": "Job was cancelled",
                })

            try:
                resolved_output_file = (
                    resolve_windows_path(job.output_file)
                    if job.output_file.startswith("F:")
                    else job.output_file
                )

                with open(resolved_output_file, "r", encoding="utf-8") as f:
                    result_data = json.load(f)

                result_format = request.args.get("format", "toon")

                if result_format == "toon":
                    try:
                        ai_analysis = analyze_scan_results(result_data)
                        toon_analysis = create_toon_analysis_result(
                            result_data, ai_analysis, include_raw_findings=True, max_findings=50
                        )
                        return jsonify({
                            "success": True,
                            "status": "completed",
                            "job": job.to_dict(),
                            "result_format": "toon-analysis",
                            "toon_result": toon_analysis,
                        })
                    except Exception as analysis_err:
                        logger.warning(
                            f"AI analysis failed for job {job_id}, returning raw: {analysis_err}"
                        )

                return jsonify({
                    "success": True,
                    "status": "completed",
                    "job": job.to_dict(),
                    "result_format": "json",
                    "result": result_data,
                })
            except FileNotFoundError:
                return jsonify({
                    "success": False,
                    "error": "Result file not found",
                }), 404
        except Exception as e:
            logger.error(f"Error getting job result: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/jobs/<job_id>/result-toon", methods=["GET"])
    def get_job_result_toon(job_id: str):
        try:
            job = job_manager.get_job(job_id)
            if not job:
                return jsonify({"error": "Job not found"}), 404

            if job.status != JobStatus.COMPLETED:
                return jsonify({
                    "success": False,
                    "status": job.status.value,
                    "message": f"Job is {job.status.value}, not yet completed",
                })

            try:
                resolved_output_file = (
                    resolve_windows_path(job.output_file)
                    if job.output_file.startswith("F:")
                    else job.output_file
                )

                with open(resolved_output_file, "r", encoding="utf-8") as f:
                    result_data = json.load(f)

                include_findings = request.args.get("include_findings", "true").lower() == "true"
                page = max(1, int(request.args.get("page", 1)))
                page_size = min(
                    MAX_PAGE_SIZE, max(1, int(request.args.get("page_size", DEFAULT_PAGE_SIZE)))
                )

                ai_analysis = analyze_scan_results(result_data)
                total_findings = ai_analysis.get("total_findings", 0)
                total_pages = max(1, (total_findings + page_size - 1) // page_size)

                toon_analysis = create_toon_analysis_result(
                    result_data,
                    ai_analysis,
                    include_raw_findings=False,
                    max_findings=0,
                )

                if include_findings and total_findings > 0:
                    tool_name = result_data.get("tool_name", "unknown")
                    scan_data = result_data.get("scan_result", {})
                    all_findings = _extract_findings(scan_data, tool_name)

                    severity_order = {
                        "CRITICAL": 0,
                        "HIGH": 1,
                        "ERROR": 1,
                        "MEDIUM": 2,
                        "WARNING": 2,
                        "LOW": 3,
                        "INFO": 4,
                        "UNKNOWN": 5,
                    }
                    all_findings.sort(
                        key=lambda f: severity_order.get(f.get("severity", "UNKNOWN"), 5)
                    )

                    offset = (page - 1) * page_size
                    page_findings = all_findings[offset : offset + page_size]
                    toon_analysis["findings"] = page_findings
                    toon_analysis["findings_truncated"] = page < total_pages

                return jsonify({
                    "success": True,
                    "status": "completed",
                    "result_format": "toon-analysis",
                    "toon_result": toon_analysis,
                    "pagination": {
                        "current_page": page,
                        "page_size": page_size,
                        "total_findings": total_findings,
                        "total_pages": total_pages,
                        "has_next": page < total_pages,
                        "has_prev": page > 1,
                    },
                })
            except FileNotFoundError:
                return jsonify({
                    "success": False,
                    "error": "Result file not found",
                }), 404
        except Exception as e:
            logger.error(f"Error getting TOON job result: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
    def cancel_job(job_id: str):
        try:
            success = job_manager.cancel_job(job_id)
            if success:
                return jsonify({
                    "success": True,
                    "message": f"Job {job_id} cancelled",
                })
            return jsonify({
                "success": False,
                "message": "Job not found or cannot be cancelled",
            }), 400
        except Exception as e:
            logger.error(f"Error cancelling job: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/jobs/cleanup", methods=["POST"])
    def cleanup_jobs():
        try:
            count = job_manager.cleanup_old_jobs()
            return jsonify({
                "success": True,
                "message": f"Cleaned up {count} old jobs",
            })
        except Exception as e:
            logger.error(f"Error cleaning up jobs: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/scan/statistics", methods=["GET"])
    def get_scan_statistics():
        try:
            with scan_stats_lock:
                scan_statistics = dict(scan_stats)

            process_health = check_process_health()

            total_scans = scan_statistics.get("total_scans", 0)
            completed_scans = scan_statistics.get("completed_scans", 0)
            failed_scans = scan_statistics.get("failed_scans", 0)
            retried_scans = scan_statistics.get("retried_scans", 0)

            success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
            retry_rate = (retried_scans / total_scans * 100) if total_scans > 0 else 0
            failure_rate = (failed_scans / total_scans * 100) if total_scans > 0 else 0

            all_jobs = job_manager.list_jobs(limit=1000)
            jobs_by_status = {}
            for job in all_jobs:
                status = job.status.value
                jobs_by_status[status] = jobs_by_status.get(status, 0) + 1

            try:
                cpu_count = multiprocessing.cpu_count()
                system_memory = psutil.virtual_memory()
            except Exception:
                cpu_count = "N/A"
                system_memory = None

            return jsonify({
                "success": True,
                "scan_statistics": scan_statistics,
                "metrics": {
                    "success_rate_percent": round(success_rate, 2),
                    "retry_rate_percent": round(retry_rate, 2),
                    "failure_rate_percent": round(failure_rate, 2),
                },
                "job_statistics": {
                    "total_jobs": len(all_jobs),
                    "jobs_by_status": jobs_by_status,
                },
                "process_health": process_health,
                "system_info": {
                    "multiprocessing_enabled": USE_MULTIPROCESSING,
                    "max_parallel_scans": MAX_PARALLEL_SCANS,
                    "max_process_workers": (
                        MAX_PROCESS_WORKERS if USE_MULTIPROCESSING else "N/A"
                    ),
                    "max_retry_attempts": MAX_RETRY_ATTEMPTS,
                    "cpu_count": cpu_count,
                    "system_memory_total_gb": (
                        round(system_memory.total / (1024**3), 2) if system_memory else "N/A"
                    ),
                    "system_memory_available_gb": (
                        round(system_memory.available / (1024**3), 2)
                        if system_memory
                        else "N/A"
                    ),
                    "system_memory_percent": (
                        system_memory.percent if system_memory else "N/A"
                    ),
                },
                "timestamp": datetime.now().isoformat(),
            })
        except Exception as e:
            logger.error(f"Error getting scan statistics: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/jobs/<job_id>/check", methods=["GET"])
    def check_job_result_file(job_id: str):
        try:
            job = job_manager.get_job(job_id)
            if not job:
                return jsonify({
                    "status": "not_ok",
                    "exists": False,
                    "message": "Job not found",
                })

            if job.status == JobStatus.PENDING:
                return jsonify({
                    "status": "not_ok",
                    "exists": False,
                    "job_status": "pending",
                    "message": "Job is pending",
                })
            if job.status == JobStatus.RUNNING:
                return jsonify({
                    "status": "not_ok",
                    "exists": False,
                    "job_status": "running",
                    "message": "Job is still running",
                })
            if job.status == JobStatus.FAILED:
                return jsonify({
                    "status": "not_ok",
                    "exists": False,
                    "job_status": "failed",
                    "message": "Job failed",
                    "error": job.error,
                })
            if job.status == JobStatus.CANCELLED:
                return jsonify({
                    "status": "not_ok",
                    "exists": False,
                    "job_status": "cancelled",
                    "message": "Job was cancelled",
                })

            if job.output_file:
                resolved_output_file = (
                    resolve_windows_path(job.output_file)
                    if job.output_file.startswith("F:")
                    else job.output_file
                )
                file_exists = os.path.exists(resolved_output_file)

                if file_exists:
                    file_size = os.path.getsize(resolved_output_file)
                    return jsonify({
                        "status": "ok",
                        "exists": True,
                        "job_status": "completed",
                        "output_file": job.output_file,
                        "file_size_bytes": file_size,
                        "message": "Result file exists",
                    })
                return jsonify({
                    "status": "not_ok",
                    "exists": False,
                    "job_status": "completed",
                    "message": "Job completed but result file not found",
                })

            return jsonify({
                "status": "not_ok",
                "exists": False,
                "job_status": "completed",
                "message": "Job completed but no output file specified",
            })
        except Exception as e:
            logger.error(f"Error checking job result file: {str(e)}")
            return jsonify({
                "status": "not_ok",
                "exists": False,
                "error": str(e),
            }), 500
