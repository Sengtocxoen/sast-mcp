"""
Analysis routes: ai-summary, summarize, toon-status.
"""
import json
import logging

from flask import Flask, request, jsonify

from core import job_manager, resolve_windows_path, JobStatus
from tools.ai_analysis import (
    analyze_scan_with_ai,
    analyze_scan_results,
    create_toon_analysis_result,
    is_ai_configured,
    summarize_findings,
)
from tools.toon_converter import is_toon_available

logger = logging.getLogger(__name__)


def register(app: Flask) -> None:
    """Register analysis routes on the Flask app."""

    @app.route("/api/analysis/ai-summary", methods=["POST"])
    def ai_summary():
        try:
            params = request.json or {}
            job_id = params.get("job_id", "")
            analysis_type = params.get("analysis_type", "full")
            custom_prompt = params.get("custom_prompt", None)
            include_sections = params.get("include", ["summary", "remediation", "priorities"])

            if not job_id:
                return jsonify({"error": "job_id parameter is required"}), 400

            job = job_manager.get_job(job_id)
            if not job:
                return jsonify({"error": "Job not found"}), 404

            if job.status != JobStatus.COMPLETED:
                return jsonify({
                    "error": "Job not completed",
                    "status": job.status.value,
                }), 400

            resolved_output_file = (
                resolve_windows_path(job.output_file)
                if job.output_file.startswith("F:")
                else job.output_file
            )
            ai_payload_path = resolved_output_file.rsplit(".", 1)[0] + ".ai-payload.json"

            try:
                with open(ai_payload_path, "r", encoding="utf-8") as f:
                    ai_payload = json.load(f)

                analysis_result = analyze_scan_with_ai(
                    ai_payload, custom_prompt=custom_prompt
                )

                return jsonify({
                    "success": True,
                    "job_id": job_id,
                    "analysis_type": analysis_type,
                    "result_format": "toon-analysis",
                    "analysis": analysis_result,
                    "ai_configured": is_ai_configured(),
                })
            except FileNotFoundError:
                logger.info(
                    f"AI payload file not found for job {job_id}, falling back to heuristic analysis"
                )
                try:
                    with open(resolved_output_file, "r", encoding="utf-8") as f:
                        result_data = json.load(f)

                    ai_analysis = analyze_scan_results(result_data)
                    toon_result = create_toon_analysis_result(
                        result_data,
                        ai_analysis,
                        include_raw_findings=True,
                        max_findings=50,
                    )

                    return jsonify({
                        "success": True,
                        "job_id": job_id,
                        "analysis_type": analysis_type,
                        "result_format": "toon-analysis",
                        "analysis_source": "heuristic",
                        "ai_configured": is_ai_configured(),
                        "toon_result": toon_result,
                    })
                except FileNotFoundError:
                    return jsonify({
                        "error": "Result file not found. Job may have been cleaned up.",
                    }), 404
        except Exception as e:
            logger.error(f"Error in AI summary endpoint: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/analysis/summarize", methods=["POST"])
    def summarize():
        try:
            params = request.json or {}
            job_id = params.get("job_id", "")

            if not job_id:
                return jsonify({"error": "job_id parameter is required"}), 400

            job = job_manager.get_job(job_id)
            if not job:
                return jsonify({"error": "Job not found"}), 404

            if job.status != JobStatus.COMPLETED:
                return jsonify({
                    "error": "Job not completed",
                    "status": job.status.value,
                }), 400

            try:
                resolved_output_file = (
                    resolve_windows_path(job.output_file)
                    if job.output_file.startswith("F:")
                    else job.output_file
                )

                with open(resolved_output_file, "r", encoding="utf-8") as f:
                    scan_results = json.load(f)

                summary = summarize_findings(scan_results)

                return jsonify({
                    "success": True,
                    "job_id": job_id,
                    "summary": summary,
                })
            except FileNotFoundError:
                return jsonify({"error": "Result file not found"}), 404
        except Exception as e:
            logger.error(f"Error in summarize endpoint: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/analysis/toon-status", methods=["GET"])
    def toon_status():
        try:
            return jsonify({
                "toon_available": is_toon_available(),
                "ai_configured": is_ai_configured(),
                "features": {
                    "toon_conversion": is_toon_available(),
                    "ai_analysis": is_ai_configured(),
                    "statistical_summary": True,
                },
                "message": "TOON conversion is "
                + ("enabled" if is_toon_available() else "disabled")
                + ", AI analysis is "
                + ("configured" if is_ai_configured() else "not configured"),
            })
        except Exception as e:
            logger.error(f"Error in toon-status endpoint: {str(e)}")
            return jsonify({"error": str(e)}), 500
