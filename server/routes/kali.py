"""
Kali / security tool routes: nikto, nmap, sqlmap, wpscan, dirb, lynis, clamav.
"""
import json
import logging
import os
from typing import Any, Dict

from flask import Flask, request, jsonify

from core import (
    execute_command,
    resolve_windows_path,
    run_scan_synchronously,
    run_scan_in_background,
    response_as_toon,
)
from config import (
    FORCE_SYNC_SCANS,
    NIKTO_TIMEOUT,
    NMAP_TIMEOUT,
    SQLMAP_TIMEOUT,
    WPSCAN_TIMEOUT,
    DIRB_TIMEOUT,
    LYNIS_TIMEOUT,
    CLAMAV_TIMEOUT,
)

logger = logging.getLogger(__name__)


def _nikto_scan(params: Dict[str, Any]) -> Dict[str, Any]:
    """Internal function to execute nikto scan."""
    target = params.get("target", "")
    port = params.get("port", "80")
    ssl = params.get("ssl", False)
    output_format = params.get("output_format", "txt")
    output_file = params.get("output_file", "")
    additional_args = params.get("additional_args", "")

    if not target:
        return {"error": "Target parameter is required", "success": False}

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
    if output_file:
        result["output_file_original"] = output_file
        result["output_file_resolved"] = resolved_output_file
    if resolved_output_file and os.path.exists(resolved_output_file):
        try:
            with open(resolved_output_file, "r") as f:
                result["file_content"] = f.read()
        except Exception as e:
            logger.warning(f"Error reading output file: {e}")
    result["summary"] = {"target": target, "port": port}
    return result


def register(app: Flask) -> None:
    """Register Kali/security tool routes on the Flask app."""

    @app.route("/api/web/nikto", methods=["POST"])
    def nikto():
        try:
            params = request.json or {}
            force_sync = params.get("force_sync", False)
            background = params.get("background", not FORCE_SYNC_SCANS)
            if FORCE_SYNC_SCANS or force_sync or not background:
                result = run_scan_synchronously("nikto", params, _nikto_scan)
                return jsonify(result)
            result = run_scan_in_background("nikto", params, _nikto_scan)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in nikto endpoint: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/network/nmap", methods=["POST"])
    def nmap():
        try:
            params = request.json or {}
            target = params.get("target", "")
            scan_type = params.get("scan_type", "-sV")
            ports = params.get("ports", "")
            output_format = params.get("output_format", "normal")
            output_file = params.get("output_file", "")
            additional_args = params.get("additional_args", "")

            if not target:
                return jsonify({"error": "Target parameter is required"}), 400

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
            if output_file:
                result["output_file_original"] = output_file
                result["output_file_resolved"] = resolved_output_file
            if resolved_output_file and os.path.exists(resolved_output_file):
                try:
                    with open(resolved_output_file, "r") as f:
                        result["file_content"] = f.read()
                except Exception as e:
                    logger.warning(f"Error reading output file: {e}")
            return jsonify(response_as_toon("nmap", params, result))
        except Exception as e:
            logger.error(f"Error in nmap endpoint: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/web/sqlmap", methods=["POST"])
    def sqlmap():
        try:
            params = request.json or {}
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
            if output_dir:
                result["output_dir_original"] = output_dir
                result["output_dir_resolved"] = resolved_output_dir
            return jsonify(response_as_toon("sqlmap", params, result))
        except Exception as e:
            logger.error(f"Error in sqlmap endpoint: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/web/wpscan", methods=["POST"])
    def wpscan():
        try:
            params = request.json or {}
            target = params.get("target", "")
            enumerate_opt = params.get("enumerate", "vp")
            api_token = params.get("api_token", "")
            output_file = params.get("output_file", "")
            additional_args = params.get("additional_args", "")

            if not target:
                return jsonify({"error": "Target parameter is required"}), 400

            resolved_output_file = ""
            if output_file:
                resolved_output_file = resolve_windows_path(output_file)

            command = f"wpscan --url {target}"
            if enumerate_opt:
                command += f" --enumerate {enumerate_opt}"
            if api_token:
                command += f" --api-token {api_token}"
            if resolved_output_file:
                command += f" --output {resolved_output_file} --format json"
            if additional_args:
                command += f" {additional_args}"

            result = execute_command(command, timeout=WPSCAN_TIMEOUT)
            if output_file:
                result["output_file_original"] = output_file
                result["output_file_resolved"] = resolved_output_file
            if resolved_output_file and os.path.exists(resolved_output_file):
                try:
                    with open(resolved_output_file, "r") as f:
                        result["parsed_output"] = json.load(f)
                except Exception as e:
                    logger.warning(f"Error reading output file: {e}")
            return jsonify(response_as_toon("wpscan", params, result))
        except Exception as e:
            logger.error(f"Error in wpscan endpoint: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/web/dirb", methods=["POST"])
    def dirb():
        try:
            params = request.json or {}
            target = params.get("target", "")
            wordlist = params.get("wordlist", "/usr/share/dirb/wordlists/common.txt")
            extensions = params.get("extensions", "")
            output_file = params.get("output_file", "")
            additional_args = params.get("additional_args", "")

            if not target:
                return jsonify({"error": "Target parameter is required"}), 400

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
            if output_file:
                result["output_file_original"] = output_file
                result["output_file_resolved"] = resolved_output_file
            if resolved_output_file and os.path.exists(resolved_output_file):
                try:
                    with open(resolved_output_file, "r") as f:
                        result["file_content"] = f.read()
                except Exception as e:
                    logger.warning(f"Error reading output file: {e}")
            return jsonify(response_as_toon("dirb", params, result))
        except Exception as e:
            logger.error(f"Error in dirb endpoint: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/system/lynis", methods=["POST"])
    def lynis():
        try:
            params = request.json or {}
            target = params.get("target", "")
            audit_mode = params.get("audit_mode", "system")
            quick = params.get("quick", False)
            log_file = params.get("log_file", "")
            report_file = params.get("report_file", "")
            additional_args = params.get("additional_args", "")

            resolved_target = resolve_windows_path(target) if target else ""
            resolved_log_file = resolve_windows_path(log_file) if log_file else ""
            resolved_report_file = resolve_windows_path(report_file) if report_file else ""

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
            if target:
                result["target_original"] = target
                result["target_resolved"] = resolved_target
            if log_file:
                result["log_file_original"] = log_file
                result["log_file_resolved"] = resolved_log_file
            if report_file:
                result["report_file_original"] = report_file
                result["report_file_resolved"] = resolved_report_file
            if resolved_log_file and os.path.exists(resolved_log_file):
                try:
                    with open(resolved_log_file, "r") as f:
                        result["log_content"] = f.read()
                except Exception as e:
                    logger.warning(f"Error reading log file: {e}")
            if resolved_report_file and os.path.exists(resolved_report_file):
                try:
                    with open(resolved_report_file, "r") as f:
                        result["report_content"] = f.read()
                except Exception as e:
                    logger.warning(f"Error reading report file: {e}")
            return jsonify(response_as_toon("lynis", params, result))
        except Exception as e:
            logger.error(f"Error in lynis endpoint: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/malware/clamav", methods=["POST"])
    def clamav():
        try:
            params = request.json or {}
            target = params.get("target", "")
            recursive = params.get("recursive", True)
            infected_only = params.get("infected_only", False)
            output_file = params.get("output_file", "")
            additional_args = params.get("additional_args", "")

            if not target:
                return jsonify({"error": "Target parameter is required"}), 400

            resolved_target = resolve_windows_path(target)
            resolved_output_file = resolve_windows_path(output_file) if output_file else ""

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
            result["original_path"] = target
            result["resolved_path"] = resolved_target
            if output_file:
                result["output_file_original"] = output_file
                result["output_file_resolved"] = resolved_output_file
            if resolved_output_file and os.path.exists(resolved_output_file):
                try:
                    with open(resolved_output_file, "r") as f:
                        result["file_content"] = f.read()
                except Exception as e:
                    logger.warning(f"Error reading output file: {e}")
            return jsonify(response_as_toon("clamav", params, result))
        except Exception as e:
            logger.error(f"Error in clamav endpoint: {str(e)}")
            return jsonify({"error": str(e)}), 500
