"""
SAST tool endpoints: Semgrep, Bearer, Graudit, Bandit, Gosec, Brakeman, NodeJSScan, ESLint.
Edit this file to fix or tune any of these tools.
"""
import json
import logging
import traceback
from typing import Any, Dict

from flask import Flask, request, jsonify

from config import (
    BANDIT_TIMEOUT,
    FORCE_SYNC_SCANS,
    SEMGREP_TIMEOUT,
)
from core import (
    execute_command,
    resolve_windows_path,
    run_scan_in_background,
    run_scan_synchronously,
    response_as_toon,
)

logger = logging.getLogger(__name__)


def _semgrep_scan(params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("target", ".")
    config = params.get("config", "auto")
    lang = params.get("lang", "")
    severity = params.get("severity", "")
    output_format = params.get("output_format", "json")
    additional_args = params.get("additional_args", "")
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
    result["original_path"] = target
    result["resolved_path"] = resolved_target
    if result.get("return_code", 0) != 0 or not result.get("stdout"):
        result["error"] = result.get("stderr", "semgrep failed with no output")
        result["summary"] = {}
        return result
    summary = {}
    if output_format == "json" and result.get("stdout"):
        try:
            parsed = json.loads(result["stdout"])
            result["parsed_output"] = parsed
            if "results" in parsed:
                summary["total_findings"] = len(parsed["results"])
            if "errors" in parsed:
                summary["total_errors"] = len(parsed["errors"])
        except Exception:
            pass
    result["summary"] = summary
    return result


def register(app: Flask) -> None:
    @app.route("/api/sast/semgrep", methods=["POST"])
    def semgrep():
        try:
            params = request.json or {}
            force_sync = params.get("force_sync", False)
            background = params.get("background", not FORCE_SYNC_SCANS)
            if FORCE_SYNC_SCANS or force_sync or not background:
                result = run_scan_synchronously("semgrep", params, _semgrep_scan)
                return jsonify(result)
            result = run_scan_in_background("semgrep", params, _semgrep_scan)
            return jsonify(result)
        except Exception as e:
            logger.error(f"semgrep: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/sast/bearer", methods=["POST"])
    def bearer():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            scanner = params.get("scanner", "")
            output_format = params.get("format", "json")
            only_policy = params.get("only_policy", "")
            severity = params.get("severity", "")
            additional_args = params.get("additional_args", "")
            resolved_target = resolve_windows_path(target)
            command = f"bearer scan {resolved_target} --quiet"
            if scanner:
                command += f" --scanner={scanner}"
            if output_format:
                command += f" --format={output_format}"
            if only_policy:
                command += f" --only-policy={only_policy}"
            if severity:
                command += f" --severity={severity}"
            if additional_args:
                command += f" {additional_args}"
            command += " 2>&1"
            result = execute_command(command, timeout=3600)
            result["original_path"] = target
            result["resolved_path"] = resolved_target
            if output_format == "json" and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("bearer", params, result))
        except Exception as e:
            logger.error(f"bearer: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/sast/graudit", methods=["POST"])
    def graudit():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            database = params.get("database", "all")
            additional_args = params.get("additional_args", "")
            resolved_target = resolve_windows_path(target)
            command = f"graudit -d {database}"
            if additional_args:
                command += f" {additional_args}"
            command += f" {resolved_target}"
            result = execute_command(command, timeout=300)
            result["original_path"] = target
            result["resolved_path"] = resolved_target
            return jsonify(response_as_toon("graudit", params, result))
        except Exception as e:
            logger.error(f"graudit: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/sast/bandit", methods=["POST"])
    def bandit():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            severity_level = params.get("severity_level", "")
            confidence_level = params.get("confidence_level", "")
            output_format = params.get("format", "json")
            additional_args = params.get("additional_args", "")
            resolved_target = resolve_windows_path(target)
            command = f"bandit -r {resolved_target} -f {output_format}"
            if severity_level:
                command += f" -ll -l {severity_level.upper()}"
            if confidence_level:
                command += f" -ii -i {confidence_level.upper()}"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, timeout=BANDIT_TIMEOUT)
            result["original_path"] = target
            result["resolved_path"] = resolved_target
            if output_format == "json" and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("bandit", params, result))
        except Exception as e:
            logger.error(f"bandit: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/sast/gosec", methods=["POST"])
    def gosec():
        try:
            params = request.json or {}
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
            if output_format == "json" and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("gosec", params, result))
        except Exception as e:
            logger.error(f"gosec: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/sast/brakeman", methods=["POST"])
    def brakeman():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            output_format = params.get("format", "json")
            confidence_level = params.get("confidence_level", "")
            additional_args = params.get("additional_args", "")
            resolved_target = resolve_windows_path(target)
            command = f"brakeman -p {resolved_target} -f {output_format}"
            if confidence_level:
                command += f" -w {confidence_level}"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, timeout=300)
            result["original_path"] = target
            result["resolved_path"] = resolved_target
            if output_format == "json" and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("brakeman", params, result))
        except Exception as e:
            logger.error(f"brakeman: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/sast/nodejsscan", methods=["POST"])
    def nodejsscan():
        try:
            params = request.json or {}
            # path(s): single "target" or list "paths" (CLI: [path ...])
            paths_param = params.get("paths")
            if paths_param is not None:
                paths = [resolve_windows_path(p) for p in (paths_param if isinstance(paths_param, list) else [paths_param])]
            else:
                paths = [resolve_windows_path(params.get("target", "."))]
            output_format = params.get("output_format", "json").lower()
            output_file = params.get("output_file", "")
            config_file = params.get("config", "")
            missing_controls = params.get("missing_controls", False)
            exit_warning = params.get("exit_warning", False)
            additional_args = params.get("additional_args", "")
            command_parts = ["nodejsscan"]
            if output_format == "sarif":
                command_parts.append("--sarif")
            elif output_format == "sonarqube":
                command_parts.append("--sonarqube")
            elif output_format == "html":
                command_parts.append("--html")
            else:
                command_parts.append("--json")
            if output_file:
                command_parts.extend(["-o", output_file])
            if config_file:
                command_parts.extend(["-c", resolve_windows_path(config_file)])
            if missing_controls:
                command_parts.append("--missing-controls")
            if exit_warning:
                command_parts.append("-w")
            if additional_args:
                command_parts.append(additional_args)
            command_parts.extend(paths)
            command = " ".join(command_parts)
            result = execute_command(command, timeout=3600)
            if output_format == "json" and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("nodejsscan", params, result))
        except Exception as e:
            logger.error(f"nodejsscan: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/sast/eslint-security", methods=["POST"])
    def eslint_security():
        try:
            params = request.json or {}
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
            if output_format == "json" and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("eslint-security", params, result))
        except Exception as e:
            logger.error(f"eslint-security: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500
