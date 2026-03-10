"""Dependency scanning: Safety, npm audit, OWASP Dependency-Check, Snyk."""
import json
import logging
import os
import shutil
import tempfile
import traceback
from typing import Any, Dict

from flask import Flask, request, jsonify

from config import DEPENDENCY_CHECK_PATH, DEPENDENCY_CHECK_TIMEOUT
from core import execute_command, resolve_windows_path, response_as_toon

logger = logging.getLogger(__name__)


def register(app: Flask) -> None:
    @app.route("/api/dependencies/safety", methods=["POST"])
    def safety():
        try:
            params = request.json or {}
            # Safety CLI 3: "safety scan" scans project directory (cwd); no more "safety check -r file"
            target = params.get("target", ".")
            resolved = resolve_windows_path(target)
            stage = params.get("stage", "")  # development | cicd | production
            key = params.get("key", "")  # API key for cicd/production; or env SAFETY_API_KEY
            debug = params.get("debug", False)
            proxy_host = params.get("proxy_host", "")
            proxy_port = params.get("proxy_port", "")
            proxy_protocol = params.get("proxy_protocol", "")
            disable_optional_telemetry = params.get("disable_optional_telemetry", False)
            additional_args = params.get("additional_args", "")
            command_parts = ["safety"]
            if stage:
                command_parts.extend(["--stage", stage])
            if key:
                command_parts.extend(["--key", key])
            if proxy_host:
                command_parts.extend(["--proxy-host", proxy_host])
                if proxy_port:
                    command_parts.extend(["--proxy-port", proxy_port])
                if proxy_protocol:
                    command_parts.extend(["--proxy-protocol", proxy_protocol])
            if disable_optional_telemetry:
                command_parts.append("--disable-optional-telemetry")
            if debug:
                command_parts.append("--debug")
            if additional_args:
                command_parts.append(additional_args)
            command_parts.append("scan")
            command = " ".join(command_parts)
            result = execute_command(command, cwd=resolved, timeout=1800)
            if result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("safety", params, result))
        except Exception as e:
            logger.error(f"safety: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/dependencies/npm-audit", methods=["POST"])
    def npm_audit():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            json_output = params.get("json_output", True)
            audit_level = params.get("audit_level", "")
            production = params.get("production", False)
            additional_args = params.get("additional_args", "")
            resolved = resolve_windows_path(target)
            command = "npm audit"
            if json_output:
                command += " --json"
            if audit_level:
                command += f" --audit-level={audit_level}"
            if production:
                command += " --production"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, cwd=resolved, timeout=180)
            result["original_path"] = target
            result["resolved_path"] = resolved
            if json_output and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("npm-audit", params, result))
        except Exception as e:
            logger.error(f"npm_audit: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/dependencies/dependency-check", methods=["POST"])
    def dependency_check():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            project_name = params.get("project_name", "project")
            output_format = params.get("format", "JSON")
            scan = params.get("scan", target)
            nvd_api_key = params.get("nvd_api_key", "")
            noupdate = params.get("noupdate", False)
            pretty_print = params.get("pretty_print", False)
            additional_args = params.get("additional_args", "")
            resolved_target = resolve_windows_path(target)
            scan_paths = [resolve_windows_path(p.strip()) for p in str(scan).split(",") if p.strip()]
            output_dir = tempfile.mkdtemp()
            scan_flags = " ".join(f"-s {p}" for p in scan_paths)
            command = f"{DEPENDENCY_CHECK_PATH} --project {project_name} {scan_flags} -f {output_format} -o {output_dir}"
            if nvd_api_key:
                command += f" --nvdApiKey {nvd_api_key}"
            if noupdate:
                command += " -n"
            if pretty_print:
                command += " --prettyPrint"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, cwd=resolved_target, timeout=DEPENDENCY_CHECK_TIMEOUT)
            result["original_path"] = target
            result["resolved_path"] = resolved_target
            try:
                for fname in os.listdir(output_dir):
                    path = os.path.join(output_dir, fname)
                    with open(path) as f:
                        if fname.endswith(".json"):
                            result["parsed_report"] = json.load(f)
                        else:
                            result["report_content"] = f.read()
            except Exception as ex:
                logger.warning(f"Read report: {ex}")
            finally:
                try:
                    shutil.rmtree(output_dir)
                except Exception:
                    pass
            return jsonify(response_as_toon("dependency-check", params, result))
        except Exception as e:
            logger.error(f"dependency_check: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/dependencies/snyk", methods=["POST"])
    def snyk():
        try:
            from config import SNYK_TIMEOUT
            params = request.json or {}
            target = params.get("target", ".")
            test_type = params.get("test_type", "test")
            severity_threshold = params.get("severity_threshold", "")
            json_output = params.get("json_output", True)
            output_file = params.get("output_file", "")
            additional_args = params.get("additional_args", "")
            resolved = resolve_windows_path(target)
            resolved_out = resolve_windows_path(output_file) if output_file else ""
            command = f"snyk {test_type} {resolved}"
            if json_output:
                command += " --json"
            if severity_threshold:
                command += f" --severity-threshold={severity_threshold}"
            if resolved_out:
                command += f" > {resolved_out}"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, timeout=SNYK_TIMEOUT)
            result["original_path"] = target
            result["resolved_path"] = resolved
            if output_file:
                result["output_file_original"] = output_file
                result["output_file_resolved"] = resolved_out
            if json_output and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            if resolved_out and os.path.exists(resolved_out):
                try:
                    with open(resolved_out) as f:
                        result["file_content"] = f.read()
                        if json_output:
                            try:
                                result["parsed_output"] = json.loads(result["file_content"])
                            except Exception:
                                pass
                except Exception as ex:
                    logger.warning(f"Read snyk output: {ex}")
            return jsonify(response_as_toon("snyk", params, result))
        except Exception as e:
            logger.error(f"snyk: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500
