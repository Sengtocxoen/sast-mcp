"""Infrastructure as Code: Checkov, tfsec."""
import json
import logging
import traceback
from typing import Any, Dict

from flask import Flask, request, jsonify

from server.core import execute_command, resolve_windows_path, response_as_toon

logger = logging.getLogger(__name__)


def register(app: Flask) -> None:
    @app.route("/api/iac/checkov", methods=["POST"])
    def checkov():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            framework = params.get("framework", "")
            output_format = params.get("output_format", "json")
            compact = params.get("compact", False)
            quiet = params.get("quiet", False)
            additional_args = params.get("additional_args", "")
            resolved = resolve_windows_path(target)
            command = f"checkov -d {resolved} -o {output_format}"
            if framework:
                command += f" --framework {framework}"
            if compact:
                command += " --compact"
            if quiet:
                command += " --quiet"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, timeout=3600)
            result["original_path"] = target
            result["resolved_path"] = resolved
            if output_format == "json" and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("checkov", params, result))
        except Exception as e:
            logger.error(f"checkov: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/iac/tfsec", methods=["POST"])
    def tfsec():
        try:
            params = request.json or {}
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
            if output_format == "json" and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("tfsec", params, result))
        except Exception as e:
            logger.error(f"tfsec: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500
