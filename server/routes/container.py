"""Container / Trivy."""
import json
import logging
import traceback
from typing import Any, Dict

from flask import Flask, request, jsonify

from server.core import execute_command, resolve_windows_path, response_as_toon

logger = logging.getLogger(__name__)


def register(app: Flask) -> None:
    @app.route("/api/container/trivy", methods=["POST"])
    def trivy():
        try:
            params = request.json or {}
            target = params.get("target", "")
            if not target:
                return jsonify({"error": "Target parameter is required"}), 400
            scan_type = params.get("scan_type", "fs")
            output_format = params.get("format", "json")
            severity = params.get("severity", "")
            additional_args = params.get("additional_args", "")
            resolved = resolve_windows_path(target)
            command = f"trivy {scan_type} --format {output_format}"
            if severity:
                command += f" --severity {severity}"
            if additional_args:
                command += f" {additional_args}"
            command += f" {resolved}"
            result = execute_command(command, timeout=3600)
            result["original_path"] = target
            result["resolved_path"] = resolved
            if output_format == "json" and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("trivy", params, result))
        except Exception as e:
            logger.error(f"trivy: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500
