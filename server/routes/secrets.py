"""Secret scanning: TruffleHog, Gitleaks. Edit here to fix or tune these tools."""
import json
import logging
import os
import traceback
from typing import Any, Dict

from flask import Flask, request, jsonify

from config import TRUFFLEHOG_TIMEOUT, MAX_TIMEOUT
from core import execute_command, resolve_windows_path, response_as_toon

logger = logging.getLogger(__name__)


def register(app: Flask) -> None:
    @app.route("/api/secrets/trufflehog", methods=["POST"])
    def trufflehog():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            scan_type = params.get("scan_type", "filesystem")
            json_output = params.get("json_output", True)
            only_verified = params.get("only_verified", False)
            additional_args = params.get("additional_args", "")
            resolved = resolve_windows_path(target)
            command = f"trufflehog {scan_type} {resolved}"
            if json_output:
                command += " --json"
            if only_verified:
                command += " --only-verified"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, timeout=TRUFFLEHOG_TIMEOUT)
            result["original_path"] = target
            result["resolved_path"] = resolved
            if json_output and result.get("stdout"):
                try:
                    result["parsed_secrets"] = [json.loads(l) for l in result["stdout"].strip().split("\n") if l.strip()]
                except Exception:
                    pass
            return jsonify(response_as_toon("trufflehog", params, result))
        except Exception as e:
            logger.error(f"trufflehog: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/secrets/gitleaks", methods=["POST"])
    def gitleaks():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            config = params.get("config", "")
            report_format = params.get("report_format", "json")
            report_path = params.get("report_path", "")
            verbose = params.get("verbose", False)
            additional_args = params.get("additional_args", "")
            resolved = resolve_windows_path(target)
            command = f"gitleaks detect --source={resolved} --report-format={report_format}"
            if config:
                command += f" --config={config}"
            if report_path:
                command += f" --report-path={report_path}"
            if verbose:
                command += " -v"
            # Limit git history depth by default to avoid timeout on large repos (3000+ refs)
            if "--log-opts" not in (additional_args or ""):
                command += " --log-opts=--max-count=1000"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, timeout=MAX_TIMEOUT)
            result["original_path"] = target
            result["resolved_path"] = resolved
            if report_path and os.path.exists(report_path):
                try:
                    with open(report_path) as f:
                        result["parsed_report"] = json.load(f) if report_format == "json" else f.read()
                except Exception as ex:
                    logger.warning(f"Read report: {ex}")
            return jsonify(response_as_toon("gitleaks", params, result))
        except Exception as e:
            logger.error(f"gitleaks: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500
