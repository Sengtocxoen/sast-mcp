"""Infrastructure as Code: Checkov, tfsec."""
import json
import logging
import traceback
from typing import Any, Dict

from flask import Flask, request, jsonify

from core import execute_command, resolve_windows_path, response_as_toon

logger = logging.getLogger(__name__)


def register(app: Flask) -> None:
    @app.route("/api/iac/checkov", methods=["POST"])
    def checkov():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            files = params.get("file", []) or params.get("files", [])  # -f FILE [FILE ...]; mutually exclusive with -d
            if isinstance(files, str):
                files = [files]
            output_format = params.get("output_format", "json").lower()
            output_file_path = params.get("output_file_path", "")
            framework = params.get("framework", "")
            frameworks = params.get("frameworks", [])  # multiple --framework
            skip_framework = params.get("skip_framework", "")
            skip_frameworks = params.get("skip_frameworks", [])
            skip_path = params.get("skip_path", "")
            skip_paths = params.get("skip_paths", [])
            check = params.get("check", "")
            skip_check = params.get("skip_check", "")
            soft_fail = params.get("soft_fail", False)
            soft_fail_on = params.get("soft_fail_on", "")
            hard_fail_on = params.get("hard_fail_on", "")
            bc_api_key = params.get("bc_api_key", "")
            prisma_api_url = params.get("prisma_api_url", "")
            config_file = params.get("config_file", "")
            baseline = params.get("baseline", "")
            create_baseline = params.get("create_baseline", False)
            compact = params.get("compact", False)
            quiet = params.get("quiet", False)
            support = params.get("support", False)
            additional_args = params.get("additional_args", "")

            valid_outputs = {"cli", "csv", "cyclonedx", "cyclonedx_json", "json", "junitxml",
                            "github_failed_only", "gitlab_sast", "sarif", "spdx"}
            if output_format not in valid_outputs:
                output_format = "json"

            command_parts = ["checkov"]
            if support:
                command_parts.append("--support")
            if files:
                for f in files:
                    command_parts.extend(["-f", resolve_windows_path(f)])
            else:
                resolved = resolve_windows_path(target)
                command_parts.extend(["-d", resolved])
            command_parts.extend(["-o", output_format])
            if output_file_path:
                command_parts.extend(["--output-file-path", resolve_windows_path(output_file_path)])
            for fw in (frameworks if isinstance(frameworks, list) else [frameworks] if frameworks else []):
                if fw:
                    command_parts.extend(["--framework", fw])
            if framework:
                command_parts.extend(["--framework", framework])
            for sf in (skip_frameworks if isinstance(skip_frameworks, list) else [skip_frameworks] if skip_frameworks else []):
                if sf:
                    command_parts.extend(["--skip-framework", sf])
            if skip_framework:
                command_parts.extend(["--skip-framework", skip_framework])
            for sp in (skip_paths if isinstance(skip_paths, list) else [skip_paths] if skip_paths else []):
                if sp:
                    command_parts.extend(["--skip-path", sp])
            if skip_path:
                command_parts.extend(["--skip-path", skip_path])
            if check:
                command_parts.extend(["-c", check])
            if skip_check:
                command_parts.extend(["--skip-check", skip_check])
            if soft_fail:
                command_parts.append("--soft-fail")
            if soft_fail_on:
                command_parts.extend(["--soft-fail-on", soft_fail_on])
            if hard_fail_on:
                command_parts.extend(["--hard-fail-on", hard_fail_on])
            if bc_api_key:
                command_parts.extend(["--bc-api-key", bc_api_key])
            if prisma_api_url:
                command_parts.extend(["--prisma-api-url", prisma_api_url])
            if config_file:
                command_parts.extend(["--config-file", resolve_windows_path(config_file)])
            if baseline:
                command_parts.extend(["--baseline", resolve_windows_path(baseline)])
            if create_baseline:
                command_parts.append("--create-baseline")
            if compact:
                command_parts.append("--compact")
            if quiet:
                command_parts.append("--quiet")
            if additional_args:
                command_parts.append(additional_args)

            command = " ".join(command_parts)
            result = execute_command(command, timeout=3600)
            if not files:
                result["original_path"] = target
                result["resolved_path"] = resolve_windows_path(target)
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
