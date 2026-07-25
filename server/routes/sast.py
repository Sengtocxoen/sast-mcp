"""
SAST tool endpoints: Opengrep, Bearer, Graudit, Bandit, Gosec, Brakeman, NodeJSScan, ESLint.
Edit this file to fix or tune any of these tools.
"""
import json
import logging
import shlex
import traceback
from typing import Any, Dict

from flask import Flask, request, jsonify

from config import (
    BANDIT_TIMEOUT,
    FORCE_SYNC_SCANS,
    OPENGREP_TIMEOUT,
)
from core import (
    execute_command,
    resolve_grep_engine,
    resolve_windows_path,
    validate_scan_target,
    run_scan_in_background,
    run_scan_synchronously,
    response_as_toon,
)


def _safe_args(additional_args: str) -> str:
    """Split additional_args and re-quote each token to prevent shell injection."""
    if not additional_args:
        return ""
    try:
        tokens = shlex.split(additional_args)
    except ValueError:
        tokens = additional_args.split()
    return " ".join(shlex.quote(t) for t in tokens)

logger = logging.getLogger(__name__)


def _opengrep_scan(params: Dict[str, Any]) -> Dict[str, Any]:
    target = params.get("target", ".")
    config = params.get("config", "auto")
    lang = params.get("lang", "")
    severity = params.get("severity", "")
    output_format = params.get("output_format", "json")
    additional_args = params.get("additional_args", "")
    resolved_target = validate_scan_target(target)
    engine = resolve_grep_engine()
    command = f"{engine} scan --config={shlex.quote(config)}"
    if lang:
        command += f" --lang={shlex.quote(lang)}"
    if severity:
        command += f" --severity={shlex.quote(severity)}"
    command += f" --{shlex.quote(output_format)}"
    if additional_args:
        command += f" {_safe_args(additional_args)}"
    command += f" {shlex.quote(resolved_target)}"
    result = execute_command(command, timeout=OPENGREP_TIMEOUT)
    result["original_path"] = target
    result["resolved_path"] = resolved_target
    # Opengrep/Semgrep exit codes:
    #   0 = no findings
    #   1 = findings found (success — NOT an error)
    #   2 = fatal error (bad config, crash, etc.)
    return_code = result.get("return_code", 0)
    if return_code == 2 or (return_code not in (0, 1) and not result.get("stdout")):
        result["error"] = result.get("stderr", "opengrep/semgrep failed with no output")
        result["summary"] = {}
        return result
    summary = {}
    if output_format == "json" and result.get("stdout"):
        try:
            parsed = json.loads(result["stdout"])
            result["parsed_output"] = parsed
            if "results" in parsed:
                summary["total_findings"] = len(parsed["results"])
            # "errors" in opengrep JSON are parse warnings (files it couldn't analyze),
            # not tool failures. Surface as a warning count, not as an error.
            if "errors" in parsed:
                parse_errors = parsed["errors"]
                summary["total_parse_warnings"] = len(parse_errors)
                if parse_errors:
                    result["parse_warnings"] = parse_errors
        except Exception:
            pass
    result["summary"] = summary
    return result


def register(app: Flask) -> None:
    @app.route("/api/sast/opengrep", methods=["POST"])
    def opengrep():
        try:
            params = request.json or {}
            force_sync = params.get("force_sync", False)
            background = params.get("background", not FORCE_SYNC_SCANS)
            if FORCE_SYNC_SCANS or force_sync or not background:
                result = run_scan_synchronously("opengrep", params, _opengrep_scan)
                return jsonify(result)
            result = run_scan_in_background("opengrep", params, _opengrep_scan)
            return jsonify(result)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"opengrep: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    # Alias: semgrep is CLI-compatible with opengrep (opengrep is a fork of it),
    # so clients may call either endpoint. Both run the same resolver-backed scan.
    @app.route("/api/sast/semgrep", methods=["POST"])
    def semgrep():
        try:
            params = request.json or {}
            force_sync = params.get("force_sync", False)
            background = params.get("background", not FORCE_SYNC_SCANS)
            if FORCE_SYNC_SCANS or force_sync or not background:
                result = run_scan_synchronously("semgrep", params, _opengrep_scan)
                return jsonify(result)
            result = run_scan_in_background("semgrep", params, _opengrep_scan)
            return jsonify(result)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
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
            resolved_target = validate_scan_target(target)
            command = f"bearer scan {shlex.quote(resolved_target)} --quiet"
            if scanner:
                command += f" --scanner={shlex.quote(scanner)}"
            if output_format:
                command += f" --format={shlex.quote(output_format)}"
            if only_policy:
                command += f" --only-policy={shlex.quote(only_policy)}"
            if severity:
                command += f" --severity={shlex.quote(severity)}"
            if additional_args:
                command += f" {_safe_args(additional_args)}"
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
            # graudit v4.0 removed the "all" db — default to no -d flag (uses built-in defaults)
            database = params.get("database", "")
            additional_args = params.get("additional_args", "")
            resolved_target = validate_scan_target(target)
            command = "graudit"
            if database:
                command += f" -d {shlex.quote(database)}"
            if additional_args:
                command += f" {_safe_args(additional_args)}"
            command += f" {shlex.quote(resolved_target)}"
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
            resolved_target = validate_scan_target(target)
            command = f"bandit -r {shlex.quote(resolved_target)} -f {shlex.quote(output_format)}"
            if severity_level:
                sev = severity_level.upper()
                if sev not in ("LOW", "MEDIUM", "HIGH"):
                    return jsonify({"error": f"Invalid severity_level: {severity_level}"}), 400
                command += f" -ll -l {sev}"
            if confidence_level:
                conf = confidence_level.upper()
                if conf not in ("LOW", "MEDIUM", "HIGH"):
                    return jsonify({"error": f"Invalid confidence_level: {confidence_level}"}), 400
                command += f" -ii -i {conf}"
            if additional_args:
                command += f" {_safe_args(additional_args)}"
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
            exclude_dirs = params.get("exclude_dirs", "")
            command = f"gosec -fmt={shlex.quote(output_format)}"
            if severity:
                command += f" -severity={shlex.quote(severity)}"
            if confidence:
                command += f" -confidence={shlex.quote(confidence)}"
            if exclude_dirs:
                command += f" -exclude-dir={shlex.quote(exclude_dirs)}"
            if additional_args:
                command += f" {_safe_args(additional_args)}"
            # gosec uses ./... style patterns — only quote if it looks like a real path
            command += f" {shlex.quote(target) if target.startswith('/') or ':' in target else target}"
            result = execute_command(command, timeout=300)
            # Detect SSA panic (gosec bug on complex codebases)
            stderr = result.get("stderr", "")
            if "panic" in stderr.lower() or "nil pointer dereference" in stderr.lower():
                result["warnings"] = result.get("warnings", [])
                result["warnings"].append(
                    "gosec SSA analyzer panicked on one or more packages (gosec internal bug). "
                    "Partial results may be available. Use exclude_dirs param to skip problematic packages."
                )
                result["partial_results"] = True
                result["success"] = bool(result.get("stdout"))
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
            resolved_target = validate_scan_target(target)
            command = f"brakeman -p {shlex.quote(resolved_target)} -f {shlex.quote(output_format)}"
            if confidence_level:
                command += f" -w {shlex.quote(confidence_level)}"
            if additional_args:
                command += f" {_safe_args(additional_args)}"
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
                paths = [validate_scan_target(p) for p in (paths_param if isinstance(paths_param, list) else [paths_param])]
            else:
                paths = [validate_scan_target(params.get("target", "."))]
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
                command_parts.extend(["-o", shlex.quote(output_file)])
            if config_file:
                command_parts.extend(["-c", shlex.quote(validate_scan_target(config_file))])
            if missing_controls:
                command_parts.append("--missing-controls")
            if exit_warning:
                command_parts.append("-w")
            if additional_args:
                command_parts.extend(shlex.split(_safe_args(additional_args)))
            command_parts.extend(shlex.quote(p) for p in paths)
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
            resolved_target = validate_scan_target(target)
            # ESLint v9 dropped .eslintrc.* format by default — force legacy config lookup
            command = f"ESLINT_USE_FLAT_CONFIG=false eslint {shlex.quote(resolved_target)} -f {shlex.quote(output_format)}"
            if config:
                command += f" -c {shlex.quote(validate_scan_target(config))}"
            if fix:
                command += " --fix"
            if additional_args:
                command += f" {_safe_args(additional_args)}"
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
