"""Secret scanning: TruffleHog, Gitleaks. Edit here to fix or tune these tools."""
import json
import logging
import os
import tempfile
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
        """Gitleaks writes findings ONLY to --report-path.

        Without that flag, stdout carries just the banner and a "leaks found: N"
        log line, so the TOON wrapper parsed zero findings and reported "No
        findings detected" — a false clean. Measured against
        Deca/deca-uam-api: gitleaks itself said `leaks found: 9` while this
        endpoint returned total_findings: 0. The report path is therefore no
        longer optional; one is created when the caller omits it.
        """
        tmp_report = ""
        try:
            params = request.json or {}
            target = params.get("target", ".")
            config = params.get("config", "")
            report_format = params.get("report_format", "json")
            report_path = params.get("report_path", "")
            verbose = params.get("verbose", False)
            additional_args = params.get("additional_args", "")
            resolved = resolve_windows_path(target)

            if not report_path:
                fd, tmp_report = tempfile.mkstemp(prefix="gitleaks-", suffix=f".{report_format}")
                os.close(fd)
                report_path = tmp_report

            command = f"gitleaks detect --source={resolved} --report-format={report_format}"
            if config:
                command += f" --config={config}"
            command += f" --report-path={report_path}"
            if verbose:
                command += " -v"
            # Limit git history depth by default to avoid timeout on large repos
            # (3000+ refs). --log-opts is invalid in --no-git mode, where there is
            # no history to walk, so it must not be added then.
            extra = additional_args or ""
            if "--log-opts" not in extra and "--no-git" not in extra:
                command += " --log-opts=--max-count=1000"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, timeout=MAX_TIMEOUT)
            result["original_path"] = target
            result["resolved_path"] = resolved
            result["report_path"] = report_path

            findings = None
            if os.path.exists(report_path):
                try:
                    with open(report_path, errors="ignore") as f:
                        body = f.read()
                    if report_format == "json":
                        findings = json.loads(body) if body.strip() else []
                        result["parsed_report"] = findings
                    else:
                        result["parsed_report"] = body
                except Exception as ex:
                    logger.warning(f"Read report: {ex}")

            rc = result.get("return_code")
            if isinstance(findings, list):
                result["summary"] = {"total_findings": len(findings)}
            # rc 1 == leaks found. So an empty or unreadable report CONTRADICTS the
            # exit code, and reporting zero would be the original false clean all
            # over again (an auto-created report file that gitleaks never wrote to
            # still exists and still parses as []). Only a non-empty report is
            # allowed to answer "how many".
            if rc == 1 and not findings:
                result["success"] = False
                result["scan_proven"] = False
                result.pop("summary", None)
                result["error"] = (
                    "gitleaks exited 1 (leaks found) but its report is empty or unreadable — "
                    "treat this as unproven, not clean")
            elif rc not in (0, 1) and findings is None:
                result["success"] = False
                result["scan_proven"] = False
                result["error"] = result.get("stderr") or f"gitleaks failed (exit {rc})"
            return jsonify(response_as_toon("gitleaks", params, result))
        except Exception as e:
            logger.error(f"gitleaks: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500
        finally:
            if tmp_report:
                try:
                    os.unlink(tmp_report)
                except OSError:
                    pass
